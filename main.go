package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"gosnoop/internal/ebpf/dns"
	"gosnoop/internal/ebpf/exec"
	"gosnoop/internal/ebpf/file"
	"gosnoop/internal/event"
	"gosnoop/internal/filter"
	"gosnoop/internal/support"

	"github.com/cilium/ebpf/rlimit"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

type eventCollector interface {
	// Name is the identifier used by the -collectors flag.
	Name() string
	// ReceiveEvents loads and attaches the collector's probes. It returns an
	// error rather than exiting, so one unsupported probe cannot take the whole
	// tool down with it.
	ReceiveEvents(ctx context.Context, wg *sync.WaitGroup, c chan<- event.Event) error
	// Close releases the probes. It is safe to call on a collector whose
	// ReceiveEvents failed.
	Close() error
}

// collectorNames lists every collector, in the order they are started.
var collectorNames = []string{"exec", "file", "dns"}

func newCollector(name string, opts options) eventCollector {
	switch name {
	case "exec":
		return &exec.Exec{IncludeEnvp: opts.includeEnvp}
	case "file":
		return &file.File{}
	case "dns":
		return &dns.Dns{}
	}
	return nil
}

type options struct {
	collectors  []string
	includeEnvp bool
	keepGoing   bool
	filter      filter.Filter
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("gosnoop: ")

	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run() error {
	opts, err := parseFlags()
	if err != nil {
		return err
	}

	// Fail on an unusable kernel with something actionable, rather than letting
	// the first collector die with a raw loader dump.
	if err := support.Check(); err != nil {
		return err
	}

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing the memlock limit: %s", support.Describe(err))
	}

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	ctx, ctxCancel := context.WithCancel(context.Background())
	defer ctxCancel()

	wg := sync.WaitGroup{}
	events := make(chan event.Event)

	started := make([]eventCollector, 0, len(opts.collectors))
	var failures []error

	for _, name := range opts.collectors {
		c := newCollector(name, opts)
		if err := c.ReceiveEvents(ctx, &wg, events); err != nil {
			failures = append(failures, fmt.Errorf("%s collector: %w", name, err))
			log.Printf("warning: the %s collector is disabled: %s", name, support.Describe(err))
			continue
		}
		started = append(started, c)
	}

	defer func() {
		for _, c := range started {
			if err := c.Close(); err != nil {
				log.Printf("warning: %s collector: %s", c.Name(), err)
			}
		}
	}()

	if len(started) == 0 {
		return fmt.Errorf("no collector could be started:\n%w", errors.Join(failures...))
	}
	if len(failures) > 0 && !opts.keepGoing {
		return fmt.Errorf("%d of %d collectors failed to start and -keep-going is off", len(failures), len(opts.collectors))
	}

	names := make([]string, 0, len(started))
	for _, c := range started {
		names = append(names, c.Name())
	}
	log.Printf("tracing with the %s collector(s), press ctrl-c to stop", strings.Join(names, ", "))

	go func() {
		<-stopper
		ctxCancel()
		wg.Wait()
		close(events)
	}()

	out := json.NewEncoder(os.Stdout)
	for e := range events {
		if !opts.filter.Match(e.Base()) {
			continue
		}
		if err := out.Encode(e); err != nil {
			log.Printf("warning: failed to write event: %s", err)
		}
	}

	return nil
}

func parseFlags() (options, error) {
	var (
		collectors   = flag.String("collectors", strings.Join(collectorNames, ","), "comma separated collectors to run: "+strings.Join(collectorNames, ", "))
		pidList      = flag.String("pid", "", "only report events from these pids (comma separated)")
		pidTreeList  = flag.String("pid-tree", "", "only report events from these pids and anything they spawned (comma separated)")
		commList     = flag.String("comm", "", "only report events from processes with these command names (comma separated)")
		excludeComms = flag.String("exclude-comm", "", "drop events from processes with these command names (comma separated)")
		includeEnvp  = flag.Bool("envp", false, "include the environment of exec events, which is noisy and often sensitive")
		includeSelf  = flag.Bool("include-self", false, "report gosnoop's own events instead of hiding them")
		keepGoing    = flag.Bool("keep-going", true, "keep running when some collectors fail to start")
		showVersion  = flag.Bool("version", false, "print the version and exit")
	)

	flag.Usage = usage
	flag.Parse()

	if *showVersion {
		fmt.Printf("gosnoop %s\n", version)
		os.Exit(0)
	}
	if flag.NArg() > 0 {
		return options{}, fmt.Errorf("unexpected argument %q, gosnoop takes flags only", flag.Arg(0))
	}

	opts := options{
		includeEnvp: *includeEnvp,
		keepGoing:   *keepGoing,
	}

	requested := splitList(*collectors)

	for _, name := range collectorNames {
		if slices.Contains(requested, name) {
			opts.collectors = append(opts.collectors, name)
		}
	}
	for _, name := range requested {
		if !slices.Contains(collectorNames, name) {
			return options{}, fmt.Errorf("unknown collector %q, pick from %s", name, strings.Join(collectorNames, ", "))
		}
	}
	if len(opts.collectors) == 0 {
		return options{}, errors.New("-collectors is empty, there would be nothing to trace")
	}

	pids, err := parsePIDs(*pidList, "-pid")
	if err != nil {
		return options{}, err
	}
	treePIDs, err := parsePIDs(*pidTreeList, "-pid-tree")
	if err != nil {
		return options{}, err
	}

	opts.filter = filter.Filter{
		PIDs:         pids,
		TreePIDs:     treePIDs,
		Comms:        parseSet(*commList),
		ExcludeComms: parseSet(*excludeComms),
	}
	if !*includeSelf {
		// Without this, tracing file events means tracing the writes gosnoop
		// makes to report file events.
		opts.filter.ExcludePIDs = map[int]bool{os.Getpid(): true}
	}

	return opts, nil
}

func usage() {
	out := flag.CommandLine.Output()
	fmt.Fprintf(out, `gosnoop %s - trace process execution, file access and DNS lookups with eBPF.

Requires root (or CAP_BPF, CAP_PERFMON and CAP_SYS_RESOURCE) and a kernel built
with BTF. Events are written to stdout as one JSON object per line.

Usage:
  gosnoop [flags]

Flags:
`, version)
	flag.PrintDefaults()
	fmt.Fprint(out, `
Examples:
  gosnoop                                  trace everything
  gosnoop -collectors dns                  only trace DNS lookups
  gosnoop -collectors exec,file -comm curl trace what curl runs and opens
  gosnoop -pid-tree 4242                   trace pid 4242 and its descendants
`)
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func parseSet(s string) map[string]bool {
	parts := splitList(s)
	if len(parts) == 0 {
		return nil
	}
	set := make(map[string]bool, len(parts))
	for _, part := range parts {
		set[part] = true
	}
	return set
}

func parsePIDs(s, flagName string) (map[int]bool, error) {
	parts := splitList(s)
	if len(parts) == 0 {
		return nil, nil
	}
	set := make(map[int]bool, len(parts))
	for _, part := range parts {
		pid, err := strconv.Atoi(part)
		if err != nil || pid < 1 {
			return nil, fmt.Errorf("%s: %q is not a pid", flagName, part)
		}
		set[pid] = true
	}
	return set, nil
}
