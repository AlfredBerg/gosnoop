// Package support probes the kernel for the features GoSnoop needs, and turns
// eBPF loader failures into something a human can act on instead of a raw
// verifier or relocation dump.
package support

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/features"
)

// BTFPath is where the kernel exposes its own BTF. GoSnoop's probes are CO-RE
// relocated against it at load time.
const BTFPath = "/sys/kernel/btf/vmlinux"

// tracefsPaths are the usual mount points for the tracefs that holds the
// syscall tracepoints the file and exec collectors attach to.
var tracefsPaths = []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"}

// Check reports whether this kernel can run GoSnoop at all. The returned error
// lists every unmet requirement together with what to do about it.
//
// It deliberately does not probe individual attach points: a single missing
// tracepoint should cost you one collector, not the whole tool.
func Check() error {
	var problems []string

	for _, check := range []func() error{checkBTF, checkRingbuf, checkProgramTypes, checkTracefs} {
		err := check()
		switch {
		case err == nil:
		case errors.Is(err, errNeedPrivileges):
			// Nothing past this point can be established without privileges, so
			// say that once instead of repeating it per feature.
			return fmt.Errorf("GoSnoop cannot probe the kernel: %v. %s", err, privilegeHint)
		default:
			problems = append(problems, err.Error())
		}
	}

	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("this kernel cannot run GoSnoop:\n  - %s", strings.Join(problems, "\n  - "))
}

// errNeedPrivileges marks a check that could not run because the process is
// missing the capabilities eBPF needs, rather than because the kernel is unfit.
var errNeedPrivileges = errors.New("permission denied")

func checkBTF() error {
	if _, err := os.Stat(BTFPath); errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%s is missing, so this kernel was built without BTF. "+
			"GoSnoop's probes are CO-RE relocated and need CONFIG_DEBUG_INFO_BTF=y", BTFPath)
	}

	if _, err := btf.LoadKernelSpec(); err != nil {
		return fmt.Errorf("the kernel BTF at %s could not be parsed: %v. "+
			"This usually means github.com/cilium/ebpf is older than the kernel's BTF format; upgrade it and rebuild", BTFPath, err)
	}
	return nil
}

func checkRingbuf() error {
	if err := features.HaveMapType(ebpf.RingBuf); err != nil {
		return describe("BPF ring buffer maps", err, "they require Linux 5.8 or later")
	}
	return nil
}

func checkProgramTypes() error {
	if err := features.HaveProgramType(ebpf.TracePoint); err != nil {
		return describe("tracepoint programs", err, "they require Linux 4.7 or later")
	}
	if err := features.HaveProgramType(ebpf.Kprobe); err != nil {
		return describe("kprobe programs", err, "they require Linux 4.1 or later")
	}
	return nil
}

// checkTracefs only looks for the mount point. The directory is root-only on
// most distributions, so "it exists but I may not read it" is as much as we can
// establish before actually attaching.
func checkTracefs() error {
	for _, path := range tracefsPaths {
		if _, err := os.Stat(filepath.Join(path, "events")); err == nil || errors.Is(err, fs.ErrPermission) {
			return nil
		}
	}
	return fmt.Errorf("no tracefs found under %s, so the syscall tracepoints are unreachable. "+
		"Mount it with `mount -t tracefs tracefs /sys/kernel/tracing`", strings.Join(tracefsPaths, " or "))
}

func describe(what string, err error, requirement string) error {
	switch {
	case errors.Is(err, ebpf.ErrNotSupported):
		return fmt.Errorf("%s are not supported by this kernel: %s", what, requirement)
	case errors.Is(err, fs.ErrPermission):
		return fmt.Errorf("%s could not be probed: %w", what, errNeedPrivileges)
	default:
		return fmt.Errorf("%s could not be probed: %v", what, err)
	}
}

const privilegeHint = "Run GoSnoop as root, or grant it CAP_BPF, CAP_PERFMON and CAP_SYS_RESOURCE"

// Describe renders a collector failure for a human: the error itself, the full
// verifier log when the kernel rejected a program, and a hint about what to do.
func Describe(err error) string {
	var b strings.Builder
	b.WriteString(err.Error())

	var verr *ebpf.VerifierError
	if errors.As(err, &verr) {
		fmt.Fprintf(&b, "\nverifier log:\n%+v", verr)
	}
	if hint := Hint(err); hint != "" {
		fmt.Fprintf(&b, "\nhint: %s", hint)
	}
	return b.String()
}

// Hint returns a suggestion for an eBPF load or attach failure, or "" when
// there is nothing useful to add.
func Hint(err error) string {
	var verr *ebpf.VerifierError

	switch {
	case errors.Is(err, fs.ErrPermission):
		return privilegeHint + "."
	case errors.Is(err, ebpf.ErrNotSupported):
		return "this kernel lacks a program, map or helper the probe needs; see the requirements in the README."
	case errors.Is(err, fs.ErrNotExist):
		return "the attach point does not exist on this kernel. The syscall or kernel function is probably compiled out, renamed, or not traceable here."
	case errors.As(err, &verr):
		return "the kernel verifier rejected the program (full log above). This is a GoSnoop bug on this kernel version; please report it with the log."
	case strings.Contains(err.Error(), "apply CO-RE relocations"):
		return "a kernel struct GoSnoop reads does not look the way the probe expects on this kernel. " +
			"This is a GoSnoop portability bug; please report it with your kernel version."
	}
	return ""
}
