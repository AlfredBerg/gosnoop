<div align="center"><img src="assets/gopher.webp" width="200"/></div>

# GoSnoop

Trace what the machine is doing, system wide, with eBPF:

* **exec** — every program that is executed, with its arguments and (optionally) its environment
* **file** — the `stat`, `open` and `creat` families of syscalls, with the path resolved
* **dns** — outgoing DNS queries, with the questions decoded

Every event carries the process that caused it plus its ancestry, and is printed
to stdout as one JSON object per line.

# Example

<img src="assets/example.png"/>

# Requirements

* Linux 5.8 or later (the probes use BPF ring buffers)
* a kernel built with BTF — `CONFIG_DEBUG_INFO_BTF=y`, which exposes
  `/sys/kernel/btf/vmlinux`. Every mainstream distribution ships this.
* tracefs mounted at `/sys/kernel/tracing` (or `/sys/kernel/debug/tracing`)
* root, or `CAP_BPF`, `CAP_PERFMON` and `CAP_SYS_RESOURCE`

x86-64 and arm64 are both supported. GoSnoop checks all of this at startup and
tells you which requirement is missing instead of dumping a loader error.

# Usage

```
gosnoop [flags]
```

| Flag | Meaning |
| --- | --- |
| `-collectors exec,file,dns` | which collectors to run (default: all of them) |
| `-pid 123,456` | only report events from these pids |
| `-pid-tree 123` | only report events from these pids and anything they spawned |
| `-comm bash,curl` | only report events from processes with these command names |
| `-exclude-comm node` | drop events from these command names |
| `-envp` | include the environment of exec events (noisy, and often sensitive) |
| `-include-self` | report GoSnoop's own events, which are hidden by default |
| `-keep-going` | keep running when some collectors fail to start (default: true) |
| `-version` | print the version and exit |

```sh
# everything
sudo ./gosnoop

# just the DNS lookups, as they happen
sudo ./gosnoop -collectors dns

# what does this build actually run and read?
sudo ./gosnoop -pid-tree $(pgrep -f 'make build')

# pipe it through jq
sudo ./gosnoop -collectors exec | jq -r '.process.comm + ": " + .data.path'
```

If one collector cannot start — an unsupported kprobe, a tracepoint this kernel
does not have — GoSnoop prints a warning explaining why and keeps running with
the rest. Pass `-keep-going=false` if you would rather it stopped.

# Build

You need Go (see `go.mod` for the minimum), `clang` and the libbpf headers.
`clang` compiles the eBPF C into BPF bytecode; nothing links against the host
libc, so no `gcc-multilib` or glibc development headers are required.

```sh
# Debian / Ubuntu
sudo apt install clang llvm libbpf-dev

# Fedora / RHEL
sudo dnf install clang llvm libbpf-devel

# Arch
sudo pacman -S clang llvm libbpf
```

Then:

```sh
make generate   # compile the eBPF programs and regenerate the Go bindings
make build      # build the binary (static, CGO_ENABLED=0)
make test
make help       # all targets
```

`make generate` is only needed after changing something under `ebpf/`; the
generated `.o` files and bindings are checked in, so a plain `go build` works
from a clean checkout without clang.

If libbpf's headers are somewhere clang does not look by default, point
bpf2go at them:

```sh
BPF2GO_CFLAGS="-O2 -g -Wall -Werror -I/path/to/libbpf/include" make generate
```

# Troubleshooting

### `parsing .BTF header: header contains non-zero byte` / `non-zero trailer`

The kernel's BTF uses a header format that is newer than the `github.com/cilium/ebpf`
version GoSnoop was built against. Upgrade the dependency and rebuild:

```sh
go get github.com/cilium/ebpf@latest && make generate build
```

This is what made GoSnoop fail to start on kernels that set `hdr_len = 32`.

### `GoSnoop cannot probe the kernel: ... permission denied`

eBPF needs privileges. Run it under `sudo`, or grant the binary the
capabilities it needs:

```sh
sudo setcap cap_bpf,cap_perfmon,cap_sys_resource+ep ./gosnoop
```

On some hardened kernels `kernel.unprivileged_bpf_disabled=2` blocks the
capability route entirely and only root will do.

### `/sys/kernel/btf/vmlinux is missing`

The kernel was built without BTF, so CO-RE has nothing to relocate against.
There is no workaround short of a kernel with `CONFIG_DEBUG_INFO_BTF=y`. This
mostly shows up on custom or embedded kernels, and on some older LTS images.

### `no tracefs found`

Mount it:

```sh
sudo mount -t tracefs tracefs /sys/kernel/tracing
```

### `the <name> collector is disabled: ... attaching kprobe to udp_sendmsg`

The kernel function the probe hooks is not traceable here — it may be inlined,
renamed, or in the kprobe blacklist. The other collectors keep running. The DNS
collector is the usual casualty, since `udp_sendmsg` is the only hook it has.

### `file: not tracing sys_enter_open, sys_enter_newstat, ...`

Expected on arm64 and other architectures that never had those syscalls; the
equivalents (`openat`, `newfstatat`) are traced instead.

### `the kernel verifier rejected the program`

A GoSnoop bug on your kernel version. The full verifier log is printed with the
warning — please open an issue with it and your `uname -r`.

### No events at all

By default GoSnoop hides its own pid so it does not trace itself reporting on
itself. If you are testing with a filter, check it matches: `-comm` wants the
kernel's `comm` (truncated to 15 characters for the current process), not a
path.

# TODO

* Build terminal UI to inspect captured data
* Add non path arguments for newfstatat syscall
* Support dns over TCP

# References
* https://gist.github.com/oghie/b4e3accf1f87afcb939f884723e2b462 https://medium.com/@nurkholish.halim/a-deep-dive-into-ebpf-writing-an-efficient-dns-monitoring-2c9dea92abdf
* https://github.com/whoopscs/dnsflux/blob/1870de1d70049f97849acc184a24c0f29f925e5a/platform/bpf/dnsfilter.c#L90
* https://github.com/iovisor/bcc/commit/c110a4dd0c8f8e15e3107f3a0807683a81657cbf#diff-7e530bfb3b516e09e3747909a2e21b8ae66651315b1930ee144a5a9f82e749a8R99 Rocky Xing for handling FD
