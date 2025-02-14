
<div align="center"><img src="assets/gopher.webp" width="200"/></div>

# GoSnoop
Inspect syscalls system wide for program executions and files being read or written, as well as if files exist.  
The program also logs outgoing DNS requests.

This is achived by using eBPF.

# Examples

# Install:
Requires Linux kernel version 5.7 or later, as well as root permissions (to be able to run eBPF programs)




# TODO:
* Build terminal UI to inspect captured data
* Support dns over TCP


# Build:
## Debian
* See requirements and install dependencies from https://ebpf-go.dev/guides/getting-started/#ebpf-c-program
* install dependencies `apt install libbpf-dev clang gcc-multilib`
* `go generate ./...` to build eBPF programs and generate go files for them
* `CGO_ENABLED=0 go build` to build the program. `CGO_ENABLED=0` is required to avoid dynamic linking (making sure the program is portable)


# References
* https://gist.github.com/oghie/b4e3accf1f87afcb939f884723e2b462 https://medium.com/@nurkholish.halim/a-deep-dive-into-ebpf-writing-an-efficient-dns-monitoring-2c9dea92abdf
* https://github.com/whoopscs/dnsflux/blob/1870de1d70049f97849acc184a24c0f29f925e5a/platform/bpf/dnsfilter.c#L90
* https://github.com/iovisor/bcc/commit/c110a4dd0c8f8e15e3107f3a0807683a81657cbf#diff-7e530bfb3b516e09e3747909a2e21b8ae66651315b1930ee144a5a9f82e749a8R99 Rocky Xing for handling FD