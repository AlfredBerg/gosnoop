
<div align="center"><img src="assets/gopher.webp" width="200"/></div>



# TODO:
* Resolve fd in file.c (e.g. openat)
* improve the process info (identify docker container)
* TCP dns
* arg for output to file (redirecting to file results in loop) and filtering


# requirements for building on debian
* see https://ebpf-go.dev/guides/getting-started/#whats-next
* apt install libbpf-dev
* sudo ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm
* clang, apt install clang, add /lib/llvm-14/bin/ to PATH
* sudo apt-get install gcc-multilib



# References
* https://gist.github.com/oghie/b4e3accf1f87afcb939f884723e2b462 https://medium.com/@nurkholish.halim/a-deep-dive-into-ebpf-writing-an-efficient-dns-monitoring-2c9dea92abdf
* https://github.com/whoopscs/dnsflux/blob/1870de1d70049f97849acc184a24c0f29f925e5a/platform/bpf/dnsfilter.c#L90
* https://github.com/iovisor/bcc/commit/c110a4dd0c8f8e15e3107f3a0807683a81657cbf#diff-7e530bfb3b516e09e3747909a2e21b8ae66651315b1930ee144a5a9f82e749a8R99 Rocky Xing for handling FD