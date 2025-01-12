
<div align="center"><img src="assets/gopher.webp" width="200"/></div>



# TODO:
* Resolve fd in file.c (e.g. openat)
* improve the process infomration (identify docker container, add process stack)
* arg for output to file (redirecting to file results in loop) and filtering


# requirements for building on debian
* see https://ebpf-go.dev/guides/getting-started/#whats-next
* apt install libbpf-dev
* sudo ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm
* clang, apt install clang, add /lib/llvm-14/bin/ to PATH
* sudo apt-get install gcc-multilib



# References
* https://gist.github.com/oghie/b4e3accf1f87afcb939f884723e2b462 https://medium.com/@nurkholish.halim/a-deep-dive-into-ebpf-writing-an-efficient-dns-monitoring-2c9dea92abdf