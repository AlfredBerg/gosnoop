package dns

//go:generate go tool bpf2go -type event -target amd64,arm64 dns ../../../ebpf/dns/udp.c -- -I./../../../vmlinux/ -I./../../../ebpf/
