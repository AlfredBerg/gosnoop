package dns

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event -target amd64 dns ../../../ebpf/dns/udp.c -- -I./../../../vmlinux/ -I./../../../ebpf/
