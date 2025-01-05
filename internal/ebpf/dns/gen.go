package dns

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event -target amd64 -cflags "-I/home/berg/git/gosnoop/vmlinux/" dns ../../../ebpf/dns/udp.c
