package dns

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event dns ../../../ebpf/dns/udp.c
