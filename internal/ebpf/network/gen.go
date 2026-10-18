package network

//go:generate go tool bpf2go -type event -target amd64,arm64 network ../../../ebpf/network/network.c -- -I./../../../vmlinux/ -I./../../../ebpf/
