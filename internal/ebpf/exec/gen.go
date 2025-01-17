package exec

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event exec ../../../ebpf/syscalls/exec.c -- -I./../../../vmlinux/ -I./../../../ebpf/
