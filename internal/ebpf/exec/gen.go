package exec

//go:generate go tool bpf2go -type event exec ../../../ebpf/syscalls/exec.c -- -I./../../../vmlinux/ -I./../../../ebpf/
