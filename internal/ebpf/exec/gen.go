package exec

//TODO: Don't specify /home/berg/
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event -cflags "-I./../../../vmlinux/" exec ../../../ebpf/syscalls/exec.c
