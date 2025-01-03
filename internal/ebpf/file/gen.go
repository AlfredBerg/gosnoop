package file

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event -cflags "-I./../../../vmlinux/" file ../../../ebpf/syscalls/file.c
