package file

//go:generate go tool bpf2go -type event file ../../../ebpf/syscalls/file.c -- -I./../../../vmlinux/ -I./../../../ebpf/
