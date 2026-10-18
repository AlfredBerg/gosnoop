package dnsanswer

//go:generate go tool bpf2go -type event -target amd64,arm64 dnsAnswer ../../../ebpf/dnsanswer/answer.c -- -I./../../../vmlinux/ -I./../../../ebpf/
