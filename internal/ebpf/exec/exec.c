//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>


SEC("kprobe/sys_execve") 
int count_packets() {
    bpf_printk("running");
    return 0;
}

char _license[] SEC("license") = "GPL";