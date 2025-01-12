#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define BUF_SIZE 256
#define COMM_SIZE 64
#define MAX_STACK 15

struct processInfo
{
    __u32 pid;
    __u8 comm[BUF_SIZE]; // name of process

    __u32 spid[MAX_STACK];
    __u8 scomm[MAX_STACK][COMM_SIZE]; // name of process
};