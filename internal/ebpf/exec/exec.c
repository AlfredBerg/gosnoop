// go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ptrace.h>
#include <linux/types.h>

#define BUF_SIZE 254

typedef unsigned int uint32_t;

struct event
{
    __u32 pid;
    __u8 path[BUF_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} ring_buffer SEC(".maps");

// from /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format
struct exec_ctx
{
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    int __syscall_nr;
    const char *filename;
    const char *const *argv;
    const char *const *envp;
};

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct exec_ctx *ctx)
{
    struct event *event = 0;
    event = bpf_ringbuf_reserve(&ring_buffer, sizeof(struct event), 0);
    if (!event)
    {
        return 0;
    }

    bpf_probe_read_user_str(&event->path, sizeof(event->path), (void *)ctx->filename);

    bpf_printk("Program Pathname: %s", event->path);

    bpf_ringbuf_submit(event, 0);

    return 0;
}

char _license[] SEC("license") = "GPL";