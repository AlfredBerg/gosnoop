// go:build ignore

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define BUF_SIZE 256
#define MAX_ARGS 15

typedef unsigned int uint32_t;

struct event
{
    __u32 pid;
    __u8 comm[BUF_SIZE]; // name of process

    __u8 path[BUF_SIZE];
    __u8 argv[MAX_ARGS][BUF_SIZE];
    __u8 envp[MAX_ARGS][BUF_SIZE];
};

// Needed to not have event struct be optmized away
struct event *unused __attribute__((unused));

struct
{
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

    // Zero out the struct as there might be some data from the previous use of the ring buffer
    for (int i = 0; i < sizeof(struct event); i++)
    {
        ((volatile char *)event)[i] = 0;
    }

    bpf_probe_read_user_str(&event->path, sizeof(event->path), (void *)ctx->filename);

    for (int i = 0; i < MAX_ARGS; i++)
    {
        const char *argp = NULL;

        bpf_probe_read_user(&argp, sizeof(argp), &ctx->argv[i]);

        if (!argp)
        {
            break;
        }

        bpf_probe_read_user_str(event->argv[i], sizeof(event->argv[i]), argp);
    }


    for (int i = 0; i < MAX_ARGS; i++)
    {
        const char *env = NULL;

        bpf_probe_read_user(&env, sizeof(env), &ctx->envp[i]);

        if (!env)
        {
            break;
        }

        bpf_probe_read_user_str(event->envp[i], sizeof(event->envp[i]), env);
    }

    event->pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);

    return 0;
}

char _license[] SEC("license") = "Dual MIT/GPL";