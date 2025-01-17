// go:build ignore

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <string.h>

#include "utils/process-utils.h"

#define BUF_SIZE 256
#define MAX_ARGS 15

typedef unsigned int uint32_t;

struct event
{
    struct processInfo processInfo;

    __u8 sysCall[BUF_SIZE];

    __u8 path[BUF_SIZE];
};

// Needed to not have event struct be optmized away
struct event *unused __attribute__((unused));

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} ring_buffer SEC(".maps");

// from /sys/kernel/debug/tracing/events/syscalls/sys_enter_newstat/format
struct stat_ctx
{
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    int __syscall_nr;
    const char *filename;
    // stat *statbuf;
};

SEC("tracepoint/syscalls/sys_enter_newstat")
int trace_stat(struct stat_ctx *ctx)
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

    const char syscall[] = "stat";
    memcpy(&event->sysCall, syscall, sizeof(syscall));

    collectProcessInfo(&event->processInfo);

    bpf_ringbuf_submit(event, 0);

    return 0;
}

// from /sys/kernel/debug/tracing/events/syscalls/sys_enter_newlstat/format
struct lstat_ctx
{
    unsigned short common_type;
    int common_pid;

    int __syscall_nr;
    const char *filename;
    // stat *statbuf;
};

SEC("tracepoint/syscalls/sys_enter_newlstat")
int trace_lstat(struct lstat_ctx *ctx)
{
    struct event *event = 0;
    event = bpf_ringbuf_reserve(&ring_buffer, sizeof(struct event), 0);
    if (!event)
        return 0;

    // Zero out the struct as there might be some data from the previous use of the ring buffer
    for (int i = 0; i < sizeof(struct event); i++)
    {
        ((volatile char *)event)[i] = 0;
    }

    bpf_probe_read_user_str(&event->path, sizeof(event->path), (void *)ctx->filename);

    const char syscall[] = "lstat";
    memcpy(&event->sysCall, syscall, sizeof(syscall));

    collectProcessInfo(&event->processInfo);

    bpf_ringbuf_submit(event, 0);

    return 0;
}

// from /sys/kernel/debug/tracing/events/syscalls/sys_enter_open/format
struct open_ctx
{
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    int __syscall_nr;
    const char *filename;
    // int flags;
    // umode_t mode
};

SEC("tracepoint/syscalls/sys_enter_open")
int trace_open(struct open_ctx *ctx)
{
    struct event *event = 0;
    event = bpf_ringbuf_reserve(&ring_buffer, sizeof(struct event), 0);
    if (!event)
        return 0;

    // Zero out the struct as there might be some data from the previous use of the ring buffer
    for (int i = 0; i < sizeof(struct event); i++)
    {
        ((volatile char *)event)[i] = 0;
    }

    bpf_probe_read_user_str(&event->path, sizeof(event->path), (void *)ctx->filename);

    const char syscall[] = "open";
    memcpy(&event->sysCall, syscall, sizeof(syscall));

    collectProcessInfo(&event->processInfo);

    bpf_ringbuf_submit(event, 0);

    return 0;
}

// from /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
struct openat_ctx
{
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    int __syscall_nr;
    int dfd;
    const char *filename;
    // int flags;
    // umode_t mode;
};

// TODO: The dfd file descriptor should be resolved in combination with filename as described here https://manpages.debian.org/unstable/manpages-dev/openat.2.en.html
// might be possible to use for insipration https://github.com/iovisor/bcc/commit/c110a4dd0c8f8e15e3107f3a0807683a81657cbf#diff-7e530bfb3b516e09e3747909a2e21b8ae66651315b1930ee144a5a9f82e749a8R99
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct openat_ctx *ctx)
{
    struct event *event = 0;
    event = bpf_ringbuf_reserve(&ring_buffer, sizeof(struct event), 0);
    if (!event)
        return 0;

    // Zero out the struct as there might be some data from the previous use of the ring buffer
    for (int i = 0; i < sizeof(struct event); i++)
    {
        ((volatile char *)event)[i] = 0;
    }

    bpf_probe_read_user_str(&event->path, sizeof(event->path), (void *)ctx->filename);

    // Skip printing any path if only the fd is passed (until some good way to resolve it is found)
    if (!event->path[0])
    {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }

    const char syscall[] = "openat";
    memcpy(&event->sysCall, syscall, sizeof(syscall));

    collectProcessInfo(&event->processInfo);

    bpf_ringbuf_submit(event, 0);

    return 0;
}

// from /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat2/format
struct openat2_ctx
{
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    int __syscall_nr;
    int dfd;
    const char *filename;
    struct open_how *how;
    // size_t usize
};

// TODO: The dfd file descriptor should be resolved in combination with filename as described here https://manpages.debian.org/unstable/manpages-dev/openat2.2.en.html
SEC("tracepoint/syscalls/sys_enter_openat2")
int trace_openat2(struct openat2_ctx *ctx)
{
    struct event *event = 0;
    event = bpf_ringbuf_reserve(&ring_buffer, sizeof(struct event), 0);
    if (!event)
        return 0;

    // Zero out the struct as there might be some data from the previous use of the ring buffer
    for (int i = 0; i < sizeof(struct event); i++)
    {
        ((volatile char *)event)[i] = 0;
    }

    bpf_probe_read_user_str(&event->path, sizeof(event->path), (void *)ctx->filename);

    // Skip printing any path if only the fd is passed (until some good way to resolve it is found)
    if (!event->path[0])
    {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }

    const char syscall[] = "openat2";
    memcpy(&event->sysCall, syscall, sizeof(syscall));

    collectProcessInfo(&event->processInfo);

    bpf_ringbuf_submit(event, 0);

    return 0;
}

// from /sys/kernel/debug/tracing/events/syscalls/sys_enter_creat/format
struct creat_ctx
{
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    int __syscall_nr;
    const char *pathname;
    // umode_t mode
};

SEC("tracepoint/syscalls/sys_enter_creat")
int trace_creat(struct creat_ctx *ctx)
{
    struct event *event = 0;
    event = bpf_ringbuf_reserve(&ring_buffer, sizeof(struct event), 0);
    if (!event)
        return 0;

    // Zero out the struct as there might be some data from the previous use of the ring buffer
    for (int i = 0; i < sizeof(struct event); i++)
    {
        ((volatile char *)event)[i] = 0;
    }

    bpf_probe_read_user_str(&event->path, sizeof(event->path), (void *)ctx->pathname);

    const char syscall[] = "creat";
    memcpy(&event->sysCall, syscall, sizeof(syscall));

    collectProcessInfo(&event->processInfo);

    bpf_ringbuf_submit(event, 0);

    return 0;
}

char _license[] SEC("license") = "Dual MIT/GPL";