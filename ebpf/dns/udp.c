// go:build ignore

// Originally from https://github.com/whoopscs/dnsflux/blob/1870de1d70049f97849acc184a24c0f29f925e5a/platform/bpf/dnsfilter.c but adapted. Note the GPL license

#include <vmlinux.h>

#include "utils/arch-compat.h" // must precede bpf_tracing.h

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "utils/iov-compat.h"
#include "utils/process-utils.h"

#define DNS_PORT 53

#define PAYLOAD_MAX 512

// Struct to send DNS data and metadata to userspace
struct event
{
    struct processInfo processInfo;

    __u16 pkt_len;
    __u8 pkt_data[PAYLOAD_MAX];
};

// Needed to not have event struct be optmized away
struct event *unused __attribute__((unused));

// Ring buffer for kernel -> userspace communication
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} ring_buffer SEC(".maps");

static __always_inline void handleDns(struct sock *sk, struct msghdr *msg, size_t len)
{
    if (!sk)
        return;

    __u16 dport;
    BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);

    if (bpf_ntohs(dport) != DNS_PORT)
        return;

    struct event *event = bpf_ringbuf_reserve(&ring_buffer, sizeof(*event), 0);
    if (!event)
        return;

    // Zero out the struct as there might be some data from the previous use of the ring buffer
    for (int i = 0; i < sizeof(struct event); i++)
    {
        ((volatile char *)event)[i] = 0;
    }

    event->pkt_len = readMsgPayload(msg, event->pkt_data, sizeof(event->pkt_data));

    collectProcessInfo(&event->processInfo);

    bpf_ringbuf_submit(event, 0);
}

// TODO: Does ipv6 work?
SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(udp_sendmsg_probe, struct sock *sk, struct msghdr *msg, size_t len)
{
    handleDns(sk, msg, len);
    return 0;
}

// Not working currently for unclear reasons
// SEC("kprobe/tcp_sendmsg")
// int BPF_KPROBE(tcp_sendmsg_probe, struct sock *sk, struct msghdr *msg, size_t size)
// {
//     handleDns(sk, msg, size);
//     return 0;
// }

char _license[] SEC("license") = "GPL";
