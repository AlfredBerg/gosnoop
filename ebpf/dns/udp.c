#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <string.h>

#define DNS_PORT 53
#define IPPROTO_UDP 17

#define PAYLOAD_MAX 512

// Struct to send DNS data and metadata to userspace
struct event
{
    __u32 pid;

    __u16 sport;
    __u16 dport;
    __u32 saddr;
    __u32 daddr;
    __u32 ifindex;

    __u8 comm[64];

    __u16 pkt_len;
    __u8 pkt_data[PAYLOAD_MAX];
};

// Needed to not have event struct be optmized away
struct event *unused __attribute__((unused));

// Ring buffer for kernel -> userspace communication
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
} ring_buffer SEC(".maps");

//TODO: Does ipv6 work?
SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(udp_sendmsg_probe, struct sock *sk, struct msghdr *msg, size_t len)
{
    if (!sk)
        return 0;

    __u16 sport, dport;
    BPF_CORE_READ_INTO(&sport, sk, __sk_common.skc_num);
    BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);

    if (bpf_ntohs(dport) != DNS_PORT)
        return 0;

    struct event *event = bpf_ringbuf_reserve(&ring_buffer, sizeof(*event), 0);
    if (!event)
        return 0;

    if (msg)
    {
        struct iovec *iov;
        BPF_CORE_READ_INTO(&iov, msg, msg_iter.iov);
        if (iov)
        {
            void *base;
            size_t len;
            BPF_CORE_READ_INTO(&base, iov, iov_base);
            BPF_CORE_READ_INTO(&len, iov, iov_len);

            if (base && len <= sizeof(event->pkt_data))
            {
                bpf_probe_read_user(event->pkt_data, len, base);
                event->pkt_len = len;
            }
        }
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    event->sport = sport;
    event->dport = dport;
    BPF_CORE_READ_INTO(&event->saddr, sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&event->daddr, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&event->ifindex, sk, __sk_common.skc_bound_dev_if);
    event->saddr = bpf_htonl(event->saddr);
    event->daddr = bpf_htonl(event->daddr);
    event->sport = bpf_htons(event->sport);
    event->dport = bpf_htons(event->dport);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char _license[] SEC("license") = "Dual MIT/GPL";
