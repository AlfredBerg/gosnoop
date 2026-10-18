// go:build ignore

// Captures DNS answers as the process that asked receives them, so userspace
// can tell which domain an IP address was looked up as.
//
// The hook is a kretprobe on udp_recvmsg and udpv6_recvmsg rather than the
// receive path of the network stack: by the time recvmsg returns the datagram
// sits in a linear user buffer, whereas an skb on its way up the stack may keep
// its payload in page fragments that a kprobe cannot read. It also sees the
// answer a stub resolver (127.0.0.53) hands back to the application, which
// is the one that matters when the upstream query is made by someone else.

#include <vmlinux.h>

#include "utils/arch-compat.h" // must precede bpf_tracing.h

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "utils/iov-compat.h"

#define DNS_PORT 53

// A DNS header is 12 bytes; anything shorter is not an answer.
#define DNS_HEADER_LEN 12

// Answers with several records and EDNS0 routinely exceed the classic 512
// bytes; 1232 is the size resolvers are advised to advertise.
#define PAYLOAD_MAX 1536

struct event
{
    __u16 pkt_len;
    __u8 pkt_data[PAYLOAD_MAX];
};

// Needed to not have event struct be optmized away
struct event *unused __attribute__((unused));

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} ring_buffer SEC(".maps");

// What recvmsg was asked to fill, remembered from entry to return. The
// iterator no longer describes the buffer once the kernel has copied into it.
struct pending_recv
{
    __u64 base;
    __u64 buflen;
    __u64 msg_name;
    __u16 dport;
    __u16 pad[3];
};

// LRU, so a thread that dies inside recvmsg cannot leak its entry.
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct pending_recv);
} pending SEC(".maps");

static __always_inline int recv_enter(struct sock *sk, struct msghdr *msg)
{
    if (!sk)
        return 0;

    // A connected socket tells us its peer; an unconnected one has to be
    // judged by the sender address recvmsg fills in on the way out.
    __u16 dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    if (dport != 0 && dport != DNS_PORT)
        return 0;

    struct pending_recv p = {};
    void *base = NULL;
    __u64 len = 0;
    if (!getMsgFirstBuffer(msg, &base, &len))
        return 0;

    p.base = (__u64)base;
    p.buflen = len;
    p.msg_name = (__u64)BPF_CORE_READ(msg, msg_name);
    p.dport = dport;

    __u64 id = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&pending, &id, &p, BPF_ANY);
    return 0;
}

static __always_inline int recv_return(long ret)
{
    __u64 id = bpf_get_current_pid_tgid();
    struct pending_recv *p = bpf_map_lookup_elem(&pending, &id);
    if (!p)
        return 0;

    struct pending_recv call = *p;
    bpf_map_delete_elem(&pending, &id);

    if (ret < DNS_HEADER_LEN)
        return 0;

    __u16 sport = call.dport;
    if (call.msg_name)
    {
        // sin_port and sin6_port both sit right after the 2 byte family.
        __be16 port = 0;
        if (bpf_probe_read_kernel(&port, sizeof(port), (void *)(call.msg_name + 2)) != 0)
            return 0;
        sport = bpf_ntohs(port);
    }
    if (sport != DNS_PORT)
        return 0;

    __u64 n = ret;
    if (n > call.buflen)
        n = call.buflen;
    if (n > PAYLOAD_MAX)
        n = PAYLOAD_MAX;

    struct event *event = bpf_ringbuf_reserve(&ring_buffer, sizeof(*event), 0);
    if (!event)
        return 0;

    if (bpf_probe_read_user(event->pkt_data, n, (void *)call.base) != 0)
    {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    event->pkt_len = n;

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(udp_recvmsg_enter, struct sock *sk, struct msghdr *msg)
{
    return recv_enter(sk, msg);
}

SEC("kretprobe/udp_recvmsg")
int BPF_KRETPROBE(udp_recvmsg_exit, int ret)
{
    return recv_return(ret);
}

SEC("kprobe/udpv6_recvmsg")
int BPF_KPROBE(udpv6_recvmsg_enter, struct sock *sk, struct msghdr *msg)
{
    return recv_enter(sk, msg);
}

SEC("kretprobe/udpv6_recvmsg")
int BPF_KRETPROBE(udpv6_recvmsg_exit, int ret)
{
    return recv_return(ret);
}

char _license[] SEC("license") = "GPL";
