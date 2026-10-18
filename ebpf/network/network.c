// go:build ignore

// Reports which process talks to which IP endpoint.
//
// TCP outbound: a kprobe on tcp_connect, which runs inside connect() once the
//   route and the source port are chosen, so the current task is the one
//   connecting and the socket is fully addressed. Where that function cannot be
//   probed, the stable sock:inet_sock_set_state tracepoint (on the move to
//   SYN_SENT) is the fallback; it fires before the source port is picked, so it
//   reports local port 0. Later transitions (ESTABLISHED, CLOSE) happen in
//   softirq context, where "current" is whoever was interrupted, so neither
//   hook uses them.
// TCP inbound: a kretprobe on inet_csk_accept, which runs in the accepting task
//   and returns the new socket.
// UDP: kprobes on udp_sendmsg and udpv6_sendmsg. UDP has no handshake, so a
//   "connection" is the first datagram a socket sends to a given remote
//   address and port; repeats are suppressed (see seen_udp_flows).

#include <vmlinux.h>

#include "utils/arch-compat.h" // must precede bpf_tracing.h

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "utils/process-utils.h"

#define GS_AF_INET 2
#define GS_AF_INET6 10

#define GS_IPPROTO_TCP 6
#define GS_IPPROTO_UDP 17

#define DIR_OUTBOUND 1
#define DIR_INBOUND 2

// Struct to send network data and metadata to userspace. Addresses are in
// network byte order; IPv4 addresses use the first four bytes. Ports are in
// host byte order.
struct event
{
    struct processInfo processInfo;

    __u32 uid;
    __u32 netns;

    __u16 sport;
    __u16 dport;

    __u8 family;
    __u8 protocol;
    __u8 direction;
    // UDP only: the datagram carried no destination of its own and went to
    // the peer the socket was connect()ed to.
    __u8 connected;

    __u8 saddr[16];
    __u8 daddr[16];
};

// Needed to not have event struct be optmized away
struct event *unused __attribute__((unused));

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} ring_buffer SEC(".maps");

struct udp_flow_key
{
    __u64 sk;
    __u32 pid;
    __u16 sport;
    __u16 dport;
    __u8 family;
    __u8 pad[3];
    __u8 daddr[16];
};

// Least-recently-used so a process spraying datagrams at many destinations
// recycles entries instead of filling the map up.
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct udp_flow_key);
    __type(value, __u8);
} seen_udp_flows SEC(".maps");

static __always_inline struct event *reserve_event(void)
{
    struct event *event = bpf_ringbuf_reserve(&ring_buffer, sizeof(*event), 0);
    if (!event)
        return 0;

    // Zero out the struct as there might be some data from the previous use of the ring buffer
    for (int i = 0; i < sizeof(struct event); i++)
    {
        ((volatile char *)event)[i] = 0;
    }
    return event;
}

static __always_inline void fill_process(struct event *event, struct sock *sk)
{
    collectProcessInfo(&event->processInfo);
    event->uid = (__u32)bpf_get_current_uid_gid();
    event->netns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
}

static __always_inline bool is_v4_mapped(const __u8 *a)
{
    for (int i = 0; i < 10; i++)
    {
        if (a[i] != 0)
            return false;
    }
    return a[10] == 0xff && a[11] == 0xff;
}

// ---- TCP ----

// Reports a TCP socket whose addresses are all filled in.
static __always_inline void report_tcp_sock(struct sock *sk, __u8 direction)
{
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != GS_AF_INET && family != GS_AF_INET6)
        return;

    struct event *event = reserve_event();
    if (!event)
        return;

    event->protocol = GS_IPPROTO_TCP;
    event->direction = direction;
    event->family = family;
    event->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    event->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    if (family == GS_AF_INET6)
    {
        bpf_core_read(event->saddr, 16, &sk->__sk_common.skc_v6_rcv_saddr);
        bpf_core_read(event->daddr, 16, &sk->__sk_common.skc_v6_daddr);
    }
    else
    {
        bpf_core_read(event->saddr, 4, &sk->__sk_common.skc_rcv_saddr);
        bpf_core_read(event->daddr, 4, &sk->__sk_common.skc_daddr);
    }

    fill_process(event, sk);

    bpf_ringbuf_submit(event, 0);
}

SEC("kprobe/tcp_connect")
int BPF_KPROBE(tcp_connect_probe, struct sock *sk)
{
    if (sk)
        report_tcp_sock(sk, DIR_OUTBOUND);
    return 0;
}

SEC("tracepoint/sock/inet_sock_set_state")
int trace_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    if (ctx->protocol != GS_IPPROTO_TCP || ctx->newstate != TCP_SYN_SENT)
        return 0;

    struct event *event = reserve_event();
    if (!event)
        return 0;

    event->protocol = GS_IPPROTO_TCP;
    event->direction = DIR_OUTBOUND;
    event->family = ctx->family;
    event->sport = ctx->sport;
    event->dport = ctx->dport;

    if (ctx->family == GS_AF_INET6)
    {
        __builtin_memcpy(event->saddr, ctx->saddr_v6, 16);
        __builtin_memcpy(event->daddr, ctx->daddr_v6, 16);
    }
    else
    {
        __builtin_memcpy(event->saddr, ctx->saddr, 4);
        __builtin_memcpy(event->daddr, ctx->daddr, 4);
    }

    fill_process(event, (struct sock *)ctx->skaddr);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(inet_csk_accept_ret, struct sock *sk)
{
    if (!sk)
        return 0;

    // inet_csk_accept is shared with the other connection oriented protocols.
    if (BPF_CORE_READ(sk, sk_protocol) != GS_IPPROTO_TCP)
        return 0;

    report_tcp_sock(sk, DIR_INBOUND);
    return 0;
}

// ---- UDP ----

// Reports the datagram being sent unless this socket already sent one to the
// same destination. daddr must be dport's address in network byte order.
static __always_inline void report_udp(struct sock *sk, __u8 family, const __u8 *daddr, __u16 dport, __u8 connected)
{
    struct udp_flow_key key = {};
    key.sk = (__u64)sk;
    key.pid = bpf_get_current_pid_tgid() >> 32;
    key.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    key.dport = dport;
    key.family = family;
    __builtin_memcpy(key.daddr, daddr, family == GS_AF_INET6 ? 16 : 4);

    if (bpf_map_lookup_elem(&seen_udp_flows, &key))
        return;

    struct event *event = reserve_event();
    if (!event)
        return;

    event->protocol = GS_IPPROTO_UDP;
    event->direction = DIR_OUTBOUND;
    event->family = family;
    event->connected = connected;
    event->sport = key.sport;
    event->dport = dport;
    __builtin_memcpy(event->daddr, daddr, family == GS_AF_INET6 ? 16 : 4);

    if (family == GS_AF_INET6)
        bpf_core_read(event->saddr, 16, &sk->__sk_common.skc_v6_rcv_saddr);
    else
        bpf_core_read(event->saddr, 4, &sk->__sk_common.skc_rcv_saddr);

    fill_process(event, sk);

    __u8 one = 1;
    bpf_map_update_elem(&seen_udp_flows, &key, &one, BPF_ANY);

    bpf_ringbuf_submit(event, 0);
}

// Also reached for IPv4 traffic on an AF_INET6 socket: udpv6_sendmsg hands
// those to udp_sendmsg with a sockaddr_in, so they are reported here as IPv4
// and udpv6_sendmsg skips them.
SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(udp_sendmsg_probe, struct sock *sk, struct msghdr *msg, size_t len)
{
    if (!sk)
        return 0;

    void *name = BPF_CORE_READ(msg, msg_name);
    if (name)
    {
        struct sockaddr_in sin = {};
        if (bpf_probe_read_kernel(&sin, sizeof(sin), name) != 0 || sin.sin_family != GS_AF_INET)
            return 0;
        report_udp(sk, GS_AF_INET, (const __u8 *)&sin.sin_addr, bpf_ntohs(sin.sin_port), 0);
        return 0;
    }

    __u16 dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    if (dport == 0)
        return 0;
    __be32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    report_udp(sk, GS_AF_INET, (const __u8 *)&daddr, dport, 1);
    return 0;
}

SEC("kprobe/udpv6_sendmsg")
int BPF_KPROBE(udpv6_sendmsg_probe, struct sock *sk, struct msghdr *msg, size_t len)
{
    if (!sk)
        return 0;

    struct in6_addr daddr = {};
    __u16 dport;
    __u8 connected = 0;

    void *name = BPF_CORE_READ(msg, msg_name);
    if (name)
    {
        struct sockaddr_in6 sin6 = {};
        if (bpf_probe_read_kernel(&sin6, sizeof(sin6), name) != 0 || sin6.sin6_family != GS_AF_INET6)
            return 0;
        daddr = sin6.sin6_addr;
        dport = bpf_ntohs(sin6.sin6_port);
    }
    else
    {
        dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
        if (dport == 0)
            return 0;
        bpf_core_read(&daddr, sizeof(daddr), &sk->__sk_common.skc_v6_daddr);
        connected = 1;
    }

    // Handled by the udp_sendmsg probe.
    if (is_v4_mapped((const __u8 *)&daddr))
        return 0;

    report_udp(sk, GS_AF_INET6, (const __u8 *)&daddr, dport, connected);
    return 0;
}

char _license[] SEC("license") = "GPL";
