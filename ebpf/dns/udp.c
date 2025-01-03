#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <string.h>


#define DNS_PORT 53
#define IPPROTO_UDP 17 // Define IPPROTO_UDP if not available

// Structure to send DNS data to userspace
struct event
{
    __u32 pid;
    __u8 request[513];
};

// Needed to not have event struct be optmized away
struct event *unused __attribute__((unused));

// Ring buffer map for userspace communication
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12); // 4KB buffer size
} ring_buffer SEC(".maps");

SEC("xdp")
int dns_monitor(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
    {
        return XDP_PASS;
    }

    // Check if it's an IP packet
    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        return XDP_PASS;
    }

    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
    {
        return XDP_PASS;
    }

    // Check if it's a UDP packet
    if (iph->protocol != IPPROTO_UDP)
    {
        return XDP_PASS;
    }

    struct udphdr *udph = (struct udphdr *)((void *)iph + (iph->ihl * 4));
    if ((void *)(udph + 1) > data_end)
    {
        return XDP_PASS;
    }

    bpf_printk("ingress if %d srcport: %d dest port %d", ctx->ingress_ifindex, bpf_ntohs(udph->source), bpf_ntohs(udph->dest));

    // Check if the destination port is DNS (53)
    if (udph->source != bpf_htons(DNS_PORT))
    {
        return XDP_PASS;
    }
    bpf_printk("got dns packet");

    // DNS payload starts after UDP header
    void *dns_payload = (void *)(udph + 1);
    if (dns_payload >= data_end)
    {
        return XDP_PASS;
    }

    // Parse the DNS query
    struct event *event = bpf_ringbuf_reserve(&ring_buffer, sizeof(*event), 0);
    if (!event)
    {
        return XDP_PASS;
    }

    __builtin_memset(event, 0, sizeof(*event));

    // int cpyLen = sizeof(event->request);
    // if (sizeof(dns_payload) < cpyLen){
    //     cpyLen = sizeof(dns_payload);
    // }
    // Calculate the available length of the DNS payload
    __u64 available_length = (void *)data_end - dns_payload;

    // Limit the copy length to the size of the request buffer
    __u64 copy_length = available_length < sizeof(event->request) ? available_length : sizeof(event->request);
    for (__u64 i = 0; i < copy_length; i++)
    {
        if (dns_payload + i >= data_end)
            break;
        event->request[i] = ((char *)dns_payload)[i];
    }

    bpf_printk("send dns to userspace");
    // Send the event to userspace
    bpf_ringbuf_submit(event, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "Dual MIT/GPL";
