// MIT License - Copyright (c) 2025 dev-monsa
// S2-advanced socket_filter: Socket packet filtering with deep inspection.

#include "../../../../common/include/bpf_helpers.h"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_ntohs(x) __builtin_bswap16(x)
#define bpf_htons(x) __builtin_bswap16(x)
#else
#define bpf_ntohs(x) (x)
#define bpf_htons(x) (x)
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
#include <linux/udp.h>

struct socket_filter_event {
    __u64 timestamp_ns;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 protocol;
    __u32 len;
    __u64 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} sf_counts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} sf_events SEC(".maps");

SEC("socket")
int msb_socket_filter(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;
    __u64 *count, one = 1, new_count;
    struct socket_filter_event *evt;
    __u32 saddr, daddr;
    __u16 sport = 0, dport = 0;
    __u8 protocol;

    if ((void *)(eth + 1) > data_end)
        return 0;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return 0;

    ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return 0;

    saddr = ip->saddr;
    daddr = ip->daddr;
    protocol = ip->protocol;

    if (protocol == IPPROTO_TCP) {
        tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return 0;
        sport = bpf_ntohs(tcp->source);
        dport = bpf_ntohs(tcp->dest);
    } else if (protocol == IPPROTO_UDP) {
        udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return 0;
        sport = bpf_ntohs(udp->source);
        dport = bpf_ntohs(udp->dest);
    }

    count = bpf_map_lookup_elem(&sf_counts, &daddr);
    if (!count) {
        bpf_map_update_elem(&sf_counts, &daddr, &one, BPF_ANY);
        new_count = 1;
    } else {
        new_count = __sync_fetch_and_add(count, 1) + 1;
    }

    // Sample 1/100 packets
    if ((new_count % 100) != 0)
        return 0;

    evt = bpf_ringbuf_reserve(&sf_events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->saddr = saddr;
    evt->daddr = daddr;
    evt->sport = sport;
    evt->dport = dport;
    evt->protocol = protocol;
    evt->len = skb->len;
    evt->count = new_count;

    bpf_ringbuf_submit(evt, 0);

    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
