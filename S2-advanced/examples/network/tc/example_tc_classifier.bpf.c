// MIT License - Copyright (c) 2025 dev-monsa
// S2-advanced TC: Traffic Control with QoS and flow tracking.

#include "../../../../common/include/bpf_helpers.h"
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
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

struct tc_event {
    __u64 timestamp_ns;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 protocol;
    __u32 len;
    __u32 mark;
    __u64 count;
};

struct flow_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 protocol;
};

struct flow_stats {
    __u64 packets;
    __u64 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct flow_key);
    __type(value, struct flow_stats);
} tc_flow_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} tc_events SEC(".maps");

SEC("tc")
int msb_tc_classifier(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;
    struct flow_key key = {0};
    struct flow_stats *stats, new_stats = {0};
    struct tc_event *evt;
    __u16 sport = 0, dport = 0;

    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return TC_ACT_OK;

    ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    key.saddr = ip->saddr;
    key.daddr = ip->daddr;
    key.protocol = ip->protocol;

    if (key.protocol == IPPROTO_TCP) {
        tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        sport = bpf_ntohs(tcp->source);
        dport = bpf_ntohs(tcp->dest);
    } else if (key.protocol == IPPROTO_UDP) {
        udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        sport = bpf_ntohs(udp->source);
        dport = bpf_ntohs(udp->dest);
    }

    key.sport = sport;
    key.dport = dport;

    stats = bpf_map_lookup_elem(&tc_flow_stats, &key);
    if (!stats) {
        new_stats.packets = 1;
        new_stats.bytes = skb->len;
        bpf_map_update_elem(&tc_flow_stats, &key, &new_stats, BPF_ANY);
    } else {
        __sync_fetch_and_add(&stats->packets, 1);
        __sync_fetch_and_add(&stats->bytes, skb->len);
    }

    // Sample 1/100 packets
    if (stats && (stats->packets % 100) != 0)
        return TC_ACT_OK;

    evt = bpf_ringbuf_reserve(&tc_events, sizeof(*evt), 0);
    if (!evt)
        return TC_ACT_OK;

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->saddr = key.saddr;
    evt->daddr = key.daddr;
    evt->sport = sport;
    evt->dport = dport;
    evt->protocol = key.protocol;
    evt->len = skb->len;
    evt->mark = skb->mark;
    evt->count = stats ? stats->packets : 1;

    bpf_ringbuf_submit(evt, 0);
    bpf_printk("tc: %x:%u -> %x:%u proto=%u len=%u\n", 
               key.saddr, sport, key.daddr, dport, key.protocol, skb->len);

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
