// MIT License - Copyright (c) 2025 dev-monsa
// S2-advanced XDP: Comprehensive packet inspection, DDoS detection, per-CPU stats, L2-L4 header parsing.

#include "../../../../common/include/bpf_helpers.h"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_ntohs(x) __builtin_bswap16(x)
#define bpf_htons(x) __builtin_bswap16(x)
#else
#define bpf_ntohs(x) (x)
#define bpf_htons(x) (x)
#endif
#include <linux/udp.h>

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

// IP protocols
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

// TCP flags
#ifndef TCP_FLAG_FIN
#define TCP_FLAG_FIN 0x01
#endif
#ifndef TCP_FLAG_SYN
#define TCP_FLAG_SYN 0x02
#endif
#ifndef TCP_FLAG_RST
#define TCP_FLAG_RST 0x04
#endif
#ifndef TCP_FLAG_ACK
#define TCP_FLAG_ACK 0x10
#endif

// Packet event structure
struct xdp_event {
    __u64 timestamp_ns;
    __u32 ifindex;
    __u32 rx_queue;
    __u32 pkt_len;
    __u16 eth_proto;
    __u8 ip_proto;
    __u8 action;  // XDP_PASS/DROP/ABORTED etc
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 tcp_flags;
};

// Per-CPU packet/byte counters
struct xdp_stats {
    __u64 packets;
    __u64 bytes;
    __u64 dropped;
    __u64 passed;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xdp_stats);
} xdp_statistics SEC(".maps");

// Source IP tracking for DDoS detection
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);   // src IP
    __type(value, __u64); // packet count
} src_ip_counts SEC(".maps");

// Ringbuf for sampled events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} xdp_events SEC(".maps");

static __always_inline int parse_packet(struct xdp_md *ctx, struct xdp_event *evt)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct udphdr *udph;
    __u16 h_proto;

    // Parse Ethernet
    if ((void *)(eth + 1) > data_end)
        return -1;
    
    h_proto = __builtin_bswap16(eth->h_proto);
    evt->eth_proto = h_proto;

    // Parse IPv4
    if (h_proto == ETH_P_IP) {
        iph = (struct iphdr *)(eth + 1);
        if ((void *)(iph + 1) > data_end)
            return -1;
        
        evt->ip_proto = iph->protocol;
        evt->src_ip = __builtin_bswap32(iph->saddr);
        evt->dst_ip = __builtin_bswap32(iph->daddr);

        // Parse TCP
        if (iph->protocol == IPPROTO_TCP) {
            tcph = (struct tcphdr *)((void *)iph + (iph->ihl * 4));
            if ((void *)(tcph + 1) > data_end)
                return 0;
            evt->src_port = __builtin_bswap16(tcph->source);
            evt->dst_port = __builtin_bswap16(tcph->dest);
            evt->tcp_flags = (((__u8 *)tcph)[13]);
        }
        // Parse UDP
        else if (iph->protocol == IPPROTO_UDP) {
            udph = (struct udphdr *)((void *)iph + (iph->ihl * 4));
            if ((void *)(udph + 1) > data_end)
                return 0;
            evt->src_port = __builtin_bswap16(udph->source);
            evt->dst_port = __builtin_bswap16(udph->dest);
        }
    }

    return 0;
}

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
    __u32 key = 0;
    struct xdp_stats *stats;
    struct xdp_event evt = {};
    __u32 pkt_len = ctx->data_end - ctx->data;
    int action = XDP_PASS;

    // Update per-CPU stats
    stats = bpf_map_lookup_elem(&xdp_statistics, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->packets, 1);
        __sync_fetch_and_add(&stats->bytes, pkt_len);
        __sync_fetch_and_add(&stats->passed, 1);
    }

    // Parse packet headers
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.ifindex = ctx->ingress_ifindex;
    evt.rx_queue = ctx->rx_queue_index;
    evt.pkt_len = pkt_len;
    evt.action = action;

    if (parse_packet(ctx, &evt) == 0) {
        // Track source IPs for DDoS detection
        if (evt.src_ip != 0) {
            __u64 *count = bpf_map_lookup_elem(&src_ip_counts, &evt.src_ip);
            if (count)
                __sync_fetch_and_add(count, 1);
            else {
                __u64 one = 1;
                bpf_map_update_elem(&src_ip_counts, &evt.src_ip, &one, BPF_ANY);
            }
        }

        // Sample 1/100 packets to ringbuf
        if ((evt.timestamp_ns % 100) == 0) {
            struct xdp_event *rb_evt = bpf_ringbuf_reserve(&xdp_events, sizeof(evt), 0);
            if (rb_evt) {
                __builtin_memcpy(rb_evt, &evt, sizeof(evt));
                bpf_ringbuf_submit(rb_evt, 0);
            }
        }

        // Kernel log for interesting packets
        if (evt.ip_proto == IPPROTO_TCP && evt.tcp_flags != 0) {
            bpf_printk("XDP: TCP %pI4:%u -> %pI4:%u flags=0x%x\n",
                       &evt.src_ip, evt.src_port, &evt.dst_ip, evt.dst_port, evt.tcp_flags);
        }
    }

    return action;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
