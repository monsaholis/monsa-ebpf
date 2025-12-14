// MIT License - Copyright (c) 2025 dev-monsa
// S2-advanced sk_lookup: Socket lookup steering with connection tracking.

#include "../../../../common/include/bpf_helpers.h"
#include <linux/bpf.h>
#include <linux/in.h>
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

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct sk_lookup_event {
    __u64 timestamp_ns;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 protocol;
    __u64 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} sk_lookup_counts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} sk_lookup_events SEC(".maps");

SEC("sk_lookup")
int msb_sk_lookup(struct bpf_sk_lookup *ctx)
{
    __u32 saddr = ctx->remote_ip4;
    __u32 daddr = ctx->local_ip4;
    __u16 sport = ctx->remote_port;
    __u16 dport = ctx->local_port;
    __u64 *count, one = 1, new_count;
    struct sk_lookup_event *evt;

    count = bpf_map_lookup_elem(&sk_lookup_counts, &daddr);
    if (!count) {
        bpf_map_update_elem(&sk_lookup_counts, &daddr, &one, BPF_ANY);
        new_count = 1;
    } else {
        new_count = __sync_fetch_and_add(count, 1) + 1;
    }

    evt = bpf_ringbuf_reserve(&sk_lookup_events, sizeof(*evt), 0);
    if (!evt)
        return SK_PASS;

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->saddr = saddr;
    evt->daddr = daddr;
    evt->sport = bpf_ntohs(sport);
    evt->dport = bpf_ntohs(dport);
    evt->protocol = ctx->protocol;
    evt->count = new_count;

    bpf_printk("sk_lookup: %x:%u -> %x:%u proto=%u\n", saddr, evt->sport, daddr, evt->dport, ctx->protocol);
    bpf_ringbuf_submit(evt, 0);

    return SK_PASS;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
