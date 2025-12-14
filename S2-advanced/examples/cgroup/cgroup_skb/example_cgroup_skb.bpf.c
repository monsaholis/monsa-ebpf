// MIT License - Copyright (c) 2025 dev-monsa
// S2-advanced cgroup_skb: Cgroup socket buffer monitoring.

#include "../../../../common/include/bpf_helpers.h"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct cgroup_skb_event {
    __u64 timestamp_ns;
    __u32 saddr;
    __u32 daddr;
    __u32 len;
    __u64 cgroup_id;
    __u64 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u64);
} cgroup_skb_counts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} cgroup_skb_events SEC(".maps");

SEC("cgroup/skb")
int msb_cgroup_skb(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u64 *count, one = 1, new_count;
    struct cgroup_skb_event *evt;
    __u32 saddr = 0, daddr = 0;

    if ((void *)(eth + 1) > data_end)
        return 1;

    if (eth->h_proto == __constant_htons(ETH_P_IP)) {
        ip = (void *)(eth + 1);
        if ((void *)(ip + 1) <= data_end) {
            saddr = ip->saddr;
            daddr = ip->daddr;
        }
    }

    count = bpf_map_lookup_elem(&cgroup_skb_counts, &cgroup_id);
    if (!count) {
        bpf_map_update_elem(&cgroup_skb_counts, &cgroup_id, &one, BPF_ANY);
        new_count = 1;
    } else {
        new_count = __sync_fetch_and_add(count, 1) + 1;
    }

    // Sample 1/100
    if ((new_count % 100) != 0)
        return 1;

    evt = bpf_ringbuf_reserve(&cgroup_skb_events, sizeof(*evt), 0);
    if (!evt)
        return 1;

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->saddr = saddr;
    evt->daddr = daddr;
    evt->len = skb->len;
    evt->cgroup_id = cgroup_id;
    evt->count = new_count;

    bpf_ringbuf_submit(evt, 0);
    bpf_printk("cgroup_skb: cgroup=%llu len=%u count=%llu\n", cgroup_id, skb->len, new_count);

    return 1;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
