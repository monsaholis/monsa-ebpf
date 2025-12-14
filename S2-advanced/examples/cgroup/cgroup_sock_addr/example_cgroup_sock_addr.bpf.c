// MIT License - Copyright (c) 2025 dev-monsa
// S2-advanced cgroup_sock_addr: Cgroup socket address bind/connect monitoring.

#include "../../../../common/include/bpf_helpers.h"
#include <linux/bpf.h>

struct cgroup_sock_addr_event {
    __u64 timestamp_ns;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u32 family;
    __u64 cgroup_id;
    __u64 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u64);
} cgroup_sock_addr_counts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} cgroup_sock_addr_events SEC(".maps");

SEC("cgroup/connect4")
int msb_cgroup_sock_addr(struct bpf_sock_addr *ctx)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u64 *count, one = 1, new_count;
    struct cgroup_sock_addr_event *evt;

    count = bpf_map_lookup_elem(&cgroup_sock_addr_counts, &cgroup_id);
    if (!count) {
        bpf_map_update_elem(&cgroup_sock_addr_counts, &cgroup_id, &one, BPF_ANY);
        new_count = 1;
    } else {
        new_count = __sync_fetch_and_add(count, 1) + 1;
    }

    evt = bpf_ringbuf_reserve(&cgroup_sock_addr_events, sizeof(*evt), 0);
    if (!evt)
        return 1;

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->saddr = 0;
    evt->daddr = ctx->user_ip4;
    evt->sport = 0;
    evt->dport = ctx->user_port;
    evt->family = ctx->family;
    evt->cgroup_id = cgroup_id;
    evt->count = new_count;

    bpf_ringbuf_submit(evt, 0);
    bpf_printk("cgroup_sock_addr: cgroup=%llu daddr=%x dport=%u\n", 
               cgroup_id, ctx->user_ip4, ctx->user_port);

    return 1;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
