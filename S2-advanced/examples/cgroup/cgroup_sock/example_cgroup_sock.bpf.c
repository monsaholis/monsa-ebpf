// MIT License - Copyright (c) 2025 dev-monsa
// S2-advanced cgroup_sock: Cgroup socket creation monitoring.

#include "../../../../common/include/bpf_helpers.h"
#include <linux/bpf.h>

struct cgroup_sock_event {
    __u64 timestamp_ns;
    __u32 family;
    __u32 type;
    __u32 protocol;
    __u64 cgroup_id;
    __u64 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u64);
} cgroup_sock_counts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} cgroup_sock_events SEC(".maps");

SEC("cgroup/sock")
int msb_cgroup_sock(struct bpf_sock *sk)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u64 *count, one = 1, new_count;
    struct cgroup_sock_event *evt;

    count = bpf_map_lookup_elem(&cgroup_sock_counts, &cgroup_id);
    if (!count) {
        bpf_map_update_elem(&cgroup_sock_counts, &cgroup_id, &one, BPF_ANY);
        new_count = 1;
    } else {
        new_count = __sync_fetch_and_add(count, 1) + 1;
    }

    evt = bpf_ringbuf_reserve(&cgroup_sock_events, sizeof(*evt), 0);
    if (!evt)
        return 1;

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->family = sk->family;
    evt->type = sk->type;
    evt->protocol = sk->protocol;
    evt->cgroup_id = cgroup_id;
    evt->count = new_count;

    bpf_ringbuf_submit(evt, 0);
    bpf_printk("cgroup_sock: cgroup=%llu family=%u type=%u\n", cgroup_id, sk->family, sk->type);

    return 1;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
