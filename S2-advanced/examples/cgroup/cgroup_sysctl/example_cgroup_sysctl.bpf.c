// MIT License - Copyright (c) 2025 dev-monsa
// S2-advanced cgroup_sysctl: Cgroup sysctl access monitoring.

#include "../../../../common/include/bpf_helpers.h"
#include <linux/bpf.h>

#ifndef MAX_SYSCTL_LEN
#define MAX_SYSCTL_LEN 128
#endif

struct cgroup_sysctl_event {
    __u64 timestamp_ns;
    char name[MAX_SYSCTL_LEN];
    __u32 write;
    __u64 cgroup_id;
    __u64 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u64);
} cgroup_sysctl_counts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} cgroup_sysctl_events SEC(".maps");

SEC("cgroup/sysctl")
int msb_cgroup_sysctl(struct bpf_sysctl *ctx)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u64 *count, one = 1, new_count;
    struct cgroup_sysctl_event *evt;

    count = bpf_map_lookup_elem(&cgroup_sysctl_counts, &cgroup_id);
    if (!count) {
        bpf_map_update_elem(&cgroup_sysctl_counts, &cgroup_id, &one, BPF_ANY);
        new_count = 1;
    } else {
        new_count = __sync_fetch_and_add(count, 1) + 1;
    }

    evt = bpf_ringbuf_reserve(&cgroup_sysctl_events, sizeof(*evt), 0);
    if (!evt)
        return 1;

    evt->timestamp_ns = bpf_ktime_get_ns();
    __builtin_memset(evt->name, 0, sizeof(evt->name));
    bpf_sysctl_get_name(ctx, evt->name, sizeof(evt->name), 0);
    evt->write = ctx->write;
    evt->cgroup_id = cgroup_id;
    evt->count = new_count;

    bpf_ringbuf_submit(evt, 0);
    bpf_printk("cgroup_sysctl: cgroup=%llu write=%u\n", cgroup_id, ctx->write);

    return 1;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
