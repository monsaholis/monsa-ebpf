// MIT License - Copyright (c) 2025 dev-monsa
// S2-advanced cgroup_device: Cgroup device access control.

#include "../../../../common/include/bpf_helpers.h"
#include <linux/bpf.h>

struct cgroup_device_event {
    __u64 timestamp_ns;
    __u32 major;
    __u32 minor;
    __u32 access_type;
    __u64 cgroup_id;
    __u32 allowed;
    __u64 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u64);
} cgroup_device_counts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} cgroup_device_events SEC(".maps");

SEC("cgroup/dev")
int msb_cgroup_device(struct bpf_cgroup_dev_ctx *ctx)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u64 *count, one = 1, new_count;
    struct cgroup_device_event *evt;

    count = bpf_map_lookup_elem(&cgroup_device_counts, &cgroup_id);
    if (!count) {
        bpf_map_update_elem(&cgroup_device_counts, &cgroup_id, &one, BPF_ANY);
        new_count = 1;
    } else {
        new_count = __sync_fetch_and_add(count, 1) + 1;
    }

    evt = bpf_ringbuf_reserve(&cgroup_device_events, sizeof(*evt), 0);
    if (!evt)
        return 1;

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->major = ctx->major;
    evt->minor = ctx->minor;
    evt->access_type = ctx->access_type;
    evt->cgroup_id = cgroup_id;
    evt->allowed = 1;
    evt->count = new_count;

    bpf_ringbuf_submit(evt, 0);
    bpf_printk("cgroup_device: cgroup=%llu major=%u minor=%u\n", cgroup_id, ctx->major, ctx->minor);

    return 1;  // Allow
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
