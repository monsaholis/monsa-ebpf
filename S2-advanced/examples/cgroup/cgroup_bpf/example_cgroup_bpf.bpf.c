// MIT License - Copyright (c) 2025 dev-monsa
// S2-advanced cgroup_bpf: Cgroup BPF program attach monitoring (placeholder).

#include "../../../../common/include/bpf_helpers.h"
#include <linux/bpf.h>

struct cgroup_bpf_event {
    __u64 timestamp_ns;
    __u64 cgroup_id;
    __u32 pid;
    char comm[16];
    __u64 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u64);
} cgroup_bpf_counts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} cgroup_bpf_events SEC(".maps");

// Note: cgroup/bpf is not a standard program type, using cgroup/sock as template
SEC("cgroup/sock")
int msb_cgroup_bpf(struct bpf_sock *sk)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u64 *count, one = 1, new_count;
    struct cgroup_bpf_event *evt;

    (void)sk;

    count = bpf_map_lookup_elem(&cgroup_bpf_counts, &cgroup_id);
    if (!count) {
        bpf_map_update_elem(&cgroup_bpf_counts, &cgroup_id, &one, BPF_ANY);
        new_count = 1;
    } else {
        new_count = __sync_fetch_and_add(count, 1) + 1;
    }

    evt = bpf_ringbuf_reserve(&cgroup_bpf_events, sizeof(*evt), 0);
    if (!evt)
        return 1;

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->cgroup_id = cgroup_id;
    evt->pid = pid;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    evt->count = new_count;

    bpf_ringbuf_submit(evt, 0);
    bpf_printk("cgroup_bpf: cgroup=%llu pid=%u\n", cgroup_id, pid);

    return 1;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
