// MIT License - Copyright (c) 2025 dev-monsa
// S2-advanced LSM: File access security policy with comprehensive context.

#include "../../../../common/include/bpf_helpers.h"
#include <linux/bpf.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#ifndef PATH_MAX
#define PATH_MAX 256
#endif

struct lsm_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 gid;
    __u64 cgroup_id;
    char comm[TASK_COMM_LEN];
    char path[PATH_MAX];
    __u32 flags;
    __u32 mode;
    __s32 decision;  // 0=allow, -EPERM=deny
    __u64 count;
};

struct lsm_stats {
    __u64 allow_count;
    __u64 deny_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct lsm_stats);
} lsm_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} lsm_events SEC(".maps");

SEC("lsm/file_open")
int BPF_PROG(msb_lsm_file_open, struct file *file)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = (__u32)uid_gid;
    struct lsm_event *evt;
    struct lsm_stats *stats, new_stats = {0};
    __s32 decision = 0;  // Allow by default

    evt = bpf_ringbuf_reserve(&lsm_events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->pid = pid;
    evt->tid = (__u32)pid_tgid;
    evt->uid = uid;
    evt->gid = (__u32)(uid_gid >> 32);
    evt->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    
    // Read file path (simplified)
    __builtin_memset(evt->path, 0, sizeof(evt->path));
    bpf_probe_read_kernel_str(&evt->path, sizeof(evt->path), "unknown");
    
    evt->flags = 0;
    evt->mode = 0;
    evt->decision = decision;

    stats = bpf_map_lookup_elem(&lsm_stats_map, &pid);
    if (!stats) {
        new_stats.allow_count = 1;
        new_stats.deny_count = 0;
        bpf_map_update_elem(&lsm_stats_map, &pid, &new_stats, BPF_ANY);
        evt->count = 1;
    } else {
        if (decision == 0) {
            __sync_fetch_and_add(&stats->allow_count, 1);
            evt->count = stats->allow_count;
        } else {
            __sync_fetch_and_add(&stats->deny_count, 1);
            evt->count = stats->deny_count;
        }
    }

    bpf_ringbuf_submit(evt, 0);
    bpf_printk("lsm_file_open: pid=%u uid=%u decision=%d\n", pid, uid, decision);

    return decision;
}

char LICENSE[] SEC("license") = "GPL";
