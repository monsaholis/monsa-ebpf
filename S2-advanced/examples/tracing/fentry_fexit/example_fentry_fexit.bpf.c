// MIT License - Copyright (c) 2025 dev-monsa
// S2-advanced fentry/fexit: Fast kernel function tracing with comprehensive metrics.

#include "../../../../common/include/bpf_helpers.h"
#include <linux/ptrace.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct fentry_fexit_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 gid;
    __u64 cgroup_id;
    char comm[TASK_COMM_LEN];
    __u64 entry_ts;
    __u64 exit_ts;
    __u64 latency_ns;
    __u64 retval;
    __u64 count;
};

struct latency_stats {
    __u64 count;
    __u64 total_ns;
    __u64 min_ns;
    __u64 max_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, __u64);
} fentry_times SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct latency_stats);
} fentry_latency_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} fentry_fexit_events SEC(".maps");

SEC("fentry/do_sys_openat2")
int BPF_PROG(msb_fentry, int dfd, const char *filename)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 ts = bpf_ktime_get_ns();
    
    bpf_map_update_elem(&fentry_times, &pid_tgid, &ts, BPF_ANY);
    bpf_printk("fentry: pid=%u filename=%llx\n", (pid_tgid >> 32), (unsigned long long)filename);
    return 0;
}

SEC("fexit/do_sys_openat2")
int BPF_PROG(msb_fexit, int dfd, const char *filename, void *how, long ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 *entry_ts, exit_ts, latency_ns;
    __u64 uid_gid = bpf_get_current_uid_gid();
    struct fentry_fexit_event *evt;
    struct latency_stats *stats, new_stats = {0};

    (void)dfd;
    (void)filename;
    (void)how;

    entry_ts = bpf_map_lookup_elem(&fentry_times, &pid_tgid);
    if (!entry_ts)
        return 0;

    exit_ts = bpf_ktime_get_ns();
    latency_ns = exit_ts - *entry_ts;

    evt = bpf_ringbuf_reserve(&fentry_fexit_events, sizeof(*evt), 0);
    if (!evt)
        goto cleanup;

    evt->timestamp_ns = exit_ts;
    evt->pid = pid;
    evt->tid = (__u32)pid_tgid;
    evt->uid = (__u32)uid_gid;
    evt->gid = (__u32)(uid_gid >> 32);
    evt->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    evt->entry_ts = *entry_ts;
    evt->exit_ts = exit_ts;
    evt->latency_ns = latency_ns;
    evt->retval = ret;

    stats = bpf_map_lookup_elem(&fentry_latency_stats, &pid);
    if (!stats) {
        new_stats.count = 1;
        new_stats.total_ns = latency_ns;
        new_stats.min_ns = latency_ns;
        new_stats.max_ns = latency_ns;
        bpf_map_update_elem(&fentry_latency_stats, &pid, &new_stats, BPF_ANY);
        evt->count = 1;
    } else {
        __sync_fetch_and_add(&stats->count, 1);
        __sync_fetch_and_add(&stats->total_ns, latency_ns);
        if (latency_ns < stats->min_ns)
            stats->min_ns = latency_ns;
        if (latency_ns > stats->max_ns)
            stats->max_ns = latency_ns;
        evt->count = stats->count + 1;
    }

    bpf_ringbuf_submit(evt, 0);
    bpf_printk("fexit: pid=%u latency=%llu ret=%ld\n", pid, latency_ns, ret);

cleanup:
    bpf_map_delete_elem(&fentry_times, &pid_tgid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
