// MIT License - Copyright (c) 2025 dev-monsa
// S2-advanced tracepoint: Kernel tracepoint with comprehensive event capture.

#include "../../../../common/include/bpf_helpers.h"

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct tp_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 gid;
    __u64 cgroup_id;
    char comm[TASK_COMM_LEN];
    __u64 count;
    __s32 prio;
    __u32 cpu;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} tp_counts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} tp_events SEC(".maps");

SEC("tp/sched/sched_process_exec")
int msb_tracepoint(void *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u64 *count, one = 1, new_count;
    struct tp_event *evt;

    count = bpf_map_lookup_elem(&tp_counts, &pid);
    if (!count) {
        bpf_map_update_elem(&tp_counts, &pid, &one, BPF_ANY);
        new_count = 1;
    } else {
        new_count = __sync_fetch_and_add(count, 1) + 1;
    }

    evt = bpf_ringbuf_reserve(&tp_events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->pid = pid;
    evt->tid = (__u32)pid_tgid;
    evt->uid = (__u32)uid_gid;
    evt->gid = (__u32)(uid_gid >> 32);
    evt->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    evt->count = new_count;
    evt->prio = 0;
    evt->cpu = bpf_get_smp_processor_id();

    bpf_printk("tracepoint: pid=%u comm=%s cpu=%u\n", pid, evt->comm, evt->cpu);
    bpf_ringbuf_submit(evt, 0);

    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
