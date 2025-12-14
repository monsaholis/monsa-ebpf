// MIT License - Copyright (c) 2025 dev-monsa
// S2-advanced uprobe: User-space function entry tracing with memory sampling.

#include "../../../../common/include/bpf_helpers.h"
#include <linux/ptrace.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct uprobe_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 gid;
    __u64 cgroup_id;
    char comm[TASK_COMM_LEN];
    __u64 arg0;  // Function arguments
    __u64 arg1;
    __u64 arg2;
    __u64 count;
    char func_name[32];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} uprobe_counts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} uprobe_events SEC(".maps");

SEC("uprobe")
int msb_uprobe_entry(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u64 *count, one = 1, new_count;
    struct uprobe_event *evt;

    count = bpf_map_lookup_elem(&uprobe_counts, &pid);
    if (!count) {
        bpf_map_update_elem(&uprobe_counts, &pid, &one, BPF_ANY);
        new_count = 1;
    } else {
        new_count = __sync_fetch_and_add(count, 1) + 1;
    }

    evt = bpf_ringbuf_reserve(&uprobe_events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->pid = pid;
    evt->tid = tid;
    evt->uid = (__u32)uid_gid;
    evt->gid = (__u32)(uid_gid >> 32);
    evt->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    
    // Capture function arguments (user-space registers)
    evt->arg0 = PT_REGS_PARM1(ctx);
    evt->arg1 = PT_REGS_PARM2(ctx);
    evt->arg2 = PT_REGS_PARM3(ctx);
    evt->count = new_count;
    __builtin_memcpy(evt->func_name, "user_function", sizeof("user_function"));

    bpf_printk("uprobe: pid=%u comm=%s count=%llu\n", pid, evt->comm, new_count);
    bpf_ringbuf_submit(evt, 0);

    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
