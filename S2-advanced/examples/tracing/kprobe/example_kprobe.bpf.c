// MIT License
//
// Copyright (c) 2025 dev-monsa
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// S2-advanced: Extended kprobe example collecting comprehensive kernel function entry data.
// Demonstrates: task context, UID/GID, cgroup ID, arguments, timestamps, kernel logging.

#include "../../../../common/include/bpf_helpers.h"
#include <linux/ptrace.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

// Extended event structure capturing rich context
struct kprobe_event {
    __u64 timestamp_ns;          // Event timestamp
    __u32 pid;                   // Process ID
    __u32 tid;                   // Thread ID
    __u32 ppid;                  // Parent PID (set to 0 for now, requires BTF)
    __u32 uid;                   // User ID
    __u32 gid;                   // Group ID
    __u64 cgroup_id;             // Cgroup ID
    char comm[TASK_COMM_LEN];    // Process name
    __u64 arg0;                  // First argument (e.g., filename pointer for execve)
    __u64 arg1;                  // Second argument
    __u64 arg2;                  // Third argument
    __u64 count;                 // Call count for this PID
    char func_name[32];          // Kernel function name
};

// Per-PID call counters
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);   // PID
    __type(value, __u64); // call count
} kprobe_counts SEC(".maps");

// Ringbuf for streaming events to user-space
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024); // 1MB
} kprobe_events SEC(".maps");

SEC("kprobe/__x64_sys_execve")
int msb_kprobe_execve(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tid = (__u32)pid_tgid;
    __u64 *val;
    __u64 one = 1;
    __u64 new_count;
    struct kprobe_event *evt;

    // Update call counter
    val = bpf_map_lookup_elem(&kprobe_counts, &pid);
    if (!val) {
        bpf_map_update_elem(&kprobe_counts, &pid, &one, BPF_ANY);
        new_count = one;
    } else {
        new_count = __sync_fetch_and_add(val, 1) + 1;
    }

    // Reserve ringbuf space
    evt = bpf_ringbuf_reserve(&kprobe_events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    // Populate event with comprehensive data
    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->pid = pid;
    evt->tid = tid;
    evt->ppid = 0;  // TODO: requires BTF/CO-RE for safe task_struct access
    evt->uid = (__u32)uid_gid;
    evt->gid = (__u32)(uid_gid >> 32);
    evt->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    
    // Capture syscall arguments (PT_REGS_PARM* macros for x86_64)
    evt->arg0 = PT_REGS_PARM1(ctx); // const char __user *filename
    evt->arg1 = PT_REGS_PARM2(ctx); // const char __user *const __user *argv
    evt->arg2 = PT_REGS_PARM3(ctx); // const char __user *const __user *envp
    
    evt->count = new_count;
    __builtin_memcpy(evt->func_name, "__x64_sys_execve", sizeof("__x64_sys_execve"));

    // Kernel-side trace log (viewable via /sys/kernel/debug/tracing/trace_pipe)
    // Note: bpf_printk limited to ~3 args, split into multiple calls
    // IMPORTANT: Call bpf_printk BEFORE bpf_ringbuf_submit, as submit invalidates evt pointer
    bpf_printk("kprobe[execve]: pid=%u tid=%u comm=%s\n", pid, tid, evt->comm);
    bpf_printk("  uid=%u gid=%u cgroup=%llu count=%llu\n",
               evt->uid, evt->gid, evt->cgroup_id, new_count);

    // Submit event to ringbuf (this invalidates evt pointer)
    bpf_ringbuf_submit(evt, 0);

    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
