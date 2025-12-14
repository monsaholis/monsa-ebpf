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

// S2-advanced: Kretprobe with latency tracking, return value analysis, success/error statistics.
// Demonstrates: entry-exit timing, return value classification, per-PID stats, ringbuf + bpf_printk.

#include "../../../../common/include/bpf_helpers.h"
#include <linux/ptrace.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#ifndef MAX_ERRNO
#define MAX_ERRNO 4095
#endif

// Entry timestamp storage (kprobe records entry time)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);   // PID_TID
    __type(value, __u64); // entry timestamp (ns)
} entry_times SEC(".maps");

// Per-PID statistics
struct pid_stats {
    __u64 total_calls;
    __u64 success_calls;
    __u64 error_calls;
    __u64 total_latency_ns;
    __u64 min_latency_ns;
    __u64 max_latency_ns;
    __s64 last_retval;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);              // PID
    __type(value, struct pid_stats);
} pid_statistics SEC(".maps");

// Return event for ringbuf
struct kretprobe_event {
    __u64 timestamp_ns;
    __u64 latency_ns;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 gid;
    __u64 cgroup_id;
    char comm[TASK_COMM_LEN];
    __s64 retval;
    __u8 is_error;       // 1 if error, 0 if success
    __s32 error_code;    // extracted error code if error
    char func_name[32];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} kretprobe_events SEC(".maps");

// Helper: check if return value is an error (Linux convention: -MAX_ERRNO to -1)
static __always_inline __u8 is_error_retval(__s64 ret)
{
    return (ret < 0 && ret >= -MAX_ERRNO);
}

// Kprobe: record entry timestamp
SEC("kprobe/__x64_sys_openat")
int msb_kprobe_openat_entry(struct pt_regs *ctx)
{
    __u64 pid_tid = bpf_get_current_pid_tgid();
    __u64 ts = bpf_ktime_get_ns();
    
    bpf_map_update_elem(&entry_times, &pid_tid, &ts, BPF_ANY);
    return 0;
}

// Kretprobe: calculate latency, classify return, emit event
SEC("kretprobe/__x64_sys_openat")
int msb_kretprobe_openat_exit(struct pt_regs *ctx)
{
    __u64 pid_tid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tid >> 32);
    __u32 tid = (__u32)pid_tid;
    __u64 *entry_ts = bpf_map_lookup_elem(&entry_times, &pid_tid);
    __u64 exit_ts = bpf_ktime_get_ns();
    __u64 latency = 0;
    __s64 retval = PT_REGS_RC(ctx);
    __u8 is_err;
    __s32 err_code = 0;
    struct pid_stats *stats, zero_stats = {};
    struct kretprobe_event *evt;
    __u64 uid_gid = bpf_get_current_uid_gid();

    // Calculate latency
    if (entry_ts) {
        latency = exit_ts - *entry_ts;
        bpf_map_delete_elem(&entry_times, &pid_tid);
    }

    // Classify return value
    is_err = is_error_retval(retval);
    if (is_err)
        err_code = (__s32)(-retval);

    // Update per-PID statistics
    stats = bpf_map_lookup_elem(&pid_statistics, &pid);
    if (!stats) {
        bpf_map_update_elem(&pid_statistics, &pid, &zero_stats, BPF_ANY);
        stats = bpf_map_lookup_elem(&pid_statistics, &pid);
    }
    
    if (stats) {
        __sync_fetch_and_add(&stats->total_calls, 1);
        if (is_err)
            __sync_fetch_and_add(&stats->error_calls, 1);
        else
            __sync_fetch_and_add(&stats->success_calls, 1);
        
        if (latency > 0) {
            __sync_fetch_and_add(&stats->total_latency_ns, latency);
            
            // Update min/max (simple atomic approach)
            if (stats->min_latency_ns == 0 || latency < stats->min_latency_ns)
                stats->min_latency_ns = latency;
            if (latency > stats->max_latency_ns)
                stats->max_latency_ns = latency;
        }
        
        stats->last_retval = retval;
    }

    // Emit ringbuf event
    evt = bpf_ringbuf_reserve(&kretprobe_events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->timestamp_ns = exit_ts;
    evt->latency_ns = latency;
    evt->pid = pid;
    evt->tid = tid;
    evt->uid = (__u32)uid_gid;
    evt->gid = (__u32)(uid_gid >> 32);
    evt->cgroup_id = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    evt->retval = retval;
    evt->is_error = is_err;
    evt->error_code = err_code;
    __builtin_memcpy(evt->func_name, "__x64_sys_openat", sizeof("__x64_sys_openat"));

    bpf_ringbuf_submit(evt, 0);

    // Kernel-side log
    if (is_err) {
        bpf_printk("kretprobe[openat]: pid=%u ERROR retval=%lld errno=%d latency_us=%llu\n",
                   pid, retval, err_code, latency / 1000);
    } else {
        bpf_printk("kretprobe[openat]: pid=%u SUCCESS retval=%lld latency_us=%llu\n",
                   pid, retval, latency / 1000);
    }

    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
