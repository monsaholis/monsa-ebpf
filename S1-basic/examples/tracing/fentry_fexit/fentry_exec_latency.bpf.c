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

// fentry/fexit example: measure execve latency.

#include "../../../../common/include/bpf_helpers.h"
#include <linux/sched.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} start_ns SEC(".maps");

struct exec_latency_event {
    __u32 pid;
    char comm[TASK_COMM_LEN];
    __u64 duration_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} exec_latency_events SEC(".maps");

SEC("fentry/__x64_sys_execve")
int fentry_execve(void *ctx)
{
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start_ns, &pid, &ts, BPF_ANY);
    return 0;
}

SEC("fexit/__x64_sys_execve")
int fexit_execve(void *ctx)
{
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    __u64 *start = bpf_map_lookup_elem(&start_ns, &pid);
    if (!start)
        return 0;

    __u64 delta = bpf_ktime_get_ns() - *start;
    struct exec_latency_event evt = {
        .pid = pid,
        .duration_ns = delta,
    };
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    bpf_ringbuf_output(&exec_latency_events, &evt, sizeof(evt), 0);
    bpf_map_delete_elem(&start_ns, &pid);
    return 0;
}

char LICENSE[] SEC("license") = "MIT";
