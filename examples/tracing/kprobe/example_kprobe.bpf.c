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

// A minimal kprobe example that counts execve calls per PID and emits events.

#include "../../../common/include/bpf_helpers.h"
#include <linux/ptrace.h>
#include <linux/sched.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);   // PID
    __type(value, __u64); // exec count per PID
} exec_counts SEC(".maps");

struct exec_event {
    __u32 pid;
    char comm[TASK_COMM_LEN];
    __u64 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} exec_events SEC(".maps");

SEC("kprobe/__x64_sys_execve")
int msb_esecve(struct pt_regs *ctx)
{
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    __u64 *val = bpf_map_lookup_elem(&exec_counts, &pid);
    __u64 one = 1;
    __u64 new_count;
    struct exec_event evt = {};

    if (!val) {
        bpf_map_update_elem(&exec_counts, &pid, &one, BPF_ANY);
        new_count = one;
    } else {
        new_count = __sync_fetch_and_add(val, 1) + 1;
    }

    evt.pid = pid;
    evt.count = new_count;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    bpf_ringbuf_output(&exec_events, &evt, sizeof(evt), 0);

    return 0;
}

char LICENSE[] SEC("license") = "MIT";
