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

// Minimal LSM example: log file_open attempts via ring buffer.

#include "../../../common/include/bpf_helpers.h"
#include <linux/sched.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct file_open_event {
    __u32 pid;
    char comm[TASK_COMM_LEN];
    int mask;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} file_open_events SEC(".maps");

SEC("lsm/file_open")
int BPF_PROG(msb_file_open, struct file *file, int mask)
{
    struct file_open_event evt = {};
    evt.pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    evt.mask = mask;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    bpf_ringbuf_output(&file_open_events, &evt, sizeof(evt), 0);
    return 0; // allow by default
}

char LICENSE[] SEC("license") = "GPL";
