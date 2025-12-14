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

// Uretprobe example: measures per-PID call latency and captures last return value.

#include "../../../common/include/bpf_helpers.h"
#include <linux/ptrace.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} uretprobe_start SEC(".maps");

struct uretprobe_stat {
    __u64 calls;
    __u64 total_ns;
    __s64 last_rc;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct uretprobe_stat);
} uretprobe_stats SEC(".maps");

SEC("uprobe")
int msb_uretprobe_entry(struct pt_regs *ctx)
{
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    __u64 ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&uretprobe_start, &pid, &ts, BPF_ANY);
    return 0;
}

SEC("uretprobe")
int msb_uretprobe_exit(struct pt_regs *ctx)
{
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    __u64 *start = bpf_map_lookup_elem(&uretprobe_start, &pid);
    struct uretprobe_stat stat = {};
    struct uretprobe_stat *cur;
    __u64 delta;

    if (!start)
        return 0;

    delta = bpf_ktime_get_ns() - *start;
    bpf_map_delete_elem(&uretprobe_start, &pid);

    cur = bpf_map_lookup_elem(&uretprobe_stats, &pid);
    if (cur)
        stat = *cur;

    stat.calls += 1;
    stat.total_ns += delta;
    stat.last_rc = PT_REGS_RC(ctx);

    bpf_map_update_elem(&uretprobe_stats, &pid, &stat, BPF_ANY);
    return 0;
}

char LICENSE[] SEC("license") = "MIT";
