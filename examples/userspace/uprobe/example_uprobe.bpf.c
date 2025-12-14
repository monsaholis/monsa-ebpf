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

// Uprobe example: trace user-space function calls.

#include "../../../common/include/bpf_helpers.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);   // PID
    __type(value, __u64); // call count
} uprobe_count SEC(".maps");

SEC("uprobe")
int msb_uprobe_target(struct pt_regs *ctx)
{
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    __u64 *cnt = bpf_map_lookup_elem(&uprobe_count, &pid);
    __u64 one = 1;
    
    if (!cnt) {
        bpf_map_update_elem(&uprobe_count, &pid, &one, BPF_ANY);
    } else {
        __sync_fetch_and_add(cnt, 1);
    }
    return 0;
}

char LICENSE[] SEC("license") = "MIT";
