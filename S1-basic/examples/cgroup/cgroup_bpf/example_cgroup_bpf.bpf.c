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

// BPF LSM example: audit BPF program/map operations (load, attach, detach).
// Placed under cgroup examples by request to demonstrate BPF attach control.

#include "../../../../common/include/bpf_helpers.h"

enum counter_idx {
    PROG_LOAD_CNT = 0,
    MAP_CREATE_CNT = 1,
    PROG_ATTACH_CNT = 2,
    PROG_DETACH_CNT = 3,
    OTHER_CMD_CNT = 4,
    COUNTER_MAX,
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, COUNTER_MAX);
    __type(key, __u32);
    __type(value, __u64);
} bpf_cmd_counts SEC(".maps");

static __always_inline void bump(__u32 idx)
{
    __u64 *cnt = bpf_map_lookup_elem(&bpf_cmd_counts, &idx);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);
}

SEC("lsm/bpf")
int BPF_PROG(msb_lsm_bpf, int cmd, union bpf_attr *attr, unsigned int size)
{
    __u32 idx;

    switch (cmd) {
    case BPF_PROG_LOAD:
        idx = PROG_LOAD_CNT;
        break;
    case BPF_MAP_CREATE:
        idx = MAP_CREATE_CNT;
        break;
    case BPF_PROG_ATTACH:
        idx = PROG_ATTACH_CNT;
        break;
    case BPF_PROG_DETACH:
        idx = PROG_DETACH_CNT;
        break;
    default:
        idx = OTHER_CMD_CNT;
        break;
    }

    bump(idx);
    return 0; // allow
}

char LICENSE[] SEC("license") = "GPL";
