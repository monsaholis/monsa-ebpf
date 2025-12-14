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

// Cgroup device example: audit device access attempts per cgroup.

#include "../../../../common/include/bpf_helpers.h"

enum counter_idx {
    DEV_READ_CNT = 0,
    DEV_WRITE_CNT = 1,
    DEV_MKNOD_CNT = 2,
    DEV_OTHER_CNT = 3,
    COUNTER_MAX,
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, COUNTER_MAX);
    __type(key, __u32);
    __type(value, __u64);
} dev_counts SEC(".maps");

static __always_inline void bump(__u32 idx)
{
    __u64 *cnt = bpf_map_lookup_elem(&dev_counts, &idx);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);
}

SEC("cgroup/dev")
int msb_cgroup_dev(struct bpf_cgroup_dev_ctx *ctx)
{
    __u32 idx;

    switch (ctx->access_type) {
    case BPF_DEVCG_ACC_READ:
        idx = DEV_READ_CNT;
        break;
    case BPF_DEVCG_ACC_WRITE:
        idx = DEV_WRITE_CNT;
        break;
    case BPF_DEVCG_ACC_MKNOD:
        idx = DEV_MKNOD_CNT;
        break;
    default:
        idx = DEV_OTHER_CNT;
        break;
    }

    bump(idx);
    return 1; // allow
}

char LICENSE[] SEC("license") = "MIT";
