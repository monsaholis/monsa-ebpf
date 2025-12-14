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

// Cgroup sock_addr example: trace connect/bind/sendmsg attempts per cgroup.

#include "../../../../common/include/bpf_helpers.h"
#include <linux/in.h>
#include <linux/in6.h>

enum counter_idx {
    CONNECT_CNT = 0,
    BIND_CNT = 1,
    SENDMSG_CNT = 2,
    COUNTER_MAX,
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, COUNTER_MAX);
    __type(key, __u32);
    __type(value, __u64);
} sock_addr_counts SEC(".maps");

static __always_inline void bump(__u32 idx)
{
    __u64 *cnt = bpf_map_lookup_elem(&sock_addr_counts, &idx);
    if (cnt)
        __sync_fetch_and_add(cnt, 1);
}

SEC("cgroup/connect4")
int msb_connect4(struct bpf_sock_addr *ctx)
{
    bump(CONNECT_CNT);
    return 1; // allow
}

SEC("cgroup/connect6")
int msb_connect6(struct bpf_sock_addr *ctx)
{
    bump(CONNECT_CNT);
    return 1;
}

SEC("cgroup/bind4")
int msb_bind4(struct bpf_sock_addr *ctx)
{
    bump(BIND_CNT);
    return 1;
}

SEC("cgroup/bind6")
int msb_bind6(struct bpf_sock_addr *ctx)
{
    bump(BIND_CNT);
    return 1;
}

SEC("cgroup/sendmsg4")
int msb_sendmsg4(struct bpf_sock_addr *ctx)
{
    bump(SENDMSG_CNT);
    return 1;
}

SEC("cgroup/sendmsg6")
int msb_sendmsg6(struct bpf_sock_addr *ctx)
{
    bump(SENDMSG_CNT);
    return 1;
}

char LICENSE[] SEC("license") = "MIT";
