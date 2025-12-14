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

// sk_lookup example: count lookups per destination port and allow by default.

#include "../../../../common/include/bpf_helpers.h"
#include <linux/in.h>
#include <linux/in6.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);   // destination port (network order)
    __type(value, __u64); // lookup count
} port_counts SEC(".maps");

SEC("sk_lookup")
int msb_sk_lookup(struct bpf_sk_lookup *ctx)
{
    __u16 dport = ctx->remote_port; // already network order
    __u64 *cnt = bpf_map_lookup_elem(&port_counts, &dport);
    __u64 one = 1;

    if (!cnt) {
        bpf_map_update_elem(&port_counts, &dport, &one, BPF_ANY);
    } else {
        __sync_fetch_and_add(cnt, 1);
    }
    return SK_PASS; // allow by default
}

char LICENSE[] SEC("license") = "MIT";
