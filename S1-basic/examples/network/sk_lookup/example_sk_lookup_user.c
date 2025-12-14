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

// User-space controller for sk_lookup example. Attaches program to current netns
// and periodically prints per-dport lookup counts.

#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "build/example_sk_lookup.skel.h"

static volatile sig_atomic_t stop;

static void handle_signal(int sig)
{
    (void)sig;
    stop = 1;
}

static void print_map(struct bpf_map *map)
{
    __u16 key = 0, next_key;
    __u64 value;
    int fd = bpf_map__fd(map);

    printf("dport -> lookups\n");
    while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(fd, &next_key, &value) == 0)
            printf("  %u -> %llu\n", ntohs(next_key), (unsigned long long)value);
        key = next_key;
    }
}

int main(void)
{
    struct example_sk_lookup_bpf *skel = NULL;
    struct bpf_link *link = NULL;
    int err = 0;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    if (signal(SIGINT, handle_signal) == SIG_ERR ||
        signal(SIGTERM, handle_signal) == SIG_ERR) {
        perror("signal");
        return 1;
    }

    skel = example_sk_lookup_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open/load BPF skeleton\n");
        return 1;
    }

    link = bpf_program__attach_netns(skel->progs.msb_sk_lookup, 0); // current netns
    if (!link) {
        fprintf(stderr, "failed to attach sk_lookup program\n");
        err = 1;
        goto cleanup;
    }

    printf("Attached sk_lookup to current netns. Ctrl+C to stop.\n");
    fflush(stdout);
    while (!stop) {
        print_map(skel->maps.port_counts);
        sleep(1);
    }

cleanup:
    bpf_link__destroy(link);
    example_sk_lookup_bpf__destroy(skel);
    return err ? 1 : 0;
}
