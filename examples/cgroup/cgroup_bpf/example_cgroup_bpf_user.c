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

// User-space controller for the BPF LSM example. Loads and attaches the LSM
// program and prints BPF syscall counts.

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "build/example_cgroup_bpf.skel.h"

static volatile sig_atomic_t stop;

static void handle_signal(int sig)
{
    (void)sig;
    stop = 1;
}

static void print_stats(struct bpf_map *map)
{
    static const char *names[] = {"prog_load", "map_create", "prog_attach", "prog_detach", "other"};
    __u32 key;
    __u64 values[128];  // support up to 128 CPUs
    __u64 total;
    int fd = bpf_map__fd(map);
    unsigned int i, num_cpus = libbpf_num_possible_cpus();

    if (num_cpus > 128)
        num_cpus = 128;

    for (key = 0; key < 5; key++) {
        total = 0;
        if (bpf_map_lookup_elem(fd, &key, values) == 0) {
            for (i = 0; i < num_cpus; i++)
                total += values[i];
            printf("%s = %llu\n", names[key], (unsigned long long)total);
        }
    }
}

int main(void)
{
    struct example_cgroup_bpf_bpf *skel = NULL;
    int err = 0;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    if (signal(SIGINT, handle_signal) == SIG_ERR ||
        signal(SIGTERM, handle_signal) == SIG_ERR) {
        perror("signal");
        return 1;
    }

    skel = example_cgroup_bpf_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open/load BPF skeleton\n");
        return 1;
    }

    err = example_cgroup_bpf_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach LSM program: %d\n", err);
        goto cleanup;
    }

    printf("Attached BPF LSM hook. Ctrl+C to stop.\n");
    fflush(stdout);
    while (!stop) {
        print_stats(skel->maps.bpf_cmd_counts);
        sleep(1);
    }

cleanup:
    example_cgroup_bpf_bpf__destroy(skel);
    return err ? 1 : 0;
}
