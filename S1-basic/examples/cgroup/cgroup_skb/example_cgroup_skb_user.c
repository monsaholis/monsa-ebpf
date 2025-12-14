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

// User-space controller for cgroup_skb ingress/egress example. Attaches to a
// cgroup v2 path and prints packet counts.

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "build/example_cgroup_skb.skel.h"

static volatile sig_atomic_t stop;

static void handle_signal(int sig)
{
    (void)sig;
    stop = 1;
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: sudo %s <cgroup_path>\n", prog);
}

static void print_stats(struct bpf_map *ing, struct bpf_map *eg)
{
    __u32 key = 0;
    __u64 values[128];
    __u64 total;
    int fd;
    unsigned int i, num_cpus = libbpf_num_possible_cpus();

    if (num_cpus > 128)
        num_cpus = 128;

    fd = bpf_map__fd(ing);
    total = 0;
    if (bpf_map_lookup_elem(fd, &key, values) == 0) {
        for (i = 0; i < num_cpus; i++)
            total += values[i];
        printf("cgroup ingress packets = %llu\n", (unsigned long long)total);
    }

    fd = bpf_map__fd(eg);
    total = 0;
    if (bpf_map_lookup_elem(fd, &key, values) == 0) {
        for (i = 0; i < num_cpus; i++)
            total += values[i];
        printf("cgroup egress packets = %llu\n", (unsigned long long)total);
    }
}

int main(int argc, char **argv)
{
    const char *cg_path;
    int cg_fd = -1;
    struct example_cgroup_skb_bpf *skel = NULL;
    struct bpf_link *link_ing = NULL;
    struct bpf_link *link_eg = NULL;
    int err = 0;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }
    cg_path = argv[1];

    if (signal(SIGINT, handle_signal) == SIG_ERR ||
        signal(SIGTERM, handle_signal) == SIG_ERR) {
        perror("signal");
        return 1;
    }

    cg_fd = open(cg_path, O_DIRECTORY | O_RDONLY);
    if (cg_fd < 0) {
        perror("open cgroup path");
        return 1;
    }

    skel = example_cgroup_skb_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open/load BPF skeleton\n");
        err = 1;
        goto cleanup;
    }

    link_ing = bpf_program__attach_cgroup(skel->progs.msb_cgroup_ingress, cg_fd);
    link_eg = bpf_program__attach_cgroup(skel->progs.msb_cgroup_egress, cg_fd);
    if (!link_ing || !link_eg) {
        fprintf(stderr, "failed to attach cgroup_skb ingress/egress\n");
        err = 1;
        goto cleanup;
    }

    printf("Attached cgroup_skb ingress/egress to %s. Ctrl+C to stop.\n", cg_path);
    while (!stop) {
        print_stats(skel->maps.cgroup_pkt_count, skel->maps.cgroup_pkt_count_egress);
        sleep(1);
    }

cleanup:
    bpf_link__destroy(link_ing);
    bpf_link__destroy(link_eg);
    example_cgroup_skb_bpf__destroy(skel);
    if (cg_fd >= 0)
        close(cg_fd);
    return err ? 1 : 0;
}
