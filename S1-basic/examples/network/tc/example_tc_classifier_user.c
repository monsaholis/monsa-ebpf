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

// User-space controller for the TC classifier example. Attaches ingress TC hook
// to an interface and prints packet counts.

#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "build/example_tc_classifier.skel.h"

static volatile sig_atomic_t stop;

static void handle_signal(int sig)
{
    (void)sig;
    stop = 1;
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: sudo %s <ifname>\n", prog);
}

static int attach_tc(struct bpf_program *prog, int ifindex)
{
    struct bpf_tc_hook hook = {
        .sz = sizeof(hook),
        .ifindex = ifindex,
        .attach_point = BPF_TC_INGRESS,
    };
    struct bpf_tc_opts opts = {
        .sz = sizeof(opts),
        .handle = 1,
        .priority = 1,
        .prog_fd = bpf_program__fd(prog),
        .flags = BPF_TC_F_REPLACE,
    };
    int err;

    err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST)
        return err;

    err = bpf_tc_attach(&hook, &opts);
    if (err)
        return err;

    // store handle/priority in hook private? opts already carries.
    return 0;
}

static void detach_tc(struct bpf_program *prog, int ifindex)
{
    (void)prog;
    struct bpf_tc_hook hook = {
        .sz = sizeof(hook),
        .ifindex = ifindex,
        .attach_point = BPF_TC_INGRESS,
    };
    struct bpf_tc_opts opts = {
        .sz = sizeof(opts),
        .handle = 1,
        .priority = 1,
    };

    bpf_tc_detach(&hook, &opts);
    bpf_tc_hook_destroy(&hook);
}

static void print_stats(struct bpf_map *map)
{
    __u32 key = 0;
    __u64 values[128];
    __u64 total = 0;
    int fd = bpf_map__fd(map);
    unsigned int i, num_cpus = libbpf_num_possible_cpus();

    if (num_cpus > 128)
        num_cpus = 128;

    if (bpf_map_lookup_elem(fd, &key, values) == 0) {
        for (i = 0; i < num_cpus; i++)
            total += values[i];
        printf("tc packets = %llu\n", (unsigned long long)total);
    }
}

int main(int argc, char **argv)
{
    const char *ifname;
    int ifindex;
    struct example_tc_classifier_bpf *skel = NULL;
    int err = 0;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    ifname = argv[1];
    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        perror("if_nametoindex");
        return 1;
    }

    if (signal(SIGINT, handle_signal) == SIG_ERR ||
        signal(SIGTERM, handle_signal) == SIG_ERR) {
        perror("signal");
        return 1;
    }

    skel = example_tc_classifier_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open/load BPF skeleton\n");
        return 1;
    }

    err = attach_tc(skel->progs.msb_tc_classifier, ifindex);
    if (err) {
        fprintf(stderr, "failed to attach TC program: %d\n", err);
        goto cleanup;
    }

    printf("Attached TC classifier to %s ingress. Ctrl+C to stop.\n", ifname);
    while (!stop) {
        print_stats(skel->maps.tc_stats);
        sleep(1);
    }

cleanup:
    detach_tc(skel->progs.msb_tc_classifier, ifindex);
    example_tc_classifier_bpf__destroy(skel);
    return err ? 1 : 0;
}
