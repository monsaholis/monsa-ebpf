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

// User-space controller for the perf_event example. Attaches a CPU cycles event
// on a given CPU (default 0) and prints sample counts.

#include <linux/perf_event.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "build/example_perf_event.skel.h"

static volatile sig_atomic_t stop;

static void handle_signal(int sig)
{
    (void)sig;
    stop = 1;
}

static void usage(const char *prog) __attribute__((unused));
static void usage(const char *prog)
{
    fprintf(stderr, "Usage: sudo %s [cpu]  # default cpu=0\n", prog);
}

static int open_perf_event(int cpu)
{
    struct perf_event_attr attr = {
        .type = PERF_TYPE_HARDWARE,
        .size = sizeof(attr),
        .config = PERF_COUNT_HW_CPU_CYCLES,
        .sample_type = 0,
        .sample_period = 0,
        .freq = 0,
        .disabled = 0,
    };
    int fd = syscall(__NR_perf_event_open, &attr, -1 /* pid */, cpu, -1, 0);
    if (fd < 0)
        perror("perf_event_open");
    return fd;
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
        printf("perf samples = %llu\n", (unsigned long long)total);
    }
}

int main(int argc, char **argv)
{
    int cpu = 0;
    int pfd = -1;
    struct example_perf_event_bpf *skel = NULL;
    struct bpf_link *link = NULL;
    int err = 0;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    if (argc >= 2)
        cpu = atoi(argv[1]);

    if (signal(SIGINT, handle_signal) == SIG_ERR ||
        signal(SIGTERM, handle_signal) == SIG_ERR) {
        perror("signal");
        return 1;
    }

    pfd = open_perf_event(cpu);
    if (pfd < 0)
        return 1;

    skel = example_perf_event_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open/load BPF skeleton\n");
        err = 1;
        goto cleanup;
    }

    link = bpf_program__attach_perf_event(skel->progs.msb_perf_sample, pfd);
    if (!link) {
        fprintf(stderr, "failed to attach perf_event program\n");
        err = 1;
        goto cleanup;
    }

    printf("Attached perf event on CPU %d. Ctrl+C to stop.\n", cpu);
    fflush(stdout);
    while (!stop) {
        print_stats(skel->maps.perf_sample_count);
        sleep(1);
    }

cleanup:
    bpf_link__destroy(link);
    example_perf_event_bpf__destroy(skel);
    if (pfd >= 0)
        close(pfd);
    return err ? 1 : 0;
}
