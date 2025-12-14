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

// User-space controller for the uretprobe example. Attaches to a user-space
// symbol and reports per-PID call counts, latency, and last return value.

#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "build/example_uretprobe.skel.h"

struct uretprobe_stat {
    __u64 calls;
    __u64 total_ns;
    __s64 last_rc;
};

static volatile sig_atomic_t stop;

static void handle_signal(int sig)
{
    (void)sig;
    stop = 1;
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: sudo %s <binary> <symbol>\n", prog);
}

static void print_stats(struct bpf_map *map)
{
    __u32 key = 0, next_key;
    struct uretprobe_stat stat;
    int fd = bpf_map__fd(map);

    printf("PID -> calls avg_ms last_rc\n");
    while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(fd, &next_key, &stat) == 0) {
                 double avg_ms = stat.calls ? ((double)stat.total_ns / (double)stat.calls) / 1e6 : 0.0;
                 printf("  pid=%u calls=%llu avg_ms=%.3f last_rc=%lld\n",
                     next_key,
                     (unsigned long long)stat.calls,
                     avg_ms,
                     (long long)stat.last_rc);
        }
        key = next_key;
    }
}

int main(int argc, char **argv)
{
    const char *binary;
    const char *symbol;
    struct example_uretprobe_bpf *skel = NULL;
    struct bpf_link *link_entry = NULL;
    struct bpf_link *link_exit = NULL;
    struct bpf_uprobe_opts opts_entry = {};
    struct bpf_uprobe_opts opts_exit = {};
    int err = 0;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }
    binary = argv[1];
    symbol = argv[2];

    if (signal(SIGINT, handle_signal) == SIG_ERR ||
        signal(SIGTERM, handle_signal) == SIG_ERR) {
        perror("signal");
        return 1;
    }

    skel = example_uretprobe_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open/load BPF skeleton\n");
        return 1;
    }

    opts_entry.func_name = symbol;
    opts_entry.sz = sizeof(opts_entry);
    link_entry = bpf_program__attach_uprobe_opts(skel->progs.msb_uretprobe_entry, -1, binary, 0, &opts_entry);
    if (!link_entry) {
        fprintf(stderr, "failed to attach uprobe entry for %s:%s\n", binary, symbol);
        err = 1;
        goto cleanup;
    }

    opts_exit.func_name = symbol;
    opts_exit.retprobe = true;
    opts_exit.sz = sizeof(opts_exit);
    link_exit = bpf_program__attach_uprobe_opts(skel->progs.msb_uretprobe_exit, -1, binary, 0, &opts_exit);
    if (!link_exit) {
        fprintf(stderr, "failed to attach uretprobe for %s:%s\n", binary, symbol);
        err = 1;
        goto cleanup;
    }

    printf("Attached uprobe/uretprobe to %s:%s. Ctrl+C to stop.\n", binary, symbol);
    while (!stop) {
        print_stats(skel->maps.uretprobe_stats);
        sleep(1);
    }

cleanup:
    bpf_link__destroy(link_exit);
    bpf_link__destroy(link_entry);
    example_uretprobe_bpf__destroy(skel);
    return err ? 1 : 0;
}
