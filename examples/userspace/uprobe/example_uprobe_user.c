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

// User-space controller for the uprobe example. Attaches to a user binary and
// symbol, then prints per-PID call counts from the map.

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "build/example_uprobe.skel.h"

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

static void print_map(struct bpf_map *map)
{
    __u32 key = 0, next_key;
    __u64 value;
    int fd = bpf_map__fd(map);

    printf("PID -> calls\n");
    while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(fd, &next_key, &value) == 0)
            printf("  pid=%u calls=%llu\n", next_key, (unsigned long long)value);
        key = next_key;
    }
}

int main(int argc, char **argv)
{
    const char *binary;
    const char *symbol;
    struct example_uprobe_bpf *skel = NULL;
    struct bpf_link *link = NULL;
    struct bpf_uprobe_opts opts = {
        .sz = sizeof(struct bpf_uprobe_opts),
    };
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

    skel = example_uprobe_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open/load BPF skeleton\n");
        return 1;
    }

    opts.func_name = symbol;
    link = bpf_program__attach_uprobe_opts(skel->progs.msb_uprobe_target, -1, binary, 0, &opts);
    if (!link) {
        fprintf(stderr, "failed to attach uprobe for %s:%s\n", binary, symbol);
        err = 1;
        goto cleanup;
    }

    printf("Attached uprobe to %s:%s. Ctrl+C to stop.\n", binary, symbol);
    while (!stop) {
        print_map(skel->maps.uprobe_count);
        sleep(1);
    }

cleanup:
    bpf_link__destroy(link);
    example_uprobe_bpf__destroy(skel);
    return err ? 1 : 0;
}
