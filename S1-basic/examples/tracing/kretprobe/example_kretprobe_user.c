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

// User-space loader for the kretprobe example. Attaches the program and
// periodically dumps the PID -> return value map for __x64_sys_getpid.

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "build/example_kretprobe.skel.h"

static volatile sig_atomic_t stop;

static void handle_signal(int sig)
{
    (void)sig;
    stop = 1;
}

static int dump_map(struct bpf_map *map)
{
    int fd = bpf_map__fd(map);
    __u32 key = 0, next_key;
    __s64 value;
    int err;

    printf("PID -> getpid return value\n");
    while ((err = bpf_map_get_next_key(fd, &key, &next_key)) == 0) {
        if (bpf_map_lookup_elem(fd, &next_key, &value) == 0) {
            printf("  pid=%u ret=%lld\n", next_key, (long long)value);
        }
        key = next_key;
    }

    if (err && errno != ENOENT) {
        perror("bpf_map_get_next_key");
        return -1;
    }
    return 0;
}

int main(void)
{
    struct example_kretprobe_bpf *skel = NULL;
    int err = 0;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    if (signal(SIGINT, handle_signal) == SIG_ERR ||
        signal(SIGTERM, handle_signal) == SIG_ERR) {
        perror("signal");
        return 1;
    }

    skel = example_kretprobe_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open/load BPF skeleton\n");
        return 1;
    }

    err = example_kretprobe_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach kretprobe: %d\n", err);
        goto cleanup;
    }

    printf("Attached kretprobe to __x64_sys_getpid. Ctrl+C to stop.\n");
    fflush(stdout);
    while (!stop) {
        dump_map(skel->maps.ret_values);
        sleep(1);
    }

cleanup:
    example_kretprobe_bpf__destroy(skel);
    return err ? 1 : 0;
}
