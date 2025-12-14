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

// User-space loader for the fentry/fexit exec latency example. Polls ring buffer
// events with per-exec duration in nanoseconds.

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "build/fentry_exec_latency.skel.h"

struct exec_latency_event {
    __u32 pid;
    char comm[16];
    __u64 duration_ns;
};

static volatile sig_atomic_t stop;

static void handle_signal(int sig)
{
    (void)sig;
    stop = 1;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;
    if (data_sz < sizeof(struct exec_latency_event))
        return 0;

    const struct exec_latency_event *evt = data;
    printf("exec pid=%u comm=%s latency_ns=%llu\n",
           evt->pid, evt->comm, (unsigned long long)evt->duration_ns);
    return 0;
}

int main(void)
{
    struct fentry_exec_latency_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err = 0;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    if (signal(SIGINT, handle_signal) == SIG_ERR ||
        signal(SIGTERM, handle_signal) == SIG_ERR) {
        perror("signal");
        return 1;
    }

    skel = fentry_exec_latency_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open/load BPF skeleton\n");
        return 1;
    }

    err = fentry_exec_latency_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach fentry/fexit: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.exec_latency_events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer\n");
        err = -1;
        goto cleanup;
    }

    printf("Collecting exec latency events... Ctrl+C to stop.\n");
    while (!stop) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "ring_buffer__poll error: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    fentry_exec_latency_bpf__destroy(skel);
    return err ? 1 : 0;
}
