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

// S2-advanced kretprobe user-space: latency tracking, error classification, statistics.

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "build/example_kretprobe.skel.h"

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct kretprobe_event {
    __u64 timestamp_ns;
    __u64 latency_ns;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 gid;
    __u64 cgroup_id;
    char comm[TASK_COMM_LEN];
    __s64 retval;
    __u8 is_error;
    __s32 error_code;
    char func_name[32];
};

static volatile sig_atomic_t stop;

static void handle_signal(int sig)
{
    (void)sig;
    stop = 1;
}

static void format_timestamp(__u64 ts_ns, char *buf, size_t len)
{
    __u64 sec = ts_ns / 1000000000ULL;
    __u64 nsec = ts_ns % 1000000000ULL;
    snprintf(buf, len, "%llu.%09llu", (unsigned long long)sec, (unsigned long long)nsec);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;
    if (data_sz < sizeof(struct kretprobe_event))
        return 0;

    const struct kretprobe_event *evt = data;
    char ts[32];
    double latency_us = (double)evt->latency_ns / 1000.0;
    
    format_timestamp(evt->timestamp_ns, ts, sizeof(ts));

    printf("=== Kretprobe Event ===\n");
    printf("  Timestamp:   %s\n", ts);
    printf("  Function:    %s\n", evt->func_name);
    printf("  PID:         %u\n", evt->pid);
    printf("  TID:         %u\n", evt->tid);
    printf("  Comm:        %s\n", evt->comm);
    printf("  UID:         %u\n", evt->uid);
    printf("  GID:         %u\n", evt->gid);
    printf("  Cgroup ID:   %llu\n", (unsigned long long)evt->cgroup_id);
    printf("  Return Val:  %lld\n", (long long)evt->retval);
    printf("  Status:      %s\n", evt->is_error ? "ERROR" : "SUCCESS");
    if (evt->is_error)
        printf("  Error Code:  %d\n", evt->error_code);
    printf("  Latency:     %.3f us\n", latency_us);
    printf("\n");

    return 0;
}

int main(void)
{
    struct example_kretprobe_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
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

    rb = ring_buffer__new(bpf_map__fd(skel->maps.kretprobe_events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer\n");
        err = -1;
        goto cleanup;
    }

    printf("Attached kprobe/kretprobe to __x64_sys_openat. Ctrl+C to stop.\n");
    printf("Tracking: latency, return values, success/error stats\n");
    printf("Kernel logs: sudo cat /sys/kernel/debug/tracing/trace_pipe\n\n");
    fflush(stdout);

    while (!stop) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    example_kretprobe_bpf__destroy(skel);
    return err ? 1 : 0;
}
