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

// S2-advanced user-space: Receives and prints comprehensive kprobe events.

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "build/example_kprobe.skel.h"

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct kprobe_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u64 cgroup_id;
    char comm[TASK_COMM_LEN];
    __u64 arg0;
    __u64 arg1;
    __u64 arg2;
    __u64 count;
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
    if (data_sz < sizeof(struct kprobe_event)) {
        return 0;
    }

    const struct kprobe_event *evt = data;
    char ts[32];
    
    format_timestamp(evt->timestamp_ns, ts, sizeof(ts));

    printf("=== Kprobe Event ===\n");
    printf("  Timestamp:  %s\n", ts);
    printf("  Function:   %s\n", evt->func_name);
    printf("  PID:        %u\n", evt->pid);
    printf("  TID:        %u\n", evt->tid);
    printf("  PPID:       %u\n", evt->ppid);
    printf("  Comm:       %s\n", evt->comm);
    printf("  UID:        %u\n", evt->uid);
    printf("  GID:        %u\n", evt->gid);
    printf("  Cgroup ID:  %llu\n", (unsigned long long)evt->cgroup_id);
    printf("  Arg0:       0x%llx\n", (unsigned long long)evt->arg0);
    printf("  Arg1:       0x%llx\n", (unsigned long long)evt->arg1);
    printf("  Arg2:       0x%llx\n", (unsigned long long)evt->arg2);
    printf("  Call Count: %llu\n", (unsigned long long)evt->count);
    printf("\n");
    
    return 0;
}

int main(void)
{
    struct example_kprobe_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err = 0;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    if (signal(SIGINT, handle_signal) == SIG_ERR ||
        signal(SIGTERM, handle_signal) == SIG_ERR) {
        perror("signal");
        return 1;
    }

    skel = example_kprobe_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open/load BPF skeleton\n");
        return 1;
    }

    err = example_kprobe_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach kprobe: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.kprobe_events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer\n");
        err = -1;
        goto cleanup;
    }

    printf("Attached kprobe to __x64_sys_execve. Ctrl+C to stop.\n");
    printf("Collecting comprehensive event data (PID, UID, cgroup, args, etc.)\n");
    printf("Kernel-side logs: sudo cat /sys/kernel/debug/tracing/trace_pipe\n\n");
    fflush(stdout);
    
    while (!stop) {
        err = ring_buffer__poll(rb, 100 /* ms */);
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
    example_kprobe_bpf__destroy(skel);
    return err ? 1 : 0;
}
