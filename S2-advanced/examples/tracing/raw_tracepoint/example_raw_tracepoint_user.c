// MIT License - Copyright (c) 2025 dev-monsa
// S2-advanced raw_tracepoint user-space controller.

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "build/example_raw_tracepoint.skel.h"

#define TASK_COMM_LEN 16

struct raw_tp_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 gid;
    __u64 cgroup_id;
    char comm[TASK_COMM_LEN];
    __u64 count;
    __u32 cpu;
};

static volatile sig_atomic_t stop;

static void handle_signal(int sig) {
    (void)sig;
    stop = 1;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    (void)ctx;
    if (data_sz < sizeof(struct raw_tp_event))
        return 0;

    const struct raw_tp_event *evt = data;
    printf("=== Raw Tracepoint Event ===\n");
    printf("  PID:      %u\n", evt->pid);
    printf("  Comm:     %s\n", evt->comm);
    printf("  UID/GID:  %u/%u\n", evt->uid, evt->gid);
    printf("  CPU:      %u\n", evt->cpu);
    printf("  Cgroup:   %llu\n", (unsigned long long)evt->cgroup_id);
    printf("  Count:    %llu\n\n", (unsigned long long)evt->count);
    return 0;
}

int main(int argc, char **argv) {
    struct example_raw_tracepoint_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err = 0;

    (void)argc;
    (void)argv;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    signal(SIGINT, handle_signal);

    skel = example_raw_tracepoint_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load BPF skeleton\n");
        return 1;
    }

    err = example_raw_tracepoint_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach raw_tracepoint\n");
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.raw_tp_events), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        goto cleanup;
    }

    printf("Raw Tracepoint monitor started. Ctrl+C to stop.\n\n");
    while (!stop)
        ring_buffer__poll(rb, 100);

cleanup:
    ring_buffer__free(rb);
    example_raw_tracepoint_bpf__destroy(skel);
    return err ? 1 : 0;
}
