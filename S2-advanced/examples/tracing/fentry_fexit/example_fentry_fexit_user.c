// MIT License - Copyright (c) 2025 dev-monsa
// S2-advanced fentry/fexit user-space controller.

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "build/example_fentry_fexit.skel.h"

#define TASK_COMM_LEN 16

struct fentry_fexit_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 gid;
    __u64 cgroup_id;
    char comm[TASK_COMM_LEN];
    __u64 entry_ts;
    __u64 exit_ts;
    __u64 latency_ns;
    __u64 retval;
    __u64 count;
};

static volatile sig_atomic_t stop;

static void handle_signal(int sig) {
    (void)sig;
    stop = 1;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    (void)ctx;
    if (data_sz < sizeof(struct fentry_fexit_event))
        return 0;

    const struct fentry_fexit_event *evt = data;
    printf("=== Fentry/Fexit Event ===\n");
    printf("  PID:      %u\n", evt->pid);
    printf("  Comm:     %s\n", evt->comm);
    printf("  UID/GID:  %u/%u\n", evt->uid, evt->gid);
    printf("  Latency:  %llu ns (%.3f μs)\n", 
           (unsigned long long)evt->latency_ns,
           evt->latency_ns / 1000.0);
    printf("  RetVal:   %lld\n", (long long)evt->retval);
    printf("  Count:    %llu\n\n", (unsigned long long)evt->count);
    return 0;
}

int main(int argc, char **argv) {
    struct example_fentry_fexit_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err = 0;

    (void)argc;
    (void)argv;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    signal(SIGINT, handle_signal);

    skel = example_fentry_fexit_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load BPF skeleton\n");
        return 1;
    }

    err = example_fentry_fexit_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach fentry/fexit\n");
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.fentry_fexit_events), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        goto cleanup;
    }

    printf("Fentry/Fexit monitor started (do_sys_openat2). Ctrl+C to stop.\n\n");
    while (!stop)
        ring_buffer__poll(rb, 100);

cleanup:
    ring_buffer__free(rb);
    example_fentry_fexit_bpf__destroy(skel);
    return err ? 1 : 0;
}
