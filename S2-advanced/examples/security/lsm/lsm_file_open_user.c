// MIT License - Copyright (c) 2025 dev-monsa
// S2-advanced LSM user-space controller.

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "build/lsm_file_open.skel.h"

#define TASK_COMM_LEN 16
#define PATH_MAX 256

struct lsm_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 gid;
    __u64 cgroup_id;
    char comm[TASK_COMM_LEN];
    char path[PATH_MAX];
    __u32 flags;
    __u32 mode;
    __s32 decision;
    __u64 count;
};

static volatile sig_atomic_t stop;

static void handle_signal(int sig) {
    (void)sig;
    stop = 1;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    (void)ctx;
    if (data_sz < sizeof(struct lsm_event))
        return 0;

    const struct lsm_event *evt = data;
    printf("=== LSM File Open Event ===\n");
    printf("  PID:      %u\n", evt->pid);
    printf("  Comm:     %s\n", evt->comm);
    printf("  UID/GID:  %u/%u\n", evt->uid, evt->gid);
    printf("  Cgroup:   %llu\n", (unsigned long long)evt->cgroup_id);
    printf("  Path:     %s\n", evt->path);
    printf("  Decision: %s\n", evt->decision == 0 ? "ALLOW" : "DENY");
    printf("  Count:    %llu\n\n", (unsigned long long)evt->count);
    return 0;
}

int main(int argc, char **argv) {
    struct lsm_file_open_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err = 0;

    (void)argc;
    (void)argv;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    signal(SIGINT, handle_signal);

    skel = lsm_file_open_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load BPF skeleton\n");
        return 1;
    }

    err = lsm_file_open_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach LSM program\n");
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.lsm_events), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        goto cleanup;
    }

    printf("LSM file_open monitor started. Ctrl+C to stop.\n\n");
    while (!stop)
        ring_buffer__poll(rb, 100);

cleanup:
    ring_buffer__free(rb);
    lsm_file_open_bpf__destroy(skel);
    return err ? 1 : 0;
}
