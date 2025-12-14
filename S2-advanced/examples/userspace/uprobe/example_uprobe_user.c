// MIT License - Copyright (c) 2025 dev-monsa
// S2-advanced uprobe user-space controller.

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "build/example_uprobe.skel.h"

#define TASK_COMM_LEN 16

struct uprobe_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
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

static void handle_signal(int sig) {
    (void)sig;
    stop = 1;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    (void)ctx;
    if (data_sz < sizeof(struct uprobe_event))
        return 0;

    const struct uprobe_event *evt = data;
    printf("=== Uprobe Event ===\n");
    printf("  PID:      %u\n", evt->pid);
    printf("  Comm:     %s\n", evt->comm);
    printf("  UID/GID:  %u/%u\n", evt->uid, evt->gid);
    printf("  Cgroup:   %llu\n", (unsigned long long)evt->cgroup_id);
    printf("  Arg0-2:   0x%llx, 0x%llx, 0x%llx\n",
           (unsigned long long)evt->arg0,
           (unsigned long long)evt->arg1,
           (unsigned long long)evt->arg2);
    printf("  Count:    %llu\n\n", (unsigned long long)evt->count);
    return 0;
}

int main(int argc, char **argv) {
    struct example_uprobe_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    struct bpf_link *link = NULL;
    int err = 0;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <binary> <symbol>\n", argv[0]);
        return 1;
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    signal(SIGINT, handle_signal);

    skel = example_uprobe_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load BPF skeleton\n");
        return 1;
    }

    link = bpf_program__attach_uprobe(skel->progs.msb_uprobe_entry, false, -1, argv[1], 0);
    if (!link) {
        fprintf(stderr, "Failed to attach uprobe\n");
        err = 1;
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.uprobe_events), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        goto cleanup;
    }

    printf("Attached uprobe to %s:%s. Ctrl+C to stop.\n\n", argv[1], argv[2]);
    while (!stop)
        ring_buffer__poll(rb, 100);

cleanup:
    ring_buffer__free(rb);
    bpf_link__destroy(link);
    example_uprobe_bpf__destroy(skel);
    return err ? 1 : 0;
}
