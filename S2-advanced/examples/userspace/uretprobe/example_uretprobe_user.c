// MIT License - Copyright (c) 2025 dev-monsa
// S2-advanced uretprobe user-space controller.

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "build/example_uretprobe.skel.h"

#define TASK_COMM_LEN 16

struct uretprobe_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 gid;
    __u64 entry_ts;
    __u64 exit_ts;
    __u64 latency_ns;
    __s64 retval;
    char comm[TASK_COMM_LEN];
};

static volatile sig_atomic_t stop;

static void handle_signal(int sig) {
    (void)sig;
    stop = 1;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    (void)ctx;
    if (data_sz < sizeof(struct uretprobe_event))
        return 0;

    const struct uretprobe_event *evt = data;
    printf("=== Uretprobe Event ===\n");
    printf("  PID:      %u\n", evt->pid);
    printf("  Comm:     %s\n", evt->comm);
    printf("  UID/GID:  %u/%u\n", evt->uid, evt->gid);
    printf("  Latency:  %llu ns (%.3f μs)\n", 
           (unsigned long long)evt->latency_ns,
           evt->latency_ns / 1000.0);
    printf("  RetVal:   %lld\n\n", (long long)evt->retval);
    return 0;
}

int main(int argc, char **argv) {
    struct example_uretprobe_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    struct bpf_link *entry_link = NULL, *exit_link = NULL;
    int err = 0;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <binary> <symbol>\n", argv[0]);
        return 1;
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    signal(SIGINT, handle_signal);

    skel = example_uretprobe_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load BPF skeleton\n");
        return 1;
    }

    entry_link = bpf_program__attach_uprobe(skel->progs.msb_uretprobe_entry, false, -1, argv[1], 0);
    if (!entry_link) {
        fprintf(stderr, "Failed to attach uprobe entry\n");
        err = 1;
        goto cleanup;
    }

    exit_link = bpf_program__attach_uprobe(skel->progs.msb_uretprobe_exit, true, -1, argv[1], 0);
    if (!exit_link) {
        fprintf(stderr, "Failed to attach uprobe exit (uretprobe)\n");
        err = 1;
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.uretprobe_events), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        goto cleanup;
    }

    printf("Attached uretprobe to %s:%s. Ctrl+C to stop.\n\n", argv[1], argv[2]);
    while (!stop)
        ring_buffer__poll(rb, 100);

cleanup:
    ring_buffer__free(rb);
    bpf_link__destroy(entry_link);
    bpf_link__destroy(exit_link);
    example_uretprobe_bpf__destroy(skel);
    return err ? 1 : 0;
}
