// MIT License - Copyright (c) 2025 dev-monsa
// S2-advanced cgroup_sysctl user-space controller.

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "build/example_cgroup_sysctl.skel.h"

#ifndef MAX_SYSCTL_LEN
#define MAX_SYSCTL_LEN 128
#endif

struct cgroup_sysctl_event {
    __u64 timestamp_ns;
    char name[MAX_SYSCTL_LEN];
    __u32 write;
    __u64 cgroup_id;
    __u64 count;
};

static volatile sig_atomic_t stop;

static void handle_signal(int sig) {
    (void)sig;
    stop = 1;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    (void)ctx;
    if (data_sz < sizeof(struct cgroup_sysctl_event))
        return 0;

    const struct cgroup_sysctl_event *evt = data;
    printf("=== Cgroup Sysctl Event ===\n");
    printf("  Cgroup:   %llu\n", (unsigned long long)evt->cgroup_id);
    printf("  Name:     %s\n", evt->name);
    printf("  Write:    %s\n", evt->write ? "YES" : "NO");
    printf("  Count:    %llu\n\n", (unsigned long long)evt->count);
    return 0;
}

int main(int argc, char **argv) {
    struct example_cgroup_sysctl_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int cgroup_fd = -1;
    struct bpf_link *link = NULL;
    int err = 0;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <cgroup_path>\n", argv[0]);
        return 1;
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    signal(SIGINT, handle_signal);

    cgroup_fd = open(argv[1], O_RDONLY);
    if (cgroup_fd < 0) {
        fprintf(stderr, "Failed to open cgroup: %s\n", argv[1]);
        return 1;
    }

    skel = example_cgroup_sysctl_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load BPF skeleton\n");
        close(cgroup_fd);
        return 1;
    }

    link = bpf_program__attach_cgroup(skel->progs.msb_cgroup_sysctl, cgroup_fd);
    if (!link) {
        fprintf(stderr, "Failed to attach cgroup_sysctl\n");
        err = 1;
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.cgroup_sysctl_events), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        goto cleanup;
    }

    printf("Cgroup Sysctl monitor started for %s. Ctrl+C to stop.\n\n", argv[1]);
    while (!stop)
        ring_buffer__poll(rb, 100);

cleanup:
    ring_buffer__free(rb);
    bpf_link__destroy(link);
    close(cgroup_fd);
    example_cgroup_sysctl_bpf__destroy(skel);
    return err ? 1 : 0;
}
