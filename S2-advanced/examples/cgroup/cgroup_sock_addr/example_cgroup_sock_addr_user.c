// MIT License - Copyright (c) 2025 dev-monsa
// S2-advanced cgroup_sock_addr user-space controller.

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "build/example_cgroup_sock_addr.skel.h"

struct cgroup_sock_addr_event {
    __u64 timestamp_ns;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u32 family;
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
    if (data_sz < sizeof(struct cgroup_sock_addr_event))
        return 0;

    const struct cgroup_sock_addr_event *evt = data;
    struct in_addr dst;
    dst.s_addr = evt->daddr;

    printf("=== Cgroup Sock Addr Event ===\n");
    printf("  Cgroup:   %llu\n", (unsigned long long)evt->cgroup_id);
    printf("  Family:   %u\n", evt->family);
    printf("  Dst:      %s:%u\n", inet_ntoa(dst), evt->dport);
    printf("  Count:    %llu\n\n", (unsigned long long)evt->count);
    return 0;
}

int main(int argc, char **argv) {
    struct example_cgroup_sock_addr_bpf *skel = NULL;
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

    skel = example_cgroup_sock_addr_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load BPF skeleton\n");
        close(cgroup_fd);
        return 1;
    }

    link = bpf_program__attach_cgroup(skel->progs.msb_cgroup_sock_addr, cgroup_fd);
    if (!link) {
        fprintf(stderr, "Failed to attach cgroup_sock_addr\n");
        err = 1;
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.cgroup_sock_addr_events), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        goto cleanup;
    }

    printf("Cgroup Sock Addr monitor started for %s. Ctrl+C to stop.\n\n", argv[1]);
    while (!stop)
        ring_buffer__poll(rb, 100);

cleanup:
    ring_buffer__free(rb);
    bpf_link__destroy(link);
    close(cgroup_fd);
    example_cgroup_sock_addr_bpf__destroy(skel);
    return err ? 1 : 0;
}
