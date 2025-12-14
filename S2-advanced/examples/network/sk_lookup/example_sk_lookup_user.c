// MIT License - Copyright (c) 2025 dev-monsa
// S2-advanced sk_lookup user-space controller.

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "build/example_sk_lookup.skel.h"

struct sk_lookup_event {
    __u64 timestamp_ns;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 protocol;
    __u64 count;
};

static volatile sig_atomic_t stop;

static void handle_signal(int sig) {
    (void)sig;
    stop = 1;
}

static const char* proto_name(__u8 proto) {
    return proto == 6 ? "TCP" : proto == 17 ? "UDP" : "OTHER";
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    (void)ctx;
    if (data_sz < sizeof(struct sk_lookup_event))
        return 0;

    const struct sk_lookup_event *evt = data;
    struct in_addr src, dst;
    src.s_addr = evt->saddr;
    dst.s_addr = evt->daddr;

    printf("=== SK_LOOKUP Event ===\n");
    printf("  Proto:    %s\n", proto_name(evt->protocol));
    printf("  Src:      %s:%u\n", inet_ntoa(src), evt->sport);
    printf("  Dst:      %s:%u\n", inet_ntoa(dst), evt->dport);
    printf("  Count:    %llu\n\n", (unsigned long long)evt->count);
    return 0;
}

int main(int argc, char **argv) {
    struct example_sk_lookup_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err = 0;

    (void)argc;
    (void)argv;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    signal(SIGINT, handle_signal);

    skel = example_sk_lookup_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load BPF skeleton\n");
        return 1;
    }

    err = example_sk_lookup_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach sk_lookup\n");
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.sk_lookup_events), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        goto cleanup;
    }

    printf("SK_LOOKUP monitor started. Ctrl+C to stop.\n\n");
    while (!stop)
        ring_buffer__poll(rb, 100);

cleanup:
    ring_buffer__free(rb);
    example_sk_lookup_bpf__destroy(skel);
    return err ? 1 : 0;
}
