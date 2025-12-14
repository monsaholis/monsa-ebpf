// MIT License - Copyright (c) 2025 dev-monsa
// S2-advanced TC user-space controller.

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "build/example_tc_classifier.skel.h"

struct tc_event {
    __u64 timestamp_ns;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 protocol;
    __u32 len;
    __u32 mark;
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
    if (data_sz < sizeof(struct tc_event))
        return 0;

    const struct tc_event *evt = data;
    struct in_addr src, dst;
    src.s_addr = evt->saddr;
    dst.s_addr = evt->daddr;

    printf("=== TC Event (sampled) ===\n");
    printf("  Proto:    %s\n", proto_name(evt->protocol));
    printf("  Src:      %s:%u\n", inet_ntoa(src), evt->sport);
    printf("  Dst:      %s:%u\n", inet_ntoa(dst), evt->dport);
    printf("  Len:      %u bytes\n", evt->len);
    printf("  Mark:     0x%x\n", evt->mark);
    printf("  Count:    %llu\n\n", (unsigned long long)evt->count);
    return 0;
}

int main(int argc, char **argv) {
    struct example_tc_classifier_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err = 0;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
        return 1;
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    signal(SIGINT, handle_signal);

    skel = example_tc_classifier_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load BPF skeleton\n");
        return 1;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.tc_events), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        goto cleanup;
    }

    printf("TC classifier loaded. Attach manually with tc command.\n");
    printf("Example: tc qdisc add dev %s clsact\n", argv[1]);
    printf("         tc filter add dev %s ingress bpf obj tc_classifier.bpf.o sec tc\n\n", argv[1]);
    printf("Monitoring events. Ctrl+C to stop.\n\n");

    while (!stop)
        ring_buffer__poll(rb, 100);

cleanup:
    ring_buffer__free(rb);
    example_tc_classifier_bpf__destroy(skel);
    return err ? 1 : 0;
}
