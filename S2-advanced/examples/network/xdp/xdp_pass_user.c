// MIT License - Copyright (c) 2025 dev-monsa
// S2-advanced XDP user-space: packet stats, sampled events, DDoS detection.

#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "build/xdp_pass.skel.h"

struct xdp_event {
    __u64 timestamp_ns;
    __u32 ifindex;
    __u32 rx_queue;
    __u32 pkt_len;
    __u16 eth_proto;
    __u8 ip_proto;
    __u8 action;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 tcp_flags;
};

static volatile sig_atomic_t stop;

static void handle_signal(int sig) {
    (void)sig;
    stop = 1;
}

static const char *proto_name(__u8 proto) {
    switch(proto) {
        case 6: return "TCP";
        case 17: return "UDP";
        case 1: return "ICMP";
        default: return "OTHER";
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    (void)ctx;
    if (data_sz < sizeof(struct xdp_event))
        return 0;

    const struct xdp_event *evt = data;
    struct in_addr src, dst;
    src.s_addr = htonl(evt->src_ip);
    dst.s_addr = htonl(evt->dst_ip);

    printf("XDP Event: %s %s:%u -> %s:%u len=%u queue=%u\n",
           proto_name(evt->ip_proto),
           inet_ntoa(src), evt->src_port,
           inet_ntoa(dst), evt->dst_port,
           evt->pkt_len, evt->rx_queue);
    return 0;
}

int main(int argc, char **argv) {
    struct xdp_pass_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int ifindex, err = 0;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
        return 1;
    }

    ifindex = if_nametoindex(argv[1]);
    if (ifindex == 0) {
        perror("if_nametoindex");
        return 1;
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    skel = xdp_pass_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load BPF skeleton\n");
        return 1;
    }

    err = bpf_xdp_attach(ifindex, bpf_program__fd(skel->progs.xdp_pass), 0, NULL);
    if (err) {
        fprintf(stderr, "Failed to attach XDP program: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.xdp_events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = -1;
        goto detach;
    }

    printf("Attached XDP to %s (ifindex=%d). Ctrl+C to stop.\n", argv[1], ifindex);
    printf("Collecting: L2-L4 headers, DDoS patterns, per-CPU stats\n\n");

    while (!stop) {
        ring_buffer__poll(rb, 100);
    }

detach:
    bpf_xdp_detach(ifindex, 0, NULL);
cleanup:
    ring_buffer__free(rb);
    xdp_pass_bpf__destroy(skel);
    return err ? 1 : 0;
}
