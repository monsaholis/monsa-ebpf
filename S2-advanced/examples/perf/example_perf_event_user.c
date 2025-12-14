// MIT License - Copyright (c) 2025 dev-monsa
// S2-advanced perf_event user-space controller.

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "build/example_perf_event.skel.h"

#define TASK_COMM_LEN 16

struct perf_sample {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
    __u32 cpu;
    __u64 period;
    char comm[TASK_COMM_LEN];
    __u64 count;
};

static volatile sig_atomic_t stop;

static void handle_signal(int sig) {
    (void)sig;
    stop = 1;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    (void)ctx;
    if (data_sz < sizeof(struct perf_sample))
        return 0;

    const struct perf_sample *evt = data;
    printf("=== Perf Event Sample (cpu-cycles) ===\n");
    printf("  PID:      %u\n", evt->pid);
    printf("  Comm:     %s\n", evt->comm);
    printf("  CPU:      %u\n", evt->cpu);
    printf("  Period:   %llu\n", (unsigned long long)evt->period);
    printf("  Count:    %llu\n\n", (unsigned long long)evt->count);
    return 0;
}

static long perf_event_open(struct perf_event_attr *attr, pid_t pid,
                            int cpu, int group_fd, unsigned long flags)
{
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

int main(int argc, char **argv) {
    struct example_perf_event_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    struct perf_event_attr attr = {0};
    int perf_fd = -1;
    struct bpf_link *link = NULL;
    int err = 0;

    (void)argc;
    (void)argv;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    signal(SIGINT, handle_signal);

    skel = example_perf_event_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load BPF skeleton\n");
        return 1;
    }

    attr.type = PERF_TYPE_HARDWARE;
    attr.config = PERF_COUNT_HW_CPU_CYCLES;
    attr.sample_period = 1000000;  // Sample every 1M cycles
    attr.freq = 0;

    perf_fd = perf_event_open(&attr, -1, 0, -1, 0);
    if (perf_fd < 0) {
        fprintf(stderr, "Failed to open perf event\n");
        err = 1;
        goto cleanup;
    }

    link = bpf_program__attach_perf_event(skel->progs.msb_perf_event, perf_fd);
    if (!link) {
        fprintf(stderr, "Failed to attach perf_event\n");
        err = 1;
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.perf_events), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        goto cleanup;
    }

    printf("Perf event monitor started (cpu-cycles). Ctrl+C to stop.\n\n");
    while (!stop)
        ring_buffer__poll(rb, 100);

cleanup:
    ring_buffer__free(rb);
    bpf_link__destroy(link);
    if (perf_fd >= 0)
        close(perf_fd);
    example_perf_event_bpf__destroy(skel);
    return err ? 1 : 0;
}
