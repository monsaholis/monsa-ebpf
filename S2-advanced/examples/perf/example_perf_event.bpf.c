// MIT License - Copyright (c) 2025 dev-monsa
// S2-advanced perf_event: Hardware performance counter sampling.

#include "../../../../common/include/bpf_helpers.h"
#include <linux/bpf.h>
#include <linux/perf_event.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct perf_sample {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
    __u32 cpu;
    __u64 period;
    char comm[TASK_COMM_LEN];
    __u64 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} perf_counts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} perf_events SEC(".maps");

SEC("perf_event")
int msb_perf_event(struct bpf_perf_event_data *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 *count, one = 1, new_count;
    struct perf_sample *evt;

    count = bpf_map_lookup_elem(&perf_counts, &pid);
    if (!count) {
        bpf_map_update_elem(&perf_counts, &pid, &one, BPF_ANY);
        new_count = 1;
    } else {
        new_count = __sync_fetch_and_add(count, 1) + 1;
    }

    // Sample 1/100 events
    if ((new_count % 100) != 0)
        return 0;

    evt = bpf_ringbuf_reserve(&perf_events, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->pid = pid;
    evt->tid = (__u32)pid_tgid;
    evt->cpu = bpf_get_smp_processor_id();
    evt->period = ctx->sample_period;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    evt->count = new_count;

    bpf_printk("perf_event: pid=%u cpu=%u period=%llu\n", pid, evt->cpu, evt->period);
    bpf_ringbuf_submit(evt, 0);

    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
