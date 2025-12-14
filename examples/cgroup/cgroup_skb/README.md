# example cgroup_skb

Filter packets at cgroup level (ingress/egress).

## Purpose
- Count or filter packets per cgroup at ingress/egress to enforce per-service policies.
- Demonstrates `cgroup_skb/ingress` and `cgroup_skb/egress` attach types with minimal allow-only programs.

## Supported OS / Kernel
- Linux kernel 5.4+ with cgroup v2 mounted (bpffs and cgroup2 typically at `/sys/fs/cgroup`).
- Requires BTF for skeleton-based workflows (most modern distros ship it).

## Notes / Caveats
- Attach point is cgroup v2 only; will not work on legacy v1 hierarchy.
- Program currently always allows traffic; extend return code for drop/deny logic.
- Needs CAP_BPF + CAP_NET_ADMIN (or sudo) to load/attach.

## Build
```bash
cd examples/cgroup/cgroup_skb
./build.sh
```

## Attach
Attach to cgroup using bpftool or libbpf:
```bash
sudo bpftool cgroup attach /sys/fs/cgroup/unified ingress obj build/example_cgroup_skb.bpf.o sec cgroup_skb/ingress
sudo bpftool cgroup attach /sys/fs/cgroup/unified egress obj build/example_cgroup_skb.bpf.o sec cgroup_skb/egress
```

## Note
- Requires cgroup v2. Check with `mount | grep cgroup2`.
- Counters: `cgroup_pkt_count` (ingress) and `cgroup_pkt_count_egress` (egress).
