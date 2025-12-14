````markdown
# example cgroup_sockopt

Trace setsockopt/getsockopt calls per cgroup.

## Purpose
- Audit socket option changes (setsockopt/getsockopt) scoped by cgroup.
- Demonstrates `cgroup/setsockopt` and `cgroup/getsockopt` hooks with allow-only behavior.

## Supported OS / Kernel
- Linux kernel 5.4+ with cgroup v2 mounted (bpffs and cgroup2 typically at `/sys/fs/cgroup`).
- BTF recommended for skeleton-based workflows.

## Notes / Caveats
- Program only counts operations; adjust logic to restrict specific levels/optnames.
- Needs CAP_BPF + CAP_NET_ADMIN (or sudo) to load/attach.
- Attach to a cgroup v2 path (e.g., `/sys/fs/cgroup/unified`).

## Build
```bash
cd S2-advanced/examples/cgroup/cgroup_sockopt
./build.sh
```

## Attach
```bash
sudo bpftool cgroup attach /sys/fs/cgroup/unified setsockopt obj build/example_cgroup_sockopt.bpf.o sec cgroup/setsockopt
sudo bpftool cgroup attach /sys/fs/cgroup/unified getsockopt obj build/example_cgroup_sockopt.bpf.o sec cgroup/getsockopt
```

## Notes
Counters live in `sockopt_counts` (index 0: setsockopt, 1: getsockopt). Dump with `bpftool map dump`.

````