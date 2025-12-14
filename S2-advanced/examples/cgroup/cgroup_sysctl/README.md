````markdown
# example cgroup_sysctl

Audit sysctl read/write attempts per cgroup.

## Purpose
- Observe kernel parameter access (read/write) at the cgroup level.
- Demonstrates `cgroup/sysctl` hook with allow-only behavior.

## Supported OS / Kernel
- Linux kernel 5.9+ with cgroup v2 mounted (sysctl hooks landed in 5.9).
- BTF recommended for skeleton-based workflows.

## Notes / Caveats
- Program only counts; return 0 to deny specific sysctl accesses.
- Needs CAP_BPF + CAP_SYS_ADMIN (or sudo) to load/attach.
- Attach to a cgroup v2 path (e.g., `/sys/fs/cgroup/unified`).

## Build
```bash
cd S2-advanced/examples/cgroup/cgroup_sysctl
./build.sh
```

## Attach
```bash
sudo bpftool cgroup attach /sys/fs/cgroup/unified sysctl obj build/example_cgroup_sysctl.bpf.o sec cgroup/sysctl
```

## Notes
Counters live in `sysctl_counts` (0: read, 1: write). Dump with `bpftool map dump`.

````