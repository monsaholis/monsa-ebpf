````markdown
# example cgroup_device

Audit device access attempts per cgroup.

## Purpose
- Track attempts to read/write/mknod devices from cgroups.
- Demonstrates `cgroup/dev` hook with allow-only behavior.

## Supported OS / Kernel
- Linux kernel 5.4+ with cgroup v2 mounted (bpffs and cgroup2 typically at `/sys/fs/cgroup`).
- BTF recommended for skeleton-based workflows.

## Notes / Caveats
- Counts access types only; return non-zero to deny specific operations.
- Needs CAP_BPF + CAP_SYS_ADMIN (or sudo) to load/attach.
- Attach to a cgroup v2 path (e.g., `/sys/fs/cgroup/unified`).

## Build
```bash
cd examples/cgroup/cgroup_device
./build.sh
```

## Attach
```bash
sudo bpftool cgroup attach /sys/fs/cgroup/unified dev obj build/example_cgroup_device.bpf.o sec cgroup/dev
```

## Notes
Counters live in `dev_counts` (0: read, 1: write, 2: mknod, 3: other). Dump with `bpftool map dump`.

````