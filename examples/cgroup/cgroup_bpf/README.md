````markdown
# example cgroup_bpf

Audit BPF program/map operations (load, attach, detach) using the `lsm/bpf` hook.

> Note: Kernel has no dedicated `cgroup/bpf` hook. This example uses the BPF LSM hook to control/audit BPF syscalls system-wide and is placed here to illustrate "BPF attach control" per the request.

## Purpose
- Observe BPF program loads, map creations, and prog attach/detach attempts.
- Demonstrates `lsm/bpf` with allow-only behavior to build BPF governance.

## Supported OS / Kernel
- Linux kernel 5.7+ with `CONFIG_BPF_LSM` enabled (required for BPF LSM programs).
- BTF recommended for skeleton-based workflows.

## Notes / Caveats
- Hook is global, not per-cgroup; to gate BPF per cgroup, combine with cgroup delegation policies.
- Program only counts; return non-zero to deny operations after policy checks.
- Needs CAP_BPF + CAP_SYS_ADMIN (or sudo) to load.

## Build
```bash
cd examples/cgroup/cgroup_bpf
./build.sh
```

## Attach (load LSM program)
```bash
sudo bpftool prog load build/example_cgroup_bpf.bpf.o /sys/fs/bpf/example_cgroup_bpf type lsm
```

## Notes
Counters live in `bpf_cmd_counts` (0: prog_load, 1: map_create, 2: prog_attach, 3: prog_detach, 4: other). Dump with `bpftool map dump`.

````