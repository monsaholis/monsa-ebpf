# example cgroup_sock

Monitor socket creation events at cgroup level.

## Purpose
- Observe socket creation per cgroup to audit or rate-limit new connections.
- Demonstrates `cgroup/sock_create` hook with allow-only behavior.

## Supported OS / Kernel
- Linux kernel 5.4+ with cgroup v2 mounted.
- BTF recommended for skeleton attach.

## Notes / Caveats
- This hook does not filter by default; change return value to enforce policy.
- Requires CAP_BPF + CAP_NET_ADMIN (or sudo) to load/attach.
- Must attach to a cgroup v2 path (e.g., `/sys/fs/cgroup/unified`).

## Build
```bash
cd S1-basic/examples/cgroup/cgroup_sock
./build.sh
```

## Attach
```bash
sudo bpftool cgroup attach /sys/fs/cgroup/unified sock_create obj build/example_cgroup_sock.bpf.o sec cgroup/sock_create
```

## Note
Requires cgroup v2. Use skeleton-based loader for simplified attach.
