````markdown
# example cgroup_sock_addr

Trace connect, bind, and sendmsg attempts at the cgroup boundary.

## Purpose
- Audit outbound connection attempts and bind/sendmsg activity per cgroup.
- Demonstrates `cgroup/{connect,bind,sendmsg}` hooks with allow-only behavior.

## Supported OS / Kernel
- Linux kernel 5.4+ with cgroup v2 mounted (bpffs and cgroup2 typically at `/sys/fs/cgroup`).
- BTF recommended for skeleton-based workflows.

## Notes / Caveats
- Program currently only counts; return non-zero to deny, or adjust logic to filter by port/address.
- Needs CAP_BPF + CAP_NET_ADMIN (or sudo) to load/attach.
- Attach to a cgroup v2 path (e.g., `/sys/fs/cgroup/unified`).

## Build
```bash
cd S1-basic/examples/cgroup/cgroup_sock_addr
./build.sh
```

## Attach
Attach multiple hooks as needed. Examples:
```bash
sudo bpftool cgroup attach /sys/fs/cgroup/unified connect4 obj build/example_cgroup_sock_addr.bpf.o sec cgroup/connect4
sudo bpftool cgroup attach /sys/fs/cgroup/unified bind4 obj build/example_cgroup_sock_addr.bpf.o sec cgroup/bind4
sudo bpftool cgroup attach /sys/fs/cgroup/unified sendmsg4 obj build/example_cgroup_sock_addr.bpf.o sec cgroup/sendmsg4
```

## Notes
Counters live in `sock_addr_counts` (index 0: connect, 1: bind, 2: sendmsg). Dump with `bpftool map dump`.

````