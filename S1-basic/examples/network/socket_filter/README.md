# example socket_filter

Socket filter to count packets (similar to tcpdump).

## Purpose
- Minimal classic BPF socket filter attached to a raw socket to demonstrate packet filtering.
- Shows how to drop everything for testing plumbing.

## Supported OS / Kernel
- Linux kernel 4.9+ with BPF and BTF (for skeleton build) available.
- Works on both cgroup v1/v2 systems; no cgroup dependency.

## Notes / Caveats
- Filter is drop-all; change return value to pass traffic.
- Requires CAP_NET_ADMIN (or sudo) to create and bind raw socket.
- Runs in process context; not as fast as XDP/TC for heavy traffic.

## Build
```bash
cd S1-basic/examples/network/socket_filter
./build.sh
```

## Note
Attach to socket using `setsockopt(SO_ATTACH_BPF)` from user-space program.
Typically used for packet capture and monitoring.
