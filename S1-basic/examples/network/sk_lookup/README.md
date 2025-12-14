````markdown
# example sk_lookup

Count socket lookup attempts per destination port and allow by default.

## Purpose
- Observe which destination ports are being matched in the current netns.
- Demonstrates `sk_lookup` hook for allow/deny decisions during socket lookup.

## Supported OS / Kernel
- Linux kernel 5.9+ (sk_lookup introduced 5.9).
- BTF recommended for skeleton-based workflows.

## Notes / Caveats
- Program currently allows all lookups; change return to `SK_DROP` to deny.
- Attaches to a network namespace (default: current netns via user loader).
- Needs CAP_BPF + CAP_NET_ADMIN (or sudo) to load/attach.

## Build
```bash
cd S1-basic/examples/network/sk_lookup
./build.sh
```

## Run (user-space controller)
```bash
sudo ./build/example_sk_lookup_user
```

## Inspect
```bash
sudo bpftool map dump pinned /sys/fs/bpf/...   # if you pin manually
```

````