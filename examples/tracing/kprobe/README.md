# example kprobe (exec counter, beginner)

Minimal eBPF kprobe that counts `execve` calls per PID and emits events. Build produces the BPF object plus an auto-generated libbpf skeleton for a user-space loader.

## Build

```bash
cd examples/tracing/kprobe
./build.sh
```

Artifacts land in `build/`:
- `example_kprobe.bpf.o` — load with `bpftool` or your own libbpf-based loader
- `example_kprobe.skel.h` — drop into a C user program if desired
- `example_kprobe_user` — user-space loader with ring-buffer callback (built when `pkg-config libbpf` is available)

## Quick test with bpftool

```bash
cd examples/tracing/kprobe
sudo bpftool prog load build/example_kprobe.bpf.o /sys/fs/bpf/example_kprobe
sudo bpftool net attach kprobe id $(sudo bpftool prog show pinned /sys/fs/bpf/example_kprobe | awk '/id/ {print $2}') func __x64_sys_execve

# run some commands to generate execve events
ls >/dev/null

# dump per-PID counts
sudo bpftool map dump pinned /sys/fs/bpf/example_kprobe --name exec_counts

# detach/cleanup
sudo rm /sys/fs/bpf/example_kprobe
```

## User-space loader (ring buffer callback)
- Dependencies: `libbpf-dev`, `pkg-config`, `clang` must be installed for `build.sh` to build `example_kprobe_user`.
- Run as root to receive events via ring buffer.

```bash
cd examples/tracing/kprobe
./build.sh

# receive ring buffer events (Ctrl+C to quit)
sudo ./build/example_kprobe_user
```

Example output:
```
listening for execve events... (Ctrl+C to quit)
execve pid=1234 comm=bash count=1
execve pid=1234 comm=ls count=2
```
