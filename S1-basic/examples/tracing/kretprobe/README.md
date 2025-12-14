# example kretprobe

Captures return values from `__x64_sys_getpid` using kretprobe.

## Build
```bash
cd S1-basic/examples/tracing/kretprobe
./build.sh
```

## Attach
```bash
sudo bpftool prog load build/example_kretprobe.bpf.o /sys/fs/bpf/example_kretprobe
sudo bpftool map dump pinned /sys/fs/bpf/example_kretprobe --name ret_values
sudo rm /sys/fs/bpf/example_kretprobe
```
