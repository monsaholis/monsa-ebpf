# xdp_pass (minimal)

Counts packets in a percpu array map and returns `XDP_PASS`.

## Build
```bash
cd S2-advanced/examples/network/xdp
./build.sh
```

Artifact: `build/xdp_pass.bpf.o`

## Attach
Replace `<IFACE>` with your NIC (run `ip link` to list):
```bash
sudo ip link set dev <IFACE> xdp obj build/xdp_pass.bpf.o sec xdp
```

Verify packet counter:
```bash
sudo bpftool map dump pinned /sys/fs/bpf/xdp/globals/xdp_stats
```

Detach:
```bash
sudo ip link set dev <IFACE> xdp off
```
