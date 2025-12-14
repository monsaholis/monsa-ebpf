# monsa-ebpf

Beginner-friendly eBPF examples with maps, organized by program type.

Version: v0.1.1 (2025-12-14)

## Changelog
- v0.1.0 (2025-12-13): Initial README structure, example lineup, execution flow, and permission checks.

## Directory Layout

```
monsa-ebpf/
├── README.md                # Project overview and execution guide
├── docs/
│   ├── quickstart.md        # Quick build/run guide
│   ├── concepts.md          # eBPF basics, map types, attach methods
│   └── troubleshooting.md   # Kernel version/permission/toolchain issues
├── common/
│   ├── include/             # Common headers (helpers, map defs)
│   ├── lib/                 # Common utils (bpf_helpers, ringbuf helpers)
│   └── maps/                # Reusable map definition samples
├── S1-basic/
│   └── examples/
│       ├── tracing/             # kernel-side tracing hooks
│       │   ├── kprobe/          # probe kernel function entry
│       │   ├── kretprobe/       # probe kernel function return
│       │   ├── tracepoint/      # use stable tracepoints
│       │   ├── raw_tracepoint/  # raw tracepoint arguments
│       │   └── fentry_fexit/    # fentry/fexit for low overhead
│       ├── userspace/           # user-space probes
│       │   ├── uprobe/          # function entry in binaries
│       │   └── uretprobe/       # function return in binaries
│       ├── network/             # packet/datapath examples
│       │   ├── sk_lookup/       # socket lookup redirection
│       │   ├── socket_filter/   # classic socket filter
│       │   ├── tc/              # TC ingress classifier
│       │   └── xdp/             # XDP pass/drop
│       ├── security/            # LSM hooks
│       │   └── lsm/             # file open policy
│       ├── perf/                # perf event integrations
│       │   └── perf_event/      # CPU cycles sampling
│       └── cgroup/              # cgroup v2 helpers
│           ├── cgroup_bpf/      # base attach + counters
│           ├── cgroup_device/   # device access control
│           ├── cgroup_skb/      # skb path enforcement
│           ├── cgroup_sock/     # socket-level filters
│           ├── cgroup_sock_addr/# address bind/connect policy
│           ├── cgroup_sockopt/  # setsockopt inspection
│           └── cgroup_sysctl/   # sysctl access control
├── S2-advanced/
│   └── examples/                # Advanced examples with comprehensive data collection
│       ├── tracing/             # Full-context kernel tracing
│       │   ├── kprobe/          # Complete task metadata, args, per-PID counters
│       │   ├── kretprobe/       # Return values, latency, success/error stats
│       │   ├── tracepoint/      # Event stream + frequency analysis
│       │   ├── raw_tracepoint/  # Raw kernel args with custom parsing
│       │   └── fentry_fexit/    # BTF-typed args, latency profiling
│       ├── userspace/           # Application-level instrumentation
│       │   ├── uprobe/          # Function args, per-binary call patterns
│       │   └── uretprobe/       # Latency histograms, error rate tracking
│       ├── network/             # Deep packet inspection
│       │   ├── sk_lookup/       # 5-tuple tracking, connection matrix
│       │   ├── socket_filter/   # L2-L4 headers, protocol distribution
│       │   ├── tc/              # QoS metrics, drop reasons
│       │   └── xdp/             # DDoS detection, per-CPU packet rates
│       ├── security/            # Security audit trails
│       │   └── lsm/             # File ops, security context, policy violations
│       ├── perf/                # Performance profiling
│       │   └── perf_event/      # Hardware counters, stack traces, hot paths
│       └── cgroup/              # Per-container/service metrics
│           ├── cgroup_bpf/      # Program attach tracking
│           ├── cgroup_device/   # Device access patterns
│           ├── cgroup_skb/      # Per-cgroup traffic stats
│           ├── cgroup_sock/     # Socket creation patterns
│           ├── cgroup_sock_addr/# Connect/bind monitoring
│           ├── cgroup_sockopt/  # Socket option tracking
│           └── cgroup_sysctl/   # Kernel parameter changes
```
```

## Recommended Learning Path
1. **S1-basic**: Start with simple examples demonstrating core eBPF concepts
   - `docs/quickstart.md`: Install tools → build → load → verify
   - `docs/concepts.md`: Program types, maps, attach points
   - Per-example README: Execution, dependencies, kernel requirements
   
2. **S2-advanced**: Progress to comprehensive data collection
   - Extended context: timestamps, security info, performance metrics
   - Dual output: user-space (ringbuf) + kernel (bpf_printk)
   - Production-ready patterns: error handling, statistics, profiling

## S2-Advanced Features

S2-advanced examples demonstrate **comprehensive data collection** for production observability:

### Data Collection Enhancements
- **Complete metadata**: PID/TID/PPID, UID/GID, cgroup ID, comm
- **Timestamps**: Nanosecond precision for latency tracking
- **Arguments**: Full function args via PT_REGS or BTF
- **Statistics**: Per-entity counters, success/error rates
- **Dual output**: Ringbuf (user-space) + bpf_printk (kernel debug)

### Output Modes
1. **User-Space (Ringbuf)**: Rich structured events for monitoring stacks
2. **Kernel-Side (bpf_printk)**: Debug logs via `trace_pipe`
   ```bash
   sudo cat /sys/kernel/debug/tracing/trace_pipe
   ```

### Example: S2 Kprobe Output
```
=== Kprobe Event ===
  Timestamp:  12345678.123456789
  Function:   __x64_sys_execve
  PID:        1234
  TID:        1234
  Comm:       bash
  UID:        1000
  GID:        1000
  Cgroup ID:  4567890123456
  Arg0:       0x7fff12345678
  Call Count: 42
```

## Quick Start Examples
- `S1-basic/examples/tracing/kprobe`: Per-PID execve counter. Use `build.sh` to generate BPF object + skeleton.
- `S1-basic/examples/network/xdp`: Drop/pass example. Attach/detach with bpftool.
- `S1-basic/examples/tracing/fentry_fexit`: Record function entry with fentry, measure execution time with fexit.
- `S1-basic/examples/security/lsm`: File open filter (requires root, kernel ≥ 5.7 recommended).

## Map Usage Patterns
- Common map definitions in `common/maps/`, examples use `extern` declarations for reuse.
- **ringbuf**: Tracing → user space event delivery.
- **hash/array**: Counter/metric aggregation.
- **percpu_array/hash**: Lock-free high-speed counters.
- **lru_hash**: Dynamic entry management.

## Build & Run Guide

### Build all examples
```bash
./build_examples.sh
```

`build_examples.sh` builds both `S1-basic/examples` and `S2-advanced/examples` when present.

### Example: kprobe quick run
```bash
cd S1-basic/examples/tracing/kprobe
./build.sh

# Load and attach kprobe to __x64_sys_execve
sudo bpftool prog load build/example_kprobe.bpf.o /sys/fs/bpf/example_kprobe
sudo bpftool net attach kprobe id $(sudo bpftool prog show pinned /sys/fs/bpf/example_kprobe | awk '/id/ {print $2}') func __x64_sys_execve

# Check counters after execve events
sudo bpftool map dump pinned /sys/fs/bpf/example_kprobe --name exec_counts

# Cleanup
sudo rm /sys/fs/bpf/example_kprobe
```

## BVT (Build Verification Test)

`bvt_examples.sh` automatically builds and verifies all examples. Set `EXAMPLES_DIR` to target `S2-advanced/examples`.

```bash
# Build and run all tests
./bvt_examples.sh

# Skip build, test only
SKIP_BUILD=1 ./bvt_examples.sh

# Specify network interface for network tests
TEST_IFACE=eth0 ./bvt_examples.sh

# Target S2-advanced examples instead of S1-basic
EXAMPLES_DIR=./S2-advanced/examples ./bvt_examples.sh

# Specify cgroup path for cgroup tests
TEST_CG_PATH=/sys/fs/cgroup/test ./bvt_examples.sh

# Specify binary and symbol for uprobe/uretprobe tests
TEST_UPROBE_BIN=/bin/bash TEST_UPROBE_SYMBOL=readline ./bvt_examples.sh
```

### BVT Environment Variables

| Variable | Purpose | Example |
|----------|---------|---------|
| `SKIP_BUILD` | Skip build step (default: build first) | `SKIP_BUILD=1` |
| `TIMEOUT_SECONDS` | Timeout per test (default: 5) | `TIMEOUT_SECONDS=10` |
| `TEST_IFACE` | Network interface for socket_filter, xdp, tc | `TEST_IFACE=eth0` |
| `TEST_CG_PATH` | Cgroup v2 directory for cgroup tests | `TEST_CG_PATH=/sys/fs/cgroup/test` |
| `TEST_UPROBE_BIN` | Binary path for uprobe | `TEST_UPROBE_BIN=/bin/bash` |
| `TEST_UPROBE_SYMBOL` | Symbol name for uprobe | `TEST_UPROBE_SYMBOL=readline` |
| `TEST_URETPROBE_BIN` | Binary path for uretprobe | `TEST_URETPROBE_BIN=/bin/bash` |
| `TEST_URETPROBE_SYMBOL` | Symbol name for uretprobe | `TEST_URETPROBE_SYMBOL=readline` |
| `EXAMPLES_DIR` | Override examples root (S1-basic or S2-advanced) | `EXAMPLES_DIR=./S2-advanced/examples` |

### Adding New Examples to BVT

When adding a new example, update `bvt_examples.sh`:

1. Ensure your example has:
   - `build.sh` that compiles BPF object, generates skeleton, and builds user binary
   - User binary named `example_<name>_user`
   - Attach message printed via `printf` (e.g., `"Attached <type> to <target>. Ctrl+C to stop.\n"`)

2. Add test block in `main()` function of `bvt_examples.sh`:
   ```bash
   local new_example_bin="$EXAMPLES_DIR/<category>/<name>/build/example_<name>_user"
   if ensure_bin "$new_example_bin"; then
     run_test "<name>" "Attached <type>" "$SUDO" "$TIMEOUT_BIN" "$TIMEOUT_SECONDS" "$new_example_bin" || status=1
   fi
   ```

3. If your example requires runtime arguments, guard with env var checks and document in the table above.

## Kernel & Permission Requirements
- **Kernel headers**: Install `linux-headers-$(uname -r)` or distribution-specific package
- **Capabilities**: CAP_BPF/CAP_SYS_ADMIN required (typically run with sudo)
- **Kernel version**: ≥ 5.4 recommended (fentry/fexit stable on 5.5+/5.10+)

## License
All examples use the MIT License (see header in each file).
