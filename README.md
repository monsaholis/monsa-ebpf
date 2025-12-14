# monsa-ebpf

Beginner-friendly eBPF examples with maps, organized by program type.

Version: v0.1.0 (2025-12-13)

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
│       ├── tracing/
│       │   ├── kprobe/          # Function entry
│       │   ├── kretprobe/       # Function return
│       │   ├── tracepoint/      # Stable tracepoint
│       │   ├── raw_tracepoint/  # High-performance raw tracepoint
│       │   └── fentry_fexit/    # Modern fentry/fexit
│       ├── userspace/
│       │   ├── uprobe/          # ELF symbol entry
│       │   └── uretprobe/       # Return probe
│       ├── network/
│       │   ├── xdp/             # NIC ingress fast path
│       │   ├── tc/              # TC classifier/action
│       │   ├── socket_filter/   # Socket filter
│       │   └── sk_lookup/       # Socket lookup
│       ├── security/
│       │   └── lsm/             # LSM hook example
│       ├── perf/
│       │   └── perf_event/      # Performance counters/profiling
│       ├── cgroup/
│       │   ├── cgroup_skb/      # Ingress/egress filtering
│       │   ├── cgroup_sock/     # Socket create
│       │   ├── cgroup_sock_addr/# Bind/connect/sendmsg
│       │   ├── cgroup_sockopt/  # Getsockopt/setsockopt tracing
│       │   ├── cgroup_device/   # Device access control
│       │   ├── cgroup_sysctl/   # Sysctl access control
│       │   └── cgroup_bpf/      # BPF LSM: bpf syscall audit/block
│       └── advanced/
│           ├── iterators/       # iter/task, iter/bpf_map
│           ├── struct_ops/      # TCP CC and other struct_ops
│           ├── freplace/        # BPF_PROG_TYPE_EXT function replacement
│           └── flow_dissector/  # Packet parser customization
└── tools/
    ├── bpftool/             # bpftool binary or build scripts
    ├── build/               # Common build scripts (Makefile, CMake)
    └── run/                 # Loader samples (Go/Rust/C), attach scripts
```

## Recommended Learning Path
1. `docs/quickstart.md`: Install clang/bpftool → build "hello_bpf" → load → read maps.
2. `docs/concepts.md`: Program types, attach points, map types (hash/array/lru/percpu/ringbuf/cgroup/stack/queue), user/kernel cooperation patterns.
3. Per-example README: Execution commands, dependencies, minimum kernel version.

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

### Example: kprobe quick run
```bash
cd S1-basic/examples/tracing/kprobe
./build.sh

# Load and attach kprobe to __x64_sys_execve
sudo bpftool prog load build/example_kprobe.bpf.o /sys/fs/bpf/example_kprobe
sudo bpftool net attach kprobe id $(sudo bpftool prog show pinned /sys/fs/bpf/example_kprobe | awk '/id/ {print $2}') func __x64_sys_execve

# Check counters after execve events
cd S1-basic/examples/tracing/kprobe

# Cleanup
sudo rm /sys/fs/bpf/example_kprobe
```

## BVT (Build Verification Test)

`bvt_examples.sh` automatically builds and verifies all examples.

```bash
# Build and run all tests
./bvt_examples.sh

# Skip build, test only
SKIP_BUILD=1 ./bvt_examples.sh

# Specify network interface for network tests
TEST_IFACE=eth0 ./bvt_examples.sh

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
