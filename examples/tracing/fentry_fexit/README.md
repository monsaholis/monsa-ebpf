# fentry_exec_latency (fentry/fexit)

Measures `__x64_sys_execve` latency using fentry/fexit and sends results via ring buffer.

## Build
```bash
cd examples/tracing/fentry_fexit
./build.sh
```

Artifacts in `build/`:
- `fentry_exec_latency.bpf.o`
- `fentry_exec_latency.skel.h`

## Notes
- Requires kernel support for fentry/fexit (generally 5.5+ with BTF).
- Attach using a libbpf-based loader (skeleton) for simplicity. bpftool attachment for fentry/fexit varies by distro; skeleton is recommended.
- Run the generated user loader after you implement one, or integrate into your existing loader flow.
