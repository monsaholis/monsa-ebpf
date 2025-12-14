# example perf_event

Sample on hardware perf events (CPU cycles, cache misses, etc.).

## Build
```bash
cd S2-advanced/examples/perf/perf_event
./build.sh
```

## Note
Attach using `perf_event_open()` syscall and then attach BPF program to the fd.
Use skeleton-based loader with libbpf for simplified setup.

## Example usage
Profile CPU cycles, attach BPF program to count samples per second.
