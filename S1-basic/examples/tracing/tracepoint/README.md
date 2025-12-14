# example tracepoint

Counts execve calls using stable tracepoint API.

## Build
```bash
cd S1-basic/examples/tracing/tracepoint
./build.sh
```

## Note
Tracepoints provide stable kernel ABI compared to kprobes. Use libbpf skeleton for attach.
