# example raw_tracepoint

Raw tracepoint for sched_process_fork - lower overhead than regular tracepoint.

## Build
```bash
cd S1-basic/examples/tracing/raw_tracepoint
./build.sh
```

## Note
Raw tracepoints provide better performance but less stable API. Use skeleton for attach.
