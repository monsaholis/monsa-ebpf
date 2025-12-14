# example uretprobe

Traces user-space function returns, reporting per-PID call counts, average latency, and last return value.

## Build
```bash
cd examples/userspace/uretprobe
./build.sh
```

## Attach
Use the provided loader to attach to a binary and symbol name:
```bash
sudo ./build/example_uretprobe_user /path/to/binary target_symbol
```

Example: attach to `malloc` in `/usr/bin/ls` (symbol names may vary by distro):
```bash
sudo ./build/example_uretprobe_user /usr/bin/ls malloc
```

## Notes
- Requires libbpf with `pkg-config` for building the user-space controller.
- Uses uprobe for entry timestamps and uretprobe for return handling, so both hooks must attach to the same symbol.
- Use `objdump -t /path/to/binary | grep <symbol>` or `nm -D` to find exported symbols.
