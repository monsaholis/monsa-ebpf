# example uprobe

Traces user-space function calls in ELF binaries.

## Build
```bash
cd S2-advanced/examples/userspace/uprobe
./build.sh
```

## Attach
Requires libbpf-based loader specifying target binary and function symbol:
```c
bpf_program__attach_uprobe(prog, false, -1, "/path/to/binary", offset_or_symbol);
```

## Note
Use `objdump -t /path/to/binary | grep function_name` to find symbol offset.
