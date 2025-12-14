# lsm_file_open (LSM hook)

Logs file open attempts via `lsm/file_open` hook and ring buffer events.

## Build
```bash
cd S1-basic/examples/security/lsm
./build.sh
```

Artifacts in `build/`:
- `lsm_file_open.bpf.o`
- `lsm_file_open.skel.h`

## Notes
- Requires kernel with BPF LSM enabled (and typically BTF).
- Attach using a libbpf-based loader generated from the skeleton. bpftool attach support for LSM may vary by distro; skeleton is recommended.
- The program permits all opens; it only logs.
