#!/usr/bin/env bash
# MIT License
#
# Copyright (c) 2025 dev-monsa
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

set -euo pipefail

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="$SRC_DIR/build"
BPF_C="$SRC_DIR/example_uretprobe.bpf.c"
BPF_OBJ="$OUT_DIR/example_uretprobe.bpf.o"
BPF_SKEL="$OUT_DIR/example_uretprobe.skel.h"
USER_C="$SRC_DIR/example_uretprobe_user.c"
USER_BIN="$OUT_DIR/example_uretprobe_user"

mkdir -p "$OUT_DIR"

clang -target bpf -D__TARGET_ARCH_x86 -O2 -g \
  -I"$SRC_DIR/../../../common/include" \
  -isystem /usr/include/x86_64-linux-gnu \
  -c "$BPF_C" -o "$BPF_OBJ"

bpftool gen skeleton "$BPF_OBJ" > "$BPF_SKEL"

echo "Built BPF object: $BPF_OBJ"
echo "Generated skeleton: $BPF_SKEL"

if [ -f "$USER_C" ]; then
  if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists libbpf; then
    cc -O2 -g -Wall -Wextra -I"$OUT_DIR" \
      $(pkg-config --cflags libbpf) \
      "$USER_C" -o "$USER_BIN" \
      $(pkg-config --libs libbpf) -lelf -lz
    echo "Built user-space controller: $USER_BIN"
  else
    echo "Skipping user-space controller build (libbpf via pkg-config not found)" >&2
  fi
fi
