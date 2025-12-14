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

# Bootstrap script to install the minimal toolchain for building eBPF samples
# on Debian/Ubuntu-like systems.
# Installs: clang, llvm, libbpf-dev, pkg-config, make, gcc, bpftool (via linux-tools).

if [[ $EUID -ne 0 ]]; then
  echo "[bootstrap-ebpf] Please run as root (sudo)." >&2
  exit 1
fi

echo "[bootstrap-ebpf] Updating package lists..."
apt-get update -y

echo "[bootstrap-ebpf] Installing toolchain and headers..."
apt-get install -y \
  clang \
  llvm \
  libbpf-dev \
  pkg-config \
  gcc \
  make \
  linux-headers-$(uname -r)

# bpftool is shipped with linux-tools on Ubuntu/Debian; pick matching kernel version.
echo "[bootstrap-ebpf] Installing bpftool via linux-tools-$(uname -r)..."
apt-get install -y "linux-tools-$(uname -r)" linux-tools-common || true

echo "[bootstrap-ebpf] Done. Verify versions:"
clang --version | head -n1 || true
bpftool version || true
