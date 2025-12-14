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

# Smoke-test selected example binaries with short timeouts. This assumes the
# examples have been built already. Set SKIP_BUILD=1 to skip building.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EXAMPLES_DIR="$SCRIPT_DIR/S1-basic/examples"
TIMEOUT_BIN="${TIMEOUT_BIN:-timeout}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-2}"
SUDO="${SUDO:-sudo}"

if [[ $EUID -eq 0 ]]; then
  SUDO=""
else
  echo "[test] This script requires root privileges for eBPF operations."
  echo "[test] Please enter your password to cache sudo credentials..."
  sudo -v || { echo "[test] Failed to obtain sudo access" >&2; exit 1; }
  # Keep sudo alive in background
  while true; do sudo -n true; sleep 50; kill -0 "$$" 2>/dev/null || exit; done 2>/dev/null &
  SUDO_KEEPALIVE_PID=$!
  trap "kill $SUDO_KEEPALIVE_PID 2>/dev/null || true" EXIT
fi

# Auto-detect test environment if not set
if [[ -z "${TEST_IFACE:-}" ]]; then
  # Use lo (loopback) as default test interface
  TEST_IFACE="lo"
  echo "[test] Auto-detected TEST_IFACE=$TEST_IFACE"
fi

if [[ -z "${TEST_CG_PATH:-}" ]]; then
  # Try to use cgroup v2 if available
  if [[ -d "/sys/fs/cgroup" ]] && mount | grep -q cgroup2; then
    TEST_CG_PATH="/sys/fs/cgroup"
    echo "[test] Auto-detected TEST_CG_PATH=$TEST_CG_PATH"
  fi
fi

if [[ -z "${TEST_UPROBE_BIN:-}" ]]; then
  # Use bash as default uprobe target
  TEST_UPROBE_BIN="/usr/bin/bash"
  TEST_UPROBE_SYMBOL="main"
  echo "[test] Auto-detected TEST_UPROBE_BIN=$TEST_UPROBE_BIN:$TEST_UPROBE_SYMBOL"
fi

if [[ -z "${TEST_URETPROBE_BIN:-}" ]]; then
  TEST_URETPROBE_BIN="${TEST_UPROBE_BIN:-/usr/bin/bash}"
  TEST_URETPROBE_SYMBOL="${TEST_UPROBE_SYMBOL:-main}"
fi

require_timeout() {
  if ! command -v "$TIMEOUT_BIN" >/dev/null 2>&1; then
    echo "[test] Required command not found: $TIMEOUT_BIN" >&2
    exit 1
  fi
}

maybe_build() {
  if [[ "${SKIP_BUILD:-0}" == "1" ]]; then
    return
  fi
  echo "[test] Building examples via build_examples.sh"
  if ! "$SCRIPT_DIR/build_examples.sh"; then
    echo "[test] build_examples.sh failed; continuing to run available tests" >&2
  fi
}

ensure_bin() {
  local path="$1"
  if [[ ! -x "$path" ]]; then
    echo "[test] Skip; binary not found or not executable: $path"
    return 1
  fi
  return 0
}

run_test() {
  local name="$1"; shift
  local expect="$1"; shift
  local cmd=("$@")
  local log_file
  log_file="$(mktemp)"
  trap 'rm -f "$log_file"' RETURN

  echo "[test] Running $name: ${cmd[*]}"
  set +e
  stdbuf -oL -eL "${cmd[@]}" >"$log_file" 2>&1 &
  local pid=$!
  sleep 4
  if ps -p "$pid" >/dev/null 2>&1; then
    kill -TERM "$pid" 2>/dev/null || true
    sleep 1
    kill -KILL "$pid" 2>/dev/null || true
  fi
  wait "$pid" 2>/dev/null
  local rc=$?
  set -e

  echo "[test] --- $name output (first 5 and last 15 lines) ---"
  if [[ -s "$log_file" ]]; then
    head -5 "$log_file" 2>/dev/null || true
    if [[ $(wc -l < "$log_file" 2>/dev/null || echo 0) -gt 20 ]]; then
      echo "... (output truncated) ..."
      tail -15 "$log_file" 2>/dev/null || true
    else
      tail -n +6 "$log_file" 2>/dev/null || true
    fi
  else
    echo "(no output)"
  fi
  echo "[test] --- end output ---"

  # Check for system capability issues that should be skipped
  if grep -qi "failed to attach to netns" "$log_file" 2>/dev/null; then
    echo "[test] Skip $name; netns attach not supported or insufficient permissions."
    return 0
  fi
  if grep -qi "perf_event_open.*No such file or directory" "$log_file" 2>/dev/null; then
    echo "[test] Skip $name; perf_event_open not available (check /proc/sys/kernel/perf_event_paranoid)."
    return 0
  fi

  if [[ -n "$expect" ]] && ! grep -qi "$expect" "$log_file"; then
    echo "[test] FAIL: $name (expected text not found: $expect)" >&2
    return 1
  fi

  if [[ $rc -ne 0 && $rc -ne 143 && $rc -ne 137 ]]; then
    echo "[test] FAIL: $name (exit $rc)" >&2
    return 1
  fi

  echo "[test] PASS: $name"
  return 0
}

main() {
  require_timeout
  maybe_build

  local status=0

  # network/sk_lookup: attaches to current netns, no args.
  local sk_lookup_bin="$EXAMPLES_DIR/network/sk_lookup/build/example_sk_lookup_user"
  if ensure_bin "$sk_lookup_bin"; then
    run_test "sk_lookup" "Attached sk_lookup to current netns" "$SUDO" "$sk_lookup_bin" || status=1
  fi

  # network/socket_filter: needs interface name.
  local socket_filter_bin="$EXAMPLES_DIR/network/socket_filter/build/example_socket_filter_user"
  if ensure_bin "$socket_filter_bin"; then
    if [[ -n "${TEST_IFACE:-}" ]]; then
      run_test "socket_filter" "Attached socket filter" "$SUDO" "$socket_filter_bin" "$TEST_IFACE" || status=1
    else
      echo "[test] Skip socket_filter; set TEST_IFACE for the target interface."
    fi
  fi

  # cgroup/cgroup_skb: needs cgroup v2 path.
  local cg_path="${TEST_CG_PATH:-}"
  local cgroup_skb_bin="$EXAMPLES_DIR/cgroup/cgroup_skb/build/example_cgroup_skb_user"
  if ensure_bin "$cgroup_skb_bin"; then
    if [[ -n "$cg_path" && -d "$cg_path" ]]; then
      run_test "cgroup_skb" "Attached cgroup_skb" "$SUDO" "$cgroup_skb_bin" "$cg_path" || status=1
    else
      echo "[test] Skip cgroup_skb; set TEST_CG_PATH to a cgroup v2 directory."
    fi
  fi

  # cgroup/cgroup_sock: needs cgroup v2 path.
  local cgroup_sock_bin="$EXAMPLES_DIR/cgroup/cgroup_sock/build/example_cgroup_sock_user"
  if ensure_bin "$cgroup_sock_bin"; then
    if [[ -n "$cg_path" && -d "$cg_path" ]]; then
      run_test "cgroup_sock" "Attached cgroup/sock_create" "$SUDO" "$cgroup_sock_bin" "$cg_path" || status=1
    else
      echo "[test] Skip cgroup_sock; set TEST_CG_PATH to a cgroup v2 directory."
    fi
  fi

  # userspace/uprobe: needs binary and symbol.
  local uprobe_bin="$EXAMPLES_DIR/userspace/uprobe/build/example_uprobe_user"
  if ensure_bin "$uprobe_bin"; then
    if [[ -n "${TEST_UPROBE_BIN:-}" && -n "${TEST_UPROBE_SYMBOL:-}" ]]; then
      run_test "uprobe" "Attached" "$SUDO" "$uprobe_bin" "$TEST_UPROBE_BIN" "$TEST_UPROBE_SYMBOL" || status=1
    else
      echo "[test] Skip uprobe; set TEST_UPROBE_BIN and TEST_UPROBE_SYMBOL."
    fi
  fi

  # userspace/uretprobe: needs binary and symbol.
  local uretprobe_bin="$EXAMPLES_DIR/userspace/uretprobe/build/example_uretprobe_user"
  if ensure_bin "$uretprobe_bin"; then
    if [[ -n "${TEST_URETPROBE_BIN:-}" && -n "${TEST_URETPROBE_SYMBOL:-}" ]]; then
      run_test "uretprobe" "Attached uprobe/uretprobe" "$SUDO" "$uretprobe_bin" "$TEST_URETPROBE_BIN" "$TEST_URETPROBE_SYMBOL" || status=1
    else
      echo "[test] Skip uretprobe; set TEST_URETPROBE_BIN and TEST_URETPROBE_SYMBOL."
    fi
  fi

  # tracing/kprobe: listens for execve events via ring buffer.
  local kprobe_bin="$EXAMPLES_DIR/tracing/kprobe/build/example_kprobe_user"
  if ensure_bin "$kprobe_bin"; then
    run_test "kprobe" "listening for execve events" "$SUDO" "$kprobe_bin" || status=1
  fi

  # tracing/kretprobe: attaches to __x64_sys_getpid.
  local kretprobe_bin="$EXAMPLES_DIR/tracing/kretprobe/build/example_kretprobe_user"
  if ensure_bin "$kretprobe_bin"; then
    run_test "kretprobe" "Attached kretprobe" "$SUDO" "$kretprobe_bin" || status=1
  fi

  # tracing/tracepoint: attaches to sys_enter_execve.
  local tracepoint_bin="$EXAMPLES_DIR/tracing/tracepoint/build/example_tracepoint_user"
  if ensure_bin "$tracepoint_bin"; then
    run_test "tracepoint" "Attached tracepoint to sys_enter_execve" "$SUDO" "$tracepoint_bin" || status=1
  fi

  # tracing/raw_tracepoint: attaches to sched_process_fork.
  local raw_tracepoint_bin="$EXAMPLES_DIR/tracing/raw_tracepoint/build/example_raw_tracepoint_user"
  if ensure_bin "$raw_tracepoint_bin"; then
    run_test "raw_tracepoint" "Attached raw tracepoint to sched_process_fork" "$SUDO" "$raw_tracepoint_bin" || status=1
  fi

  # tracing/fentry_fexit: collects exec latency via ring buffer.
  local fentry_fexit_bin="$EXAMPLES_DIR/tracing/fentry_fexit/build/fentry_exec_latency_user"
  if ensure_bin "$fentry_fexit_bin"; then
    run_test "fentry_fexit" "Collecting exec latency" "$SUDO" "$fentry_fexit_bin" || status=1
  fi

  # network/xdp: needs interface name.
  local xdp_bin="$EXAMPLES_DIR/network/xdp/build/xdp_pass_user"
  if ensure_bin "$xdp_bin"; then
    if [[ -n "${TEST_IFACE:-}" ]]; then
      run_test "xdp" "Attached XDP program" "$SUDO" "$xdp_bin" "$TEST_IFACE" || status=1
    else
      echo "[test] Skip xdp; set TEST_IFACE for the target interface."
    fi
  fi

  # network/tc: needs interface name.
  local tc_bin="$EXAMPLES_DIR/network/tc/build/example_tc_classifier_user"
  if ensure_bin "$tc_bin"; then
    if [[ -n "${TEST_IFACE:-}" ]]; then
      run_test "tc" "Attached TC classifier" "$SUDO" "$tc_bin" "$TEST_IFACE" || status=1
    else
      echo "[test] Skip tc; set TEST_IFACE for the target interface."
    fi
  fi

  # cgroup/cgroup_device: needs cgroup v2 path.
  local cgroup_device_bin="$EXAMPLES_DIR/cgroup/cgroup_device/build/example_cgroup_device_user"
  if ensure_bin "$cgroup_device_bin"; then
    if [[ -n "$cg_path" && -d "$cg_path" ]]; then
      run_test "cgroup_device" "Attached cgroup/dev" "$SUDO" "$cgroup_device_bin" "$cg_path" || status=1
    else
      echo "[test] Skip cgroup_device; set TEST_CG_PATH to a cgroup v2 directory."
    fi
  fi

  # cgroup/cgroup_sysctl: needs cgroup v2 path.
  local cgroup_sysctl_bin="$EXAMPLES_DIR/cgroup/cgroup_sysctl/build/example_cgroup_sysctl_user"
  if ensure_bin "$cgroup_sysctl_bin"; then
    if [[ -n "$cg_path" && -d "$cg_path" ]]; then
      run_test "cgroup_sysctl" "Attached cgroup/sysctl" "$SUDO" "$cgroup_sysctl_bin" "$cg_path" || status=1
    else
      echo "[test] Skip cgroup_sysctl; set TEST_CG_PATH to a cgroup v2 directory."
    fi
  fi

  # cgroup/cgroup_sock_addr: needs cgroup v2 path.
  local cgroup_sock_addr_bin="$EXAMPLES_DIR/cgroup/cgroup_sock_addr/build/example_cgroup_sock_addr_user"
  if ensure_bin "$cgroup_sock_addr_bin"; then
    if [[ -n "$cg_path" && -d "$cg_path" ]]; then
      run_test "cgroup_sock_addr" "Attached cgroup sock_addr hooks" "$SUDO" "$cgroup_sock_addr_bin" "$cg_path" || status=1
    else
      echo "[test] Skip cgroup_sock_addr; set TEST_CG_PATH to a cgroup v2 directory."
    fi
  fi

  # cgroup/cgroup_sockopt: needs cgroup v2 path.
  local cgroup_sockopt_bin="$EXAMPLES_DIR/cgroup/cgroup_sockopt/build/example_cgroup_sockopt_user"
  if ensure_bin "$cgroup_sockopt_bin"; then
    if [[ -n "$cg_path" && -d "$cg_path" ]]; then
      run_test "cgroup_sockopt" "Attached cgroup sockopt" "$SUDO" "$cgroup_sockopt_bin" "$cg_path" || status=1
    else
      echo "[test] Skip cgroup_sockopt; set TEST_CG_PATH to a cgroup v2 directory."
    fi
  fi

  # cgroup/cgroup_bpf: LSM for BPF syscall monitoring, no args.
  local cgroup_bpf_bin="$EXAMPLES_DIR/cgroup/cgroup_bpf/build/example_cgroup_bpf_user"
  if ensure_bin "$cgroup_bpf_bin"; then
    run_test "cgroup_bpf" "Attached BPF LSM hook" "$SUDO" "$cgroup_bpf_bin" || status=1
  fi

  # perf/perf_event: attaches to CPU cycles on CPU 0 by default.
  local perf_event_bin="$EXAMPLES_DIR/perf/perf_event/build/example_perf_event_user"
  if ensure_bin "$perf_event_bin"; then
    run_test "perf_event" "Attached perf event on CPU" "$SUDO" "$perf_event_bin" || status=1
  fi

  # security/lsm: listens for file_open LSM events.
  local lsm_bin="$EXAMPLES_DIR/security/lsm/build/lsm_file_open_user"
  if ensure_bin "$lsm_bin"; then
    run_test "lsm" "Listening for file_open LSM events" "$SUDO" "$lsm_bin" || status=1
  fi

  if [[ $status -eq 0 ]]; then
    echo "[test] All selected tests completed."
  else
    echo "[test] Some tests failed. See logs above." >&2
  fi

  return $status
}

set +u  # Disable unbound variable check to avoid trap cleanup issues
main "$@"
