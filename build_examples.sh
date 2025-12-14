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

# Build all example subprojects by executing their local build.sh, if present.
# Usage: ./build_example.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
EXAMPLES_DIRS=(
  "$SCRIPT_DIR/S1-basic/examples"
  "$SCRIPT_DIR/S2-advanced/examples"
)

build_scripts=()
for dir in "${EXAMPLES_DIRS[@]}"; do
  if [[ -d "$dir" ]]; then
    while IFS= read -r build_script; do
      build_scripts+=("$build_script")
    done < <(find "$dir" -type f -name build.sh | sort)
  else
    echo "[build_example] Skip missing examples directory: $dir"
  fi
done

if [[ ${#build_scripts[@]} -eq 0 ]]; then
  echo "[build_example] No examples directories found." >&2
  exit 1
fi

status=0
failed_builds=()
for build_script in "${build_scripts[@]}"; do
  echo "[build_example] Running $build_script"
  if ! (cd "$(dirname "$build_script")" && chmod +x "$(basename "$build_script")" && ./"$(basename "$build_script")"); then
    echo "[build_example] ❌ FAILED: $build_script" >&2
    failed_builds+=("$build_script")
    status=1
  else
    echo "[build_example] ✅ SUCCESS: $build_script"
  fi
done

if [[ $status -eq 0 ]]; then
  echo "[build_example] ✅ All builds completed successfully."
else
  echo "" >&2
  echo "[build_example] ❌ Some builds failed:" >&2
  for failed in "${failed_builds[@]}"; do
    echo "  - $failed" >&2
  done
  echo "[build_example] Total: ${#failed_builds[@]} failed out of ${#build_scripts[@]} builds" >&2
fi

exit $status
