#!/usr/bin/env bash
set -euo pipefail

output="${1:-}"
root_dir=$(cd "$(dirname "$0")/../.." && pwd)

cd "$root_dir"
moon build --target wasm --release src/guest_wasm

wasm_path="target/wasm/release/build/guest_wasm/guest_wasm.wasm"
if [[ ! -f "$root_dir/$wasm_path" ]]; then
  echo "missing wasm output: $wasm_path" >&2
  exit 1
fi

if [[ -n "$output" ]]; then
  if [[ "$output" != /* ]]; then
    output="$root_dir/$output"
  fi
  mkdir -p "$(dirname "$output")"
  {
    echo "guest wasm built"
    echo "wasm path: $wasm_path"
    date -u "+%Y-%m-%dT%H:%M:%SZ"
  } > "$output"
fi
