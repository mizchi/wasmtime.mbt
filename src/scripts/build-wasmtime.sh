#!/usr/bin/env bash
set -euo pipefail

output="${1:-}"
if [[ -z "$output" ]]; then
  echo "usage: $(basename "$0") <output-stamp>" >&2
  exit 1
fi

root_dir=$(cd "$(dirname "$0")/../.." && pwd)

if [[ "$output" != /* ]]; then
  output="$root_dir/$output"
fi

cd "$root_dir"

git submodule update --init deps/wasmtime

cd deps/wasmtime
cargo build -p wasmtime-c-api --release

cd "$root_dir"

version_header="src/wasmtime_version.h"
version_line=$(grep -E '^#define WASMTIME_VERSION "' deps/wasmtime/crates/c-api/include/wasmtime.h | head -n 1)
version_value=$(echo "$version_line" | sed -E 's/^#define WASMTIME_VERSION "([^"]+)".*$/\1/')
if [[ -z "$version_value" ]]; then
  echo "failed to detect WASMTIME_VERSION from wasmtime.h" >&2
  exit 1
fi
cat > "$version_header" <<EOF
#ifndef WASMTIME_VERSION_H
#define WASMTIME_VERSION_H
#define WASMTIME_VERSION "${version_value}"
#endif
EOF

mkdir -p "$(dirname "$output")"
{
  echo "wasmtime-c-api built"
  date -u "+%Y-%m-%dT%H:%M:%SZ"
} > "$output"
