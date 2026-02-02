#!/usr/bin/env bash
set -euo pipefail

output="${1:-}"
if [[ -z "$output" ]]; then
  echo "usage: $(basename "$0") <output-stamp>" >&2
  exit 1
fi

start_dir=$(pwd)
root_dir=$(cd "$(dirname "$0")/../.." && pwd)
wasmtime_repo="https://github.com/bytecodealliance/wasmtime.git"
wasmtime_rev_file="$root_dir/deps/wasmtime.rev"
wasmtime_rev=""

if [[ "$output" != /* ]]; then
  output="$root_dir/$output"
fi

cd "$root_dir"

if [[ -f "$wasmtime_rev_file" ]]; then
  wasmtime_rev=$(tr -d ' \t\r\n' < "$wasmtime_rev_file")
fi

if [[ -f "$root_dir/.gitmodules" ]] && git -C "$root_dir" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git -C "$root_dir" submodule update --init deps/wasmtime
fi

if [[ ! -d "$root_dir/deps/wasmtime" ]]; then
  mkdir -p "$root_dir/deps"
  git clone "$wasmtime_repo" "$root_dir/deps/wasmtime"
fi

if [[ -n "$wasmtime_rev" ]] && [[ -d "$root_dir/deps/wasmtime/.git" || -f "$root_dir/deps/wasmtime/.git" ]]; then
  git -C "$root_dir/deps/wasmtime" fetch --quiet --depth 1 origin "$wasmtime_rev" || true
  git -C "$root_dir/deps/wasmtime" checkout -q "$wasmtime_rev" || true
fi

if [[ ! -f "$root_dir/deps/wasmtime/Cargo.toml" ]]; then
  echo "missing deps/wasmtime/Cargo.toml (root: $root_dir)" >&2
  exit 1
fi

cd deps/wasmtime
cargo build -p wasmtime-c-api --release

cd "$root_dir"

if ! ls "$root_dir/deps/wasmtime/target/release/libwasmtime."* >/dev/null 2>&1; then
  echo "missing libwasmtime.* in deps/wasmtime/target/release" >&2
  exit 1
fi

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
  echo "pre-build start cwd: $start_dir"
  echo "pre-build root: $root_dir"
  echo "wasmtime dir: $root_dir/deps/wasmtime"
  echo "wasmtime lib dir: $root_dir/deps/wasmtime/target/release"
  if [[ -n "$wasmtime_rev" ]]; then
    echo "wasmtime rev: $wasmtime_rev"
  fi
  date -u "+%Y-%m-%dT%H:%M:%SZ"
} > "$output"
