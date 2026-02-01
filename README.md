# mizchi/wasmtime.mbt

MoonBit bindings to the Wasmtime C API (native target). This repo starts with a minimal
bridge that verifies native linking and exposes `version()` plus basic engine lifecycle.

## Status

- native target only
- requires Wasmtime C API headers and library at build time

## Build Requirements

This repo vendors Wasmtime as a git submodule and builds the C API via a
MoonBit `pre-build` hook. You need a Rust toolchain (cargo) available.

The build hook:

- initializes `deps/wasmtime` (git submodule)
- runs `cargo build -p wasmtime-c-api --release`

The link flags are set in `src/moon.pkg`:

```text
cc-link-flags: -Ldeps/wasmtime/target/release -lwasmtime
```

The pre-build step also generates `src/wasmtime_version.h` from
`deps/wasmtime/crates/c-api/include/wasmtime.h` so the MoonBit API can expose
the Wasmtime version without depending on the full C headers during compile.

## Quick Commands

```bash
just           # check + test (native target)
just fmt       # format code
just check     # type check
just test      # run tests
just run       # run main
just info      # generate type definition files
```

## Example

```mbt
fn main {
  println(@wasmtime.version())
}
```
