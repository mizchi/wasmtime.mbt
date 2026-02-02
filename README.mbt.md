# mizchi/wasmtime.mbt

MoonBit bindings to the Wasmtime C API (native target). This repo starts with a minimal
bridge that verifies native linking and exposes `version()` plus basic engine lifecycle.

## Status

- native target only
- requires Wasmtime C API headers and library at build time
 - packages: core (`mizchi/wasmtime`) and WASI helpers (`mizchi/wasmtime/wasi`)

## Build Requirements

This repo vendors Wasmtime as a git submodule and builds the C API via a
MoonBit `pre-build` hook. You need a Rust toolchain (cargo) available.

The build hook:

- initializes `deps/wasmtime` (git submodule)
- runs `cargo build -p wasmtime-c-api --release`

When `deps/wasmtime` is missing (e.g. installed via `.mooncakes`), the build
script will clone Wasmtime from GitHub and checkout the pinned commit in
`deps/wasmtime.rev` before building. Git is required in that case.

The link flags are set in `src/moon.pkg`:

```text
cc-link-flags: -Ldeps/wasmtime/target/release -lwasmtime
```

The pre-build step also generates `src/wasmtime_version.h` from
`deps/wasmtime/crates/c-api/include/wasmtime.h` so the MoonBit API can expose
the Wasmtime version without depending on the full C headers during compile.

## Using as a dependency (.mooncakes)

When this module is installed as a dependency under
`.mooncakes/mizchi/wasmtime`, the pre-build hook in this repo is not executed
automatically. If you need Wasmtime built from a consumer module, add a
pre-build step there to call the script inside `.mooncakes`.

Example `moon.pkg` in the consumer:

```
import {
  "mizchi/wasmtime",
}

options(
  "pre-build": [
    {
      "input": [
        ".mooncakes/mizchi/wasmtime/src/scripts/build-wasmtime.sh"
      ],
      "output": [
        "build-stamps/wasmtime_prebuild.stamp"
      ],
      "command": "mkdir -p build-stamps && bash .mooncakes/mizchi/wasmtime/src/scripts/build-wasmtime.sh src/build-stamps/wasmtime_build.stamp && date -u +%Y-%m-%dT%H:%M:%SZ > $output"
    }
  ],
)
```

The build script writes a log at `src/build-stamps/wasmtime_build.stamp` so you
can confirm the cwd and resolved paths.

## Quick Commands

```bash
just           # check + test (native target)
just fmt       # format code
just check     # type check
just test      # run tests
just run       # run main
just info      # generate type definition files
just prebuild-log # show pre-build log
```

Note: `just test` uses `--release` to avoid crashes in debug builds when
linking against the Wasmtime C API.

## Example

```mbt
fn main {
  println(@wasmtime.version())
}
```

## Decision Log

- 2026-02-02: Adopted Plan B (module/linker/WASI helpers) as the primary path.
  - Reason: better extensibility for WASI I/O/imports and lower steady-state cost
    when reusing compiled modules.
  - Plan A job helpers removed from core; keep core minimal.

## Recommended (Plan B): sync WASI with module reuse

Prefer the linker/module path when you need richer WASI I/O or want to reuse
compiled modules.

```mbt
import {
  "mizchi/wasmtime" as @wasmtime,
  "mizchi/wasmtime/wasi" as @wasi,
}

let engine = @wasmtime.engine_new()
let (store, context, linker) = @wasi.wasi_context_linker_with_preopen_or_raise(
  engine,
  "src/testdata",
  guest_path=".",
)
let wat = #|(module (func (export "run") (result i32) i32.const 7))
let module_val = @wasmtime.module_new_from_wat_or_raise(engine, wat)
let instance = @wasmtime.linker_instantiate_or_raise(linker, context, module_val)
let func = @wasmtime.instance_export_func_or_raise(context, instance, "run")
let args = @wasmtime.make_val_buffer(0)
let results = @wasmtime.make_val_buffer(1)
let trap_ptr = @wasmtime.make_ptr_buffer()
let err_ptr = @wasmtime.make_ptr_buffer()
let call_res = @wasmtime.func_call_sync_result_autoclean(
  context,
  func,
  args,
  results,
  trap_ptr,
  err_ptr,
)
match call_res {
  Ok(()) => { () }
  Err(err) => raise err
}
@wasmtime.module_delete(module_val)
@wasmtime.linker_delete(linker)
@wasmtime.wasmtime_store_delete(store)
@wasmtime.engine_delete(engine)
```

## Async Result Example (native)

```mbt
let (engine, store, context) = @wasmtime.async_context_new(4 * 1024 * 1024)
let args = @wasmtime.make_val_buffer(0)
let results = @wasmtime.make_val_buffer(0)
let trap_ptr = @wasmtime.make_ptr_buffer()
let err_ptr = @wasmtime.make_ptr_buffer()

let params : Bytes = []
let results_sig : Bytes = []
let ty = @wasmtime.functype_new_from_valkinds_or_raise(params, results_sig)
let cb_ptr = @wasmtime.func_noop_callback_ptr()
let func_bytes = @wasmtime.func_buffer_new_with_ptr(context, ty, cb_ptr, 0, 0)

let future_result =
  @wasmtime.func_call_async_result_autoclean(context, func_bytes, args, results, trap_ptr, err_ptr)
match future_result {
  Ok(future) => {
    while not(@wasmtime.call_future_poll(future)) { () }
    @wasmtime.call_future_delete(future)
  }
  Err(_err) => {
    // trap/error pointers are already deleted
  }
}
// Error example: "func_call_async failed (error=true, trap=false)"
@wasmtime.functype_delete(ty)
@wasmtime.async_context_delete(engine, store)
```
