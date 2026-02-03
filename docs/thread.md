# Threading (Wasmtime experiments)

## Status

- Experimental: uses Wasmtime's wasm threads + shared memory features.
- Not supported on Windows in this repository (pthread/mmap based).

## Repository layout (binding vs runtime)

- Core Wasmtime binding stays in the root package:
  - `src/ffi_native.mbt`
  - `src/wasmtime.mbt`
  - `src/wasmtime_stub.c`
- Thread runtime lives under a dedicated package:
  - `src/thread_runtime`
- Benchmarks are grouped under the runtime package:
  - `src/thread_runtime/bench_threads`

## Experimental Wasmtime features used

- `config_wasm_threads_set(true)`
- `config_shared_memory_set(true)`
- Shared memory import with `shared` memory type in WAT:
  - `(memory (import "env" "mem") ... shared)`
- Atomic ops in guest (`i32.atomic.load`, `i32.atomic.store`) for ring coordination.

Source locations:
- Config/FFI surface: `src/ffi_native.mbt`
- Native implementation and WAT generation: `src/wasmtime_stub.c`

## MoonBit-side execution contract

## Supervisor API (OTP-ish, experimental)

Thread runtime exposes a small supervisor API in `@mizchi/wasmtime/thread_runtime`
to model OTP-like restart behavior on the host side.

- `SupervisorSpec`:
  - `strategy`: `OneForOne` | `OneForAll` | `RestForOne`
  - `max_restarts`: restart limit (`< 0` means unlimited)
  - `backoff_iters`: spin-loop backoff between restarts
  - `poll_iters`: max non-blocking join attempts (`< 0` means blocking join)
  - `poll_backoff_iters`: spin-loop backoff between poll attempts
- `ChildSpec`:
  - `id`: string identifier
  - `start`: `(ThreadRuntime) -> Result[ThreadHandle, Error]`
  - `restart`: `Permanent` | `Transient` | `Temporary`
- Helpers: `child_wat` and `child_wasm` (WAT or WASM bytes).
- `SupervisorResult::Timeout(restarts, pending)` returns running handles.

Example (supervisor + WAT child):

```moonbit
fn main {
  let rt = match thread_runtime_new(1) { // 1 page shared mem
    Ok(rt) => rt
    Err(err) => {
      println("thread_runtime_new failed: \{err}")
      return
    }
  }
  let spec = supervisor_spec(
    strategy=RestartStrategy::OneForOne,
    max_restarts=3,
    backoff_iters=1000,
    poll_iters=1000,
    poll_backoff_iters=100,
  )
  let child = child_wat(
    "worker",
    wat,
    "run",
    args,
    restart=RestartPolicy::Transient,
  )
  match supervisor_run(rt, spec, [child]) {
    Ok(result) => {
      match result {
        SupervisorResult::Timeout(_, pending) => {
          // Either keep polling, or drop handles.
          for item in pending {
            let _ = thread_runtime_detach(item.handle)
          }
        }
        _ => ()
      }
    }
    Err(err) => println("supervisor_run failed: \{err}")
  }
}
```

Notes:

- `poll_iters >= 0` uses `try_join` in a loop and returns
  `SupervisorResult::Timeout` when it cannot observe completion.
- Timeout does **not** kill the running thread; it returns pending handles
  so the caller can re-join later or detach to drop them.
- Recommended handling for `Timeout`:
  - If the workload is expected to complete, re-run `supervisor_run` with a
    larger `poll_iters` and the pending handles joined explicitly.
  - If the workload is fire-and-forget, call `thread_runtime_detach` on each
    pending handle and proceed.
  - If you need a cancellation story, add a shared-memory flag and let the
    guest cooperatively stop (hard kill is not supported).

### Host setup

1) Create `Config` and enable wasm threads + shared memory.
2) Compute shared memory size to fit ring header + data.
3) Create `SharedMemory` with `shared=true` and import it as `env.mem`.
4) Spawn two host threads; each thread:
   - Creates its own `Store`.
   - Clones the shared memory handle.
   - Instantiates the module.
   - Calls an exported entrypoint (`produce` or `consume`).

### Guest entrypoints

- `produce(n: i32, mask: i32)`
- `consume(n: i32, mask: i32)`

The guest reads/writes only through the shared memory import.

### Shared memory layout (bytes)

```
0   : u32 head
4   : u32 tail
8   : u64 sum
16  : u64 prod_spins
24  : u64 cons_spins
32  : u32 data[slots]
```

### Ring invariants

- `slots` must be power of two.
- `mask = slots - 1`.
- `items` must fit in `i32`.
- Exactly two threads: single-producer, single-consumer.

### Notes

- The wasm guest loops are tight spins (no `sched_yield`).
- The OS ring uses `sched_yield` in spin loops.

## Benchmarks

### Harness

- Package: `src/thread_runtime/bench_threads`
- Command: `moon run src/thread_runtime/bench_threads --target native -- [options]`
- Options:
  - `--items N` (default: 1_000_000)
  - `--slots N` (default: 1024)
  - `--sweep`
  - `--slots-list CSV`
  - `--csv`
  - `--csv-only`

Cases:
- `os_ring_cold`
- `os_ring_warm`
- `wasm_ring_cold`
- `wasm_ring_warm`

### Sample results (2026-02-02, items=1_000_000)

Command:

```
moon run src/thread_runtime/bench_threads --target native -- --sweep --slots-list 64,256,1024 --csv-only
```

CSV:

```
label,items,slots,elapsed_ns,per_ps,prod_spins,cons_spins
os_ring_cold,1000000,64,7528000,7528,32441,40952
os_ring_warm,1000000,64,8489000,8489,33449,43650
wasm_ring_cold,1000000,64,50044000,50044,1119009,6934212
wasm_ring_warm,1000000,64,50521000,50521,998052,8671732
os_ring_cold,1000000,256,21257000,21257,1106,10161
os_ring_warm,1000000,256,21717000,21717,1100,11278
wasm_ring_cold,1000000,256,66714000,66714,1778098,10189794
wasm_ring_warm,1000000,256,65569000,65569,1496308,16038640
os_ring_cold,1000000,1024,39250000,39250,1590,4446
os_ring_warm,1000000,1024,46029000,46029,1317,4429
wasm_ring_cold,1000000,1024,63713000,63713,885303,15227392
wasm_ring_warm,1000000,1024,66580000,66580,1208170,17699885
```

### Interpretation (summary)

- Wasm is slower than native OS ring (about 1.5x to 6.6x in this sample), but stable and functional.
- Warm/cold are close, so thread creation overhead is not dominant.
- Spin counts are higher in wasm, since it does not yield in the guest loop.

## TODO / Next steps

- Consider `atomic.wait` / backoff in guest to reduce spin cost.
- Run workload-specific benchmarks (e.g. WASI file I/O tasks).
- Evaluate whether to expose an API layer beyond the benchmark harness.

## Examples

- `src/examples/thread_supervisor`: supervisor + timeout + detach usage
