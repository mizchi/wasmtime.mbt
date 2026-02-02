///|
fn bench_time(label : String, iters : Int, f : () -> Bool) -> Bool {
  let warmup = 3
  for _ in 0..<warmup {
    if not(f()) {
      println("\{label}: warmup failed")
      return false
    }
  }
  let start = @wasmtime.clock_now_ns()
  for _ in 0..<iters {
    if not(f()) {
      println("\{label}: iteration failed")
      return false
    }
  }
  let end = @wasmtime.clock_now_ns()
  let elapsed = end - start
  let per =
    if iters > 0 {
      elapsed / Int::to_uint64(iters)
    } else {
      0
    }
  println("\{label}: total=\{elapsed} ticks, per=\{per} ticks")
  true
}

///|
fn run_wasm_job(wat : String) -> Bool {
  let handle =
    try @wasmtime.wasm_job_spawn_wat_or_raise(wat, "run") catch {
      err => {
        println(err)
        return false
      }
    } noraise {
      value => value
    }
  let result =
    try @wasmtime.wasm_job_join_or_raise(handle) catch {
      err => {
        println(err)
        return false
      }
    } noraise {
      value => value
    }
  @builtin.ignore(result)
  true
}

///|
fn bench_wasm_job(iters : Int) -> Bool {
  let wat =
    #|(module
    #|  (func (export "run") (result i32)
    #|    i32.const 7))
  bench_time("wasm_job_spawn_wat", iters, () => run_wasm_job(wat))
}

///|
fn run_wasi_job(wat : String, stdin_path : String) -> Bool {
  let handle =
    try @wasmtime.wasi_job_spawn_wat_or_raise(wat, "run", stdin_path) catch {
      err => {
        println(err)
        return false
      }
    } noraise {
      value => value
    }
  let result =
    try @wasmtime.wasi_job_join_or_raise(handle) catch {
      err => {
        println(err)
        return false
      }
    } noraise {
      value => value
    }
  @builtin.ignore(result)
  true
}

///|
fn bench_wasi_job(iters : Int) -> Bool {
  let wat =
    #|(module
    #|  (import "wasi_snapshot_preview1" "fd_read"
    #|    (func $fd_read (param i32 i32 i32 i32) (result i32)))
    #|  (memory 1)
    #|  (export "memory" (memory 0))
    #|  (func (export "run") (result i32)
    #|    i32.const 8
    #|    i32.const 16
    #|    i32.store
    #|    i32.const 12
    #|    i32.const 100
    #|    i32.store
    #|    i32.const 0
    #|    i32.const 8
    #|    i32.const 1
    #|    i32.const 4
    #|    call $fd_read
    #|    drop
    #|    i32.const 4
    #|    i32.load))
  let stdin_path = "src/testdata/wasm_job_input.txt"
  bench_time("wasi_job_spawn_wat", iters, () => run_wasi_job(wat, stdin_path))
}

///|
fn main {
  println("bench_job: start")
  if not(bench_wasm_job(200)) {
    return
  }
  let _ = bench_wasi_job(100)
}
