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
fn sync_wasi_call_result(engine : @wasmtime.Engine, wat : String) -> Result[Int, Error] {
  let store = @wasmtime.wasmtime_store_new(engine)
  let context = @wasmtime.wasmtime_store_context(store)
  let wasi = @wasmtime.wasi_config_new_or_raise()
  let preopen_ok = try? @wasmtime.wasi_config_preopen_dir_or_raise(
    wasi,
    "src/testdata",
    guest_path=".",
    dir_perms=@wasmtime.WASI_DIR_PERMS_READ,
    file_perms=@wasmtime.WASI_FILE_PERMS_READ,
  )
  match preopen_ok {
    Ok(_) => ()
    Err(err) => {
      @wasmtime.wasmtime_store_delete(store)
      return Err(err)
    }
  }
  let set_wasi_ok = try? @wasmtime.context_set_wasi_or_raise(context, wasi)
  match set_wasi_ok {
    Ok(_) => ()
    Err(err) => {
      @wasmtime.wasmtime_store_delete(store)
      return Err(err)
    }
  }
  let linker = @wasmtime.linker_new(engine)
  match @wasmtime.linker_define_wasi_result(linker) {
    Ok(_) => ()
    Err(err) => {
      @wasmtime.linker_delete(linker)
      @wasmtime.wasmtime_store_delete(store)
      return Err(err)
    }
  }
  let module_val =
    match @wasmtime.module_new_from_wat_result(engine, wat) {
      Ok(val) => val
      Err(err) => {
        @wasmtime.linker_delete(linker)
        @wasmtime.wasmtime_store_delete(store)
        return Err(err)
      }
    }
  let instance =
    match @wasmtime.linker_instantiate_result(linker, context, module_val) {
      Ok(inst) => inst
      Err(err) => {
        @wasmtime.module_delete(module_val)
        @wasmtime.linker_delete(linker)
        @wasmtime.wasmtime_store_delete(store)
        return Err(err)
      }
    }
  let func =
    match @wasmtime.instance_export_func_result(context, instance, "run") {
      Ok(func_val) => func_val
      Err(err) => {
        @wasmtime.module_delete(module_val)
        @wasmtime.linker_delete(linker)
        @wasmtime.wasmtime_store_delete(store)
        return Err(err)
      }
    }
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
  let result =
    match call_res {
      Ok(_) => Ok(@wasmtime.val_buffer_get_i32(results, 0))
      Err(err) => Err(err)
    }
  @wasmtime.module_delete(module_val)
  @wasmtime.linker_delete(linker)
  @wasmtime.wasmtime_store_delete(store)
  result
}

///|
fn sync_wasi_call_reuse_module_result(
  engine : @wasmtime.Engine,
  module_val : @wasmtime.Module,
) -> Result[Int, Error] {
  let store = @wasmtime.wasmtime_store_new(engine)
  let context = @wasmtime.wasmtime_store_context(store)
  let wasi = @wasmtime.wasi_config_new_or_raise()
  let preopen_ok = try? @wasmtime.wasi_config_preopen_dir_or_raise(
    wasi,
    "src/testdata",
    guest_path=".",
    dir_perms=@wasmtime.WASI_DIR_PERMS_READ,
    file_perms=@wasmtime.WASI_FILE_PERMS_READ,
  )
  match preopen_ok {
    Ok(_) => ()
    Err(err) => {
      @wasmtime.wasmtime_store_delete(store)
      return Err(err)
    }
  }
  let set_wasi_ok = try? @wasmtime.context_set_wasi_or_raise(context, wasi)
  match set_wasi_ok {
    Ok(_) => ()
    Err(err) => {
      @wasmtime.wasmtime_store_delete(store)
      return Err(err)
    }
  }
  let linker = @wasmtime.linker_new(engine)
  match @wasmtime.linker_define_wasi_result(linker) {
    Ok(_) => ()
    Err(err) => {
      @wasmtime.linker_delete(linker)
      @wasmtime.wasmtime_store_delete(store)
      return Err(err)
    }
  }
  let instance =
    match @wasmtime.linker_instantiate_result(linker, context, module_val) {
      Ok(inst) => inst
      Err(err) => {
        @wasmtime.linker_delete(linker)
        @wasmtime.wasmtime_store_delete(store)
        return Err(err)
      }
    }
  let func =
    match @wasmtime.instance_export_func_result(context, instance, "run") {
      Ok(func_val) => func_val
      Err(err) => {
        @wasmtime.linker_delete(linker)
        @wasmtime.wasmtime_store_delete(store)
        return Err(err)
      }
    }
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
  let result =
    match call_res {
      Ok(_) => Ok(@wasmtime.val_buffer_get_i32(results, 0))
      Err(err) => Err(err)
    }
  @wasmtime.linker_delete(linker)
  @wasmtime.wasmtime_store_delete(store)
  result
}

///|
fn bench_sync_wasi_full(iters : Int) -> Bool {
  let wat =
    #|(module
    #|  (import "wasi_snapshot_preview1" "path_open"
    #|    (func $path_open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
    #|  (import "wasi_snapshot_preview1" "fd_read"
    #|    (func $fd_read (param i32 i32 i32 i32) (result i32)))
    #|  (import "wasi_snapshot_preview1" "fd_close"
    #|    (func $fd_close (param i32) (result i32)))
    #|  (memory 1)
    #|  (export "memory" (memory 0))
    #|  (data (i32.const 64) "wasm_job_input.txt")
    #|  (func (export "run") (result i32)
    #|    i32.const 3
    #|    i32.const 0
    #|    i32.const 64
    #|    i32.const 18
    #|    i32.const 0
    #|    i64.const 2
    #|    i64.const 0
    #|    i32.const 0
    #|    i32.const 32
    #|    call $path_open
    #|    drop
    #|    i32.const 8
    #|    i32.const 100
    #|    i32.store
    #|    i32.const 12
    #|    i32.const 100
    #|    i32.store
    #|    i32.const 32
    #|    i32.load
    #|    i32.const 8
    #|    i32.const 1
    #|    i32.const 4
    #|    call $fd_read
    #|    drop
    #|    i32.const 32
    #|    i32.load
    #|    call $fd_close
    #|    drop
    #|    i32.const 4
    #|    i32.load))
  let engine = @wasmtime.engine_new()
  let ok = bench_time("sync_wasi_full", iters, () => {
    match sync_wasi_call_result(engine, wat) {
      Ok(result) => result == 5
      Err(err) => {
        println(err)
        false
      }
    }
  })
  @wasmtime.engine_delete(engine)
  ok
}

///|
fn bench_sync_wasi_reuse_module(iters : Int) -> Bool {
  let wat =
    #|(module
    #|  (import "wasi_snapshot_preview1" "path_open"
    #|    (func $path_open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
    #|  (import "wasi_snapshot_preview1" "fd_read"
    #|    (func $fd_read (param i32 i32 i32 i32) (result i32)))
    #|  (import "wasi_snapshot_preview1" "fd_close"
    #|    (func $fd_close (param i32) (result i32)))
    #|  (memory 1)
    #|  (export "memory" (memory 0))
    #|  (data (i32.const 64) "wasm_job_input.txt")
    #|  (func (export "run") (result i32)
    #|    i32.const 3
    #|    i32.const 0
    #|    i32.const 64
    #|    i32.const 18
    #|    i32.const 0
    #|    i64.const 2
    #|    i64.const 0
    #|    i32.const 0
    #|    i32.const 32
    #|    call $path_open
    #|    drop
    #|    i32.const 8
    #|    i32.const 100
    #|    i32.store
    #|    i32.const 12
    #|    i32.const 100
    #|    i32.store
    #|    i32.const 32
    #|    i32.load
    #|    i32.const 8
    #|    i32.const 1
    #|    i32.const 4
    #|    call $fd_read
    #|    drop
    #|    i32.const 32
    #|    i32.load
    #|    call $fd_close
    #|    drop
    #|    i32.const 4
    #|    i32.load))
  let engine = @wasmtime.engine_new()
  let module_res = @wasmtime.module_new_from_wat_result(engine, wat)
  match module_res {
    Ok(module_val) => {
      let ok = bench_time("sync_wasi_reuse_module", iters, () => {
        match sync_wasi_call_reuse_module_result(engine, module_val) {
          Ok(result) => result == 5
          Err(err) => {
            println(err)
            false
          }
        }
      })
      @wasmtime.module_delete(module_val)
      @wasmtime.engine_delete(engine)
      ok
    }
    Err(err) => {
      println(err)
      @wasmtime.engine_delete(engine)
      false
    }
  }
}

///|
fn main {
  println("bench_plan_b: start")
  if not(bench_sync_wasi_full(20)) {
    return
  }
  let _ = bench_sync_wasi_reuse_module(50)
}
