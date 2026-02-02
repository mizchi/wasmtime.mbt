///|
test "version" {
  let ver = version()
  assert_true(ver.length() > 0)
}

///|
test "engine_new/delete" {
  let engine = engine_new()
  engine_delete(engine)
}

///|
test "store_new/delete" {
  let engine = engine_new()
  let store = store_new(engine)
  store_delete(store)
  engine_delete(engine)
}

///|
test "config_new/engine_new_with_config" {
  let config = config_new()
  config_debug_info_set(config, true)
  config_consume_fuel_set(config, true)
  config_wasm_simd_set(config, true)
  let engine = engine_new_with_config(config)
  engine_delete(engine)
}

///|
test "wasm_job_spawn_wat" {
  let wat =
    #|(module
    #|  (func (export "run") (result i32)
    #|    i32.const 7))
  let handle = wasm_job_spawn_wat_or_raise(wat, "run")
  let result = wasm_job_join_or_raise(handle)
  assert_eq(result, 7)
}

///|
test "wasi_job_spawn_wat_stdin" {
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
  let handle = wasi_job_spawn_wat_or_raise(
    wat,
    "run",
    "src/testdata/wasm_job_input.txt",
  )
  let result = wasi_job_join_or_raise(handle)
  assert_eq(result, 5)
}

///|
test "wasi_sync_call_stdin" {
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
  let engine = engine_new()
  let store = wasmtime_store_new(engine)
  let context = wasmtime_store_context(store)
  let wasi = wasi_config_new_or_raise()
  wasi_config_set_stdin_file_or_raise(wasi, "src/testdata/wasm_job_input.txt")
  context_set_wasi_or_raise(context, wasi)
  let linker = linker_new(engine)
  linker_define_wasi_or_raise(linker)
  let module_val = module_new_from_wat_or_raise(engine, wat)
  let instance = linker_instantiate_or_raise(linker, context, module_val)
  let func = instance_export_func_or_raise(context, instance, "run")
  let args = make_val_buffer(0)
  let results = make_val_buffer(1)
  let trap_ptr = make_ptr_buffer()
  let err_ptr = make_ptr_buffer()
  let call_res = func_call_sync_result_autoclean(
    context,
    func,
    args,
    results,
    trap_ptr,
    err_ptr,
  )
  match call_res {
    Ok(_) => {
      let result = val_buffer_get_i32(results, 0)
      assert_eq(result, 5)
    }
    Err(err) => raise err
  }
  module_delete(module_val)
  linker_delete(linker)
  wasmtime_store_delete(store)
  engine_delete(engine)
}

///|
test "wasi_sync_call_preopen_file" {
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
  let engine = engine_new()
  let (store, context, linker) = wasi_context_linker_with_preopen_or_raise(
    engine,
    "src/testdata",
    guest_path=".",
    dir_perms=WASI_DIR_PERMS_READ,
    file_perms=WASI_FILE_PERMS_READ,
  )
  let module_val = module_new_from_wat_or_raise(engine, wat)
  let instance = linker_instantiate_or_raise(linker, context, module_val)
  let func = instance_export_func_or_raise(context, instance, "run")
  let args = make_val_buffer(0)
  let results = make_val_buffer(1)
  let trap_ptr = make_ptr_buffer()
  let err_ptr = make_ptr_buffer()
  let call_res = func_call_sync_result_autoclean(
    context,
    func,
    args,
    results,
    trap_ptr,
    err_ptr,
  )
  match call_res {
    Ok(_) => {
      let result = val_buffer_get_i32(results, 0)
      assert_eq(result, 5)
    }
    Err(err) => raise err
  }
  module_delete(module_val)
  linker_delete(linker)
  wasmtime_store_delete(store)
  engine_delete(engine)
}

///|
test "wasi_sync_call_stdout_stderr_files" {
  let wat =
    #|(module
    #|  (import "wasi_snapshot_preview1" "fd_write"
    #|    (func $fd_write (param i32 i32 i32 i32) (result i32)))
    #|  (memory 1)
    #|  (export "memory" (memory 0))
    #|  (data (i32.const 64) "hello\n")
    #|  (data (i32.const 80) "oops\n")
    #|  (func (export "run") (result i32)
    #|    i32.const 8
    #|    i32.const 64
    #|    i32.store
    #|    i32.const 12
    #|    i32.const 6
    #|    i32.store
    #|    i32.const 16
    #|    i32.const 80
    #|    i32.store
    #|    i32.const 20
    #|    i32.const 5
    #|    i32.store
    #|    i32.const 1
    #|    i32.const 8
    #|    i32.const 1
    #|    i32.const 32
    #|    call $fd_write
    #|    drop
    #|    i32.const 2
    #|    i32.const 16
    #|    i32.const 1
    #|    i32.const 36
    #|    call $fd_write
    #|    drop
    #|    i32.const 0))
  let stdout_path = "src/testdata/wasm_job_stdout.txt"
  let stderr_path = "src/testdata/wasm_job_stderr.txt"
  let engine = engine_new()
  let (store, context, linker) = wasi_context_linker_with_stdio_files_or_raise(
    engine,
    stdout_path=stdout_path,
    stderr_path=stderr_path,
  )
  let module_val = module_new_from_wat_or_raise(engine, wat)
  let instance = linker_instantiate_or_raise(linker, context, module_val)
  let func = instance_export_func_or_raise(context, instance, "run")
  let args = make_val_buffer(0)
  let results = make_val_buffer(1)
  let trap_ptr = make_ptr_buffer()
  let err_ptr = make_ptr_buffer()
  let call_res = func_call_sync_result_autoclean(
    context,
    func,
    args,
    results,
    trap_ptr,
    err_ptr,
  )
  match call_res {
    Ok(_) => {
      let result = val_buffer_get_i32(results, 0)
      assert_eq(result, 0)
    }
    Err(err) => raise err
  }
  let stdout_text = read_file_string_or_raise(stdout_path)
  let stderr_text = read_file_string_or_raise(stderr_path)
  assert_eq(stdout_text, "hello\n")
  assert_eq(stderr_text, "oops\n")
  module_delete(module_val)
  linker_delete(linker)
  wasmtime_store_delete(store)
  engine_delete(engine)
}
