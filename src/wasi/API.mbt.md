# WASI helpers

## WASI config + sync call (POC)

Compile a module, instantiate it with a linker, and call an exported function.

```mbt nocheck
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
let engine = @wasmtime.engine_new()
let (store, context, linker) = wasi_context_linker_with_stdio_files_or_raise(
  engine,
  stdin_path="src/testdata/wasm_job_input.txt",
)
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
  Ok(()) => {
    let result = @wasmtime.val_buffer_get_i32(results, 0)
    inspect(result, content="5")
  }
  Err(err) => raise err
}
@wasmtime.module_delete(module_val)
@wasmtime.linker_delete(linker)
@wasmtime.wasmtime_store_delete(store)
@wasmtime.engine_delete(engine)
```

## WASI context/linker helper (POC)

Create a WASI-enabled store/context/linker in one call.

```mbt nocheck
let engine = @wasmtime.engine_new()
let wasi = wasi_config_new_or_raise()
wasi_config_inherit_stdio(wasi)
let (store, context, linker) = wasi_context_linker_new_or_raise(engine, wasi)
@wasmtime.linker_delete(linker)
@wasmtime.wasmtime_store_delete(store)
@wasmtime.engine_delete(engine)
```

Create a WASI-enabled store/context/linker with stdout/stderr files.

```mbt nocheck
let engine = @wasmtime.engine_new()
let (store, context, linker) = wasi_context_linker_with_stdio_files_or_raise(
  engine,
  stdout_path="src/testdata/wasm_job_stdout.txt",
  stderr_path="src/testdata/wasm_job_stderr.txt",
)
@wasmtime.linker_delete(linker)
@wasmtime.wasmtime_store_delete(store)
@wasmtime.engine_delete(engine)
```

Create a WASI-enabled store/context/linker with a preopened directory.

```mbt nocheck
let engine = @wasmtime.engine_new()
let (store, context, linker) = wasi_context_linker_with_preopen_or_raise(
  engine,
  "src/testdata",
  guest_path=".",
  dir_perms=WASI_DIR_PERMS_READ,
  file_perms=WASI_FILE_PERMS_READ,
)
@wasmtime.linker_delete(linker)
@wasmtime.wasmtime_store_delete(store)
@wasmtime.engine_delete(engine)
```

## WASI preopen dir + path_open (POC)

Open a file via `path_open` from a preopened directory and read it.

```mbt nocheck
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
let (store, context, linker) = wasi_context_linker_with_preopen_or_raise(
  engine,
  "src/testdata",
  guest_path=".",
  dir_perms=WASI_DIR_PERMS_READ,
  file_perms=WASI_FILE_PERMS_READ,
)
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
  Ok(()) => {
    let result = @wasmtime.val_buffer_get_i32(results, 0)
    inspect(result, content="5")
  }
  Err(err) => raise err
}
@wasmtime.module_delete(module_val)
@wasmtime.linker_delete(linker)
@wasmtime.wasmtime_store_delete(store)
@wasmtime.engine_delete(engine)
```

## WASI stdout/stderr files (POC)

Redirect stdout/stderr to host files and verify contents.

```mbt nocheck
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
let engine = @wasmtime.engine_new()
let (store, context, linker) = wasi_context_linker_with_stdio_files_or_raise(
  engine,
  stdout_path=stdout_path,
  stderr_path=stderr_path,
)
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
  Ok(()) => {
    let result = @wasmtime.val_buffer_get_i32(results, 0)
    inspect(result, content="0")
  }
  Err(err) => raise err
}
let stdout_text = read_file_string_or_raise(stdout_path)
let stderr_text = read_file_string_or_raise(stderr_path)
inspect(stdout_text, content="hello\\n")
inspect(stderr_text, content="oops\\n")
@wasmtime.module_delete(module_val)
@wasmtime.linker_delete(linker)
@wasmtime.wasmtime_store_delete(store)
@wasmtime.engine_delete(engine)
```
