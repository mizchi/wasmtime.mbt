# API Documentation

## version

Get the Wasmtime version string from the native library.

```mbt check
///|
test {
  inspect(version().length() > 0, content="true")
}
```

## engine_new / engine_delete

Create and destroy a Wasmtime engine (opaque pointer from the C API).

```mbt nocheck
let engine = engine_new()
engine_delete(engine)
```

## store_new / store_delete

Create and destroy a store associated with an engine.

```mbt nocheck
let engine = engine_new()
let store = store_new(engine)
store_delete(store)
engine_delete(engine)
```

## config_new / engine_new_with_config

Create a configuration, set options, and create an engine with it.

```mbt nocheck
let config = config_new()
config_debug_info_set(config, true)
config_consume_fuel_set(config, true)
let engine = engine_new_with_config(config)
engine_delete(engine)
```

## Config options

Most Wasmtime config options are exposed as `config_*_set` functions.

```mbt nocheck
let config = config_new()
config_wasm_simd_set(config, true)
config_wasm_multi_value_set(config, true)
config_wasm_tail_call_set(config, false)
let engine = engine_new_with_config(config)
engine_delete(engine)
```

## Async support (native)

Async APIs are available when Wasmtime is built with async support.
Use a Wasmtime store/context to configure async yield behavior.

```mbt nocheck
let (engine, store, context) = async_context_new(4 * 1024 * 1024)
let err = context_fuel_async_yield_interval(context, 10000)
if not(error_is_null(err)) { error_delete(err) }
async_context_delete(engine, store)
```

## Async bytes helpers (native)

Low-level async APIs use bytes buffers for `wasmtime_val_t` arrays and out
pointers for traps/errors.

```mbt nocheck
let (engine, store, context) = async_context_new(4 * 1024 * 1024)
let args = make_val_buffer(0)
let results = make_val_buffer(0)
let trap_ptr = make_ptr_buffer()
let err_ptr = make_ptr_buffer()

let params : Bytes = []
let results_sig : Bytes = []
let ty = functype_new_from_valkinds_or_raise(params, results_sig)
let cb_ptr = func_noop_callback_ptr()
let func_bytes = func_buffer_new_with_ptr(context, ty, cb_ptr, 0, 0)

// `func_bytes` is a bytes view of a `wasmtime_func_t` value created with
// func_buffer_new_with_ptr. Keep all buffers alive until the future is deleted.
// Keep all buffers alive until the future is deleted.
let future = func_call_async(context, func_bytes, args, results, trap_ptr, err_ptr)
while not(call_future_poll(future)) {
  // drive the async execution
  ()
}
call_future_delete(future)
if not(ptr_buffer_is_null(err_ptr)) { error_delete_ptr_buffer(err_ptr) }
if not(ptr_buffer_is_null(trap_ptr)) { trap_delete_ptr_buffer(trap_ptr) }
functype_delete(ty)
async_context_delete(engine, store)
```

## Async bytes helpers with Result

When you want a Result-based API with auto-cleanup on failure:

```mbt nocheck
let (engine, store, context) = async_context_new(4 * 1024 * 1024)
let args = make_val_buffer(0)
let results = make_val_buffer(0)
let trap_ptr = make_ptr_buffer()
let err_ptr = make_ptr_buffer()

let params : Bytes = []
let results_sig : Bytes = []
let ty = functype_new_from_valkinds_or_raise(params, results_sig)
let cb_ptr = func_noop_callback_ptr()
let func_bytes = func_buffer_new_with_ptr(context, ty, cb_ptr, 0, 0)

let future_result =
  func_call_async_result_autoclean(context, func_bytes, args, results, trap_ptr, err_ptr)
match future_result {
  Ok(future) => {
    while not(call_future_poll(future)) { () }
    call_future_delete(future)
  }
  Err(_err) => {
    // trap/error pointers are already deleted
  }
}
// Error example: "func_call_async failed (error=true, trap=false)"
functype_delete(ty)
async_context_delete(engine, store)
```

## Async polling thread (native)

Spawn a background OS thread to poll a `CallFuture`.
Keep the `CallFuture` and any buffers alive until the thread is joined.

```mbt nocheck
let (engine, store, context) = async_context_new(4 * 1024 * 1024)
let args = make_val_buffer(0)
let results = make_val_buffer(0)
let trap_ptr = make_ptr_buffer()
let err_ptr = make_ptr_buffer()

let params : Bytes = []
let results_sig : Bytes = []
let ty = functype_new_from_valkinds_or_raise(params, results_sig)
let cb_ptr = func_noop_callback_ptr()
let func_bytes = func_buffer_new_with_ptr(context, ty, cb_ptr, 0, 0)

let future = func_call_async(context, func_bytes, args, results, trap_ptr, err_ptr)
let thread = call_future_thread_spawn_or_raise(future, poll_sleep_us=1000)
call_future_thread_join_or_raise(thread)
call_future_delete(future)

if not(ptr_buffer_is_null(err_ptr)) { error_delete_ptr_buffer(err_ptr) }
if not(ptr_buffer_is_null(trap_ptr)) { trap_delete_ptr_buffer(trap_ptr) }
functype_delete(ty)
async_context_delete(engine, store)
```

## Target/cache helpers

String-based helpers use UTF-8 bytes and return an Error pointer.
A null error means success.

```mbt nocheck
let config = config_new()
let err = config_target_set(config, "x86_64-unknown-linux-gnu")
if not(error_is_null(err)) {
  error_delete(err)
}
```
