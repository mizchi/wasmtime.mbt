# Async callback pointer example

This project exposes a built-in no-op C callback pointer for testing.
Use it to create a host function without writing extra C.

Steps (MoonBit):

```mbt nocheck
let (engine, store, context) = async_context_new(4 * 1024 * 1024)
let params : Bytes = []
let results : Bytes = []
let ty = functype_new_from_valkinds_or_raise(params, results)
let cb_ptr = func_noop_callback_ptr()
let func_bytes = func_buffer_new_with_ptr(context, ty, cb_ptr, 0, 0)
// func_bytes can now be used with func_call_async_bytes
functype_delete(ty)
async_context_delete(engine, store)
```

For real callbacks, add a small C shim that exports a function returning
`uint64_t` of a static `wasmtime_func_callback_t` and bind it in MoonBit with
`extern "C" fn your_callback_ptr() -> UInt64`.
