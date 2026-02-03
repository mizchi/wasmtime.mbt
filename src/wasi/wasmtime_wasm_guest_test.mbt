///|
const GUEST_WASM_PATH : String = "target/wasm/release/build/guest_wasm/guest_wasm.wasm"

///|
test "moonbit wasm guest runs in wasmtime host" {
  let wasm = read_file_bytes_or_raise(GUEST_WASM_PATH)
  @wasmtime.spectest_capture_reset()
  let engine = @wasmtime.engine_new()
  let store = @wasmtime.wasmtime_store_new(engine)
  let context = @wasmtime.wasmtime_store_context(store)
  let linker = @wasmtime.linker_new(engine)
  @wasmtime.linker_define_spectest_print_char_or_raise(linker, context)
  let module_val = @wasmtime.module_new_from_wasm_or_raise(engine, wasm)
  let instance = @wasmtime.linker_instantiate_or_raise(
    linker, context, module_val,
  )
  let func = @wasmtime.instance_export_func_or_raise(
    context, instance, "_start",
  )
  let args = @wasmtime.make_val_buffer(0)
  let results = @wasmtime.make_val_buffer(0)
  let trap_ptr = @wasmtime.make_ptr_buffer()
  let err_ptr = @wasmtime.make_ptr_buffer()
  match
    @wasmtime.func_call_sync_result_autoclean(
      context, func, args, results, trap_ptr, err_ptr,
    ) {
    Ok(_) => ()
    Err(err) => {
      @wasmtime.module_delete(module_val)
      @wasmtime.linker_delete(linker)
      @wasmtime.wasmtime_store_delete(store)
      @wasmtime.engine_delete(engine)
      fail("wasm guest call failed: \{err}")
    }
  }
  let output = @utf8.decode_lossy(@wasmtime.spectest_capture_bytes())
  @wasmtime.module_delete(module_val)
  @wasmtime.linker_delete(linker)
  @wasmtime.wasmtime_store_delete(store)
  @wasmtime.engine_delete(engine)
  assert_true(output.contains("guest:42"))
}
