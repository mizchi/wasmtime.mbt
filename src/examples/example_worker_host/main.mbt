///|
fn call_run(wasm : Bytes, value : Int, use_gc : Bool) -> Result[Int, Error] {
  println("host: init engine")
  let config = @wasmtime.config_new()
  if use_gc {
    @wasmtime.config_wasm_gc_set(config, true)
    @wasmtime.config_wasm_function_references_set(config, true)
    @wasmtime.config_wasm_reference_types_set(config, true)
  }
  let engine = @wasmtime.engine_new_with_config(config)
  println("host: init store")
  let store = @wasmtime.wasmtime_store_new(engine)
  let context = @wasmtime.wasmtime_store_context(store)
  println("host: init linker")
  let linker = @wasmtime.linker_new(engine)
  println("host: compile module")
  let result = @wasmtime.module_new_from_wasm_result(engine, wasm)
    .bind(module_val => @wasmtime.linker_instantiate_result(linker, context, module_val))
    .bind(instance => @wasmtime.instance_export_func_result(context, instance, "run"))
    .bind(func_buf => {
      println("host: call run")
      let args = @wasmtime.make_val_buffer(1)
      @wasmtime.val_buffer_set_i32(args, 0, value)
      let results = @wasmtime.make_val_buffer(1)
      let trap_ptr = @wasmtime.make_ptr_buffer()
      let err_ptr = @wasmtime.make_ptr_buffer()
      match @wasmtime.func_call_sync_result_autoclean(
        context,
        func_buf,
        args,
        results,
        trap_ptr,
        err_ptr,
      ) {
        Ok(_) => Ok(@wasmtime.val_buffer_get_i32(results, 0))
        Err(err) => Err(err)
      }
    })
  @wasmtime.linker_delete(linker)
  @wasmtime.wasmtime_store_delete(store)
  @wasmtime.engine_delete(engine)
  @wasmtime.config_delete(config)
  result
}

///|
fn main {
  let target = @wasm_artifacts.WasmTarget::WasmGc
  let use_gc = target is @wasm_artifacts.WasmTarget::WasmGc
  let root = match @wasm_artifacts.workspace_root_from_cwd() {
    Some(root) => root
    None => ""
  }
  let path = @wasm_artifacts.from_moonbit_module(
    "mizchi/wasmtime/examples/example_worker",
    target=target,
    root=root,
  )
  println("host: load wasm from \{path}")
  let wasm = match @wasm_artifacts.from_wasm_bytes(path) {
    Ok(bytes) => {
      println("host: wasm bytes = \{bytes.length()}")
      bytes
    }
    Err(err) => {
      println("failed to load wasm: \{err}")
      return
    }
  }
  let value = 21
  match call_run(wasm, value, use_gc) {
    Ok(result) => println("host: run(\{value}) = \{result}")
    Err(err) => println("call failed: \{err}")
  }
}
