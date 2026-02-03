///|
/// Convert WAT to wasm bytes (Result-based).
pub fn wat2wasm_result(wat : String) -> Result[Bytes, Error] {
  let wat_bytes = @utf8.encode(wat)
  let err_ptr = make_ptr_buffer()
  let wasm = wat2wasm_bytes(wat_bytes, wat_bytes.length(), err_ptr)
  if not(ptr_buffer_is_null(err_ptr)) {
    error_delete_ptr_buffer(err_ptr)
    Err(@builtin.Failure::Failure("wat2wasm failed"))
  } else if wasm.length() == 0 {
    Err(@builtin.Failure::Failure("wat2wasm returned empty"))
  } else {
    Ok(wasm)
  }
}

///|
/// Convert WAT to wasm bytes (raise on failure).
pub fn wat2wasm_or_raise(wat : String) -> Bytes raise {
  match wat2wasm_result(wat) {
    Ok(bytes) => bytes
    Err(err) => raise err
  }
}

///|
/// Compile a module from wasm bytes (Result-based).
pub fn module_new_from_wasm_result(
  engine : Engine,
  wasm : Bytes,
) -> Result[Module, Error] {
  let err_ptr = make_ptr_buffer()
  let module_val = module_new_bytes(engine, wasm, wasm.length(), err_ptr)
  if not(ptr_buffer_is_null(err_ptr)) {
    error_delete_ptr_buffer(err_ptr)
    Err(@builtin.Failure::Failure("module_new failed"))
  } else {
    Ok(module_val)
  }
}

///|
/// Compile a module from wasm bytes (raise on failure).
pub fn module_new_from_wasm_or_raise(
  engine : Engine,
  wasm : Bytes,
) -> Module raise {
  match module_new_from_wasm_result(engine, wasm) {
    Ok(module_val) => module_val
    Err(err) => raise err
  }
}

///|
/// Compile a module from WAT (Result-based).
pub fn module_new_from_wat_result(
  engine : Engine,
  wat : String,
) -> Result[Module, Error] {
  match wat2wasm_result(wat) {
    Ok(wasm) => module_new_from_wasm_result(engine, wasm)
    Err(err) => Err(err)
  }
}

///|
/// Compile a module from WAT (raise on failure).
pub fn module_new_from_wat_or_raise(
  engine : Engine,
  wat : String,
) -> Module raise {
  match module_new_from_wat_result(engine, wat) {
    Ok(module_val) => module_val
    Err(err) => raise err
  }
}

///|
/// Define WASI in a linker (Result-based).
pub fn linker_define_wasi_result(linker : Linker) -> Result[Unit, Error] {
  let err = linker_define_wasi(linker)
  if error_is_null(err) {
    Ok(())
  } else {
    error_delete(err)
    Err(@builtin.Failure::Failure("linker_define_wasi failed"))
  }
}

///|
/// Define WASI in a linker (raise on failure).
pub fn linker_define_wasi_or_raise(linker : Linker) -> Unit raise {
  match linker_define_wasi_result(linker) {
    Ok(_) => ()
    Err(err) => raise err
  }
}

///|
/// Instantiate a module with a linker (Result-based).
pub fn linker_instantiate_result(
  linker : Linker,
  context : Context,
  module_val : Module,
) -> Result[Bytes, Error] {
  let instance = make_instance_buffer()
  let trap_ptr = make_ptr_buffer()
  let err_ptr = make_ptr_buffer()
  let ok = linker_instantiate_bytes(
    linker, context, module_val, instance, trap_ptr, err_ptr,
  )
  if ok && ptr_buffer_is_null(err_ptr) && ptr_buffer_is_null(trap_ptr) {
    Ok(instance)
  } else {
    error_delete_ptr_buffer(err_ptr)
    trap_delete_ptr_buffer(trap_ptr)
    Err(@builtin.Failure::Failure("linker_instantiate failed"))
  }
}

///|
/// Instantiate a module with a linker (raise on failure).
pub fn linker_instantiate_or_raise(
  linker : Linker,
  context : Context,
  module_val : Module,
) -> Bytes raise {
  match linker_instantiate_result(linker, context, module_val) {
    Ok(instance) => instance
    Err(err) => raise err
  }
}

///|
/// Lookup an exported function by name (Result-based).
pub fn instance_export_func_result(
  context : Context,
  instance : Bytes,
  name : String,
) -> Result[Bytes, Error] {
  let name_bytes = @utf8.encode(name)
  let func_buf = make_func_buffer()
  if instance_export_get_func_bytes(
      context,
      instance,
      name_bytes,
      name_bytes.length(),
      func_buf,
    ) {
    Ok(func_buf)
  } else {
    Err(@builtin.Failure::Failure("instance_export_get_func failed"))
  }
}

///|
/// Lookup an exported function by name (raise on failure).
pub fn instance_export_func_or_raise(
  context : Context,
  instance : Bytes,
  name : String,
) -> Bytes raise {
  match instance_export_func_result(context, instance, name) {
    Ok(func_buf) => func_buf
    Err(err) => raise err
  }
}
