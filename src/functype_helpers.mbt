///|
/// Create a function type from value kind arrays.
pub fn functype_new_from_valkinds(params : Bytes, results : Bytes) -> FuncType {
  functype_new_from_kinds(params, params.length(), results, results.length())
}

///|
/// Create a function type and return a Result.
pub fn functype_new_from_valkinds_result(
  params : Bytes,
  results : Bytes,
) -> Result[FuncType, Error] {
  let ty = functype_new_from_valkinds(params, results)
  if functype_is_null(ty) {
    Err(@builtin.Failure::Failure("functype_new_from_valkinds failed"))
  } else {
    Ok(ty)
  }
}

///|
/// Create a function type or raise on failure.
pub fn functype_new_from_valkinds_or_raise(
  params : Bytes,
  results : Bytes,
) -> FuncType raise {
  let ty = functype_new_from_valkinds(params, results)
  if functype_is_null(ty) {
    fail("functype_new_from_valkinds failed")
  } else {
    ty
  }
}

///|
/// Get a pointer to a no-op host callback.
pub fn func_noop_callback_ptr() -> UInt64 {
  noop_callback_ptr()
}

///|
/// Create a host function into a bytes buffer using raw callback pointers.
pub fn func_buffer_new_with_ptr(
  context : Context,
  ty : FuncType,
  cb_ptr : UInt64,
  data_ptr : UInt64,
  finalizer_ptr : UInt64,
) -> Bytes {
  let buf = make_func_buffer()
  func_new_ptr_bytes(context, ty, cb_ptr, data_ptr, finalizer_ptr, buf)
  buf
}
