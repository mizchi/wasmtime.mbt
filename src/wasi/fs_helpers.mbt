///|
/// Read a host file into bytes (Result-based).
pub fn read_file_bytes_result(path : String) -> Result[Bytes, Error] {
  let path_bytes = @utf8.encode(path)
  let err_ptr = @wasmtime.make_ptr_buffer()
  let bytes = @wasmtime.read_file_bytes(path_bytes, path_bytes.length(), err_ptr)
  if not(@wasmtime.ptr_buffer_is_null(err_ptr)) {
    @wasmtime.error_delete_ptr_buffer(err_ptr)
    Err(@builtin.Failure::Failure("read_file_bytes failed"))
  } else {
    Ok(bytes)
  }
}

///|
/// Read a host file into bytes (raise on failure).
pub fn read_file_bytes_or_raise(path : String) -> Bytes raise {
  match read_file_bytes_result(path) {
    Ok(bytes) => bytes
    Err(err) => raise err
  }
}

///|
/// Read a host file into a String (lossy UTF-8).
pub fn read_file_string_or_raise(path : String) -> String raise {
  let bytes = read_file_bytes_or_raise(path)
  @utf8.decode_lossy(bytes)
}
