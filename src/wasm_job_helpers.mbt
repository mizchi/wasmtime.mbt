///|
/// Status codes for wasm job execution.
pub type WasmJobStatus = Int

pub const WASM_JOB_OK : WasmJobStatus = 0
pub const WASM_JOB_WAT_ERROR : WasmJobStatus = 1
pub const WASM_JOB_MODULE_ERROR : WasmJobStatus = 2
pub const WASM_JOB_INSTANTIATE_ERROR : WasmJobStatus = 3
pub const WASM_JOB_TRAP : WasmJobStatus = 4
pub const WASM_JOB_EXPORT_NOT_FOUND : WasmJobStatus = 5
pub const WASM_JOB_EXPORT_NOT_FUNC : WasmJobStatus = 6
pub const WASM_JOB_CALL_ERROR : WasmJobStatus = 7
pub const WASM_JOB_BAD_RESULT : WasmJobStatus = 8
pub const WASM_JOB_WASI_CONFIG_ERROR : WasmJobStatus = 9
pub const WASM_JOB_WASI_LINKER_ERROR : WasmJobStatus = 10
pub const WASM_JOB_WASI_STDIN_ERROR : WasmJobStatus = 11

///|
fn read_i32_le(buf : Bytes) -> Int {
  let b0 = buf[0].to_uint()
  let b1 = buf[1].to_uint() << 8
  let b2 = buf[2].to_uint() << 16
  let b3 = buf[3].to_uint() << 24
  (b0.lor(b1).lor(b2).lor(b3)).reinterpret_as_int()
}

///|
/// Spawn a wasm job from WAT (Result-based).
pub fn wasm_job_spawn_wat_result(wat : String, func : String) -> Result[UInt64, Error] {
  let wat_bytes = @utf8.encode(wat)
  let func_bytes = @utf8.encode(func)
  let handle = wasm_job_spawn_wat_bytes(
    wat_bytes,
    wat_bytes.length(),
    func_bytes,
    func_bytes.length(),
  )
  if handle == 0 {
    Err(@builtin.Failure::Failure("wasm_job_spawn_wat failed"))
  } else {
    Ok(handle)
  }
}

///|
/// Spawn a wasm job from WAT (raise on failure).
pub fn wasm_job_spawn_wat_or_raise(wat : String, func : String) -> UInt64 raise {
  let wat_bytes = @utf8.encode(wat)
  let func_bytes = @utf8.encode(func)
  let handle = wasm_job_spawn_wat_bytes(
    wat_bytes,
    wat_bytes.length(),
    func_bytes,
    func_bytes.length(),
  )
  if handle == 0 {
    fail("wasm_job_spawn_wat failed")
  } else {
    handle
  }
}

///|
/// Join a wasm job and return the result (Result-based).
pub fn wasm_job_join_result(handle : UInt64) -> Result[Int, Error] {
  let result_buf = Bytes::make(4, 0)
  let status_buf = Bytes::make(4, 0)
  if not(wasm_job_join_bytes(handle, result_buf, status_buf)) {
    Err(@builtin.Failure::Failure("wasm_job_join failed"))
  } else {
    let status = read_i32_le(status_buf)
    if status == WASM_JOB_OK {
      Ok(read_i32_le(result_buf))
    } else {
      Err(@builtin.Failure::Failure("wasm_job failed (status=\{status})"))
    }
  }
}

///|
/// Join a wasm job and return the result (raise on failure).
pub fn wasm_job_join_or_raise(handle : UInt64) -> Int raise {
  let result_buf = Bytes::make(4, 0)
  let status_buf = Bytes::make(4, 0)
  if not(wasm_job_join_bytes(handle, result_buf, status_buf)) {
    fail("wasm_job_join failed")
  }
  let status = read_i32_le(status_buf)
  if status == WASM_JOB_OK {
    read_i32_le(result_buf)
  } else {
    fail("wasm_job failed (status=\{status})")
  }
}

///|
/// Spawn a WASI-backed wasm job from WAT (Result-based).
pub fn wasi_job_spawn_wat_result(
  wat : String,
  func : String,
  stdin_path : String,
) -> Result[UInt64, Error] {
  let wat_bytes = @utf8.encode(wat)
  let func_bytes = @utf8.encode(func)
  let stdin_bytes = @utf8.encode(stdin_path)
  let handle = wasi_job_spawn_wat_bytes(
    wat_bytes,
    wat_bytes.length(),
    func_bytes,
    func_bytes.length(),
    stdin_bytes,
    stdin_bytes.length(),
  )
  if handle == 0 {
    Err(@builtin.Failure::Failure("wasi_job_spawn_wat failed"))
  } else {
    Ok(handle)
  }
}

///|
/// Spawn a WASI-backed wasm job from WAT (raise on failure).
pub fn wasi_job_spawn_wat_or_raise(
  wat : String,
  func : String,
  stdin_path : String,
) -> UInt64 raise {
  let wat_bytes = @utf8.encode(wat)
  let func_bytes = @utf8.encode(func)
  let stdin_bytes = @utf8.encode(stdin_path)
  let handle = wasi_job_spawn_wat_bytes(
    wat_bytes,
    wat_bytes.length(),
    func_bytes,
    func_bytes.length(),
    stdin_bytes,
    stdin_bytes.length(),
  )
  if handle == 0 {
    fail("wasi_job_spawn_wat failed")
  } else {
    handle
  }
}

///|
/// Join a WASI wasm job and return the result (Result-based).
pub fn wasi_job_join_result(handle : UInt64) -> Result[Int, Error] {
  let result_buf = Bytes::make(4, 0)
  let status_buf = Bytes::make(4, 0)
  if not(wasi_job_join_bytes(handle, result_buf, status_buf)) {
    Err(@builtin.Failure::Failure("wasi_job_join failed"))
  } else {
    let status = read_i32_le(status_buf)
    if status == WASM_JOB_OK {
      Ok(read_i32_le(result_buf))
    } else {
      Err(@builtin.Failure::Failure("wasi_job failed (status=\{status})"))
    }
  }
}

///|
/// Join a WASI wasm job and return the result (raise on failure).
pub fn wasi_job_join_or_raise(handle : UInt64) -> Int raise {
  let result_buf = Bytes::make(4, 0)
  let status_buf = Bytes::make(4, 0)
  if not(wasi_job_join_bytes(handle, result_buf, status_buf)) {
    fail("wasi_job_join failed")
  }
  let status = read_i32_le(status_buf)
  if status == WASM_JOB_OK {
    read_i32_le(result_buf)
  } else {
    fail("wasi_job failed (status=\{status})")
  }
}
