///|
/// Thread runtime handle.
pub struct ThreadRuntime {
  handle : UInt64
}

///|
/// Thread handle for a spawned job.
pub struct ThreadHandle {
  handle : UInt64
}

///|
/// Native: create a thread runtime with shared memory pages.
#borrow(error_out)
extern "C" fn thread_runtime_new_native(
  pages : UInt64,
  error_out : Bytes,
) -> UInt64 = "wasmtime_thread_runtime_new"

///|
/// Native: delete a thread runtime.
extern "C" fn thread_runtime_delete_native(handle : UInt64) -> Unit = "wasmtime_thread_runtime_delete"

///|
/// Native: spawn a wasm thread from WAT.
#borrow(wat, entry, args, error_out)
extern "C" fn thread_runtime_spawn_wat_native(
  runtime : UInt64,
  wat : Bytes,
  wat_len : Int,
  entry : Bytes,
  entry_len : Int,
  args : Bytes,
  args_len : Int,
  error_out : Bytes,
) -> UInt64 = "wasmtime_thread_runtime_spawn_wat"

///|
/// Native: spawn a wasm thread from WASM bytes.
#borrow(wasm, entry, args, error_out)
extern "C" fn thread_runtime_spawn_wasm_native(
  runtime : UInt64,
  wasm : Bytes,
  wasm_len : Int,
  entry : Bytes,
  entry_len : Int,
  args : Bytes,
  args_len : Int,
  error_out : Bytes,
) -> UInt64 = "wasmtime_thread_runtime_spawn_wasm"

///|
/// Native: join a spawned thread.
#borrow(error_out)
extern "C" fn thread_runtime_join_native(
  handle : UInt64,
  error_out : Bytes,
) -> Bool = "wasmtime_thread_runtime_join"

///|
/// Native: try join a spawned thread (non-blocking).
#borrow(error_out)
extern "C" fn thread_runtime_try_join_native(
  handle : UInt64,
  error_out : Bytes,
) -> Bool = "wasmtime_thread_runtime_try_join"

///|
/// Native: detach a spawned thread.
#borrow(error_out)
extern "C" fn thread_runtime_detach_native(
  handle : UInt64,
  error_out : Bytes,
) -> Bool = "wasmtime_thread_runtime_detach"

///|
/// Native: write bytes into shared memory.
#borrow(src, error_out)
extern "C" fn thread_runtime_mem_write_native(
  runtime : UInt64,
  offset : UInt64,
  src : Bytes,
  len : Int,
  error_out : Bytes,
) -> Bool = "wasmtime_thread_runtime_mem_write"

///|
/// Native: read bytes from shared memory.
#borrow(dst, error_out)
extern "C" fn thread_runtime_mem_read_native(
  runtime : UInt64,
  offset : UInt64,
  dst : Bytes,
  len : Int,
  error_out : Bytes,
) -> Bool = "wasmtime_thread_runtime_mem_read"

///|
/// Native: read an error message into bytes.
#borrow(bytes)
extern "C" fn error_message_bytes(bytes : Bytes) -> Bytes = "wasmtime_error_message_bytes"

///|
/// Convert an error pointer buffer into `Error`.
fn take_error_or(err_ptr : Bytes, fallback : String) -> Error {
  if @wasmtime.ptr_buffer_is_null(err_ptr) {
    @builtin.Failure::Failure(fallback)
  } else {
    let msg_bytes = error_message_bytes(err_ptr)
    let msg = if msg_bytes.length() > 0 {
      @utf8.decode_lossy(msg_bytes)
    } else {
      fallback
    }
    @wasmtime.error_delete_ptr_buffer(err_ptr)
    @builtin.Failure::Failure(msg)
  }
}

///|
/// Compute pages required for a shared memory size.
pub fn shared_pages_for_bytes(bytes : UInt64) -> UInt64 {
  let page : UInt64 = 65536
  if bytes == 0 {
    1
  } else {
    (bytes + page - 1) / page
  }
}

///|
/// Create a runtime with wasm threads + shared memory enabled.
pub fn thread_runtime_new(shared_pages : Int) -> Result[ThreadRuntime, Error] {
  if shared_pages <= 0 {
    return Err(@builtin.Failure::Failure("shared_pages must be > 0"))
  }
  let err_ptr = @wasmtime.make_ptr_buffer()
  let handle = thread_runtime_new_native(Int::to_uint64(shared_pages), err_ptr)
  if handle == 0 || not(@wasmtime.ptr_buffer_is_null(err_ptr)) {
    Err(take_error_or(err_ptr, "thread_runtime_new failed"))
  } else {
    Ok(ThreadRuntime::{ handle, })
  }
}

///|
/// Delete the runtime and its engine.
pub fn thread_runtime_delete(rt : ThreadRuntime) -> Unit {
  thread_runtime_delete_native(rt.handle)
}

///|
/// Spawn a wasm thread from WAT (entry must return no values).
pub fn thread_runtime_spawn_wat(
  rt : ThreadRuntime,
  wat : String,
  entry : String,
  args : Bytes,
) -> Result[ThreadHandle, Error] {
  let err_ptr = @wasmtime.make_ptr_buffer()
  let wat_bytes = @utf8.encode(wat)
  let entry_bytes = @utf8.encode(entry)
  let handle = thread_runtime_spawn_wat_native(
    rt.handle,
    wat_bytes,
    wat_bytes.length(),
    entry_bytes,
    entry_bytes.length(),
    args,
    args.length(),
    err_ptr,
  )
  if handle == 0 || not(@wasmtime.ptr_buffer_is_null(err_ptr)) {
    Err(take_error_or(err_ptr, "thread_runtime_spawn_wat failed"))
  } else {
    Ok(ThreadHandle::{ handle, })
  }
}

///|
/// Spawn a wasm thread from WASM bytes (entry must return no values).
pub fn thread_runtime_spawn_wasm(
  rt : ThreadRuntime,
  wasm : Bytes,
  entry : String,
  args : Bytes,
) -> Result[ThreadHandle, Error] {
  let err_ptr = @wasmtime.make_ptr_buffer()
  let entry_bytes = @utf8.encode(entry)
  let handle = thread_runtime_spawn_wasm_native(
    rt.handle,
    wasm,
    wasm.length(),
    entry_bytes,
    entry_bytes.length(),
    args,
    args.length(),
    err_ptr,
  )
  if handle == 0 || not(@wasmtime.ptr_buffer_is_null(err_ptr)) {
    Err(take_error_or(err_ptr, "thread_runtime_spawn_wasm failed"))
  } else {
    Ok(ThreadHandle::{ handle, })
  }
}

///|
/// Join a spawned wasm thread.
pub fn thread_runtime_join(handle : ThreadHandle) -> Result[Unit, Error] {
  let err_ptr = @wasmtime.make_ptr_buffer()
  let ok = thread_runtime_join_native(handle.handle, err_ptr)
  if ok && @wasmtime.ptr_buffer_is_null(err_ptr) {
    Ok(())
  } else {
    Err(take_error_or(err_ptr, "thread_runtime_join failed"))
  }
}

///|
/// Try join a spawned wasm thread (returns false if still running).
pub fn thread_runtime_try_join(handle : ThreadHandle) -> Result[Bool, Error] {
  let err_ptr = @wasmtime.make_ptr_buffer()
  let done = thread_runtime_try_join_native(handle.handle, err_ptr)
  if @wasmtime.ptr_buffer_is_null(err_ptr) {
    Ok(done)
  } else {
    Err(take_error_or(err_ptr, "thread_runtime_try_join failed"))
  }
}

///|
/// Detach a spawned wasm thread (drops the handle).
pub fn thread_runtime_detach(handle : ThreadHandle) -> Result[Unit, Error] {
  let err_ptr = @wasmtime.make_ptr_buffer()
  let ok = thread_runtime_detach_native(handle.handle, err_ptr)
  if ok && @wasmtime.ptr_buffer_is_null(err_ptr) {
    Ok(())
  } else {
    Err(take_error_or(err_ptr, "thread_runtime_detach failed"))
  }
}

///|
/// Write bytes into shared memory at the given offset.
pub fn thread_runtime_mem_write(
  rt : ThreadRuntime,
  offset : UInt64,
  bytes : Bytes,
) -> Result[Unit, Error] {
  let err_ptr = @wasmtime.make_ptr_buffer()
  let ok = thread_runtime_mem_write_native(
    rt.handle,
    offset,
    bytes,
    bytes.length(),
    err_ptr,
  )
  if ok && @wasmtime.ptr_buffer_is_null(err_ptr) {
    Ok(())
  } else {
    Err(take_error_or(err_ptr, "thread_runtime_mem_write failed"))
  }
}

///|
/// Read bytes from shared memory at the given offset.
pub fn thread_runtime_mem_read(
  rt : ThreadRuntime,
  offset : UInt64,
  len : Int,
) -> Result[Bytes, Error] {
  if len < 0 {
    return Err(
      @builtin.Failure::Failure("thread_runtime_mem_read length invalid"),
    )
  }
  let err_ptr = @wasmtime.make_ptr_buffer()
  let out = Bytes::make(len, 0)
  let ok = thread_runtime_mem_read_native(rt.handle, offset, out, len, err_ptr)
  if ok && @wasmtime.ptr_buffer_is_null(err_ptr) {
    Ok(out)
  } else {
    Err(take_error_or(err_ptr, "thread_runtime_mem_read failed"))
  }
}
