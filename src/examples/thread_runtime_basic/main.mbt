fn make_i32_args(value : Int) -> Bytes {
  let args = @wasmtime.make_val_buffer(1)
  @wasmtime.val_buffer_set_i32(args, 0, value)
  args
}

///|
suberror ExampleError {
  ExampleError(String)
}

///|
fn spawn_all(
  rt : @thread_runtime.ThreadRuntime,
  wat : String,
  args : Bytes,
  threads : Int,
) -> Result[Array[@thread_runtime.ThreadHandle], Error] {
  let handles : Array[@thread_runtime.ThreadHandle] = []
  for _ in 0..<threads {
    let res = rt.spawn_wat(wat, "run", args)
    guard res is Ok(handle) else {
      return Err(res.unwrap_err())
    }
    handles.push(handle)
  }
  Ok(handles)
}

///|
fn join_all(handles : Array[@thread_runtime.ThreadHandle]) -> Result[Unit, Error] {
  for h in handles {
    let res = h.join()
    guard res is Ok(_) else {
      return Err(res.unwrap_err())
    }
  }
  Ok(())
}

///|
fn validate_atomic_count(
  bytes : Bytes,
  threads : Int,
  iters : Int,
) -> Result[Unit, Error] {
  let count = @thread_runtime.read_u32_le(bytes, 0).to_int()
  let expected = threads * iters
  if count == expected {
    Ok(())
  } else {
    Err(
      ExampleError::ExampleError(
        "count mismatch: got=\{count} expected=\{expected}",
      ),
    )
  }
}

///|
fn run_atomic_counter(threads : Int, iters : Int) -> Result[Unit, Error] {
  let pages = @thread_runtime.shared_pages_for_bytes(4UL)
  let wat = @wasm_threads_patterns.wat_atomic_counter(pages)
  @thread_runtime.ThreadRuntime::new(pages.to_int()).bind(rt => {
    let args = make_i32_args(iters)
    let result =
      spawn_all(rt, wat, args, threads)
      .bind(handles => join_all(handles))
      .bind(_ => rt.mem_read(0, 4))
      .bind(bytes => validate_atomic_count(bytes, threads, iters))
    rt.delete()
    result
  })
}

///|
fn main {
  let threads = 4
  let iters = 10000
  match run_atomic_counter(threads, iters) {
    Ok(_) => println("atomic counter ok")
    Err(err) => println("atomic counter failed: \{err}")
  }
}
