///|
/// Call a function synchronously with buffer-derived counts.
pub fn func_call_sync(
  context : Context,
  func_bytes : Bytes,
  args : Bytes,
  results : Bytes,
  trap_ptr : Bytes,
  err_ptr : Bytes,
) -> Unit raise {
  let nargs = val_buffer_count_or_raise(args)
  let nresults = val_buffer_count_or_raise(results)
  let ok = func_call_bytes(
    context, func_bytes, args, nargs, results, nresults, trap_ptr, err_ptr,
  )
  if not(ok) {
    fail("func_call_bytes failed")
  }
}

///|
/// Call a function synchronously and return a Result.
pub fn func_call_sync_result(
  context : Context,
  func_bytes : Bytes,
  args : Bytes,
  results : Bytes,
  trap_ptr : Bytes,
  err_ptr : Bytes,
) -> Result[Unit, Error] {
  let nargs = val_buffer_count_result(args)
  let nresults = val_buffer_count_result(results)
  match (nargs, nresults) {
    (Ok(nargs_val), Ok(nresults_val)) => {
      let ok = func_call_bytes(
        context, func_bytes, args, nargs_val, results, nresults_val, trap_ptr, err_ptr,
      )
      if ok && ptr_buffer_is_null(err_ptr) && ptr_buffer_is_null(trap_ptr) {
        Ok(())
      } else {
        let err_present = not(ptr_buffer_is_null(err_ptr))
        let trap_present = not(ptr_buffer_is_null(trap_ptr))
        Err(
          @builtin.Failure::Failure(
            "func_call_sync failed (error=\{err_present}, trap=\{trap_present})",
          ),
        )
      }
    }
    (Ok(_), Err(err)) => Err(err)
    (Err(err), _) => Err(err)
  }
}

///|
/// Call a function synchronously, auto-cleaning trap/error pointers on failure.
pub fn func_call_sync_result_autoclean(
  context : Context,
  func_bytes : Bytes,
  args : Bytes,
  results : Bytes,
  trap_ptr : Bytes,
  err_ptr : Bytes,
) -> Result[Unit, Error] {
  let res = func_call_sync_result(
    context, func_bytes, args, results, trap_ptr, err_ptr,
  )
  match res {
    Ok(_) => {
      ptr_buffer_clear(err_ptr)
      ptr_buffer_clear(trap_ptr)
      Ok(())
    }
    Err(err) => {
      error_delete_ptr_buffer(err_ptr)
      trap_delete_ptr_buffer(trap_ptr)
      Err(err)
    }
  }
}
