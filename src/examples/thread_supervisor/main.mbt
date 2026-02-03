///|
fn read_u32_le(bytes : Bytes, offset : Int) -> UInt64 {
  let b0 = bytes[offset].to_uint64()
  let b1 = bytes[offset + 1].to_uint64()
  let b2 = bytes[offset + 2].to_uint64()
  let b3 = bytes[offset + 3].to_uint64()
  b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
}

///|
fn make_i32_args(value : Int) -> Bytes {
  let args = @wasmtime.make_val_buffer(1)
  @wasmtime.val_buffer_set_i32(args, 0, value)
  args
}

///|
fn wat_counter(pages : UInt64) -> String {
  (
    $|(module
    $|  (memory (import "env" "mem") \{pages} \{pages} shared)
    $|  (func (export "run") (param $n i32)
    $|    (local $i i32)
    $|    (local.set $i (i32.const 0))
    $|    (loop $loop
    $|      (local.set $i (i32.add (local.get $i) (i32.const 1)))
    $|      (br_if $loop (i32.lt_u (local.get $i) (local.get $n)))
    $|    )
    $|    (i32.store (i32.const 0) (local.get $i))
    $|  )
    $|)
  )
}

///|
fn wat_trap(pages : UInt64) -> String {
  (
    $|(module
    $|  (memory (import "env" "mem") \{pages} \{pages} shared)
    $|  (func (export "run")
    $|    unreachable
    $|  )
    $|)
  )
}

///|
fn exit_reason_to_string(reason : @thread_runtime.ExitReason) -> String {
  match reason {
    @thread_runtime.ExitReason::Normal => "normal"
    @thread_runtime.ExitReason::Timeout => "timeout"
    @thread_runtime.ExitReason::Trap(err) => "trap: \{err}"
  }
}

///|
fn print_usage() -> Unit {
  println(
    "Usage: moon run src/examples/thread_supervisor --target native -- [options]",
  )
  println("  --mode ok|restart|timeout|all (default: all)")
  println("  --timeout-n N           loop count for timeout example")
  println("  --timeout-iters N       try_join attempts before timeout")
  println("  --timeout-backoff N     spin iterations between polls")
  println("  --timeout-retry-iters N repoll attempts after timeout")
  println("  --timeout-retry-backoff N spin iterations between repolls")
  println("  --help                  show this help")
}

///|
fn parse_int_value(value : String, default : Int) -> Int {
  try @strconv.parse_int(value) catch {
    _ => default
  } noraise {
    v => v
  }
}

///|
fn arg_value(args : Array[String], flag : String) -> String? {
  let mut i = 1
  let len = args.length()
  while i < len {
    if args[i] == flag {
      if i + 1 < len {
        return Some(args[i + 1])
      } else {
        return None
      }
    }
    i = i + 1
  }
  None
}

///|
fn has_flag(args : Array[String], flag : String) -> Bool {
  for arg in args {
    if arg == flag {
      return true
    }
  }
  false
}

///|
fn parse_int_option(args : Array[String], flag : String, default : Int) -> Int {
  match arg_value(args, flag) {
    Some(value) => parse_int_value(value, default)
    None => default
  }
}

///|
enum ExampleMode {
  All
  Ok
  Restart
  Timeout
}

///|
fn parse_mode(value : String) -> ExampleMode? {
  match value {
    "all" => Some(ExampleMode::All)
    "ok" => Some(ExampleMode::Ok)
    "restart" => Some(ExampleMode::Restart)
    "timeout" => Some(ExampleMode::Timeout)
    _ => None
  }
}

///|
fn spin_backoff(iters : Int) -> Unit {
  if iters <= 0 {
    ()
  } else {
    for _ in 0..<iters {
      ()
    }
  }
}

///|
fn repoll_pending(
  pending : Array[@thread_runtime.PendingHandle],
  poll_iters : Int,
  poll_backoff : Int,
) -> Array[@thread_runtime.PendingHandle] {
  if pending.length() == 0 || poll_iters <= 0 {
    return pending
  }
  let mut remaining = pending
  let mut i = 0
  while i < poll_iters {
    if remaining.length() == 0 {
      return remaining
    }
    let next = Array::new()
    for item in remaining {
      match @thread_runtime.thread_runtime_try_join(item.handle) {
        Ok(true) => println("repoll done: \{item.id}")
        Ok(false) => next.push(item)
        Err(err) => println("repoll error: \{item.id} (\{err})")
      }
    }
    remaining = next
    spin_backoff(poll_backoff)
    i = i + 1
  }
  remaining
}

///|
fn detach_pending(pending : Array[@thread_runtime.PendingHandle]) -> Unit {
  for item in pending {
    match @thread_runtime.thread_runtime_detach(item.handle) {
      Ok(_) => println("detached: \{item.id}")
      Err(err) => println("detach failed: \{item.id} (\{err})")
    }
  }
}

///|
fn run_ok_example(rt : @thread_runtime.ThreadRuntime) -> Unit {
  let pages : UInt64 = 1
  let wat = wat_counter(pages)
  let args = make_i32_args(100_000)
  let handle = match
    @thread_runtime.thread_runtime_spawn_wat(rt, wat, "run", args) {
    Ok(h) => h
    Err(err) => {
      println("spawn failed: \{err}")
      return
    }
  }
  match @thread_runtime.thread_runtime_join(handle) {
    Ok(_) => ()
    Err(err) => {
      println("join failed: \{err}")
      return
    }
  }
  match @thread_runtime.thread_runtime_mem_read(rt, 0, 4) {
    Ok(bytes) => {
      let count = read_u32_le(bytes, 0)
      println("counter done: \{count}")
    }
    Err(err) => println("mem read failed: \{err}")
  }
}

///|
fn run_restart_example(rt : @thread_runtime.ThreadRuntime) -> Unit {
  let pages : UInt64 = 1
  let wat = wat_trap(pages)
  let args = @wasmtime.make_val_buffer(0)
  let child = @thread_runtime.child_wat(
    "trap_worker",
    wat,
    "run",
    args,
    restart=@thread_runtime.RestartPolicy::Transient,
  )
  let spec = @thread_runtime.supervisor_spec(
    strategy=@thread_runtime.RestartStrategy::OneForOne,
    max_restarts=2,
    poll_iters=-1,
  )
  let result = @thread_runtime.supervisor_run(rt, spec, [child])
  match result {
    Ok(@thread_runtime.SupervisorResult::RestartLimit(id, restarts, reason)) =>
      println(
        "restart limit: id=\{id} restarts=\{restarts} reason=\{exit_reason_to_string(reason)}",
      )
    Ok(@thread_runtime.SupervisorResult::Completed(restarts)) =>
      println("completed with restarts=\{restarts}")
    Ok(@thread_runtime.SupervisorResult::Timeout(_, pending)) => {
      println("unexpected timeout during restart example")
      detach_pending(pending)
    }
    Err(err) => println("supervisor error: \{err}")
  }
}

///|
fn run_timeout_example(
  rt : @thread_runtime.ThreadRuntime,
  n : Int,
  poll_iters : Int,
  poll_backoff : Int,
  retry_iters : Int,
  retry_backoff : Int,
) -> Unit {
  let pages : UInt64 = 1
  let wat = wat_counter(pages)
  let args = make_i32_args(n)
  let child = @thread_runtime.child_wat(
    "long_worker",
    wat,
    "run",
    args,
    restart=@thread_runtime.RestartPolicy::Temporary,
  )
  let spec = @thread_runtime.supervisor_spec(
    strategy=@thread_runtime.RestartStrategy::OneForOne,
    max_restarts=0,
    poll_iters~,
    poll_backoff_iters=poll_backoff,
  )
  let result = @thread_runtime.supervisor_run(rt, spec, [child])
  match result {
    Ok(@thread_runtime.SupervisorResult::Timeout(_, pending)) => {
      println("timeout: \{pending.length()} pending")
      let remaining = repoll_pending(pending, retry_iters, retry_backoff)
      if remaining.length() > 0 {
        println("detaching remaining: \{remaining.length()}")
        detach_pending(remaining)
      } else {
        println("all completed after repoll")
      }
    }
    Ok(@thread_runtime.SupervisorResult::Completed(restarts)) =>
      println("completed unexpectedly (restarts=\{restarts})")
    Ok(@thread_runtime.SupervisorResult::RestartLimit(id, restarts, reason)) =>
      println(
        "restart limit: id=\{id} restarts=\{restarts} reason=\{exit_reason_to_string(reason)}",
      )
    Err(err) => println("supervisor error: \{err}")
  }
}

///|
fn main {
  let args = @env.args()
  if has_flag(args, "--help") {
    print_usage()
    return
  }
  let mode = match arg_value(args, "--mode") {
    Some(value) =>
      match parse_mode(value) {
        Some(m) => m
        None => {
          println("unknown mode: \{value}")
          print_usage()
          return
        }
      }
    None => ExampleMode::All
  }
  let timeout_n = parse_int_option(args, "--timeout-n", 200_000_000)
  let timeout_iters = parse_int_option(args, "--timeout-iters", 10)
  let timeout_backoff = parse_int_option(args, "--timeout-backoff", 10_000)
  let timeout_retry_iters = parse_int_option(args, "--timeout-retry-iters", 200)
  let timeout_retry_backoff = parse_int_option(
    args, "--timeout-retry-backoff", timeout_backoff,
  )
  let rt = match @thread_runtime.thread_runtime_new(1) {
    Ok(v) => v
    Err(err) => {
      println("runtime init failed: \{err}")
      return
    }
  }
  if mode is ExampleMode::All || mode is ExampleMode::Ok {
    println("== ok example ==")
    run_ok_example(rt)
  }
  if mode is ExampleMode::All || mode is ExampleMode::Restart {
    println("== restart example ==")
    run_restart_example(rt)
  }
  if mode is ExampleMode::All || mode is ExampleMode::Timeout {
    println("== timeout example ==")
    run_timeout_example(
      rt, timeout_n, timeout_iters, timeout_backoff, timeout_retry_iters, timeout_retry_backoff,
    )
  }
  @thread_runtime.thread_runtime_delete(rt)
}
