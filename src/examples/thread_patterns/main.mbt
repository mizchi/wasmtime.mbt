fn make_i32_args(value : Int) -> Bytes {
  let args = @wasmtime.make_val_buffer(1)
  @wasmtime.val_buffer_set_i32(args, 0, value)
  args
}

///|
fn make_i32_args2(a : Int, b : Int) -> Bytes {
  let args = @wasmtime.make_val_buffer(2)
  @wasmtime.val_buffer_set_i32(args, 0, a)
  @wasmtime.val_buffer_set_i32(args, 1, b)
  args
}

///|
fn make_i32_args4(a : Int, b : Int, c : Int, d : Int) -> Bytes {
  let args = @wasmtime.make_val_buffer(4)
  @wasmtime.val_buffer_set_i32(args, 0, a)
  @wasmtime.val_buffer_set_i32(args, 1, b)
  @wasmtime.val_buffer_set_i32(args, 2, c)
  @wasmtime.val_buffer_set_i32(args, 3, d)
  args
}

///|
suberror ExampleError {
  ExampleError(String)
}

///|
fn print_usage() -> Unit {
  println(
    (
      #|Usage: thread_patterns [--mode <mode>] [--threads <n>] [--iters <n>] [--slots <n>] [--spin <n>] [--wait-ns <n>]
      #|
      #|  mode: all | atomic | slots | pingpong | work | barrier | fanin | workqueue | reduce | broadcast | mapreduce | ring | ring-mpmc
      #|  threads: used by atomic/slots/work/barrier/fanin/workqueue/reduce/broadcast/mapreduce/ring-mpmc (default 4)
      #|  iters: iterations per thread (default 10000)
      #|  slots: ring queue capacity (default 64)
      #|  spin: ring-mpmc spin limit before wait (default 1000)
      #|  wait-ns: ring-mpmc wait timeout in ns (default 1000000)
      #|
    ),
  )
}

///|
fn arg_value(args : Array[String], flag : String) -> String? {
  let len = args.length()
  for i in 0..<len {
    if args[i] == flag && i + 1 < len {
      return Some(args[i + 1])
    }
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
fn parse_int_value(value : String, default_value : Int) -> Int {
  try @strconv.parse_int(value) catch {
    _ => default_value
  } noraise {
    v => v
  }
}

///|
fn parse_int_option(
  args : Array[String],
  flag : String,
  default_value : Int,
) -> Int {
  match arg_value(args, flag) {
    Some(value) => parse_int_value(value, default_value)
    None => default_value
  }
}

///|
enum ExampleMode {
  All
  AtomicCounter
  Slots
  PingPong
  WorkSteal
  Barrier
  FanIn
  WorkQueue
  Reduce
  Broadcast
  MapReduce
  RingQueue
  RingQueueMPMC
}

///|
fn parse_mode(value : String) -> ExampleMode? {
  match value {
    "all" => Some(ExampleMode::All)
    "atomic" => Some(ExampleMode::AtomicCounter)
    "slots" => Some(ExampleMode::Slots)
    "pingpong" => Some(ExampleMode::PingPong)
    "work" => Some(ExampleMode::WorkSteal)
    "barrier" => Some(ExampleMode::Barrier)
    "fanin" => Some(ExampleMode::FanIn)
    "workqueue" => Some(ExampleMode::WorkQueue)
    "reduce" => Some(ExampleMode::Reduce)
    "broadcast" => Some(ExampleMode::Broadcast)
    "mapreduce" => Some(ExampleMode::MapReduce)
    "ring" => Some(ExampleMode::RingQueue)
    "ring-mpmc" => Some(ExampleMode::RingQueueMPMC)
    _ => None
  }
}

///|
fn clamp_positive(value : Int, default_value : Int) -> Int {
  if value <= 0 {
    default_value
  } else {
    value
  }
}

///|
fn round_up_pow2(value : Int) -> Int {
  if value <= 1 {
    1
  } else {
    let mut v = value - 1
    v = v | (v >> 1)
    v = v | (v >> 2)
    v = v | (v >> 4)
    v = v | (v >> 8)
    v = v | (v >> 16)
    v + 1
  }
}

///|
fn[T] with_runtime(
  pages : UInt64,
  f : (@thread_runtime.ThreadRuntime) -> Result[T, Error],
) -> Result[T, Error] {
  let runtime_result = @thread_runtime.thread_runtime_new(pages.to_int())
  guard runtime_result is Ok(rt) else {
    return Err(runtime_result.unwrap_err())
  }
  let result = f(rt)
  @thread_runtime.thread_runtime_delete(rt)
  result
}

///|
fn run_atomic_counter(threads : Int, iters : Int) -> Result[Unit, Error] {
  let pages = @thread_runtime.shared_pages_for_bytes(4UL)
  let wat = @wasm_threads_patterns.wat_atomic_counter(pages)
  with_runtime(pages, rt => {
    let args = make_i32_args(iters)
    let handles : Array[@thread_runtime.ThreadHandle] = []
    for _ in 0..<threads {
      let spawn_result = @thread_runtime.thread_runtime_spawn_wat(
        rt,
        wat,
        "run",
        args,
      )
      guard spawn_result is Ok(handle) else {
        return Err(spawn_result.unwrap_err())
      }
      handles.push(handle)
    }
    for handle in handles {
      let join_result = @thread_runtime.thread_runtime_join(handle)
      guard join_result is Ok(_) else {
        return Err(join_result.unwrap_err())
      }
    }
    let bytes_result = @thread_runtime.thread_runtime_mem_read(rt, 0, 4)
    guard bytes_result is Ok(bytes) else {
      return Err(bytes_result.unwrap_err())
    }
    let count = @thread_runtime.read_u32_le(bytes, 0).to_int()
    let expected = threads * iters
    if count == expected {
      Ok(())
    } else {
      Err(
        ExampleError::ExampleError(
          "atomic counter mismatch: got=\{count} expected=\{expected}",
        ),
      )
    }
  })
}

///|
fn run_slots(threads : Int) -> Result[Unit, Error] {
  let bytes = (threads * 4).to_uint64()
  let pages = @thread_runtime.shared_pages_for_bytes(bytes)
  let wat = @wasm_threads_patterns.wat_slots(pages)
  with_runtime(pages, rt => {
    let handles : Array[@thread_runtime.ThreadHandle] = []
    for i in 0..<threads {
      let args = make_i32_args2(i, i + 1)
      let spawn_result = @thread_runtime.thread_runtime_spawn_wat(
        rt,
        wat,
        "run",
        args,
      )
      guard spawn_result is Ok(handle) else {
        return Err(spawn_result.unwrap_err())
      }
      handles.push(handle)
    }
    for handle in handles {
      let join_result = @thread_runtime.thread_runtime_join(handle)
      guard join_result is Ok(_) else {
        return Err(join_result.unwrap_err())
      }
    }
    let len = threads * 4
    let data_result = @thread_runtime.thread_runtime_mem_read(rt, 0, len)
    guard data_result is Ok(data) else {
      return Err(data_result.unwrap_err())
    }
    let mut sum : Int = 0
    for i in 0..<threads {
      let value = @thread_runtime.read_u32_le(data, i * 4).to_int()
      sum = sum + value
    }
    let expected = threads * (threads + 1) / 2
    if sum == expected {
      Ok(())
    } else {
      Err(
        ExampleError::ExampleError(
          "slot sum mismatch: got=\{sum} expected=\{expected}",
        ),
      )
    }
  })
}

///|
fn run_ping_pong(iters : Int) -> Result[Unit, Error] {
  let pages = @thread_runtime.shared_pages_for_bytes(12UL)
  let wat = @wasm_threads_patterns.wat_ping_pong(pages)
  with_runtime(pages, rt => {
    let args = make_i32_args(iters)
    let ping_result = @thread_runtime.thread_runtime_spawn_wat(
      rt,
      wat,
      "ping",
      args,
    )
    guard ping_result is Ok(ping) else {
      return Err(ping_result.unwrap_err())
    }
    let pong_result = @thread_runtime.thread_runtime_spawn_wat(
      rt,
      wat,
      "pong",
      args,
    )
    guard pong_result is Ok(pong) else {
      return Err(pong_result.unwrap_err())
    }
    let join_ping = @thread_runtime.thread_runtime_join(ping)
    guard join_ping is Ok(_) else {
      return Err(join_ping.unwrap_err())
    }
    let join_pong = @thread_runtime.thread_runtime_join(pong)
    guard join_pong is Ok(_) else {
      return Err(join_pong.unwrap_err())
    }
    let bytes_result = @thread_runtime.thread_runtime_mem_read(rt, 0, 12)
    guard bytes_result is Ok(bytes) else {
      return Err(bytes_result.unwrap_err())
    }
    let state = @thread_runtime.read_u32_le(bytes, 0).to_int()
    let ping_count = @thread_runtime.read_u32_le(bytes, 4).to_int()
    let pong_count = @thread_runtime.read_u32_le(bytes, 8).to_int()
    if state == 0 && ping_count == iters && pong_count == iters {
      Ok(())
    } else {
      Err(
        ExampleError::ExampleError(
          "pingpong mismatch: state=\{state} ping=\{ping_count} pong=\{pong_count} iters=\{iters}",
        ),
      )
    }
  })
}

///|
fn run_work_steal(threads : Int, iters : Int) -> Result[Unit, Error] {
  let pages = @thread_runtime.shared_pages_for_bytes(8UL)
  let wat = @wasm_threads_patterns.wat_work_steal(pages)
  with_runtime(pages, rt => {
    let args = make_i32_args(iters)
    let handles : Array[@thread_runtime.ThreadHandle] = []
    for _ in 0..<threads {
      let spawn_result = @thread_runtime.thread_runtime_spawn_wat(
        rt,
        wat,
        "run",
        args,
      )
      guard spawn_result is Ok(handle) else {
        return Err(spawn_result.unwrap_err())
      }
      handles.push(handle)
    }
    for handle in handles {
      let join_result = @thread_runtime.thread_runtime_join(handle)
      guard join_result is Ok(_) else {
        return Err(join_result.unwrap_err())
      }
    }
    let bytes_result = @thread_runtime.thread_runtime_mem_read(rt, 4, 4)
    guard bytes_result is Ok(bytes) else {
      return Err(bytes_result.unwrap_err())
    }
    let sum = @thread_runtime.read_u32_le(bytes, 0).to_int()
    let expected = iters * (iters + 1) / 2
    if sum == expected {
      Ok(())
    } else {
      Err(
        ExampleError::ExampleError(
          "work sum mismatch: got=\{sum} expected=\{expected}",
        ),
      )
    }
  })
}

///|
fn run_barrier(threads : Int) -> Result[Unit, Error] {
  let pages = @thread_runtime.shared_pages_for_bytes(12UL)
  let wat = @wasm_threads_patterns.wat_barrier(pages)
  with_runtime(pages, rt => {
    let args = make_i32_args(threads)
    let handles : Array[@thread_runtime.ThreadHandle] = []
    for _ in 0..<threads {
      let spawn_result = @thread_runtime.thread_runtime_spawn_wat(
        rt,
        wat,
        "run",
        args,
      )
      guard spawn_result is Ok(handle) else {
        return Err(spawn_result.unwrap_err())
      }
      handles.push(handle)
    }
    for handle in handles {
      let join_result = @thread_runtime.thread_runtime_join(handle)
      guard join_result is Ok(_) else {
        return Err(join_result.unwrap_err())
      }
    }
    let bytes_result = @thread_runtime.thread_runtime_mem_read(rt, 8, 4)
    guard bytes_result is Ok(bytes) else {
      return Err(bytes_result.unwrap_err())
    }
    let done = @thread_runtime.read_u32_le(bytes, 0).to_int()
    if done == threads {
      Ok(())
    } else {
      Err(
        ExampleError::ExampleError(
          "barrier done mismatch: got=\{done} expected=\{threads}",
        ),
      )
    }
  })
}

///|
fn run_fan_in(threads : Int) -> Result[Unit, Error] {
  let bytes = (32 + threads * 4).to_uint64()
  let pages = @thread_runtime.shared_pages_for_bytes(bytes)
  let wat = @wasm_threads_patterns.wat_fan_in(pages)
  with_runtime(pages, rt => {
    let agg_args = make_i32_args(threads)
    let aggregate_result = @thread_runtime.thread_runtime_spawn_wat(
      rt,
      wat,
      "aggregate",
      agg_args,
    )
    guard aggregate_result is Ok(aggregate) else {
      return Err(aggregate_result.unwrap_err())
    }
    let handles : Array[@thread_runtime.ThreadHandle] = []
    for i in 0..<threads {
      let args = make_i32_args2(i, i + 1)
      let spawn_result = @thread_runtime.thread_runtime_spawn_wat(
        rt,
        wat,
        "worker",
        args,
      )
      guard spawn_result is Ok(handle) else {
        return Err(spawn_result.unwrap_err())
      }
      handles.push(handle)
    }
    for handle in handles {
      let join_result = @thread_runtime.thread_runtime_join(handle)
      guard join_result is Ok(_) else {
        return Err(join_result.unwrap_err())
      }
    }
    let join_aggregate = @thread_runtime.thread_runtime_join(aggregate)
    guard join_aggregate is Ok(_) else {
      return Err(join_aggregate.unwrap_err())
    }
    let bytes_result = @thread_runtime.thread_runtime_mem_read(rt, 4, 4)
    guard bytes_result is Ok(bytes) else {
      return Err(bytes_result.unwrap_err())
    }
    let sum = @thread_runtime.read_u32_le(bytes, 0).to_int()
    let expected = threads * (threads + 1) / 2
    if sum == expected {
      Ok(())
    } else {
      Err(
        ExampleError::ExampleError(
          "fanin sum mismatch: got=\{sum} expected=\{expected}",
        ),
      )
    }
  })
}

///|
fn run_work_queue(threads : Int, iters : Int) -> Result[Unit, Error] {
  let bytes = (32 + iters * 4).to_uint64()
  let pages = @thread_runtime.shared_pages_for_bytes(bytes)
  let wat = @wasm_threads_patterns.wat_work_queue(pages)
  with_runtime(pages, rt => {
    let prod_args = make_i32_args(iters)
    let producer_result = @thread_runtime.thread_runtime_spawn_wat(
      rt,
      wat,
      "produce",
      prod_args,
    )
    guard producer_result is Ok(producer) else {
      return Err(producer_result.unwrap_err())
    }
    let cons_args = make_i32_args(iters)
    let handles : Array[@thread_runtime.ThreadHandle] = []
    for _ in 0..<threads {
      let spawn_result = @thread_runtime.thread_runtime_spawn_wat(
        rt,
        wat,
        "consume",
        cons_args,
      )
      guard spawn_result is Ok(handle) else {
        return Err(spawn_result.unwrap_err())
      }
      handles.push(handle)
    }
    for handle in handles {
      let join_result = @thread_runtime.thread_runtime_join(handle)
      guard join_result is Ok(_) else {
        return Err(join_result.unwrap_err())
      }
    }
    let join_producer = @thread_runtime.thread_runtime_join(producer)
    guard join_producer is Ok(_) else {
      return Err(join_producer.unwrap_err())
    }
    let bytes_result = @thread_runtime.thread_runtime_mem_read(rt, 4, 4)
    guard bytes_result is Ok(bytes) else {
      return Err(bytes_result.unwrap_err())
    }
    let sum = @thread_runtime.read_u32_le(bytes, 0).to_int()
    let expected = iters * (iters + 1) / 2
    if sum == expected {
      Ok(())
    } else {
      Err(
        ExampleError::ExampleError(
          "workqueue sum mismatch: got=\{sum} expected=\{expected}",
        ),
      )
    }
  })
}

///|
fn run_reduce(threads : Int) -> Result[Unit, Error] {
  let pages = @thread_runtime.shared_pages_for_bytes(12UL)
  let wat = @wasm_threads_patterns.wat_reduce(pages)
  with_runtime(pages, rt => {
    let await_args = make_i32_args(threads)
    let awaiter_result = @thread_runtime.thread_runtime_spawn_wat(
      rt,
      wat,
      "await",
      await_args,
    )
    guard awaiter_result is Ok(awaiter) else {
      return Err(awaiter_result.unwrap_err())
    }
    let handles : Array[@thread_runtime.ThreadHandle] = []
    for i in 0..<threads {
      let args = make_i32_args2(i + 1, threads)
      let spawn_result = @thread_runtime.thread_runtime_spawn_wat(
        rt,
        wat,
        "reduce",
        args,
      )
      guard spawn_result is Ok(handle) else {
        return Err(spawn_result.unwrap_err())
      }
      handles.push(handle)
    }
    for handle in handles {
      let join_result = @thread_runtime.thread_runtime_join(handle)
      guard join_result is Ok(_) else {
        return Err(join_result.unwrap_err())
      }
    }
    let join_awaiter = @thread_runtime.thread_runtime_join(awaiter)
    guard join_awaiter is Ok(_) else {
      return Err(join_awaiter.unwrap_err())
    }
    let bytes_result = @thread_runtime.thread_runtime_mem_read(rt, 8, 4)
    guard bytes_result is Ok(bytes) else {
      return Err(bytes_result.unwrap_err())
    }
    let sum = @thread_runtime.read_u32_le(bytes, 0).to_int()
    let expected = threads * (threads + 1) / 2
    if sum == expected {
      Ok(())
    } else {
      Err(
        ExampleError::ExampleError(
          "reduce sum mismatch: got=\{sum} expected=\{expected}",
        ),
      )
    }
  })
}

///|
fn run_broadcast(threads : Int, value : Int) -> Result[Unit, Error] {
  let bytes = (32 + threads * 4).to_uint64()
  let pages = @thread_runtime.shared_pages_for_bytes(bytes)
  let wat = @wasm_threads_patterns.wat_broadcast(pages)
  with_runtime(pages, rt => {
    let bcast_args = make_i32_args2(value, threads)
    let broadcaster_result = @thread_runtime.thread_runtime_spawn_wat(
      rt,
      wat,
      "broadcast",
      bcast_args,
    )
    guard broadcaster_result is Ok(broadcaster) else {
      return Err(broadcaster_result.unwrap_err())
    }
    let handles : Array[@thread_runtime.ThreadHandle] = []
    for i in 0..<threads {
      let args = make_i32_args(i)
      let spawn_result = @thread_runtime.thread_runtime_spawn_wat(
        rt,
        wat,
        "receive",
        args,
      )
      guard spawn_result is Ok(handle) else {
        return Err(spawn_result.unwrap_err())
      }
      handles.push(handle)
    }
    for handle in handles {
      let join_result = @thread_runtime.thread_runtime_join(handle)
      guard join_result is Ok(_) else {
        return Err(join_result.unwrap_err())
      }
    }
    let join_broadcaster = @thread_runtime.thread_runtime_join(broadcaster)
    guard join_broadcaster is Ok(_) else {
      return Err(join_broadcaster.unwrap_err())
    }
    let expected = threads * value
    let slot_len = threads * 4
    let data_result = @thread_runtime.thread_runtime_mem_read(rt, 32, slot_len)
    guard data_result is Ok(data) else {
      return Err(data_result.unwrap_err())
    }
    let mut sum : Int = 0
    for i in 0..<threads {
      let v = @thread_runtime.read_u32_le(data, i * 4).to_int()
      sum = sum + v
    }
    if sum == expected {
      Ok(())
    } else {
      Err(
        ExampleError::ExampleError(
          "broadcast sum mismatch: got=\{sum} expected=\{expected}",
        ),
      )
    }
  })
}

///|
fn run_map_reduce(threads : Int) -> Result[Unit, Error] {
  let bytes = (32 + threads * 4).to_uint64()
  let pages = @thread_runtime.shared_pages_for_bytes(bytes)
  let wat = @wasm_threads_patterns.wat_map_reduce(pages)
  with_runtime(pages, rt => {
    let reduce_args = make_i32_args(threads)
    let reducer_result = @thread_runtime.thread_runtime_spawn_wat(
      rt,
      wat,
      "reduce",
      reduce_args,
    )
    guard reducer_result is Ok(reducer) else {
      return Err(reducer_result.unwrap_err())
    }
    let handles : Array[@thread_runtime.ThreadHandle] = []
    for i in 0..<threads {
      let args = make_i32_args(i)
      let spawn_result = @thread_runtime.thread_runtime_spawn_wat(
        rt,
        wat,
        "map",
        args,
      )
      guard spawn_result is Ok(handle) else {
        return Err(spawn_result.unwrap_err())
      }
      handles.push(handle)
    }
    for handle in handles {
      let join_result = @thread_runtime.thread_runtime_join(handle)
      guard join_result is Ok(_) else {
        return Err(join_result.unwrap_err())
      }
    }
    let join_reducer = @thread_runtime.thread_runtime_join(reducer)
    guard join_reducer is Ok(_) else {
      return Err(join_reducer.unwrap_err())
    }
    let bytes_result = @thread_runtime.thread_runtime_mem_read(rt, 4, 4)
    guard bytes_result is Ok(bytes) else {
      return Err(bytes_result.unwrap_err())
    }
    let sum = @thread_runtime.read_u32_le(bytes, 0).to_int()
    let t = threads
    let expected = t * (t + 1) * (2 * t + 1) / 6
    if sum == expected {
      Ok(())
    } else {
      Err(
        ExampleError::ExampleError(
          "mapreduce sum mismatch: got=\{sum} expected=\{expected}",
        ),
      )
    }
  })
}

///|
fn run_ring_queue(slots : Int, iters : Int) -> Result[Unit, Error] {
  let capacity = round_up_pow2(slots)
  let mask = capacity - 1
  let bytes = (32 + capacity * 4).to_uint64()
  let pages = @thread_runtime.shared_pages_for_bytes(bytes)
  let wat = @wasm_threads_patterns.wat_ring_queue(pages)
  with_runtime(pages, rt => {
    let args = make_i32_args2(iters, mask)
    let producer_result = @thread_runtime.thread_runtime_spawn_wat(
      rt,
      wat,
      "produce",
      args,
    )
    guard producer_result is Ok(producer) else {
      return Err(producer_result.unwrap_err())
    }
    let consumer_result = @thread_runtime.thread_runtime_spawn_wat(
      rt,
      wat,
      "consume",
      args,
    )
    guard consumer_result is Ok(consumer) else {
      return Err(consumer_result.unwrap_err())
    }
    let join_producer = @thread_runtime.thread_runtime_join(producer)
    guard join_producer is Ok(_) else {
      return Err(join_producer.unwrap_err())
    }
    let join_consumer = @thread_runtime.thread_runtime_join(consumer)
    guard join_consumer is Ok(_) else {
      return Err(join_consumer.unwrap_err())
    }
    let bytes_result = @thread_runtime.thread_runtime_mem_read(rt, 8, 8)
    guard bytes_result is Ok(bytes) else {
      return Err(bytes_result.unwrap_err())
    }
    let sum = @thread_runtime.read_u64_le(bytes, 0)
    let iters_u = iters.to_uint64()
    let expected = iters_u * (iters_u + 1) / 2
    if sum == expected {
      Ok(())
    } else {
      Err(
        ExampleError::ExampleError(
          "ring sum mismatch: got=\\{sum} expected=\\{expected}",
        ),
      )
    }
  })
}

///|
fn run_ring_queue_mpmc(
  threads : Int,
  slots : Int,
  iters : Int,
  spin_limit : Int,
  wait_timeout_ns : Int,
) -> Result[Unit, Error] {
  let capacity = round_up_pow2(slots)
  let mask = capacity - 1
  let bytes = (32 + capacity * 8).to_uint64()
  let pages = @thread_runtime.shared_pages_for_bytes(bytes)
  let wat = @wasm_threads_patterns.wat_ring_queue_mpmc(pages)
  with_runtime(pages, rt => {
    let init_len = capacity * 8
    let init_bytes = Bytes::makei(init_len, i => {
      let cell = i / 8
      let offset = i % 8
      if offset < 4 {
        ((cell >> (offset * 8)) & 0xff).to_byte()
      } else {
        (0).to_byte()
      }
    })
    let write_result = @thread_runtime.thread_runtime_mem_write(
      rt,
      32,
      init_bytes,
    )
    guard write_result is Ok(_) else {
      return Err(write_result.unwrap_err())
    }
    let args = make_i32_args4(iters, mask, spin_limit, wait_timeout_ns)
    let prod_handles : Array[@thread_runtime.ThreadHandle] = []
    let cons_handles : Array[@thread_runtime.ThreadHandle] = []
    for _ in 0..<threads {
      let prod_result = @thread_runtime.thread_runtime_spawn_wat(
        rt,
        wat,
        "produce",
        args,
      )
      guard prod_result is Ok(prod_handle) else {
        return Err(prod_result.unwrap_err())
      }
      prod_handles.push(prod_handle)
      let cons_result = @thread_runtime.thread_runtime_spawn_wat(
        rt,
        wat,
        "consume",
        args,
      )
      guard cons_result is Ok(cons_handle) else {
        return Err(cons_result.unwrap_err())
      }
      cons_handles.push(cons_handle)
    }
    for handle in prod_handles {
      let join_result = @thread_runtime.thread_runtime_join(handle)
      guard join_result is Ok(_) else {
        return Err(join_result.unwrap_err())
      }
    }
    for handle in cons_handles {
      let join_result = @thread_runtime.thread_runtime_join(handle)
      guard join_result is Ok(_) else {
        return Err(join_result.unwrap_err())
      }
    }
    let bytes_result = @thread_runtime.thread_runtime_mem_read(rt, 16, 8)
    guard bytes_result is Ok(bytes) else {
      return Err(bytes_result.unwrap_err())
    }
    let sum = @thread_runtime.read_u64_le(bytes, 0)
    let total = (iters * threads).to_uint64()
    let expected = total * (total + 1) / 2
    if sum == expected {
      Ok(())
    } else {
      Err(
        ExampleError::ExampleError(
          "ring-mpmc sum mismatch: got=\\{sum} expected=\\{expected}",
        ),
      )
    }
  })
}

///|
fn run_and_report(label : String, result : Result[Unit, Error]) -> Bool {
  match result {
    Ok(_) => {
      println("ok: \{label}")
      true
    }
    Err(err) => {
      println("error: \{label}: \{err}")
      false
    }
  }
}

///|
fn run_all(
  threads : Int,
  iters : Int,
  slots : Int,
  spin_limit : Int,
  wait_timeout_ns : Int,
) -> Bool {
  let ok_atomic = run_and_report("atomic", run_atomic_counter(threads, iters))
  let ok_slots = run_and_report("slots", run_slots(threads))
  let ok_pingpong = run_and_report("pingpong", run_ping_pong(iters))
  let ok_work = run_and_report("work", run_work_steal(threads, iters))
  let ok_barrier = run_and_report("barrier", run_barrier(threads))
  let ok_fanin = run_and_report("fanin", run_fan_in(threads))
  let ok_workqueue = run_and_report("workqueue", run_work_queue(threads, iters))
  let ok_reduce = run_and_report("reduce", run_reduce(threads))
  let ok_broadcast = run_and_report("broadcast", run_broadcast(threads, 7))
  let ok_mapreduce = run_and_report("mapreduce", run_map_reduce(threads))
  let ok_ring = run_and_report("ring", run_ring_queue(slots, iters))
  let ok_ring_mpmc = run_and_report(
    "ring-mpmc",
    run_ring_queue_mpmc(threads, slots, iters, spin_limit, wait_timeout_ns),
  )
  let all_ok = ok_atomic &&
    ok_slots &&
    ok_pingpong &&
    ok_work &&
    ok_barrier &&
    ok_fanin &&
    ok_workqueue &&
    ok_reduce &&
    ok_broadcast &&
    ok_mapreduce &&
    ok_ring &&
    ok_ring_mpmc
  all_ok
}

///|
fn main {
  let args = @env.args()
  if has_flag(args, "--help") {
    print_usage()
    return
  }
  let threads = clamp_positive(parse_int_option(args, "--threads", 4), 4)
  let iters = clamp_positive(parse_int_option(args, "--iters", 10000), 10000)
  let slots = clamp_positive(parse_int_option(args, "--slots", 64), 64)
  let spin_limit = clamp_positive(parse_int_option(args, "--spin", 1000), 1000)
  let wait_timeout_ns = clamp_positive(
    parse_int_option(args, "--wait-ns", 1000000),
    1000000,
  )
  let mode = match arg_value(args, "--mode") {
    Some(value) => parse_mode(value)
    None => Some(ExampleMode::All)
  }
  match mode {
    Some(ExampleMode::All) => {
      let ok = run_all(threads, iters, slots, spin_limit, wait_timeout_ns)
      if !ok {
        println("thread patterns failed")
      }
    }
    Some(ExampleMode::AtomicCounter) =>
      if !run_and_report("atomic", run_atomic_counter(threads, iters)) {
        println("atomic counter failed")
      }
    Some(ExampleMode::Slots) =>
      if !run_and_report("slots", run_slots(threads)) {
        println("slots failed")
      }
    Some(ExampleMode::PingPong) =>
      if !run_and_report("pingpong", run_ping_pong(iters)) {
        println("pingpong failed")
      }
    Some(ExampleMode::WorkSteal) =>
      if !run_and_report("work", run_work_steal(threads, iters)) {
        println("work failed")
      }
    Some(ExampleMode::Barrier) =>
      if !run_and_report("barrier", run_barrier(threads)) {
        println("barrier failed")
      }
    Some(ExampleMode::FanIn) =>
      if !run_and_report("fanin", run_fan_in(threads)) {
        println("fanin failed")
      }
    Some(ExampleMode::WorkQueue) =>
      if !run_and_report("workqueue", run_work_queue(threads, iters)) {
        println("workqueue failed")
      }
    Some(ExampleMode::Reduce) =>
      if !run_and_report("reduce", run_reduce(threads)) {
        println("reduce failed")
      }
    Some(ExampleMode::Broadcast) =>
      if !run_and_report("broadcast", run_broadcast(threads, 7)) {
        println("broadcast failed")
      }
    Some(ExampleMode::MapReduce) =>
      if !run_and_report("mapreduce", run_map_reduce(threads)) {
        println("mapreduce failed")
      }
    Some(ExampleMode::RingQueue) =>
      if !run_and_report("ring", run_ring_queue(slots, iters)) {
        println("ring failed")
      }
    Some(ExampleMode::RingQueueMPMC) =>
      if !run_and_report(
          "ring-mpmc",
          run_ring_queue_mpmc(
            threads, slots, iters, spin_limit, wait_timeout_ns,
          ),
        ) {
        println("ring-mpmc failed")
      }
    None => {
      print_usage()
      println("unknown mode")
    }
  }
}
