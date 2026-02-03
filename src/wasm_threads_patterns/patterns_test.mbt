///|
test "wat_atomic_counter shape" {
  let wat = @wasm_threads_patterns.wat_atomic_counter(1UL)
  assert_true(wat.contains("shared"))
  assert_true(wat.contains("(export \"run\")"))
  assert_true(wat.contains("i32.atomic.rmw.add"))
}

///|
test "wat_ping_pong shape" {
  let wat = @wasm_threads_patterns.wat_ping_pong(1UL)
  assert_true(wat.contains("(export \"ping\")"))
  assert_true(wat.contains("(export \"pong\")"))
  assert_true(wat.contains("memory.atomic.wait32"))
}

///|
test "wat_ring_queues shape" {
  let spsc = @wasm_threads_patterns.wat_ring_queue(1UL)
  assert_true(spsc.contains("(export \"produce\")"))
  assert_true(spsc.contains("(export \"consume\")"))
  assert_true(spsc.contains("i64.store"))
  let mpmc = @wasm_threads_patterns.wat_ring_queue_mpmc(1UL)
  assert_true(mpmc.contains("(export \"produce\")"))
  assert_true(mpmc.contains("(export \"consume\")"))
  assert_true(mpmc.contains("i64.atomic.rmw.add"))
  assert_true(mpmc.contains("memory.atomic.wait32"))
}

///|
test "wat_reduce_broadcast_mapreduce shape" {
  let reduce = @wasm_threads_patterns.wat_reduce(1UL)
  assert_true(reduce.contains("(export \"reduce\")"))
  assert_true(reduce.contains("(export \"await\")"))
  let broadcast = @wasm_threads_patterns.wat_broadcast(1UL)
  assert_true(broadcast.contains("(export \"broadcast\")"))
  assert_true(broadcast.contains("(export \"receive\")"))
  let mapreduce = @wasm_threads_patterns.wat_map_reduce(1UL)
  assert_true(mapreduce.contains("(export \"map\")"))
  assert_true(mapreduce.contains("(export \"reduce\")"))
}
