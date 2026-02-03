///|
fn read_u32_le(bytes : Bytes, offset : Int) -> UInt64 {
  let b0 = bytes[offset].to_uint64()
  let b1 = bytes[offset + 1].to_uint64()
  let b2 = bytes[offset + 2].to_uint64()
  let b3 = bytes[offset + 3].to_uint64()
  b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
}

///|
fn read_u64_le(bytes : Bytes, offset : Int) -> UInt64 {
  let b0 = bytes[offset].to_uint64()
  let b1 = bytes[offset + 1].to_uint64()
  let b2 = bytes[offset + 2].to_uint64()
  let b3 = bytes[offset + 3].to_uint64()
  let b4 = bytes[offset + 4].to_uint64()
  let b5 = bytes[offset + 5].to_uint64()
  let b6 = bytes[offset + 6].to_uint64()
  let b7 = bytes[offset + 7].to_uint64()
  b0 |
  (b1 << 8) |
  (b2 << 16) |
  (b3 << 24) |
  (b4 << 32) |
  (b5 << 40) |
  (b6 << 48) |
  (b7 << 56)
}

///|
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
fn wat_atomic_counter(pages : UInt64) -> String {
  (
    $|(module
    $|  (memory (import "env" "mem") \{pages} \{pages} shared)
    $|  (func (export "run") (param $iters i32)
    $|    (local $i i32)
    $|    (local.set $i (i32.const 0))
    $|    (loop $loop
    $|      (drop (i32.atomic.rmw.add (i32.const 0) (i32.const 1)))
    $|      (local.set $i (i32.add (local.get $i) (i32.const 1)))
    $|      (br_if $loop (i32.lt_u (local.get $i) (local.get $iters)))
    $|    )
    $|  )
    $|)
  )
}

///|
fn wat_slots(pages : UInt64) -> String {
  (
    $|(module
    $|  (memory (import "env" "mem") \{pages} \{pages} shared)
    $|  (func (export "run") (param $slot i32) (param $value i32)
    $|    (i32.store
    $|      (i32.shl (local.get $slot) (i32.const 2))
    $|      (local.get $value)
    $|    )
    $|  )
    $|)
  )
}

///|
fn wat_ping_pong(pages : UInt64) -> String {
  (
    $|(module
    $|  (memory (import "env" "mem") \{pages} \{pages} shared)
    $|  (func $wait_for (param $expected i32) (param $wait i32)
    $|    (block $ready
    $|      (loop $loop
    $|        (br_if $ready
    $|          (i32.eq (i32.atomic.load (i32.const 0)) (local.get $expected))
    $|        )
    $|        (drop (memory.atomic.wait32 (i32.const 0) (local.get $wait) (i64.const 1000000)))
    $|        (br $loop)
    $|      )
    $|    )
    $|  )
    $|  (func (export "ping") (param $iters i32)
    $|    (local $i i32)
    $|    (local.set $i (i32.const 0))
    $|    (loop $loop
    $|      (call $wait_for (i32.const 0) (i32.const 1))
    $|      (i32.store (i32.const 0) (i32.const 1))
    $|      (drop (memory.atomic.notify (i32.const 0) (i32.const 1)))
    $|      (drop (i32.atomic.rmw.add (i32.const 4) (i32.const 1)))
    $|      (local.set $i (i32.add (local.get $i) (i32.const 1)))
    $|      (br_if $loop (i32.lt_u (local.get $i) (local.get $iters)))
    $|    )
    $|  )
    $|  (func (export "pong") (param $iters i32)
    $|    (local $i i32)
    $|    (local.set $i (i32.const 0))
    $|    (loop $loop
    $|      (call $wait_for (i32.const 1) (i32.const 0))
    $|      (i32.store (i32.const 0) (i32.const 0))
    $|      (drop (memory.atomic.notify (i32.const 0) (i32.const 1)))
    $|      (drop (i32.atomic.rmw.add (i32.const 8) (i32.const 1)))
    $|      (local.set $i (i32.add (local.get $i) (i32.const 1)))
    $|      (br_if $loop (i32.lt_u (local.get $i) (local.get $iters)))
    $|    )
    $|  )
    $|)
  )
}

///|
fn wat_work_steal(pages : UInt64) -> String {
  (
    $|(module
    $|  (memory (import "env" "mem") \{pages} \{pages} shared)
    $|  (func (export "run") (param $iters i32)
    $|    (local $i i32)
    $|    (block $done
    $|      (loop $loop
    $|        (local.set $i (i32.atomic.rmw.add (i32.const 0) (i32.const 1)))
    $|        (br_if $done (i32.ge_u (local.get $i) (local.get $iters)))
    $|        (drop (i32.atomic.rmw.add (i32.const 4) (i32.add (local.get $i) (i32.const 1))))
    $|        (br $loop)
    $|      )
    $|    )
    $|  )
    $|)
  )
}

///|
fn wat_barrier(pages : UInt64) -> String {
  (
    $|(module
    $|  (memory (import "env" "mem") \{pages} \{pages} shared)
    $|  (func (export "run") (param $threads i32)
    $|    (local $arrive i32) (local $is_last i32)
    $|    (local.set $arrive (i32.atomic.rmw.add (i32.const 0) (i32.const 1)))
    $|    (local.set $is_last
    $|      (i32.eq
    $|        (i32.add (local.get $arrive) (i32.const 1))
    $|        (local.get $threads)
    $|      )
    $|    )
    $|    (if (local.get $is_last)
    $|      (then
    $|        (i32.store (i32.const 4) (i32.const 1))
    $|        (drop (memory.atomic.notify (i32.const 4) (i32.const 2147483647)))
    $|      )
    $|    )
    $|    (block $ready
    $|      (loop $wait
    $|        (br_if $ready (i32.eq (i32.atomic.load (i32.const 4)) (i32.const 1)))
    $|        (drop (memory.atomic.wait32 (i32.const 4) (i32.const 0) (i64.const 1000000)))
    $|        (br $wait)
    $|      )
    $|    )
    $|    (drop (i32.atomic.rmw.add (i32.const 8) (i32.const 1)))
    $|  )
    $|)
  )
}

///|
fn wat_fan_in(pages : UInt64) -> String {
  (
    $|(module
    $|  (memory (import "env" "mem") \{pages} \{pages} shared)
    $|  (func (export "worker") (param $slot i32) (param $value i32)
    $|    (i32.store
    $|      (i32.add (i32.const 32) (i32.shl (local.get $slot) (i32.const 2)))
    $|      (local.get $value)
    $|    )
    $|    (drop (i32.atomic.rmw.add (i32.const 0) (i32.const 1)))
    $|    (drop (memory.atomic.notify (i32.const 0) (i32.const 1)))
    $|  )
    $|  (func (export "aggregate") (param $threads i32)
    $|    (local $ready i32) (local $i i32) (local $sum i32)
    $|    (block $done
    $|      (loop $wait
    $|        (local.set $ready (i32.atomic.load (i32.const 0)))
    $|        (br_if $done (i32.eq (local.get $ready) (local.get $threads)))
    $|        (drop (memory.atomic.wait32 (i32.const 0) (local.get $ready) (i64.const 1000000)))
    $|        (br $wait)
    $|      )
    $|    )
    $|    (local.set $sum (i32.const 0))
    $|    (local.set $i (i32.const 0))
    $|    (loop $loop
    $|      (local.set $sum
    $|        (i32.add
    $|          (local.get $sum)
    $|          (i32.load (i32.add (i32.const 32) (i32.shl (local.get $i) (i32.const 2))))
    $|        )
    $|      )
    $|      (local.set $i (i32.add (local.get $i) (i32.const 1)))
    $|      (br_if $loop (i32.lt_u (local.get $i) (local.get $threads)))
    $|    )
    $|    (i32.store (i32.const 4) (local.get $sum))
    $|  )
    $|)
  )
}

///|
fn wat_work_queue(pages : UInt64) -> String {
  (
    $|(module
    $|  (memory (import "env" "mem") \{pages} \{pages} shared)
    $|  (func (export "produce") (param $iters i32)
    $|    (local $i i32)
    $|    (local.set $i (i32.const 0))
    $|    (loop $loop
    $|      (i32.store
    $|        (i32.add (i32.const 32) (i32.shl (local.get $i) (i32.const 2)))
    $|        (i32.add (local.get $i) (i32.const 1))
    $|      )
    $|      (local.set $i (i32.add (local.get $i) (i32.const 1)))
    $|      (br_if $loop (i32.lt_u (local.get $i) (local.get $iters)))
    $|    )
    $|    (i32.store (i32.const 8) (i32.const 1))
    $|    (drop (memory.atomic.notify (i32.const 8) (i32.const 2147483647)))
    $|  )
    $|  (func (export "consume") (param $iters i32)
    $|    (local $idx i32) (local $val i32)
    $|    (block $ready
    $|      (loop $wait
    $|        (br_if $ready (i32.eq (i32.atomic.load (i32.const 8)) (i32.const 1)))
    $|        (drop (memory.atomic.wait32 (i32.const 8) (i32.const 0) (i64.const 1000000)))
    $|        (br $wait)
    $|      )
    $|    )
    $|    (block $done
    $|      (loop $loop
    $|        (local.set $idx (i32.atomic.rmw.add (i32.const 0) (i32.const 1)))
    $|        (br_if $done (i32.ge_u (local.get $idx) (local.get $iters)))
    $|        (local.set $val
    $|          (i32.load
    $|            (i32.add (i32.const 32) (i32.shl (local.get $idx) (i32.const 2)))
    $|          )
    $|        )
    $|        (drop (i32.atomic.rmw.add (i32.const 4) (local.get $val)))
    $|        (br $loop)
    $|      )
    $|    )
    $|  )
    $|)
  )
}

///|
fn wat_reduce(pages : UInt64) -> String {
  (
    $|(module
    $|  (memory (import "env" "mem") \{pages} \{pages} shared)
    $|  (func (export "reduce") (param $value i32) (param $threads i32)
    $|    (local $done i32)
    $|    (drop (i32.atomic.rmw.add (i32.const 0) (local.get $value)))
    $|    (local.set $done (i32.atomic.rmw.add (i32.const 4) (i32.const 1)))
    $|    (if
    $|      (i32.eq
    $|        (i32.add (local.get $done) (i32.const 1))
    $|        (local.get $threads)
    $|      )
    $|      (then (drop (memory.atomic.notify (i32.const 4) (i32.const 2147483647))))
    $|    )
    $|  )
    $|  (func (export "await") (param $threads i32)
    $|    (local $done i32)
    $|    (block $ready
    $|      (loop $wait
    $|        (local.set $done (i32.atomic.load (i32.const 4)))
    $|        (br_if $ready (i32.eq (local.get $done) (local.get $threads)))
    $|        (drop (memory.atomic.wait32 (i32.const 4) (local.get $done) (i64.const 1000000)))
    $|        (br $wait)
    $|      )
    $|    )
    $|    (i32.store (i32.const 8) (i32.atomic.load (i32.const 0)))
    $|  )
    $|)
  )
}

///|
fn wat_broadcast(pages : UInt64) -> String {
  (
    $|(module
    $|  (memory (import "env" "mem") \{pages} \{pages} shared)
    $|  (func (export "broadcast") (param $value i32) (param $threads i32)
    $|    (local $ack i32)
    $|    (i32.store (i32.const 4) (local.get $value))
    $|    (i32.store (i32.const 0) (i32.const 1))
    $|    (drop (memory.atomic.notify (i32.const 0) (local.get $threads)))
    $|    (block $done
    $|      (loop $wait
    $|        (local.set $ack (i32.atomic.load (i32.const 8)))
    $|        (br_if $done (i32.eq (local.get $ack) (local.get $threads)))
    $|        (drop (memory.atomic.wait32 (i32.const 8) (local.get $ack) (i64.const 1000000)))
    $|        (br $wait)
    $|      )
    $|    )
    $|  )
    $|  (func (export "receive") (param $slot i32)
    $|    (local $val i32)
    $|    (block $ready
    $|      (loop $wait
    $|        (br_if $ready (i32.eq (i32.atomic.load (i32.const 0)) (i32.const 1)))
    $|        (drop (memory.atomic.wait32 (i32.const 0) (i32.const 0) (i64.const 1000000)))
    $|        (br $wait)
    $|      )
    $|    )
    $|    (local.set $val (i32.load (i32.const 4)))
    $|    (i32.store
    $|      (i32.add (i32.const 32) (i32.shl (local.get $slot) (i32.const 2)))
    $|      (local.get $val)
    $|    )
    $|    (drop (i32.atomic.rmw.add (i32.const 8) (i32.const 1)))
    $|    (drop (memory.atomic.notify (i32.const 8) (i32.const 1)))
    $|  )
    $|)
  )
}

///|
fn wat_map_reduce(pages : UInt64) -> String {
  (
    $|(module
    $|  (memory (import "env" "mem") \{pages} \{pages} shared)
    $|  (func (export "map") (param $slot i32)
    $|    (local $value i32)
    $|    (local.set $value
    $|      (i32.mul
    $|        (i32.add (local.get $slot) (i32.const 1))
    $|        (i32.add (local.get $slot) (i32.const 1))
    $|      )
    $|    )
    $|    (i32.store
    $|      (i32.add (i32.const 32) (i32.shl (local.get $slot) (i32.const 2)))
    $|      (local.get $value)
    $|    )
    $|    (drop (i32.atomic.rmw.add (i32.const 0) (i32.const 1)))
    $|    (drop (memory.atomic.notify (i32.const 0) (i32.const 1)))
    $|  )
    $|  (func (export "reduce") (param $threads i32)
    $|    (local $ready i32) (local $i i32) (local $sum i32)
    $|    (block $done
    $|      (loop $wait
    $|        (local.set $ready (i32.atomic.load (i32.const 0)))
    $|        (br_if $done (i32.eq (local.get $ready) (local.get $threads)))
    $|        (drop (memory.atomic.wait32 (i32.const 0) (local.get $ready) (i64.const 1000000)))
    $|        (br $wait)
    $|      )
    $|    )
    $|    (local.set $sum (i32.const 0))
    $|    (local.set $i (i32.const 0))
    $|    (loop $loop
    $|      (local.set $sum
    $|        (i32.add
    $|          (local.get $sum)
    $|          (i32.load
    $|            (i32.add (i32.const 32) (i32.shl (local.get $i) (i32.const 2)))
    $|          )
    $|        )
    $|      )
    $|      (local.set $i (i32.add (local.get $i) (i32.const 1)))
    $|      (br_if $loop (i32.lt_u (local.get $i) (local.get $threads)))
    $|    )
    $|    (i32.store (i32.const 4) (local.get $sum))
    $|  )
    $|)
  )
}

///|
fn wat_ring_queue(pages : UInt64) -> String {
  (
    $|(module
    $|  (memory (import "env" "mem") \{pages} \{pages} shared)
    $|  (func (export "produce") (param $n i32) (param $mask i32)
    $|    (local $i i32) (local $head i32) (local $tail i32) (local $cap i32) (local $addr i32)
    $|    (local.set $i (i32.const 0))
    $|    (local.set $cap (i32.add (local.get $mask) (i32.const 1)))
    $|    (local.set $head (i32.atomic.load (i32.const 0)))
    $|    (loop $loop
    $|      (block $wait
    $|        (loop $spin
    $|          (local.set $tail (i32.atomic.load (i32.const 4)))
    $|          (br_if $wait (i32.lt_u (i32.sub (local.get $head) (local.get $tail)) (local.get $cap)))
    $|          (drop (memory.atomic.wait32 (i32.const 4) (local.get $tail) (i64.const 1000000)))
    $|          (br $spin)
    $|        )
    $|      )
    $|      (local.set $addr
    $|        (i32.add
    $|          (i32.const 32)
    $|          (i32.shl (i32.and (local.get $head) (local.get $mask)) (i32.const 2))
    $|        )
    $|      )
    $|      (i32.store (local.get $addr) (i32.add (local.get $i) (i32.const 1)))
    $|      (local.set $head (i32.add (local.get $head) (i32.const 1)))
    $|      (i32.atomic.store (i32.const 0) (local.get $head))
    $|      (drop (memory.atomic.notify (i32.const 0) (i32.const 1)))
    $|      (local.set $i (i32.add (local.get $i) (i32.const 1)))
    $|      (br_if $loop (i32.lt_u (local.get $i) (local.get $n)))
    $|    )
    $|  )
    $|  (func (export "consume") (param $n i32) (param $mask i32)
    $|    (local $i i32) (local $head i32) (local $tail i32) (local $addr i32) (local $sum i64)
    $|    (local.set $i (i32.const 0))
    $|    (local.set $tail (i32.atomic.load (i32.const 4)))
    $|    (local.set $sum (i64.const 0))
    $|    (loop $loop
    $|      (block $wait
    $|        (loop $spin
    $|          (local.set $head (i32.atomic.load (i32.const 0)))
    $|          (br_if $wait (i32.ne (local.get $head) (local.get $tail)))
    $|          (drop (memory.atomic.wait32 (i32.const 0) (local.get $head) (i64.const 1000000)))
    $|          (br $spin)
    $|        )
    $|      )
    $|      (local.set $addr
    $|        (i32.add
    $|          (i32.const 32)
    $|          (i32.shl (i32.and (local.get $tail) (local.get $mask)) (i32.const 2))
    $|        )
    $|      )
    $|      (local.set $sum
    $|        (i64.add
    $|          (local.get $sum)
    $|          (i64.extend_i32_u (i32.load (local.get $addr)))
    $|        )
    $|      )
    $|      (local.set $tail (i32.add (local.get $tail) (i32.const 1)))
    $|      (i32.atomic.store (i32.const 4) (local.get $tail))
    $|      (drop (memory.atomic.notify (i32.const 4) (i32.const 1)))
    $|      (local.set $i (i32.add (local.get $i) (i32.const 1)))
    $|      (br_if $loop (i32.lt_u (local.get $i) (local.get $n)))
    $|    )
    $|    (i64.store (i32.const 8) (local.get $sum))
    $|  )
    $|)
  )
}

///|
fn wat_ring_queue_mpmc(pages : UInt64) -> String {
  (
    $|(module
    $|  (memory (import "env" "mem") \{pages} \{pages} shared)
    $|  (func $wait_for (param $addr i32) (param $expected i32) (param $spin i32) (param $wait i32)
    $|    (local $spin_i i32)
    $|    (local.set $spin_i (i32.const 0))
    $|    (block $ready
    $|      (loop $wait
    $|        (br_if $ready (i32.eq (i32.atomic.load (local.get $addr)) (local.get $expected)))
    $|        (if (i32.lt_u (local.get $spin_i) (local.get $spin))
    $|          (then
    $|            (local.set $spin_i (i32.add (local.get $spin_i) (i32.const 1)))
    $|          )
    $|          (else
    $|            (local.set $spin_i (i32.const 0))
    $|            (drop (memory.atomic.wait32 (local.get $addr) (local.get $expected) (i64.extend_i32_u (local.get $wait))))
    $|          )
    $|        )
    $|        (br $wait)
    $|      )
    $|    )
    $|  )
    $|  (func (export "produce") (param $n i32) (param $mask i32) (param $spin i32) (param $wait i32)
    $|    (local $i i32) (local $seq i32) (local $tail i32) (local $addr i32)
    $|    (local $ready i32)
    $|    (local.set $i (i32.const 0))
    $|    (loop $loop
    $|      (local.set $seq (i32.atomic.rmw.add (i32.const 4) (i32.const 1)))
    $|      (local.set $tail (i32.and (local.get $seq) (local.get $mask)))
    $|      (local.set $addr (i32.add (i32.const 32) (i32.shl (local.get $tail) (i32.const 3))))
    $|      (local.set $ready (i32.add (local.get $seq) (i32.const 1)))
    $|      (call $wait_for (local.get $addr) (local.get $seq) (local.get $spin) (local.get $wait))
    $|      (i32.atomic.store (i32.add (local.get $addr) (i32.const 4)) (i32.add (local.get $seq) (i32.const 1)))
    $|      (i32.atomic.store (local.get $addr) (local.get $ready))
    $|      (drop (memory.atomic.notify (local.get $addr) (i32.const 1)))
    $|      (local.set $i (i32.add (local.get $i) (i32.const 1)))
    $|      (br_if $loop (i32.lt_u (local.get $i) (local.get $n)))
    $|    )
    $|  )
    $|  (func (export "consume") (param $n i32) (param $mask i32) (param $spin i32) (param $wait i32)
    $|    (local $i i32) (local $seq i32) (local $head i32) (local $addr i32)
    $|    (local $ready i32) (local $value i32) (local $sum i64)
    $|    (local.set $i (i32.const 0))
    $|    (local.set $sum (i64.const 0))
    $|    (loop $loop
    $|      (local.set $seq (i32.atomic.rmw.add (i32.const 0) (i32.const 1)))
    $|      (local.set $head (i32.and (local.get $seq) (local.get $mask)))
    $|      (local.set $addr (i32.add (i32.const 32) (i32.shl (local.get $head) (i32.const 3))))
    $|      (local.set $ready (i32.add (local.get $seq) (i32.const 1)))
    $|      (call $wait_for (local.get $addr) (local.get $ready) (local.get $spin) (local.get $wait))
    $|      (local.set $value (i32.atomic.load (i32.add (local.get $addr) (i32.const 4))))
    $|      (local.set $sum
    $|        (i64.add (local.get $sum) (i64.extend_i32_u (local.get $value)))
    $|      )
    $|      (i32.atomic.store (local.get $addr)
    $|        (i32.add (i32.add (local.get $seq) (local.get $mask)) (i32.const 1))
    $|      )
    $|      (drop (memory.atomic.notify (local.get $addr) (i32.const 1)))
    $|      (local.set $i (i32.add (local.get $i) (i32.const 1)))
    $|      (br_if $loop (i32.lt_u (local.get $i) (local.get $n)))
    $|    )
    $|    (drop (i64.atomic.rmw.add (i32.const 16) (local.get $sum)))
    $|  )
    $|)
  )
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
  match @thread_runtime.thread_runtime_new(pages.to_int()) {
    Ok(rt) => {
      let result = f(rt)
      @thread_runtime.thread_runtime_delete(rt)
      result
    }
    Err(err) => Err(err)
  }
}

///|
fn run_atomic_counter(threads : Int, iters : Int) -> Result[Unit, Error] {
  let pages = @thread_runtime.shared_pages_for_bytes(4UL)
  let wat = wat_atomic_counter(pages)
  with_runtime(pages, rt => {
    let args = make_i32_args(iters)
    let handles : Array[@thread_runtime.ThreadHandle] = []
    for _ in 0..<threads {
      match @thread_runtime.thread_runtime_spawn_wat(rt, wat, "run", args) {
        Ok(h) => handles.push(h)
        Err(err) => return Err(err)
      }
    }
    for handle in handles {
      match @thread_runtime.thread_runtime_join(handle) {
        Ok(_) => ()
        Err(err) => return Err(err)
      }
    }
    match @thread_runtime.thread_runtime_mem_read(rt, 0, 4) {
      Ok(bytes) => {
        let count = read_u32_le(bytes, 0).to_int()
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
      }
      Err(err) => Err(err)
    }
  })
}

///|
fn run_slots(threads : Int) -> Result[Unit, Error] {
  let bytes = (threads * 4).to_uint64()
  let pages = @thread_runtime.shared_pages_for_bytes(bytes)
  let wat = wat_slots(pages)
  with_runtime(pages, rt => {
    let handles : Array[@thread_runtime.ThreadHandle] = []
    for i in 0..<threads {
      let args = make_i32_args2(i, i + 1)
      match @thread_runtime.thread_runtime_spawn_wat(rt, wat, "run", args) {
        Ok(h) => handles.push(h)
        Err(err) => return Err(err)
      }
    }
    for handle in handles {
      match @thread_runtime.thread_runtime_join(handle) {
        Ok(_) => ()
        Err(err) => return Err(err)
      }
    }
    let len = threads * 4
    match @thread_runtime.thread_runtime_mem_read(rt, 0, len) {
      Ok(data) => {
        let mut sum : Int = 0
        for i in 0..<threads {
          let value = read_u32_le(data, i * 4).to_int()
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
      }
      Err(err) => Err(err)
    }
  })
}

///|
fn run_ping_pong(iters : Int) -> Result[Unit, Error] {
  let pages = @thread_runtime.shared_pages_for_bytes(12UL)
  let wat = wat_ping_pong(pages)
  with_runtime(pages, rt => {
    let args = make_i32_args(iters)
    let ping = match
      @thread_runtime.thread_runtime_spawn_wat(rt, wat, "ping", args) {
      Ok(h) => h
      Err(err) => return Err(err)
    }
    let pong = match
      @thread_runtime.thread_runtime_spawn_wat(rt, wat, "pong", args) {
      Ok(h) => h
      Err(err) => return Err(err)
    }
    match @thread_runtime.thread_runtime_join(ping) {
      Ok(_) => ()
      Err(err) => return Err(err)
    }
    match @thread_runtime.thread_runtime_join(pong) {
      Ok(_) => ()
      Err(err) => return Err(err)
    }
    match @thread_runtime.thread_runtime_mem_read(rt, 0, 12) {
      Ok(bytes) => {
        let state = read_u32_le(bytes, 0).to_int()
        let ping_count = read_u32_le(bytes, 4).to_int()
        let pong_count = read_u32_le(bytes, 8).to_int()
        if state == 0 && ping_count == iters && pong_count == iters {
          Ok(())
        } else {
          Err(
            ExampleError::ExampleError(
              "pingpong mismatch: state=\{state} ping=\{ping_count} pong=\{pong_count} iters=\{iters}",
            ),
          )
        }
      }
      Err(err) => Err(err)
    }
  })
}

///|
fn run_work_steal(threads : Int, iters : Int) -> Result[Unit, Error] {
  let pages = @thread_runtime.shared_pages_for_bytes(8UL)
  let wat = wat_work_steal(pages)
  with_runtime(pages, rt => {
    let args = make_i32_args(iters)
    let handles : Array[@thread_runtime.ThreadHandle] = []
    for _ in 0..<threads {
      match @thread_runtime.thread_runtime_spawn_wat(rt, wat, "run", args) {
        Ok(h) => handles.push(h)
        Err(err) => return Err(err)
      }
    }
    for handle in handles {
      match @thread_runtime.thread_runtime_join(handle) {
        Ok(_) => ()
        Err(err) => return Err(err)
      }
    }
    match @thread_runtime.thread_runtime_mem_read(rt, 4, 4) {
      Ok(bytes) => {
        let sum = read_u32_le(bytes, 0).to_int()
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
      }
      Err(err) => Err(err)
    }
  })
}

///|
fn run_barrier(threads : Int) -> Result[Unit, Error] {
  let pages = @thread_runtime.shared_pages_for_bytes(12UL)
  let wat = wat_barrier(pages)
  with_runtime(pages, rt => {
    let args = make_i32_args(threads)
    let handles : Array[@thread_runtime.ThreadHandle] = []
    for _ in 0..<threads {
      match @thread_runtime.thread_runtime_spawn_wat(rt, wat, "run", args) {
        Ok(h) => handles.push(h)
        Err(err) => return Err(err)
      }
    }
    for handle in handles {
      match @thread_runtime.thread_runtime_join(handle) {
        Ok(_) => ()
        Err(err) => return Err(err)
      }
    }
    match @thread_runtime.thread_runtime_mem_read(rt, 8, 4) {
      Ok(bytes) => {
        let done = read_u32_le(bytes, 0).to_int()
        if done == threads {
          Ok(())
        } else {
          Err(
            ExampleError::ExampleError(
              "barrier done mismatch: got=\{done} expected=\{threads}",
            ),
          )
        }
      }
      Err(err) => Err(err)
    }
  })
}

///|
fn run_fan_in(threads : Int) -> Result[Unit, Error] {
  let bytes = (32 + threads * 4).to_uint64()
  let pages = @thread_runtime.shared_pages_for_bytes(bytes)
  let wat = wat_fan_in(pages)
  with_runtime(pages, rt => {
    let agg_args = make_i32_args(threads)
    let aggregate = match
      @thread_runtime.thread_runtime_spawn_wat(rt, wat, "aggregate", agg_args) {
      Ok(h) => h
      Err(err) => return Err(err)
    }
    let handles : Array[@thread_runtime.ThreadHandle] = []
    for i in 0..<threads {
      let args = make_i32_args2(i, i + 1)
      match @thread_runtime.thread_runtime_spawn_wat(rt, wat, "worker", args) {
        Ok(h) => handles.push(h)
        Err(err) => return Err(err)
      }
    }
    for handle in handles {
      match @thread_runtime.thread_runtime_join(handle) {
        Ok(_) => ()
        Err(err) => return Err(err)
      }
    }
    match @thread_runtime.thread_runtime_join(aggregate) {
      Ok(_) => ()
      Err(err) => return Err(err)
    }
    match @thread_runtime.thread_runtime_mem_read(rt, 4, 4) {
      Ok(bytes) => {
        let sum = read_u32_le(bytes, 0).to_int()
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
      }
      Err(err) => Err(err)
    }
  })
}

///|
fn run_work_queue(threads : Int, iters : Int) -> Result[Unit, Error] {
  let bytes = (32 + iters * 4).to_uint64()
  let pages = @thread_runtime.shared_pages_for_bytes(bytes)
  let wat = wat_work_queue(pages)
  with_runtime(pages, rt => {
    let prod_args = make_i32_args(iters)
    let producer = match
      @thread_runtime.thread_runtime_spawn_wat(rt, wat, "produce", prod_args) {
      Ok(h) => h
      Err(err) => return Err(err)
    }
    let cons_args = make_i32_args(iters)
    let handles : Array[@thread_runtime.ThreadHandle] = []
    for _ in 0..<threads {
      match
        @thread_runtime.thread_runtime_spawn_wat(rt, wat, "consume", cons_args) {
        Ok(h) => handles.push(h)
        Err(err) => return Err(err)
      }
    }
    for handle in handles {
      match @thread_runtime.thread_runtime_join(handle) {
        Ok(_) => ()
        Err(err) => return Err(err)
      }
    }
    match @thread_runtime.thread_runtime_join(producer) {
      Ok(_) => ()
      Err(err) => return Err(err)
    }
    match @thread_runtime.thread_runtime_mem_read(rt, 4, 4) {
      Ok(bytes) => {
        let sum = read_u32_le(bytes, 0).to_int()
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
      }
      Err(err) => Err(err)
    }
  })
}

///|
fn run_reduce(threads : Int) -> Result[Unit, Error] {
  let pages = @thread_runtime.shared_pages_for_bytes(12UL)
  let wat = wat_reduce(pages)
  with_runtime(pages, rt => {
    let await_args = make_i32_args(threads)
    let awaiter = match
      @thread_runtime.thread_runtime_spawn_wat(rt, wat, "await", await_args) {
      Ok(h) => h
      Err(err) => return Err(err)
    }
    let handles : Array[@thread_runtime.ThreadHandle] = []
    for i in 0..<threads {
      let args = make_i32_args2(i + 1, threads)
      match @thread_runtime.thread_runtime_spawn_wat(rt, wat, "reduce", args) {
        Ok(h) => handles.push(h)
        Err(err) => return Err(err)
      }
    }
    for handle in handles {
      match @thread_runtime.thread_runtime_join(handle) {
        Ok(_) => ()
        Err(err) => return Err(err)
      }
    }
    match @thread_runtime.thread_runtime_join(awaiter) {
      Ok(_) => ()
      Err(err) => return Err(err)
    }
    match @thread_runtime.thread_runtime_mem_read(rt, 8, 4) {
      Ok(bytes) => {
        let sum = read_u32_le(bytes, 0).to_int()
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
      }
      Err(err) => Err(err)
    }
  })
}

///|
fn run_broadcast(threads : Int, value : Int) -> Result[Unit, Error] {
  let bytes = (32 + threads * 4).to_uint64()
  let pages = @thread_runtime.shared_pages_for_bytes(bytes)
  let wat = wat_broadcast(pages)
  with_runtime(pages, rt => {
    let bcast_args = make_i32_args2(value, threads)
    let broadcaster = match
      @thread_runtime.thread_runtime_spawn_wat(rt, wat, "broadcast", bcast_args) {
      Ok(h) => h
      Err(err) => return Err(err)
    }
    let handles : Array[@thread_runtime.ThreadHandle] = []
    for i in 0..<threads {
      let args = make_i32_args(i)
      match @thread_runtime.thread_runtime_spawn_wat(rt, wat, "receive", args) {
        Ok(h) => handles.push(h)
        Err(err) => return Err(err)
      }
    }
    for handle in handles {
      match @thread_runtime.thread_runtime_join(handle) {
        Ok(_) => ()
        Err(err) => return Err(err)
      }
    }
    match @thread_runtime.thread_runtime_join(broadcaster) {
      Ok(_) => ()
      Err(err) => return Err(err)
    }
    let expected = threads * value
    let slot_len = threads * 4
    match @thread_runtime.thread_runtime_mem_read(rt, 32, slot_len) {
      Ok(data) => {
        let mut sum : Int = 0
        for i in 0..<threads {
          let v = read_u32_le(data, i * 4).to_int()
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
      }
      Err(err) => Err(err)
    }
  })
}

///|
fn run_map_reduce(threads : Int) -> Result[Unit, Error] {
  let bytes = (32 + threads * 4).to_uint64()
  let pages = @thread_runtime.shared_pages_for_bytes(bytes)
  let wat = wat_map_reduce(pages)
  with_runtime(pages, rt => {
    let reduce_args = make_i32_args(threads)
    let reducer = match
      @thread_runtime.thread_runtime_spawn_wat(rt, wat, "reduce", reduce_args) {
      Ok(h) => h
      Err(err) => return Err(err)
    }
    let handles : Array[@thread_runtime.ThreadHandle] = []
    for i in 0..<threads {
      let args = make_i32_args(i)
      match @thread_runtime.thread_runtime_spawn_wat(rt, wat, "map", args) {
        Ok(h) => handles.push(h)
        Err(err) => return Err(err)
      }
    }
    for handle in handles {
      match @thread_runtime.thread_runtime_join(handle) {
        Ok(_) => ()
        Err(err) => return Err(err)
      }
    }
    match @thread_runtime.thread_runtime_join(reducer) {
      Ok(_) => ()
      Err(err) => return Err(err)
    }
    match @thread_runtime.thread_runtime_mem_read(rt, 4, 4) {
      Ok(bytes) => {
        let sum = read_u32_le(bytes, 0).to_int()
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
      }
      Err(err) => Err(err)
    }
  })
}

///|
fn run_ring_queue(slots : Int, iters : Int) -> Result[Unit, Error] {
  let capacity = round_up_pow2(slots)
  let mask = capacity - 1
  let bytes = (32 + capacity * 4).to_uint64()
  let pages = @thread_runtime.shared_pages_for_bytes(bytes)
  let wat = wat_ring_queue(pages)
  with_runtime(pages, rt => {
    let args = make_i32_args2(iters, mask)
    let producer = match
      @thread_runtime.thread_runtime_spawn_wat(rt, wat, "produce", args) {
      Ok(h) => h
      Err(err) => return Err(err)
    }
    let consumer = match
      @thread_runtime.thread_runtime_spawn_wat(rt, wat, "consume", args) {
      Ok(h) => h
      Err(err) => return Err(err)
    }
    match @thread_runtime.thread_runtime_join(producer) {
      Ok(_) => ()
      Err(err) => return Err(err)
    }
    match @thread_runtime.thread_runtime_join(consumer) {
      Ok(_) => ()
      Err(err) => return Err(err)
    }
    match @thread_runtime.thread_runtime_mem_read(rt, 8, 8) {
      Ok(bytes) => {
        let sum = read_u64_le(bytes, 0)
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
      }
      Err(err) => Err(err)
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
  let wat = wat_ring_queue_mpmc(pages)
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
    match @thread_runtime.thread_runtime_mem_write(rt, 32, init_bytes) {
      Ok(_) => ()
      Err(err) => return Err(err)
    }
    let args = make_i32_args4(iters, mask, spin_limit, wait_timeout_ns)
    let prod_handles : Array[@thread_runtime.ThreadHandle] = []
    let cons_handles : Array[@thread_runtime.ThreadHandle] = []
    for _ in 0..<threads {
      match @thread_runtime.thread_runtime_spawn_wat(rt, wat, "produce", args) {
        Ok(h) => prod_handles.push(h)
        Err(err) => return Err(err)
      }
      match @thread_runtime.thread_runtime_spawn_wat(rt, wat, "consume", args) {
        Ok(h) => cons_handles.push(h)
        Err(err) => return Err(err)
      }
    }
    for handle in prod_handles {
      match @thread_runtime.thread_runtime_join(handle) {
        Ok(_) => ()
        Err(err) => return Err(err)
      }
    }
    for handle in cons_handles {
      match @thread_runtime.thread_runtime_join(handle) {
        Ok(_) => ()
        Err(err) => return Err(err)
      }
    }
    match @thread_runtime.thread_runtime_mem_read(rt, 16, 8) {
      Ok(bytes) => {
        let sum = read_u64_le(bytes, 0)
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
      }
      Err(err) => Err(err)
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
