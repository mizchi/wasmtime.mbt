///|
/// Build a simple atomic counter module.
pub fn wat_atomic_counter(pages : UInt64) -> String {
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
/// Build a slot write module.
pub fn wat_slots(pages : UInt64) -> String {
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
/// Build a ping/pong module using atomic wait/notify.
pub fn wat_ping_pong(pages : UInt64) -> String {
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
/// Build an atomic work-stealing module.
pub fn wat_work_steal(pages : UInt64) -> String {
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
/// Build a barrier module.
pub fn wat_barrier(pages : UInt64) -> String {
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
/// Build a fan-in module.
pub fn wat_fan_in(pages : UInt64) -> String {
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
/// Build a simple work-queue module.
pub fn wat_work_queue(pages : UInt64) -> String {
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
/// Build a reduce module.
pub fn wat_reduce(pages : UInt64) -> String {
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
/// Build a broadcast module.
pub fn wat_broadcast(pages : UInt64) -> String {
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
/// Build a map-reduce module.
pub fn wat_map_reduce(pages : UInt64) -> String {
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
/// Build a single-producer/single-consumer ring queue module.
pub fn wat_ring_queue(pages : UInt64) -> String {
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
/// Build a multi-producer/multi-consumer ring queue module.
pub fn wat_ring_queue_mpmc(pages : UInt64) -> String {
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
