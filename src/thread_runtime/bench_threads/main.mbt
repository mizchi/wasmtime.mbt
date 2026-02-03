///|
/// Ring buffer benchmark: OS shared memory (cold).
#borrow(error_out, prod_spins_out, cons_spins_out)
pub extern "C" fn bench_os_shared_ring(
  items : Int,
  slots : Int,
  error_out : Bytes,
  prod_spins_out : Bytes,
  cons_spins_out : Bytes,
) -> UInt64 = "wasmtime_bench_os_shared_ring"

///|
/// Ring buffer benchmark: OS shared memory (warm).
#borrow(error_out, prod_spins_out, cons_spins_out)
pub extern "C" fn bench_os_shared_ring_warm(
  items : Int,
  slots : Int,
  error_out : Bytes,
  prod_spins_out : Bytes,
  cons_spins_out : Bytes,
) -> UInt64 = "wasmtime_bench_os_shared_ring_warm"

///|
#borrow(bytes)
extern "C" fn error_message_bytes(bytes : Bytes) -> Bytes = "wasmtime_error_message_bytes"

///|
#borrow(bytes)
extern "C" fn bytes_read_u64(bytes : Bytes) -> UInt64 = "moonbit_bytes_read_u64"

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
  let mut out : UInt64 = 0
  let mut i = 0
  while i < 8 {
    let b = bytes[offset + i].to_uint64()
    out = out | (b << (8 * i))
    i = i + 1
  }
  out
}

///|
fn ring_wat(pages : UInt64) -> String {
  (
    $|(module
    $|  (memory (import "env" "mem") \{pages} \{pages} shared)
    $|  (func (export "produce") (param $n i32) (param $mask i32)
    $|    (local $i i32) (local $head i32) (local $tail i32) (local $cap i32) (local $addr i32) (local $spins i64)
    $|    (local.set $i (i32.const 0))
    $|    (local.set $cap (i32.add (local.get $mask) (i32.const 1)))
    $|    (local.set $head (i32.atomic.load (i32.const 0)))
    $|    (local.set $spins (i64.const 0))
    $|    (loop $loop
    $|      (block $wait
    $|        (loop $spin
    $|          (local.set $tail (i32.atomic.load (i32.const 4)))
    $|          (br_if $wait (i32.lt_u (i32.sub (local.get $head) (local.get $tail)) (local.get $cap)))
    $|          (local.set $spins (i64.add (local.get $spins) (i64.const 1)))
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
    $|      (local.set $i (i32.add (local.get $i) (i32.const 1)))
    $|      (br_if $loop (i32.lt_u (local.get $i) (local.get $n)))
    $|    )
    $|    (i64.store (i32.const 16) (local.get $spins))
    $|  )
    $|  (func (export "consume") (param $n i32) (param $mask i32)
    $|    (local $i i32) (local $head i32) (local $tail i32) (local $addr i32) (local $sum i64) (local $spins i64)
    $|    (local.set $i (i32.const 0))
    $|    (local.set $tail (i32.atomic.load (i32.const 4)))
    $|    (local.set $sum (i64.const 0))
    $|    (local.set $spins (i64.const 0))
    $|    (loop $loop
    $|      (block $wait
    $|        (loop $spin
    $|          (local.set $head (i32.atomic.load (i32.const 0)))
    $|          (br_if $wait (i32.ne (local.get $head) (local.get $tail)))
    $|          (local.set $spins (i64.add (local.get $spins) (i64.const 1)))
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
    $|        (i64.add (local.get $sum) (i64.extend_i32_u (i32.load (local.get $addr))))
    $|      )
    $|      (local.set $tail (i32.add (local.get $tail) (i32.const 1)))
    $|      (i32.atomic.store (i32.const 4) (local.get $tail))
    $|      (local.set $i (i32.add (local.get $i) (i32.const 1)))
    $|      (br_if $loop (i32.lt_u (local.get $i) (local.get $n)))
    $|    )
    $|    (i64.store (i32.const 8) (local.get $sum))
    $|    (i64.store (i32.const 24) (local.get $spins))
    $|  )
    $|)
  )
}

///|
fn ring_wat_wait(
  pages : UInt64,
  wait_timeout_ns : UInt64,
  spin_limit : Int,
) -> String {
  (
    $|(module
    $|  (memory (import "env" "mem") \{pages} \{pages} shared)
    $|  (func (export "produce") (param $n i32) (param $mask i32)
    $|    (local $i i32) (local $head i32) (local $tail i32) (local $cap i32) (local $addr i32) (local $spins i64) (local $spin_i i32)
    $|    (local.set $i (i32.const 0))
    $|    (local.set $cap (i32.add (local.get $mask) (i32.const 1)))
    $|    (local.set $head (i32.atomic.load (i32.const 0)))
    $|    (local.set $spins (i64.const 0))
    $|    (local.set $spin_i (i32.const 0))
    $|    (loop $loop
    $|      (block $wait
    $|        (loop $spin
    $|          (local.set $tail (i32.atomic.load (i32.const 4)))
    $|          (br_if $wait (i32.lt_u (i32.sub (local.get $head) (local.get $tail)) (local.get $cap)))
    $|          (local.set $spins (i64.add (local.get $spins) (i64.const 1)))
    $|          (if (i32.lt_u (local.get $spin_i) (i32.const \{spin_limit}))
    $|            (then
    $|              (local.set $spin_i (i32.add (local.get $spin_i) (i32.const 1)))
    $|              (br $spin)
    $|            )
    $|            (else
    $|              (local.set $spin_i (i32.const 0))
    $|              (drop (memory.atomic.wait32 (i32.const 4) (local.get $tail) (i64.const \{wait_timeout_ns})))
    $|              (br $spin)
    $|            )
    $|          )
    $|        )
    $|      )
    $|      (local.set $spin_i (i32.const 0))
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
    $|    (i64.store (i32.const 16) (local.get $spins))
    $|  )
    $|  (func (export "consume") (param $n i32) (param $mask i32)
    $|    (local $i i32) (local $head i32) (local $tail i32) (local $addr i32) (local $sum i64) (local $spins i64) (local $spin_i i32)
    $|    (local.set $i (i32.const 0))
    $|    (local.set $tail (i32.atomic.load (i32.const 4)))
    $|    (local.set $sum (i64.const 0))
    $|    (local.set $spins (i64.const 0))
    $|    (local.set $spin_i (i32.const 0))
    $|    (loop $loop
    $|      (block $wait
    $|        (loop $spin
    $|          (local.set $head (i32.atomic.load (i32.const 0)))
    $|          (br_if $wait (i32.ne (local.get $head) (local.get $tail)))
    $|          (local.set $spins (i64.add (local.get $spins) (i64.const 1)))
    $|          (if (i32.lt_u (local.get $spin_i) (i32.const \{spin_limit}))
    $|            (then
    $|              (local.set $spin_i (i32.add (local.get $spin_i) (i32.const 1)))
    $|              (br $spin)
    $|            )
    $|            (else
    $|              (local.set $spin_i (i32.const 0))
    $|              (drop (memory.atomic.wait32 (i32.const 0) (local.get $head) (i64.const \{wait_timeout_ns})))
    $|              (br $spin)
    $|            )
    $|          )
    $|        )
    $|      )
    $|      (local.set $spin_i (i32.const 0))
    $|      (local.set $addr
    $|        (i32.add
    $|          (i32.const 32)
    $|          (i32.shl (i32.and (local.get $tail) (local.get $mask)) (i32.const 2))
    $|        )
    $|      )
    $|      (local.set $sum
    $|        (i64.add (local.get $sum) (i64.extend_i32_u (i32.load (local.get $addr))))
    $|      )
    $|      (local.set $tail (i32.add (local.get $tail) (i32.const 1)))
    $|      (i32.atomic.store (i32.const 4) (local.get $tail))
    $|      (drop (memory.atomic.notify (i32.const 4) (i32.const 1)))
    $|      (local.set $i (i32.add (local.get $i) (i32.const 1)))
    $|      (br_if $loop (i32.lt_u (local.get $i) (local.get $n)))
    $|    )
    $|    (i64.store (i32.const 8) (local.get $sum))
    $|    (i64.store (i32.const 24) (local.get $spins))
    $|  )
    $|)
  )
}

///|
fn make_ring_args(items : Int, mask : Int) -> Bytes {
  let args = @wasmtime.make_val_buffer(2)
  @wasmtime.val_buffer_set_i32(args, 0, items)
  @wasmtime.val_buffer_set_i32(args, 1, mask)
  args
}

///|
fn is_power_of_two(value : Int) -> Bool {
  value > 1 && (value & (value - 1)) == 0
}

///|
fn validate_ring_args(items : Int, slots : Int) -> String? {
  if items <= 0 || slots <= 1 {
    Some("invalid items or slots")
  } else if not(is_power_of_two(slots)) {
    Some("slots must be power of two")
  } else if items > 2_147_483_647 {
    Some("items exceed i32")
  } else {
    None
  }
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
  let mut i = 1
  let len = args.length()
  while i < len {
    if args[i] == flag {
      return true
    }
    i = i + 1
  }
  false
}

///|
fn parse_slots_list(value : String) -> Array[Int] {
  let out = Array::new()
  let parts = String::split(value, ",").to_array()
  for part in parts {
    let text = part.to_string()
    let v = try @strconv.parse_int(text) catch {
      _ => 0
    } noraise {
      value => value
    }
    if is_power_of_two(v) {
      out.push(v)
    }
  }
  out
}

///|
fn parse_timeout_list(value : String) -> Array[Int] {
  let out = Array::new()
  let parts = String::split(value, ",").to_array()
  for part in parts {
    let text = part.to_string()
    let v = try @strconv.parse_int(text) catch {
      _ => -1
    } noraise {
      value => value
    }
    if v >= 0 {
      out.push(v)
    }
  }
  out
}

///|
fn default_sweep_slots() -> Array[Int] {
  let out = Array::new()
  out.push(64)
  out.push(256)
  out.push(1024)
  out.push(4096)
  out.push(16384)
  out
}

///|
fn default_wait_timeout_us(slots : Int) -> Int? {
  if slots <= 64 {
    None
  } else if slots <= 256 {
    Some(10)
  } else {
    Some(1000)
  }
}

///|
fn wait_timeout_ns_from_us(us : Int) -> UInt64 {
  let us_u64 : UInt64 = if us < 0 { 0 } else { Int::to_uint64(us) }
  us_u64 * 1000
}

///|
fn usage() -> Unit {
  println("bench_threads ring options:")
  println("  --items N        total items per run (default: 1000000)")
  println("  --slots N        ring slots (power of two, default: 1024)")
  println("  --sweep          sweep slots list")
  println("  --slots-list CSV override sweep slots, e.g. 64,256,1024")
  println("  --wasm-wait      also run wasm atomic.wait variants")
  println(
    "  --wait-timeout-us N   atomic.wait timeout in microseconds (default: 1000)",
  )
  println(
    "  --wait-timeout-list CSV  sweep atomic.wait timeouts (microseconds)",
  )
  println("  --wait-timeout-auto     use heuristic timeout per slots")
  println("  --wait-mode wait|hybrid (default: wait)")
  println(
    "  --wait-spin N           hybrid spin count before wait (default: 100)",
  )
  println("  --csv            print CSV output (in addition to human output)")
  println("  --csv-only       print CSV output only")
  println("  --help           show this help")
}

///|
fn take_error_message(err_ptr : Bytes, fallback : String) -> String {
  let msg_bytes = error_message_bytes(err_ptr)
  let msg = if msg_bytes.length() > 0 {
    @utf8.decode_lossy(msg_bytes)
  } else {
    fallback
  }
  @wasmtime.error_delete_ptr_buffer(err_ptr)
  msg
}

///|
fn bench_os_shared_ring_result(
  items : Int,
  slots : Int,
  warm : Bool,
) -> Result[(UInt64, UInt64, UInt64), String] {
  let err_ptr = @wasmtime.make_ptr_buffer()
  let prod_spins = Bytes::make(8, 0)
  let cons_spins = Bytes::make(8, 0)
  let elapsed = if warm {
    bench_os_shared_ring_warm(items, slots, err_ptr, prod_spins, cons_spins)
  } else {
    bench_os_shared_ring(items, slots, err_ptr, prod_spins, cons_spins)
  }
  if not(@wasmtime.ptr_buffer_is_null(err_ptr)) {
    Err(take_error_message(err_ptr, "os ring failed"))
  } else {
    Ok((elapsed, bytes_read_u64(prod_spins), bytes_read_u64(cons_spins)))
  }
}

///|
fn run_wasm_ring_once(
  rt : @thread_runtime.ThreadRuntime,
  wat : String,
  items : Int,
  slots : Int,
  measure : Bool,
) -> Result[(UInt64, UInt64, UInt64), String] {
  let header_size = 32
  let total_len = header_size + slots * 4
  if total_len <= 0 {
    return Err("shared memory size invalid")
  }
  let offset : UInt64 = 0
  let zero = Bytes::make(total_len, 0)
  match @thread_runtime.thread_runtime_mem_write(rt, offset, zero) {
    Ok(_) => ()
    Err(err) => return Err("\{err}")
  }
  let mask = slots - 1
  let args = make_ring_args(items, mask)
  let start = if measure { @wasmtime.clock_now_ns() } else { 0 }
  let prod_handle = match
    @thread_runtime.thread_runtime_spawn_wat(rt, wat, "produce", args) {
    Ok(handle) => handle
    Err(err) => return Err("\{err}")
  }
  let cons_handle = match
    @thread_runtime.thread_runtime_spawn_wat(rt, wat, "consume", args) {
    Ok(handle) => handle
    Err(err) => {
      let _ = @thread_runtime.thread_runtime_join(prod_handle)
      return Err("\{err}")
    }
  }
  match @thread_runtime.thread_runtime_join(prod_handle) {
    Ok(_) => ()
    Err(err) => return Err("\{err}")
  }
  match @thread_runtime.thread_runtime_join(cons_handle) {
    Ok(_) => ()
    Err(err) => return Err("\{err}")
  }
  let end = if measure { @wasmtime.clock_now_ns() } else { 0 }
  let header = match
    @thread_runtime.thread_runtime_mem_read(rt, offset, header_size) {
    Ok(bytes) => bytes
    Err(err) => return Err("\{err}")
  }
  let head = read_u32_le(header, 0)
  let tail = read_u32_le(header, 4)
  let sum = read_u64_le(header, 8)
  let prod_spins = read_u64_le(header, 16)
  let cons_spins = read_u64_le(header, 24)
  let expected = Int::to_uint64(items) * Int::to_uint64(items + 1) / 2
  let items_u64 = Int::to_uint64(items)
  if head != items_u64 || tail != items_u64 {
    return Err("head/tail mismatch")
  }
  if sum != expected {
    return Err("sum mismatch")
  }
  let elapsed = if measure { end - start } else { 0 }
  Ok((elapsed, prod_spins, cons_spins))
}

///|
fn bench_wasm_shared_ring_runtime(
  items : Int,
  slots : Int,
  warm : Bool,
  use_wait : Bool,
  wait_timeout_ns : UInt64,
  spin_limit : Int,
) -> Result[(UInt64, UInt64, UInt64), String] {
  match validate_ring_args(items, slots) {
    Some(msg) => return Err(msg)
    None => ()
  }
  let header_size = 32
  let total_len = header_size + slots * 4
  let pages = @thread_runtime.shared_pages_for_bytes(Int::to_uint64(total_len))
  let wat = if use_wait {
    ring_wat_wait(pages, wait_timeout_ns, spin_limit)
  } else {
    ring_wat(pages)
  }
  let runtime_res = @thread_runtime.thread_runtime_new(pages.to_int())
  match runtime_res {
    Ok(rt) => {
      let result = if warm {
        let warmup = run_wasm_ring_once(rt, wat, items, slots, false)
        match warmup {
          Ok(_) => ()
          Err(msg) => {
            @thread_runtime.thread_runtime_delete(rt)
            return Err(msg)
          }
        }
        run_wasm_ring_once(rt, wat, items, slots, true)
      } else {
        run_wasm_ring_once(rt, wat, items, slots, true)
      }
      @thread_runtime.thread_runtime_delete(rt)
      result
    }
    Err(err) => Err("\{err}")
  }
}

///|
fn bench_os_shared_ring_cold(
  items : Int,
  slots : Int,
  _wait_timeout_ns : UInt64,
  _spin_limit : Int,
) -> Result[(UInt64, UInt64, UInt64), String] {
  bench_os_shared_ring_result(items, slots, false)
}

///|
fn bench_os_shared_ring_warm_result(
  items : Int,
  slots : Int,
  _wait_timeout_ns : UInt64,
  _spin_limit : Int,
) -> Result[(UInt64, UInt64, UInt64), String] {
  bench_os_shared_ring_result(items, slots, true)
}

///|
fn bench_wasm_shared_ring_cold(
  items : Int,
  slots : Int,
  _wait_timeout_ns : UInt64,
  _spin_limit : Int,
) -> Result[(UInt64, UInt64, UInt64), String] {
  bench_wasm_shared_ring_runtime(items, slots, false, false, 0, 0)
}

///|
fn bench_wasm_shared_ring_warm_result(
  items : Int,
  slots : Int,
  _wait_timeout_ns : UInt64,
  _spin_limit : Int,
) -> Result[(UInt64, UInt64, UInt64), String] {
  bench_wasm_shared_ring_runtime(items, slots, true, false, 0, 0)
}

///|
fn bench_wasm_shared_ring_cold_wait(
  items : Int,
  slots : Int,
  wait_timeout_ns : UInt64,
  spin_limit : Int,
) -> Result[(UInt64, UInt64, UInt64), String] {
  bench_wasm_shared_ring_runtime(
    items, slots, false, true, wait_timeout_ns, spin_limit,
  )
}

///|
fn bench_wasm_shared_ring_warm_wait(
  items : Int,
  slots : Int,
  wait_timeout_ns : UInt64,
  spin_limit : Int,
) -> Result[(UInt64, UInt64, UInt64), String] {
  bench_wasm_shared_ring_runtime(
    items, slots, true, true, wait_timeout_ns, spin_limit,
  )
}

///|
fn bench_case(
  label : String,
  items : Int,
  slots : Int,
  wait_timeout_ns : UInt64,
  spin_limit : Int,
  f : (Int, Int, UInt64, Int) -> Result[(UInt64, UInt64, UInt64), String],
  csv : Bool,
  csv_only : Bool,
) -> Bool {
  match f(items, slots, wait_timeout_ns, spin_limit) {
    Ok((elapsed, prod_spins_value, cons_spins_value)) => {
      let total_ops = Int::to_uint64(items)
      let per_ps = if total_ops > 0 { elapsed * 1000 / total_ops } else { 0 }
      if not(csv_only) {
        println(
          "\{label}: total=\{elapsed} ns, per=\{per_ps} ps (items=\{items}, slots=\{slots}, prod_spins=\{prod_spins_value}, cons_spins=\{cons_spins_value})",
        )
      }
      if csv {
        println(
          "\{label},\{items},\{slots},\{elapsed},\{per_ps},\{prod_spins_value},\{cons_spins_value}",
        )
      }
      true
    }
    Err(msg) => {
      println("\{label}: error: \{msg}")
      false
    }
  }
}

///|
fn run_once(
  items : Int,
  slots : Int,
  csv : Bool,
  csv_only : Bool,
  wasm_wait : Bool,
  wait_timeout_us : Int,
  wait_timeout_list : Array[Int],
  wait_mode : String,
  wait_spin : Int,
  wait_timeout_auto : Bool,
) -> Bool {
  if not(csv_only) {
    println("bench_threads: ring (items=\{items}, slots=\{slots}, threads=2)")
  }
  if not(
      bench_case(
        "os_ring_cold", items, slots, 0, 0, bench_os_shared_ring_cold, csv, csv_only,
      ),
    ) {
    return false
  }
  if not(
      bench_case(
        "os_ring_warm", items, slots, 0, 0, bench_os_shared_ring_warm_result, csv,
        csv_only,
      ),
    ) {
    return false
  }
  let _ = bench_case(
    "wasm_ring_cold", items, slots, 0, 0, bench_wasm_shared_ring_cold, csv, csv_only,
  )
  let _ = bench_case(
    "wasm_ring_warm", items, slots, 0, 0, bench_wasm_shared_ring_warm_result, csv,
    csv_only,
  )
  if wasm_wait {
    let wait_list = if wait_timeout_list.length() > 0 {
      wait_timeout_list
    } else if wait_timeout_auto {
      match default_wait_timeout_us(slots) {
        Some(v) => [v]
        None => Array::new()
      }
    } else {
      [wait_timeout_us]
    }
    if wait_list.length() > 0 {
      for us in wait_list {
        let wait_ns = wait_timeout_ns_from_us(us)
        let spin_limit = if wait_mode == "hybrid" {
          if wait_spin < 0 {
            0
          } else {
            wait_spin
          }
        } else {
          0
        }
        let _ = bench_case(
          "wasm_ring_cold_\{wait_mode}_\{us}us",
          items,
          slots,
          wait_ns,
          spin_limit,
          bench_wasm_shared_ring_cold_wait,
          csv,
          csv_only,
        )
        let _ = bench_case(
          "wasm_ring_warm_\{wait_mode}_\{us}us",
          items,
          slots,
          wait_ns,
          spin_limit,
          bench_wasm_shared_ring_warm_wait,
          csv,
          csv_only,
        )

      }
    }
  }
  true
}

///|
fn main {
  let args = @env.args()
  if has_flag(args, "--help") {
    usage()
    return
  }
  let items = match arg_value(args, "--items") {
    Some(v) => parse_int_value(v, 1_000_000)
    None => 1_000_000
  }
  let slots = match arg_value(args, "--slots") {
    Some(v) => parse_int_value(v, 1024)
    None => 1024
  }
  let sweep = has_flag(args, "--sweep")
  let wait_timeout_us = match arg_value(args, "--wait-timeout-us") {
    Some(v) => parse_int_value(v, 1000)
    None => 1000
  }
  let wait_timeout_list = match arg_value(args, "--wait-timeout-list") {
    Some(v) => parse_timeout_list(v)
    None => Array::new()
  }
  let wait_timeout_auto = has_flag(args, "--wait-timeout-auto")
  let wait_mode_raw = match arg_value(args, "--wait-mode") {
    Some(v) => v
    None => "wait"
  }
  let wait_mode = if wait_mode_raw == "hybrid" { "hybrid" } else { "wait" }
  let wait_spin = match arg_value(args, "--wait-spin") {
    Some(v) => parse_int_value(v, 100)
    None => 100
  }
  let wasm_wait = has_flag(args, "--wasm-wait") ||
    wait_timeout_list.length() > 0 ||
    wait_timeout_auto ||
    wait_mode != "wait"
  let csv_only = has_flag(args, "--csv-only")
  let csv = csv_only || has_flag(args, "--csv")
  let slots_list = match arg_value(args, "--slots-list") {
    Some(v) => {
      let parsed = parse_slots_list(v)
      if parsed.length() > 0 {
        parsed
      } else {
        default_sweep_slots()
      }
    }
    None => default_sweep_slots()
  }
  if csv {
    println("label,items,slots,elapsed_ns,per_ps,prod_spins,cons_spins")
  }
  if sweep {
    for slot in slots_list {
      if not(
          run_once(
            items, slot, csv, csv_only, wasm_wait, wait_timeout_us, wait_timeout_list,
            wait_mode, wait_spin, wait_timeout_auto,
          ),
        ) {
        return
      }
    }
  } else {
    let _ = run_once(
      items, slots, csv, csv_only, wasm_wait, wait_timeout_us, wait_timeout_list,
      wait_mode, wait_spin, wait_timeout_auto,
    )

  }
}
