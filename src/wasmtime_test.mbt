///|
test "version" {
  let ver = version()
  assert_true(ver.length() > 0)
}

///|
test "engine_new/delete" {
  let engine = engine_new()
  engine_delete(engine)
}

///|
test "store_new/delete" {
  let engine = engine_new()
  let store = store_new(engine)
  store_delete(store)
  engine_delete(engine)
}

///|
test "config_new/engine_new_with_config" {
  let config = config_new()
  config_debug_info_set(config, true)
  config_consume_fuel_set(config, true)
  config_wasm_simd_set(config, true)
  let engine = engine_new_with_config(config)
  engine_delete(engine)
}

///|
test "wasm_job_spawn_wat" {
  let wat =
    #|(module
    #|  (func (export "run") (result i32)
    #|    i32.const 7))
  let handle = wasm_job_spawn_wat_or_raise(wat, "run")
  let result = wasm_job_join_or_raise(handle)
  assert_eq(result, 7)
}

///|
test "wasi_job_spawn_wat_stdin" {
  let wat =
    #|(module
    #|  (import "wasi_snapshot_preview1" "fd_read"
    #|    (func $fd_read (param i32 i32 i32 i32) (result i32)))
    #|  (memory 1)
    #|  (export "memory" (memory 0))
    #|  (func (export "run") (result i32)
    #|    i32.const 8
    #|    i32.const 16
    #|    i32.store
    #|    i32.const 12
    #|    i32.const 100
    #|    i32.store
    #|    i32.const 0
    #|    i32.const 8
    #|    i32.const 1
    #|    i32.const 4
    #|    call $fd_read
    #|    drop
    #|    i32.const 4
    #|    i32.load))
  let handle = wasi_job_spawn_wat_or_raise(
    wat,
    "run",
    "src/testdata/wasm_job_input.txt",
  )
  let result = wasi_job_join_or_raise(handle)
  assert_eq(result, 5)
}
