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
