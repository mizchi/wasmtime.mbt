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
