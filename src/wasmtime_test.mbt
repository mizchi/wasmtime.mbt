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
