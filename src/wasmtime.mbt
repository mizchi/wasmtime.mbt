///|
/// Return the Wasmtime version string reported by the native library.
pub fn version() -> String {
  @utf8.decode_lossy(wasmtime_version_bytes())
}

///|
/// Set the target triple for a config. Returns null on success.
pub fn config_target_set(config : Config, target : String) -> WasmtimeError {
  let bytes = @utf8.encode(target)
  config_target_set_bytes(config, bytes, bytes.length())
}

///|
/// Load a cache config. Returns null on success.
pub fn config_cache_config_load(config : Config, path : String) -> WasmtimeError {
  let bytes = @utf8.encode(path)
  config_cache_config_load_bytes(config, bytes, bytes.length())
}

///|
/// Load the default cache config (pass NULL path). Returns null on success.
pub fn config_cache_config_load_default(config : Config) -> WasmtimeError {
  let bytes = Bytes::make(0, 0)
  config_cache_config_load_bytes(config, bytes, 0)
}

///|
/// Enable a Cranelift flag by name.
pub fn config_cranelift_flag_enable(config : Config, flag : String) -> Unit {
  let bytes = @utf8.encode(flag)
  config_cranelift_flag_enable_bytes(config, bytes, bytes.length())
}

///|
/// Set a Cranelift flag by name to a value.
pub fn config_cranelift_flag_set(config : Config, key : String, value : String) -> Unit {
  let key_bytes = @utf8.encode(key)
  let value_bytes = @utf8.encode(value)
  config_cranelift_flag_set_bytes(
    config,
    key_bytes,
    key_bytes.length(),
    value_bytes,
    value_bytes.length(),
  )
}
