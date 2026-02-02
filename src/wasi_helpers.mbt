///|
/// WASI directory permission flags.
pub type WasiDirPerms = Int

pub const WASI_DIR_PERMS_READ : WasiDirPerms = 1
pub const WASI_DIR_PERMS_WRITE : WasiDirPerms = 2

///|
/// WASI file permission flags.
pub type WasiFilePerms = Int

pub const WASI_FILE_PERMS_READ : WasiFilePerms = 1
pub const WASI_FILE_PERMS_WRITE : WasiFilePerms = 2

///|
/// Create a WASI config.
pub fn wasi_config_new_or_raise() -> WasiConfig {
  let config = wasi_config_new()
  config
}

///|
/// Set stdin file path for WASI.
pub fn wasi_config_set_stdin_file_or_raise(
  config : WasiConfig,
  path : String,
) -> Unit raise {
  let bytes = @utf8.encode(path)
  if not(wasi_config_set_stdin_file_bytes(config, bytes, bytes.length())) {
    fail("wasi_config_set_stdin_file failed")
  }
}

///|
/// Set stdout file path for WASI.
pub fn wasi_config_set_stdout_file_or_raise(
  config : WasiConfig,
  path : String,
) -> Unit raise {
  let bytes = @utf8.encode(path)
  if not(wasi_config_set_stdout_file_bytes(config, bytes, bytes.length())) {
    fail("wasi_config_set_stdout_file failed")
  }
}

///|
/// Set stderr file path for WASI.
pub fn wasi_config_set_stderr_file_or_raise(
  config : WasiConfig,
  path : String,
) -> Unit raise {
  let bytes = @utf8.encode(path)
  if not(wasi_config_set_stderr_file_bytes(config, bytes, bytes.length())) {
    fail("wasi_config_set_stderr_file failed")
  }
}

///|
/// Inherit stdio from host process.
pub fn wasi_config_inherit_stdio(config : WasiConfig) -> Unit {
  wasi_config_inherit_stdin(config)
  wasi_config_inherit_stdout(config)
  wasi_config_inherit_stderr(config)
}

///|
/// Preopen a host directory for WASI.
pub fn wasi_config_preopen_dir_or_raise(
  config : WasiConfig,
  host_path : String,
  guest_path? : String = ".",
  dir_perms? : WasiDirPerms = WASI_DIR_PERMS_READ,
  file_perms? : WasiFilePerms = WASI_FILE_PERMS_READ,
) -> Unit raise {
  let host_bytes = @utf8.encode(host_path)
  let guest_bytes = @utf8.encode(guest_path)
  if not(wasi_config_preopen_dir_bytes(
    config,
    host_bytes,
    host_bytes.length(),
    guest_bytes,
    guest_bytes.length(),
    dir_perms,
    file_perms,
  )) {
    fail("wasi_config_preopen_dir failed")
  }
}

///|
/// Set WASI config on a context (consumes config).
pub fn context_set_wasi_or_raise(
  context : Context,
  config : WasiConfig,
) -> Unit raise {
  let err = context_set_wasi(context, config)
  if not(error_is_null(err)) {
    error_delete(err)
    fail("context_set_wasi failed")
  }
}
