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
/// Re-export core types for convenience.
pub type WasiConfig = @wasmtime.WasiConfig
pub type Engine = @wasmtime.Engine
pub type Context = @wasmtime.Context
pub type Linker = @wasmtime.Linker
pub type WasmtimeStore = @wasmtime.WasmtimeStore

///|
/// Create a WASI config.
pub fn wasi_config_new_or_raise() -> WasiConfig {
  let config = @wasmtime.wasi_config_new()
  config
}

///|
/// Set stdin file path for WASI.
pub fn wasi_config_set_stdin_file_or_raise(
  config : WasiConfig,
  path : String,
) -> Unit raise {
  let bytes = @utf8.encode(path)
  if not(@wasmtime.wasi_config_set_stdin_file_bytes(config, bytes, bytes.length())) {
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
  if not(@wasmtime.wasi_config_set_stdout_file_bytes(config, bytes, bytes.length())) {
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
  if not(@wasmtime.wasi_config_set_stderr_file_bytes(config, bytes, bytes.length())) {
    fail("wasi_config_set_stderr_file failed")
  }
}

///|
/// Inherit stdio from host process.
pub fn wasi_config_inherit_stdio(config : WasiConfig) -> Unit {
  @wasmtime.wasi_config_inherit_stdin(config)
  @wasmtime.wasi_config_inherit_stdout(config)
  @wasmtime.wasi_config_inherit_stderr(config)
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
  if not(@wasmtime.wasi_config_preopen_dir_bytes(
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
  let err = @wasmtime.context_set_wasi(context, config)
  if not(@wasmtime.error_is_null(err)) {
    @wasmtime.error_delete(err)
    fail("context_set_wasi failed")
  }
}

///|
/// Create a WASI-enabled store/context pair.
pub fn wasi_context_new_or_raise(
  engine : Engine,
  config : WasiConfig,
) -> (WasmtimeStore, Context) raise {
  let store = @wasmtime.wasmtime_store_new(engine)
  let context = @wasmtime.wasmtime_store_context(store)
  context_set_wasi_or_raise(context, config)
  (store, context)
}

///|
/// Create a WASI-enabled store/context and linker.
pub fn wasi_context_linker_new_or_raise(
  engine : Engine,
  config : WasiConfig,
) -> (WasmtimeStore, Context, Linker) raise {
  let (store, context) = wasi_context_new_or_raise(engine, config)
  let linker = @wasmtime.linker_new(engine)
  @wasmtime.linker_define_wasi_or_raise(linker)
  (store, context, linker)
}

///|
/// Create a WASI-enabled store/context/linker with stdio files.
pub fn wasi_context_linker_with_stdio_files_or_raise(
  engine : Engine,
  stdin_path? : String = "",
  stdout_path? : String = "",
  stderr_path? : String = "",
) -> (WasmtimeStore, Context, Linker) raise {
  let wasi = wasi_config_new_or_raise()
  if stdin_path.length() > 0 {
    wasi_config_set_stdin_file_or_raise(wasi, stdin_path)
  }
  if stdout_path.length() > 0 {
    wasi_config_set_stdout_file_or_raise(wasi, stdout_path)
  }
  if stderr_path.length() > 0 {
    wasi_config_set_stderr_file_or_raise(wasi, stderr_path)
  }
  wasi_context_linker_new_or_raise(engine, wasi)
}

///|
/// Create a WASI-enabled store/context/linker with a preopened directory.
pub fn wasi_context_linker_with_preopen_or_raise(
  engine : Engine,
  host_path : String,
  guest_path? : String = ".",
  dir_perms? : WasiDirPerms = WASI_DIR_PERMS_READ,
  file_perms? : WasiFilePerms = WASI_FILE_PERMS_READ,
) -> (WasmtimeStore, Context, Linker) raise {
  let wasi = wasi_config_new_or_raise()
  wasi_config_preopen_dir_or_raise(
    wasi,
    host_path,
    guest_path=guest_path,
    dir_perms=dir_perms,
    file_perms=file_perms,
  )
  wasi_context_linker_new_or_raise(engine, wasi)
}
