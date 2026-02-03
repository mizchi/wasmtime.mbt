///|
/// Target directory under _build.
pub(all) enum WasmTarget {
  Wasm
  WasmGc
}

///|
/// Build profile directory under _build.
pub(all) enum BuildProfile {
  Debug
  Release
}

///|
pub fn wasm_target_variants() -> Array[WasmTarget] {
  [WasmTarget::Wasm, WasmTarget::WasmGc]
}

///|
pub fn build_profile_variants() -> Array[BuildProfile] {
  [BuildProfile::Debug, BuildProfile::Release]
}

///|
fn target_dir(target : WasmTarget) -> String {
  match target {
    WasmTarget::Wasm => "wasm"
    WasmTarget::WasmGc => "wasm-gc"
  }
}

///|
fn profile_dir(profile : BuildProfile) -> String {
  match profile {
    BuildProfile::Debug => "debug"
    BuildProfile::Release => "release"
  }
}

///|
/// Convert a full module path into a package path.
///
/// Example:
/// - module_path: "mizchi/testapp/internal/worker"
/// - module_name: "mizchi/testapp"
/// - result: "internal/worker"
///
/// If module_name is not a prefix, module_path is returned as-is.
pub fn package_path_from_module(
  module_path : String,
  module_name? : String = "mizchi/wasmtime",
) -> String {
  if module_name == "" {
    module_path
  } else {
    let prefix = "\{module_name}/"
    match module_path.strip_prefix(prefix) {
      Some(view) => view.to_string()
      None => module_path
    }
  }
}

///|
/// Extract package name from a package path.
pub fn package_name(package_path : String) -> String {
  let mut last = package_path[:]
  for part in package_path.split("/") {
    last = part
  }
  last.to_string()
}

///|
/// Resolve a wasm artifact path from a package path.
///
/// Example:
/// - package_path: "internal/worker"
/// - path: "_build/wasm/release/build/internal/worker/worker.wasm"
pub fn artifact_path_for_package(
  package_path : String,
  target? : WasmTarget = WasmTarget::Wasm,
  profile? : BuildProfile = BuildProfile::Release,
) -> String {
  let target_name = target_dir(target)
  let profile_name = profile_dir(profile)
  let pkg_name = package_name(package_path)
  "_build/\{target_name}/\{profile_name}/build/\{package_path}/\{pkg_name}.wasm"
}

///|
/// Resolve a wasm artifact path from a full module path.
pub fn artifact_path_from_module(
  module_path : String,
  module_name? : String = "mizchi/wasmtime",
  target? : WasmTarget = WasmTarget::Wasm,
  profile? : BuildProfile = BuildProfile::Release,
) -> String {
  let package_path = package_path_from_module(module_path, module_name=module_name)
  artifact_path_for_package(package_path, target=target, profile=profile)
}

///|
/// Read wasm bytes resolved from a module path.
pub fn artifact_bytes_from_module_result(
  module_path : String,
  module_name? : String = "mizchi/wasmtime",
  target? : WasmTarget = WasmTarget::Wasm,
  profile? : BuildProfile = BuildProfile::Release,
) -> Result[Bytes, Error] {
  let path = artifact_path_from_module(
    module_path,
    module_name=module_name,
    target=target,
    profile=profile,
  )
  @wasi.read_file_bytes_result(path)
}

///|
/// Best-effort workspace root derived from a path.
pub fn workspace_root_from_path(path : String) -> String {
  match path.find("/_build/") {
    Some(idx) => path.unsafe_substring(start=0, end=idx)
    None => path
  }
}

///|
/// Best-effort workspace root derived from current directory.
pub fn workspace_root_from_cwd() -> String? {
  match @env.current_dir() {
    Some(dir) => Some(workspace_root_from_path(dir))
    None => None
  }
}

///|
/// Short alias for artifact_path_from_module.
pub fn from_moonbit_module(
  module_path : String,
  module_name? : String = "mizchi/wasmtime",
  target? : WasmTarget = WasmTarget::Wasm,
  profile? : BuildProfile = BuildProfile::Release,
  root? : String = "",
) -> String {
  let path = artifact_path_from_module(
    module_path,
    module_name=module_name,
    target=target,
    profile=profile,
  )
  if root == "" {
    path
  } else {
    "\{root}/\{path}"
  }
}

///|
/// Short alias for artifact_bytes_from_module_result.
pub fn bytes_from_moonbit_module(
  module_path : String,
  module_name? : String = "mizchi/wasmtime",
  target? : WasmTarget = WasmTarget::Wasm,
  profile? : BuildProfile = BuildProfile::Release,
  root? : String = "",
) -> Result[Bytes, Error] {
  let path = from_moonbit_module(
    module_path,
    module_name=module_name,
    target=target,
    profile=profile,
    root=root,
  )
  from_wasm_bytes(path)
}

///|
/// Read wasm bytes from an explicit file path (e.g. Rust/Zig artifacts).
pub fn from_wasm_bytes(path : String) -> Result[Bytes, Error] {
  @wasi.read_file_bytes_result(path)
}
