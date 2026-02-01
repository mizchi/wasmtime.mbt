///|
/// Return the Wasmtime version string reported by the native library.
pub fn version() -> String {
  @utf8.decode_lossy(wasmtime_version_bytes())
}
