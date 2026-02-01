///|
/// Opaque WebAssembly engine type from the C API.
pub type Engine

///|
/// Raw UTF-8 bytes from `wasmtime_version()`.
extern "C" fn wasmtime_version_bytes() -> Bytes = "wasmtime_version_bytes"

///|
/// Create a new WebAssembly engine.
pub extern "C" fn engine_new() -> Engine = "wasm_engine_new"

///|
/// Destroy an engine created by `engine_new`.
#borrow(engine)
pub extern "C" fn engine_delete(engine : Engine) -> Unit = "wasm_engine_delete"
