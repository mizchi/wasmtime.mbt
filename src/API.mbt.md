# API Documentation

## version

Get the Wasmtime version string from the native library.

```mbt test
inspect(version().length() > 0, content="true")
```

## engine_new / engine_delete

Create and destroy a Wasmtime engine (opaque pointer from the C API).

```mbt nocheck
let engine = engine_new()
engine_delete(engine)
```
