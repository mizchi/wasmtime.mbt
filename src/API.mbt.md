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

## store_new / store_delete

Create and destroy a store associated with an engine.

```mbt nocheck
let engine = engine_new()
let store = store_new(engine)
store_delete(store)
engine_delete(engine)
```
