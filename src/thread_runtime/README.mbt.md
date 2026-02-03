# Thread Runtime (Experimental)

This package is a placeholder for the experimental thread runtime built on top of
wasmtime + wasm threads + shared memory.

- Status: experimental
- Windows: unsupported (pthread/mmap based)
- Supervisor: OTP-ish restart strategies + polling timeout (see docs)

See `docs/thread.md` for current design notes and benchmarks.
