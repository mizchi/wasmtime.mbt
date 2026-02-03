# How to use (experimental)

このリポジトリは、MoonBit をホストとして Wasmtime の wasm threads +
shared memory を使ったゲスト wasm を実行するための実験的ランタイムです。

## 前提条件

- Wasmtime の実験機能を有効化しています。
- ゲスト wasm は `env.mem` を `shared` メモリとして import し、atomic 命令を使います。
- Windows は非対応です（pthread/mmap ベース）。

## 最小例: atomic counter (WAT)

下記はホスト側の最小利用例です。WAT で共有カウンタを並列に増やし、
ホストから共有メモリを読み出します（実際に動作する例は
`src/examples/thread_runtime_basic` にあります）。

```moonbit
import @thread_runtime
import @wasmtime
import @wasm_threads_patterns

fn make_i32_args(value : Int) -> Bytes {
  let args = @wasmtime.make_val_buffer(1)
  @wasmtime.val_buffer_set_i32(args, 0, value)
  args
}

suberror ExampleError {
  ExampleError(String)
}

fn spawn_all(
  rt : @thread_runtime.ThreadRuntime,
  wat : String,
  args : Bytes,
  threads : Int,
) -> Result[Array[@thread_runtime.ThreadHandle], Error] {
  let handles : Array[@thread_runtime.ThreadHandle] = []
  for _ in 0..<threads {
    let res = rt.spawn_wat(wat, "run", args)
    guard res is Ok(handle) else {
      return Err(res.unwrap_err())
    }
    handles.push(handle)
  }
  Ok(handles)
}

fn join_all(handles : Array[@thread_runtime.ThreadHandle]) -> Result[Unit, Error] {
  for h in handles {
    let res = h.join()
    guard res is Ok(_) else {
      return Err(res.unwrap_err())
    }
  }
  Ok(())
}

fn validate_atomic_count(
  bytes : Bytes,
  threads : Int,
  iters : Int,
) -> Result[Unit, Error] {
    let count = @thread_runtime.read_u32_le(bytes, 0).to_int()
  let expected = threads * iters
  if count == expected {
    Ok(())
  } else {
    Err(
      ExampleError::ExampleError(
        "count mismatch: got=\{count} expected=\{expected}",
      ),
    )
  }
}

fn run_atomic_counter(threads : Int, iters : Int) -> Result[Unit, Error] {
  let pages = @thread_runtime.shared_pages_for_bytes(4UL)
  let wat = @wasm_threads_patterns.wat_atomic_counter(pages)
  @thread_runtime.ThreadRuntime::new(pages.to_int()).bind(rt => {
    let args = make_i32_args(iters)
    let result =
      spawn_all(rt, wat, args, threads)
      .bind(handles => join_all(handles))
      .bind(_ => rt.mem_read(0, 4))
      .bind(bytes => validate_atomic_count(bytes, threads, iters))
    rt.delete()
    result
  })
}

fn main {
  let threads = 4
  let iters = 10000
  match run_atomic_counter(threads, iters) {
    Ok(_) => println("atomic counter ok")
    Err(err) => println("atomic counter failed: \{err}")
  }
}
```

補足:

- `shared_pages_for_bytes` はバイト数を 64KiB ページ数に変換します。
- WAT のエントリポイントは `run`、引数は val buffer 経由で渡します。
- 共有メモリの読み書きは `rt.mem_read/mem_write` を使います。

## Tokio 風 API

`ThreadRuntime` と `ThreadHandle` にメソッド形式の API を追加しています。
`JoinSet` は tokio の JoinSet を意識した簡易版です。

```moonbit
let rt = match @thread_runtime.ThreadRuntime::new(pages.to_int()) {
  Ok(rt) => rt
  Err(err) => {
    println("runtime init failed: \{err}")
    return
  }
}
let set = @thread_runtime.JoinSet::new()
let handle = match rt.spawn_wat(wat, "run", args) {
  Ok(h) => h
  Err(err) => {
    println("spawn failed: \{err}")
    rt.delete()
    return
  }
}
set.push(handle)
match set.try_join_next() {
  Ok(true) => println("one task finished")
  Ok(false) => println("no task finished yet")
  Err(err) => println("join failed: \{err}")
}
rt.delete()
```

## WASM アーティファクト解決ヘルパ

`_build/wasm(-gc)/...` から wasm を探すための補助関数です。
モジュール名は同一リポジトリの `moon.mod.json` を前提にしています。

```moonbit
import @wasm_artifacts

let path = @wasm_artifacts.from_moonbit_module(
  "mizchi/testapp/internal/worker",
  module_name="mizchi/testapp",
  target=@wasm_artifacts.WasmTarget::Wasm,
)
let bytes = match @wasm_artifacts.bytes_from_moonbit_module(
  "mizchi/testapp/internal/worker",
  module_name="mizchi/testapp",
  target=@wasm_artifacts.WasmTarget::Wasm,
) {
  Ok(bytes) => bytes
  Err(err) => {
    println("wasm read failed: \{err}")
    return
  }
}
```

## 事前コンパイルした WASM を使う

WASM バイト列がある場合は `thread_runtime_spawn_wasm` を使います。

```moonbit
match rt.spawn_wasm(wasm_bytes, "run", args) {
  Ok(handle) => {
    // handle を使う
    ()
  }
  Err(err) => {
    println("spawn_wasm failed: \{err}")
    ()
  }
}
```

ゲストは `env.mem` の shared メモリ import と atomic 命令の使用が必須です。

## Supervisor (OTP-ish, experimental)

軽量な supervisor API を使うと、再起動戦略を付与できます。

```moonbit
import @thread_runtime
import @thread_runtime/supervisor

let spec = @thread_runtime/supervisor.supervisor_spec(
  strategy=@thread_runtime/supervisor.RestartStrategy::OneForOne,
  max_restarts=3,
  backoff_iters=1000,
  poll_iters=1000,
  poll_backoff_iters=100,
)
let child = @thread_runtime/supervisor.child_wat(
  "worker",
  wat,
  "run",
  args,
  restart=@thread_runtime/supervisor.RestartPolicy::Transient,
)
match @thread_runtime/supervisor.supervisor_run(rt, spec, [child]) {
  Ok(result) => {
    match result {
      @thread_runtime/supervisor.SupervisorResult::Timeout(_, pending) => {
        for item in pending {
          let _ = item.handle.detach()
        }
      }
      _ => ()
    }
  }
  Err(err) => println("supervisor_run failed: \{err}")
}
```

Supervisor を別のハンドル型で使いたい場合は、
`@thread_supervisor_core` の汎用実装を参照してください。

## Example コマンド

- thread runtime の最小例:

```bash
moon run src/examples/thread_runtime_basic --target native
```

- wasm-gc worker を native から呼び出す例:
  - worker: `src/examples/example_worker`
  - host: `src/examples/example_worker_host`
  - wasm から `run` を export するため、worker 側 `moon.pkg` に
    `link.exports = ["run"]` を追加しています。

```bash
moon build --target wasm-gc src/examples/example_worker
moon run src/examples/example_worker_host --target native
```

- thread pattern をまとめて実行:

```bash
moon run src/examples/thread_patterns -- --mode all --threads 4 --iters 1000
```

- ring queue (MPMC + spin/wait パラメータ付き):

```bash
moon run src/examples/thread_patterns -- --mode ring-mpmc --threads 4 --iters 1000 --slots 64 --spin 1000 --wait-ns 1000000
```

## 適用範囲と制約

- 実験的 API であり、仕様は変更される可能性があります。
- ゲストを強制終了する仕組みはなく、停止は共有フラグによる協調停止です。
- 現状は OS ネイティブの共有メモリより遅い傾向です（`docs/thread.md` を参照）。
