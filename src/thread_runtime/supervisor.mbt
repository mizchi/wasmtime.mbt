///|
/// Restart strategy for supervised children.
pub(all) enum RestartStrategy {
  OneForOne
  OneForAll
  RestForOne
}

///|
/// Restart policy per child.
pub(all) enum RestartPolicy {
  Permanent
  Transient
  Temporary
}

///|
/// Exit reason from a wasm thread.
pub enum ExitReason {
  Normal
  Trap(Error)
  Timeout
}

///|
/// Supervisor run result.
pub enum SupervisorResult {
  Completed(Int)
  RestartLimit(String, Int, ExitReason)
  Timeout(Int, Array[PendingHandle])
}

///|
/// Child spec for supervisor.
pub struct ChildSpec {
  id : String
  start : (ThreadRuntime) -> Result[ThreadHandle, Error]
  restart : RestartPolicy
}

///|
/// Pending handle for timeout.
pub struct PendingHandle {
  id : String
  handle : ThreadHandle
}

///|
/// Supervisor spec.
pub struct SupervisorSpec {
  strategy : RestartStrategy
  max_restarts : Int
  backoff_iters : Int
  poll_iters : Int
  poll_backoff_iters : Int
}

///|
/// Create a child spec.
pub fn child_spec(
  id : String,
  start : (ThreadRuntime) -> Result[ThreadHandle, Error],
  restart? : RestartPolicy = RestartPolicy::Permanent,
) -> ChildSpec {
  ChildSpec::{ id, start, restart }
}

///|
/// Create a child spec from WAT.
pub fn child_wat(
  id : String,
  wat : String,
  entry : String,
  args : Bytes,
  restart? : RestartPolicy = RestartPolicy::Permanent,
) -> ChildSpec {
  child_spec(id, rt => thread_runtime_spawn_wat(rt, wat, entry, args), restart~)
}

///|
/// Create a child spec from WASM bytes.
pub fn child_wasm(
  id : String,
  wasm : Bytes,
  entry : String,
  args : Bytes,
  restart? : RestartPolicy = RestartPolicy::Permanent,
) -> ChildSpec {
  child_spec(
    id,
    rt => thread_runtime_spawn_wasm(rt, wasm, entry, args),
    restart~,
  )
}

///|
/// Create a supervisor spec.
pub fn supervisor_spec(
  strategy? : RestartStrategy = RestartStrategy::OneForOne,
  max_restarts? : Int = 3,
  backoff_iters? : Int = 0,
  poll_iters? : Int = -1,
  poll_backoff_iters? : Int = 0,
) -> SupervisorSpec {
  SupervisorSpec::{
    strategy,
    max_restarts,
    backoff_iters,
    poll_iters,
    poll_backoff_iters,
  }
}

///|
/// All restart strategies.
pub fn restart_strategy_variants() -> Array[RestartStrategy] {
  [
    RestartStrategy::OneForOne,
    RestartStrategy::OneForAll,
    RestartStrategy::RestForOne,
  ]
}

///|
/// All restart policies.
pub fn restart_policy_variants() -> Array[RestartPolicy] {
  [RestartPolicy::Permanent, RestartPolicy::Transient, RestartPolicy::Temporary]
}

///|
/// Run supervised children until completion or restart limit.
pub fn supervisor_run(
  rt : ThreadRuntime,
  spec : SupervisorSpec,
  children : Array[ChildSpec],
) -> Result[SupervisorResult, Error] {
  if children.is_empty() {
    return Ok(SupervisorResult::Completed(0))
  }
  let mut restarts = 0
  let mut active = children.copy()
  while active.length() > 0 {
    let handles_result = spawn_all(rt, active)
    let handles = match handles_result {
      Ok(xs) => xs
      Err(err) => return Err(err)
    }
    let (exits, pending) = join_all(
      active,
      handles,
      spec.poll_iters,
      spec.poll_backoff_iters,
    )
    if pending.length() > 0 {
      return Ok(SupervisorResult::Timeout(restarts, pending))
    }
    match find_first_restart(active, exits) {
      None => return Ok(SupervisorResult::Completed(restarts))
      Some((idx, reason)) => {
        if not(restart_allowed(restarts, spec)) {
          return Ok(
            SupervisorResult::RestartLimit(active[idx].id, restarts, reason),
          )
        }
        restarts = restarts + 1
        spin_backoff(spec.backoff_iters)
        active = next_children(active, exits, spec.strategy, idx)
      }
    }
  }
  Ok(SupervisorResult::Completed(restarts))
}

///|
fn spawn_all(
  rt : ThreadRuntime,
  children : Array[ChildSpec],
) -> Result[Array[ThreadHandle], Error] {
  let handles = Array::new()
  for child in children {
    match (child.start)(rt) {
      Ok(handle) => handles.push(handle)
      Err(err) => return Err(err)
    }
  }
  Ok(handles)
}

///|
fn join_all(
  children : Array[ChildSpec],
  handles : Array[ThreadHandle],
  poll_iters : Int,
  poll_backoff_iters : Int,
) -> (Array[ExitReason], Array[PendingHandle]) {
  let exits = Array::new()
  let pending = Array::new()
  for i, handle in handles {
    let reason = join_reason(handle, poll_iters, poll_backoff_iters)
    exits.push(reason)
    if reason is ExitReason::Timeout {
      pending.push(PendingHandle::{ id: children[i].id, handle })
    }
  }
  (exits, pending)
}

///|
fn join_reason(
  handle : ThreadHandle,
  poll_iters : Int,
  poll_backoff_iters : Int,
) -> ExitReason {
  if poll_iters < 0 {
    return join_blocking(handle)
  }
  let mut remain = poll_iters
  while true {
    match thread_runtime_try_join(handle) {
      Ok(true) => return ExitReason::Normal
      Ok(false) => ()
      Err(err) => return ExitReason::Trap(err)
    }
    if remain <= 0 {
      return ExitReason::Timeout
    }
    remain = remain - 1
    spin_backoff(poll_backoff_iters)
  } else {
    ExitReason::Timeout
  }
}

///|
fn join_blocking(handle : ThreadHandle) -> ExitReason {
  match thread_runtime_join(handle) {
    Ok(_) => ExitReason::Normal
    Err(err) => ExitReason::Trap(err)
  }
}

///|
fn should_restart(policy : RestartPolicy, reason : ExitReason) -> Bool {
  match policy {
    RestartPolicy::Permanent => true
    RestartPolicy::Transient => reason is ExitReason::Trap(_)
    RestartPolicy::Temporary => false
  }
}

///|
fn find_first_restart(
  children : Array[ChildSpec],
  exits : Array[ExitReason],
) -> (Int, ExitReason)? {
  for i, child in children {
    let reason = exits[i]
    if should_restart(child.restart, reason) {
      return Some((i, reason))
    }
  }
  None
}

///|
fn next_children(
  children : Array[ChildSpec],
  exits : Array[ExitReason],
  strategy : RestartStrategy,
  first_restart_idx : Int,
) -> Array[ChildSpec] {
  match strategy {
    RestartStrategy::OneForOne => {
      let next = Array::new()
      for i, child in children {
        if should_restart(child.restart, exits[i]) {
          next.push(child)
        }
      }
      next
    }
    RestartStrategy::OneForAll => children.copy()
    RestartStrategy::RestForOne => {
      let next = Array::new()
      let len = children.length()
      for i in first_restart_idx..<len {
        next.push(children[i])
      }
      next
    }
  }
}

///|
fn restart_allowed(restarts : Int, spec : SupervisorSpec) -> Bool {
  spec.max_restarts < 0 || restarts < spec.max_restarts
}

///|
fn spin_backoff(iters : Int) -> Unit {
  if iters <= 0 {
    ()
  } else {
    let mut sink = 0
    for _ in 0..<iters {
      sink = sink + 1
    }
    @builtin.ignore(sink)
  }
}
