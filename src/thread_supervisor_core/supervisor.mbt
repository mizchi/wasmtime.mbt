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
/// Exit reason from a worker.
pub enum ExitReason {
  Normal
  Trap(Error)
  Timeout
}

///|
/// Supervisor run result.
pub enum SupervisorResult[H] {
  Completed(Int)
  RestartLimit(String, Int, ExitReason)
  Timeout(Int, Array[PendingHandle[H]])
}

///|
/// Child spec for supervisor.
pub struct ChildSpec[H] {
  id : String
  start : () -> Result[H, Error]
  restart : RestartPolicy
}

///|
/// Pending handle for timeout.
pub struct PendingHandle[H] {
  id : String
  handle : H
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
pub fn[H] child_spec(
  id : String,
  start : () -> Result[H, Error],
  restart? : RestartPolicy = RestartPolicy::Permanent,
) -> ChildSpec[H] {
  ChildSpec::{ id, start, restart }
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
pub fn[H] supervisor_run(
  spec : SupervisorSpec,
  children : Array[ChildSpec[H]],
  join_blocking : (H) -> Result[Unit, Error],
  try_join : (H) -> Result[Bool, Error],
) -> Result[SupervisorResult[H], Error] {
  if children.is_empty() {
    return Ok(SupervisorResult::Completed(0))
  }
  let mut restarts = 0
  let mut active = children.copy()
  while active.length() > 0 {
    let handles_result = spawn_all(active)
    let handles = match handles_result {
      Ok(xs) => xs
      Err(err) => return Err(err)
    }
    let (exits, pending) = join_all(
      active,
      handles,
      spec.poll_iters,
      spec.poll_backoff_iters,
      join_blocking,
      try_join,
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
fn[H] spawn_all(children : Array[ChildSpec[H]]) -> Result[Array[H], Error] {
  let handles : Array[H] = []
  for child in children {
    match (child.start)() {
      Ok(handle) => handles.push(handle)
      Err(err) => return Err(err)
    }
  }
  Ok(handles)
}

///|
fn[H] join_all(
  children : Array[ChildSpec[H]],
  handles : Array[H],
  poll_iters : Int,
  poll_backoff_iters : Int,
  join_blocking : (H) -> Result[Unit, Error],
  try_join : (H) -> Result[Bool, Error],
) -> (Array[ExitReason], Array[PendingHandle[H]]) {
  let exits : Array[ExitReason] = []
  let pending : Array[PendingHandle[H]] = []
  for i, handle in handles {
    let reason = join_reason(
      handle, poll_iters, poll_backoff_iters, join_blocking, try_join,
    )
    exits.push(reason)
    if reason is ExitReason::Timeout {
      pending.push(PendingHandle::{ id: children[i].id, handle })
    }
  }
  (exits, pending)
}

///|
fn[H] join_reason(
  handle : H,
  poll_iters : Int,
  poll_backoff_iters : Int,
  join_blocking : (H) -> Result[Unit, Error],
  try_join : (H) -> Result[Bool, Error],
) -> ExitReason {
  if poll_iters < 0 {
    return join_blocking_reason(handle, join_blocking)
  }
  let mut remain = poll_iters
  while true {
    let join_result = try_join(handle)
    guard join_result is Ok(done) else {
      return ExitReason::Trap(join_result.unwrap_err())
    }
    if done {
      return ExitReason::Normal
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
fn[H] join_blocking_reason(
  handle : H,
  join_blocking : (H) -> Result[Unit, Error],
) -> ExitReason {
  match join_blocking(handle) {
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
fn[H] find_first_restart(
  children : Array[ChildSpec[H]],
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
fn[H] next_children(
  children : Array[ChildSpec[H]],
  exits : Array[ExitReason],
  strategy : RestartStrategy,
  first_restart_idx : Int,
) -> Array[ChildSpec[H]] {
  match strategy {
    RestartStrategy::OneForOne => {
      let next : Array[ChildSpec[H]] = []
      for i, child in children {
        if should_restart(child.restart, exits[i]) {
          next.push(child)
        }
      }
      next
    }
    RestartStrategy::OneForAll => children.copy()
    RestartStrategy::RestForOne => {
      let next : Array[ChildSpec[H]] = []
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
