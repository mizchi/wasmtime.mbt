///|
/// Restart strategy for supervised children.
pub type RestartStrategy = @thread_supervisor_core.RestartStrategy

///|
/// Restart policy per child.
pub type RestartPolicy = @thread_supervisor_core.RestartPolicy

///|
/// Exit reason from a wasm thread.
pub type ExitReason = @thread_supervisor_core.ExitReason

///|
/// Supervisor run result.
pub type SupervisorResult = @thread_supervisor_core.SupervisorResult[
  ThreadHandle,
]

///|
/// Pending handle for timeout.
pub type PendingHandle = @thread_supervisor_core.PendingHandle[ThreadHandle]

///|
/// Child spec for supervisor.
pub struct ChildSpec {
  id : String
  start : (ThreadRuntime) -> Result[ThreadHandle, Error]
  restart : RestartPolicy
}

///|
/// Supervisor spec.
pub type SupervisorSpec = @thread_supervisor_core.SupervisorSpec

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
  @thread_supervisor_core.supervisor_spec(
    strategy~,
    max_restarts~,
    backoff_iters~,
    poll_iters~,
    poll_backoff_iters~,
  )
}

///|
/// All restart strategies.
pub fn restart_strategy_variants() -> Array[RestartStrategy] {
  @thread_supervisor_core.restart_strategy_variants()
}

///|
/// All restart policies.
pub fn restart_policy_variants() -> Array[RestartPolicy] {
  @thread_supervisor_core.restart_policy_variants()
}

///|
/// Run supervised children until completion or restart limit.
pub fn supervisor_run(
  rt : ThreadRuntime,
  spec : SupervisorSpec,
  children : Array[ChildSpec],
) -> Result[SupervisorResult, Error] {
  let core_children : Array[@thread_supervisor_core.ChildSpec[ThreadHandle]] = []
  for child in children {
    core_children.push(
      @thread_supervisor_core.child_spec(
        child.id,
        () => (child.start)(rt),
        restart=child.restart,
      ),
    )
  }
  @thread_supervisor_core.supervisor_run(
    spec, core_children, join_blocking, try_join,
  )
}

///|
fn join_blocking(handle : ThreadHandle) -> Result[Unit, Error] {
  thread_runtime_join(handle)
}

///|
fn try_join(handle : ThreadHandle) -> Result[Bool, Error] {
  thread_runtime_try_join(handle)
}
