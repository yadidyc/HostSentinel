///|
/// Response operations that can be described by a plan.
pub(all) enum ResponseActionKind {
  IsolateHost
  TerminateProcess
  CollectArtifact
  BlockNetwork
  NotifyAnalyst
} derive(Debug, Eq)

///|
/// Errors raised while constructing a response plan.
pub(all) suberror ResponsePlanError {
  EmptyPlanId
  EmptyPlanName
  EmptyActionSequence
  EmptyActionId
  EmptyActionTarget
  EmptyActionReason
  DuplicateActionId
} derive(Debug, Eq)

///|
/// One ordered response operation in a plan.
pub struct ResponseAction {
  id : String
  kind : ResponseActionKind
  target : String
  reason : String
} derive(Debug, Eq)

///|
/// Creates a validated response operation without executing it.
pub fn ResponseAction::new(
  id~ : String,
  kind~ : ResponseActionKind,
  target~ : String,
  reason~ : String,
) -> ResponseAction raise ResponsePlanError {
  if id.trim() == "" {
    raise ResponsePlanError::EmptyActionId
  }
  if target.trim() == "" {
    raise ResponsePlanError::EmptyActionTarget
  }
  if reason.trim() == "" {
    raise ResponsePlanError::EmptyActionReason
  }
  {
    id: id.trim().to_owned(),
    kind,
    target: target.trim().to_owned(),
    reason: reason.trim().to_owned(),
  }
}

///|
/// Returns the stable action identifier.
pub fn ResponseAction::id(self : ResponseAction) -> String {
  self.id
}

///|
/// Returns the operation kind.
pub fn ResponseAction::kind(self : ResponseAction) -> ResponseActionKind {
  self.kind
}

///|
/// Returns the operation target.
pub fn ResponseAction::target(self : ResponseAction) -> String {
  self.target
}

///|
/// Returns why the operation is planned.
pub fn ResponseAction::reason(self : ResponseAction) -> String {
  self.reason
}

///|
/// An ordered, declarative response plan.
pub struct ResponsePlan {
  id : String
  name : String
  actions : Array[ResponseAction]
} derive(Debug, Eq)

///|
/// Creates a plan after validating its identity and action sequence.
pub fn ResponsePlan::new(
  id~ : String,
  name~ : String,
  actions~ : Array[ResponseAction],
) -> ResponsePlan raise ResponsePlanError {
  if id.trim() == "" {
    raise ResponsePlanError::EmptyPlanId
  }
  if name.trim() == "" {
    raise ResponsePlanError::EmptyPlanName
  }
  if actions.length() == 0 {
    raise ResponsePlanError::EmptyActionSequence
  }
  let seen : Array[String] = []
  for action in actions {
    if seen.contains(action.id()) {
      raise ResponsePlanError::DuplicateActionId
    }
    seen.push(action.id())
  }
  { id: id.trim().to_owned(), name: name.trim().to_owned(), actions, }
}

///|
/// Returns the stable plan identifier.
pub fn ResponsePlan::id(self : ResponsePlan) -> String {
  self.id
}

///|
/// Returns the human-readable plan name.
pub fn ResponsePlan::name(self : ResponsePlan) -> String {
  self.name
}

///|
/// Returns actions in their declared execution order.
pub fn ResponsePlan::actions(self : ResponsePlan) -> Array[ResponseAction] {
  self.actions
}

///|
/// The outcome recorded for an operation in a dry-run report.
pub(all) enum DryRunOutcome {
  WouldExecute
} derive(Debug, Eq)

///|
/// One simulated response step.
pub struct DryRunStep {
  action_id : String
  kind : ResponseActionKind
  target : String
  reason : String
  outcome : DryRunOutcome
} derive(Debug, Eq)

///|
/// Returns the simulated action identifier.
pub fn DryRunStep::action_id(self : DryRunStep) -> String {
  self.action_id
}

///|
/// Returns the simulated operation kind.
pub fn DryRunStep::kind(self : DryRunStep) -> ResponseActionKind {
  self.kind
}

///|
/// Returns the simulated operation target.
pub fn DryRunStep::target(self : DryRunStep) -> String {
  self.target
}

///|
/// Returns the reason carried into the simulation.
pub fn DryRunStep::reason(self : DryRunStep) -> String {
  self.reason
}

///|
/// Returns the non-executing dry-run outcome.
pub fn DryRunStep::outcome(self : DryRunStep) -> DryRunOutcome {
  self.outcome
}

///|
/// A deterministic simulation report for a response plan and alert.
pub struct DryRunReport {
  plan_id : String
  alert_id : String
  host_id : HostId
  steps : Array[DryRunStep]
} derive(Debug, Eq)

///|
/// Returns the plan represented by the report.
pub fn DryRunReport::plan_id(self : DryRunReport) -> String {
  self.plan_id
}

///|
/// Returns the alert that provided the simulation context.
pub fn DryRunReport::alert_id(self : DryRunReport) -> String {
  self.alert_id
}

///|
/// Returns the host targeted by the alert context.
pub fn DryRunReport::host_id(self : DryRunReport) -> HostId {
  self.host_id
}

///|
/// Returns simulated steps in plan order.
pub fn DryRunReport::steps(self : DryRunReport) -> Array[DryRunStep] {
  self.steps
}

///|
/// Simulates a response plan without executing or mutating any operation.
pub fn dry_run_response(plan : ResponsePlan, alert : Alert) -> DryRunReport {
  let steps : Array[DryRunStep] = []
  for action in plan.actions() {
    steps.push({
      action_id: action.id(),
      kind: action.kind(),
      target: action.target(),
      reason: action.reason(),
      outcome: DryRunOutcome::WouldExecute,
    })
  }
  {
    plan_id: plan.id(),
    alert_id: alert.id(),
    host_id: alert.detection().host_id(),
    steps,
  }
}
