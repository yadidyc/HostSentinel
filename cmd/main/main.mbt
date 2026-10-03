///|
/// Command-line entry point for hunting and response workflows.
fn main {
  let args = @env.args()
  match args[1:] {
    [] | ["--help"] => print_help()
    ["--version"] => println("\{@core.project_name()} v\{@core.version()}")
    ["hunt", .. rest] => run_hunt(rest.to_owned())
    ["response", "dry-run", .. rest] => run_response_dry_run(rest.to_owned())
    ["response", ..] => print_response_help()
    _ => {
      println("unknown command")
      print_help()
    }
  }
}

///|
fn print_help() -> Unit {
  println("\{@core.project_name()} v\{@core.version()}")
  println("Usage:")
  println("  hostsentinel hunt --event <jsonl>")
  println("  hostsentinel response dry-run --event <jsonl> [--alert-id <id>]")
  println("  hostsentinel --version")
}

///|
fn print_hunt_help() -> Unit {
  println("Usage: hostsentinel hunt --event <jsonl>")
  println("Normalize one JSONL event and print its hunting summary.")
}

///|
fn print_response_help() -> Unit {
  println(
    "Usage: hostsentinel response dry-run --event <jsonl> [--alert-id <id>]",
  )
  println(
    "Build an alert context and print response actions without executing them.",
  )
}

///|
fn option_value(args : Array[String], option : String) -> String? {
  for index, value in args {
    if value == option && index + 1 < args.length() {
      return Some(args[index + 1])
    }
  }
  None
}

///|
fn run_hunt(args : Array[String]) -> Unit {
  if args is ["--help"] {
    print_hunt_help()
    return
  }
  match option_value(args, "--event") {
    Some(source) =>
      try @core.normalize_jsonl(source) catch {
        _ => println("hunt: invalid JSONL input")
      } noraise {
        events => {
          println("hunt: normalized_events=\{events.length()}")
          for event in events {
            println(
              "event id=\{event.event().id().as_string()} host=\{event.event().host_id().as_string()} kind=\{kind_token(event.event().kind())} severity=\{severity_token(event.event().severity())} fingerprint=\{event.fingerprint()}",
            )
          }
        }
      }
    None => print_hunt_help()
  }
}

///|
fn run_response_dry_run(args : Array[String]) -> Unit {
  if args is ["--help"] {
    print_response_help()
    return
  }
  let event_source = match option_value(args, "--event") {
    Some(source) => source
    None => {
      print_response_help()
      return
    }
  }
  let alert_id = match option_value(args, "--alert-id") {
    Some(value) => value
    None => "cli-alert"
  }
  try @core.normalize_jsonl(event_source) catch {
    _ => println("response dry-run: invalid JSONL input")
  } noraise {
    events => {
      if events.length() == 0 {
        println("response dry-run: no events supplied")
        return
      }
      let event = events[0]
      let rule = try! @core.Rule::new(
        id="cli-event",
        name="CLI event context",
        description="Creates a deterministic dry-run context",
        version=1,
        condition=@core.RuleCondition::EventKindIs(event.event().kind()),
      )
      let observation = @core.EventObservation::new(
        event~,
        hits=@core.evaluate_rules([rule], event, []),
      )
      let pattern = try! @core.CorrelationPattern::new(
        id="cli-event-sequence",
        name="CLI event sequence",
        rule_ids=["cli-event"],
        window_seconds=60,
      )
      let detection = @core.correlate(pattern, [observation])[0]
      let score = @core.score_detection(detection, [observation])
      let alert = try! @core.Alert::new(
        id=alert_id,
        detection~,
        score~,
        created_at=event.event().observed_at(),
      )
      let isolate = try! @core.ResponseAction::new(
        id="cli-isolate-host",
        kind=@core.ResponseActionKind::IsolateHost,
        target=event.event().host_id().as_string(),
        reason="Contain the host for analyst review",
      )
      let notify = try! @core.ResponseAction::new(
        id="cli-notify-analyst",
        kind=@core.ResponseActionKind::NotifyAnalyst,
        target="on-call",
        reason="Notify the analyst about the dry-run response",
      )
      let plan = try! @core.ResponsePlan::new(
        id="cli-containment",
        name="CLI containment response",
        actions=[isolate, notify],
      )
      let report = @core.dry_run_response(plan, alert)
      println(
        "response dry-run: alert=\{report.alert_id()} host=\{report.host_id().as_string()} risk=\{alert.score().value()} status=\{alert_status_token(alert.status())}",
      )
      for index, step in report.steps() {
        println(
          "step=\{index + 1} action=\{step.action_id()} kind=\{action_kind_token(step.kind())} target=\{step.target()} outcome=\{dry_run_outcome_token(step.outcome())}",
        )
      }
    }
  }
}

///|
fn kind_token(kind : @core.EventKind) -> String {
  match kind {
    @core.EventKind::Process => "process"
    @core.EventKind::File => "file"
    @core.EventKind::Network => "network"
    @core.EventKind::Authentication => "authentication"
    @core.EventKind::Persistence => "persistence"
  }
}

///|
fn severity_token(severity : @core.Severity) -> String {
  match severity {
    @core.Severity::Informational => "informational"
    @core.Severity::Low => "low"
    @core.Severity::Medium => "medium"
    @core.Severity::High => "high"
    @core.Severity::Critical => "critical"
  }
}

///|
fn action_kind_token(kind : @core.ResponseActionKind) -> String {
  match kind {
    @core.ResponseActionKind::IsolateHost => "isolate_host"
    @core.ResponseActionKind::TerminateProcess => "terminate_process"
    @core.ResponseActionKind::CollectArtifact => "collect_artifact"
    @core.ResponseActionKind::BlockNetwork => "block_network"
    @core.ResponseActionKind::NotifyAnalyst => "notify_analyst"
  }
}

///|
fn dry_run_outcome_token(outcome : @core.DryRunOutcome) -> String {
  match outcome {
    @core.DryRunOutcome::WouldExecute => "would_execute"
  }
}

///|
fn alert_status_token(status : @core.AlertStatus) -> String {
  match status {
    @core.AlertStatus::Open => "open"
    @core.AlertStatus::Acknowledged => "acknowledged"
    @core.AlertStatus::InProgress => "in_progress"
    @core.AlertStatus::Resolved => "resolved"
    @core.AlertStatus::Suppressed => "suppressed"
  }
}
