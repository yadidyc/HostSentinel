///|
/// Command-line entry point for hunting and response workflows.
async fn main {
  let args = @env.args()
  match args[1:] {
    [] | ["--help"] => {
      print_file_help()
      print_help()
    }
    ["normalize", .. rest] => run_file_normalize(rest.to_owned())
    ["rules", "validate", .. rest] => run_rule_validate(rest.to_owned())
    ["correlate", .. rest] => run_file_correlate(rest.to_owned())
    ["benchmark", .. rest] => run_file_benchmark(rest.to_owned())
    ["explain", .. rest] =>
      if option_value(rest.to_owned(), "--rule-file") is Some(_) {
        run_file_explain(rest.to_owned())
      } else {
        run_explain(rest.to_owned())
      }
    _ => run_legacy_cli(args)
  }
}

///|
fn run_legacy_cli(args : Array[String]) -> Unit {
  match args[1:] {
    [] | ["--help"] => print_help()
    ["--version"] => println("\{@core.project_name()} v\{@core.version()}")
    ["ingest", .. rest] => run_ingest(rest.to_owned())
    ["hunt", .. rest] => run_hunt(rest.to_owned())
    ["leads", .. rest] => run_leads(rest.to_owned())
    ["alerts", .. rest] => run_alerts(rest.to_owned())
    ["case", .. rest] => run_case(rest.to_owned())
    ["plan", .. rest] => run_plan(rest.to_owned())
    ["explain", .. rest] => run_explain(rest.to_owned())
    ["response", "dry-run", .. rest] => run_response_dry_run(rest.to_owned())
    ["response", ..] => print_response_help()
    _ => {
      println("unknown command")
      print_help()
    }
  }
}

///|
fn print_file_help() -> Unit {
  println("\{@core.project_name()} v\{@core.version()}")
  println("Usage:")
  println(
    "  hostsentinel normalize --events-file <path> [--format legacy|ocsf|sysmon|windows|auditd] [--host-id <id>] [--json|--jsonl]",
  )
  println("  hostsentinel rules validate --rule-file <path> [--json]")
  println(
    "  hostsentinel correlate --rule-file <path> --events-file <path> [--format legacy|ocsf|sysmon|windows|auditd] [--json|--jsonl] [--diagnostic]",
  )
  println(
    "  hostsentinel explain --rule-file <path> --events-file <path> [--format legacy|ocsf|sysmon|windows|auditd] [--json|--jsonl]",
  )
  println(
    "  hostsentinel benchmark --rule-file <path> --events-file <path> [--format legacy|ocsf|sysmon|windows|auditd] [--json]",
  )
}

///|
fn print_help() -> Unit {
  println("\{@core.project_name()} v\{@core.version()}")
  println("Usage:")
  println("  hostsentinel ingest --event <jsonl> [--json]")
  println("  hostsentinel hunt --event <jsonl> [--json]")
  println("  hostsentinel leads --event <jsonl> [--json]")
  println("  hostsentinel alerts --event <jsonl> [--alert-id <id>] [--json]")
  println("  hostsentinel case --event <jsonl> [--alert-id <id>] [--json]")
  println("  hostsentinel plan --event <jsonl> [--alert-id <id>] [--json]")
  println("  hostsentinel explain --event <jsonl> [--json]")
  println(
    "  hostsentinel response dry-run --event <jsonl> [--alert-id <id>] [--json]",
  )
  println("  hostsentinel --version")
}

///|
fn print_hunt_help() -> Unit {
  println("Usage: hostsentinel hunt --event <jsonl> [--json]")
  println("Normalize one JSONL event and print its hunting summary.")
  println("Use --json to emit a machine-readable event array.")
}

///|
fn print_leads_help() -> Unit {
  println("Usage: hostsentinel leads --event <jsonl> [--json]")
  println("Correlate login, process, and network telemetry by identity.")
}

///|
fn print_ingest_help() -> Unit {
  println("Usage: hostsentinel ingest --event <jsonl> [--json]")
  println("Normalize JSONL input and print the ingestion summary.")
}

///|
fn print_alerts_help() -> Unit {
  println(
    "Usage: hostsentinel alerts --event <jsonl> [--alert-id <id>] [--json]",
  )
  println("Build an offline alert summary from the first normalized event.")
}

///|
fn print_case_help() -> Unit {
  println("Usage: hostsentinel case --event <jsonl> [--alert-id <id>] [--json]")
  println("Build an offline case with one event evidence record.")
}

///|
fn print_plan_help() -> Unit {
  println("Usage: hostsentinel plan --event <jsonl> [--alert-id <id>] [--json]")
  println("Generate a response plan dry-run without executing actions.")
}

///|
fn print_explain_help() -> Unit {
  println("Usage: hostsentinel explain --event <jsonl> [--json]")
  println("Explain the deterministic event rule match used by the CLI context.")
}

///|
fn print_response_help() -> Unit {
  println(
    "Usage: hostsentinel response dry-run --event <jsonl> [--alert-id <id>] [--json]",
  )
  println(
    "Build an alert context and print response actions without executing them.",
  )
  println("Use --json to emit a machine-readable dry-run report.")
}

///|
fn run_ingest(args : Array[String]) -> Unit {
  if args is ["--help"] {
    print_ingest_help()
    return
  }
  match option_value(args, "--event") {
    Some(source) =>
      try @core.normalize_jsonl(source) catch {
        _ => println("ingest: invalid JSONL input")
      } noraise {
        events =>
          if has_flag(args, "--json") {
            println(hunt_json(events))
          } else {
            println("ingest: normalized_events=\{events.length()}")
            for event in events {
              println(
                "event id=\{event.event().id().as_string()} host=\{event.event().host_id().as_string()} kind=\{kind_token(event.event().kind())} severity=\{severity_token(event.event().severity())} fingerprint=\{event.fingerprint()}",
              )
            }
          }
      }
    None => print_ingest_help()
  }
}

///|
fn run_plan(args : Array[String]) -> Unit {
  if args is ["--help"] {
    print_plan_help()
  } else {
    run_response_dry_run(args)
  }
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
fn has_flag(args : Array[String], flag : String) -> Bool {
  args.contains(flag)
}

///|
fn cli_alert(event : @core.NormalizedEvent, alert_id : String) -> @core.Alert {
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
  try! @core.Alert::new(
    id=alert_id,
    detection~,
    score~,
    created_at=event.event().observed_at(),
  )
}

///|
fn cli_plan(event : @core.NormalizedEvent) -> @core.ResponsePlan {
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
  try! @core.ResponsePlan::new(
    id="cli-containment",
    name="CLI containment response",
    actions=[isolate, notify],
  )
}

///|
fn cli_case(event : @core.NormalizedEvent, alert : @core.Alert) -> @core.Case {
  let investigation = try! @core.Case::new(
    id="cli-case",
    alert~,
    actor="cli",
    opened_at=event.event().observed_at(),
  )
  let evidence = try! @core.Evidence::new(
    id="cli-event-evidence",
    kind=@core.EvidenceKind::Event,
    summary="Normalized event used to build the CLI alert context",
    source="cli",
    reference=event.fingerprint(),
    collected_at=event.event().observed_at(),
  )
  try! investigation.add_evidence(evidence~, actor="cli")
}

///|
fn json_string_array(values : Array[String]) -> String {
  values.map(value => "\"\{json_escape(value)}\"").join(",")
}

///|
fn alert_json(alert : @core.Alert) -> String {
  let detection = alert.detection()
  "{\"alert_id\":\"\{json_escape(alert.id())}\",\"host_id\":\"\{json_escape(detection.host_id().as_string())}\",\"pattern_id\":\"\{json_escape(detection.pattern_id())}\",\"rule_ids\":[\{json_string_array(detection.rule_ids())}],\"risk\":\{alert.score().value()},\"status\":\"\{alert_status_token(alert.status())}\"}"
}

///|
fn case_json(investigation : @core.Case) -> String {
  let evidence_ids = investigation.evidence().map(item => item.id())
  let audit_actions = investigation.audit_trail().map(entry => entry.action())
  "{\"case_id\":\"\{json_escape(investigation.id())}\",\"alert_id\":\"\{json_escape(investigation.alert().id())}\",\"evidence_ids\":[\{json_string_array(evidence_ids)}],\"audit_actions\":[\{json_string_array(audit_actions)}]}"
}

///|
fn explain_json(
  event : @core.NormalizedEvent,
  hits : Array[@core.RuleHit],
) -> String {
  let evidence = if hits.length() == 0 {
    "[]"
  } else {
    "[\{json_string_array(hits[0].evidence())}]"
  }
  let matched = if hits.length() > 0 { "true" } else { "false" }
  "{\"event_id\":\"\{json_escape(event.event().id().as_string())}\",\"rule_id\":\"cli-event\",\"matched\":\{matched},\"evidence\":\{evidence}}"
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
        events =>
          if has_flag(args, "--json") {
            println(hunt_json(events))
          } else {
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
fn lead_reason_token(reason : @core.LeadRejectionReason) -> String {
  match reason {
    @core.LeadRejectionReason::BootMismatch => "boot_mismatch"
    @core.LeadRejectionReason::SessionMismatch => "session_mismatch"
    @core.LeadRejectionReason::ProcessInstanceMismatch =>
      "process_instance_mismatch"
    @core.LeadRejectionReason::SourceNotIndependent => "source_not_independent"
    @core.LeadRejectionReason::TimeWindowMismatch => "time_window_mismatch"
    @core.LeadRejectionReason::InsufficientSignal => "insufficient_signal"
  }
}

///|
fn lead_evidence_json(event : @core.NormalizedEvent) -> String {
  "{\"event_id\":\"\{json_escape(event.event().id().as_string())}\",\"source\":\"\{json_escape(source_token(event.event().source()))}\",\"line_number\":\{event.line_number()},\"fingerprint\":\"\{json_escape(event.fingerprint())}\"}"
}

///|
fn lead_report_json(report : @core.SessionLeadReport) -> String {
  let leads = report
    .leads()
    .map(lead => {
      let evidence = lead.evidence().map(lead_evidence_json).join(",")
      "{\"host_id\":\"\{json_escape(lead.host_id().as_string())}\",\"session_id\":\"\{json_escape(lead.session_id())}\",\"process_key\":\"\{json_escape(lead.process_key())}\",\"evidence\":[\{evidence}]}"
    })
    .join(",")
  let rejections = report
    .rejections()
    .map(rejection => {
      "{\"event_ids\":[\{json_string_array(rejection.event_ids())}],\"reason\":\"\{lead_reason_token(rejection.reason())}\"}"
    })
    .join(",")
  "{\"leads\":[\{leads}],\"rejections\":[\{rejections}]}"
}

///|
fn run_leads(args : Array[String]) -> Unit {
  if args is ["--help"] {
    print_leads_help()
    return
  }
  match option_value(args, "--event") {
    Some(source) =>
      try @core.hunt_session_leads(source) catch {
        @core.NormalizationError::MissingField(line_number~, field~) =>
          println("leads: missing field \{field} on line \{line_number}")
        @core.NormalizationError::InvalidField(line_number~, field~, ..) =>
          println("leads: invalid field \{field} on line \{line_number}")
        _ => println("leads: invalid JSONL input")
      } noraise {
        report =>
          if has_flag(args, "--json") {
            println(lead_report_json(report))
          } else {
            println("leads: verified=\{report.leads().length()}")
            for lead in report.leads() {
              let ids = lead
                .evidence()
                .map(event => {
                  "\{event.event().id().as_string()}@\{source_token(event.event().source())}:\{event.line_number()}"
                })
              println(
                "lead host=\{lead.host_id().as_string()} session=\{lead.session_id()} process=\{lead.process_key()} evidence=\{ids.join(",")}",
              )
            }
            for rejection in report.rejections() {
              println(
                "rejected events=\{rejection.event_ids().join(",")} reason=\{lead_reason_token(rejection.reason())}",
              )
            }
          }
      }
    None => print_leads_help()
  }
}

///|
fn run_alerts(args : Array[String]) -> Unit {
  if args is ["--help"] {
    print_alerts_help()
    return
  }
  let event_source = match option_value(args, "--event") {
    Some(source) => source
    None => {
      print_alerts_help()
      return
    }
  }
  let alert_id = match option_value(args, "--alert-id") {
    Some(value) => value
    None => "cli-alert"
  }
  try @core.normalize_jsonl(event_source) catch {
    _ => println("alerts: invalid JSONL input")
  } noraise {
    events => {
      if events.length() == 0 {
        println("alerts: no events supplied")
        return
      }
      let alert = cli_alert(events[0], alert_id)
      if has_flag(args, "--json") {
        println(alert_json(alert))
      } else {
        println(
          "alerts: alert=\{alert.id()} host=\{alert.detection().host_id().as_string()} pattern=\{alert.detection().pattern_id()} risk=\{alert.score().value()} status=\{alert_status_token(alert.status())}",
        )
      }
    }
  }
}

///|
fn run_case(args : Array[String]) -> Unit {
  if args is ["--help"] {
    print_case_help()
    return
  }
  let event_source = match option_value(args, "--event") {
    Some(source) => source
    None => {
      print_case_help()
      return
    }
  }
  let alert_id = match option_value(args, "--alert-id") {
    Some(value) => value
    None => "cli-alert"
  }
  try @core.normalize_jsonl(event_source) catch {
    _ => println("case: invalid JSONL input")
  } noraise {
    events => {
      if events.length() == 0 {
        println("case: no events supplied")
        return
      }
      let event = events[0]
      let alert = cli_alert(event, alert_id)
      let investigation = cli_case(event, alert)
      if has_flag(args, "--json") {
        println(case_json(investigation))
      } else {
        println(
          "case: id=\{investigation.id()} alert=\{investigation.alert().id()} evidence=\{investigation.evidence().length()} audit_entries=\{investigation.audit_trail().length()}",
        )
      }
    }
  }
}

///|
fn run_explain(args : Array[String]) -> Unit {
  if args is ["--help"] {
    print_explain_help()
    return
  }
  let event_source = match option_value(args, "--event") {
    Some(source) => source
    None => {
      print_explain_help()
      return
    }
  }
  try @core.normalize_jsonl(event_source) catch {
    _ => println("explain: invalid JSONL input")
  } noraise {
    events => {
      if events.length() == 0 {
        println("explain: no events supplied")
        return
      }
      let event = events[0]
      let rule = try! @core.Rule::new(
        id="cli-event",
        name="CLI event context",
        description="Explains the deterministic event context rule",
        version=1,
        condition=@core.RuleCondition::EventKindIs(event.event().kind()),
      )
      let hits = @core.evaluate_rules([rule], event, [])
      if has_flag(args, "--json") {
        println(explain_json(event, hits))
      } else if hits.length() == 0 {
        println(
          "explain: event=\{event.event().id().as_string()} rule=cli-event matched=false",
        )
      } else {
        let evidence = hits[0].evidence().join(",")
        println(
          "explain: event=\{event.event().id().as_string()} rule=cli-event matched=true evidence=\{evidence}",
        )
      }
    }
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
      let alert = cli_alert(event, alert_id)
      let plan = cli_plan(event)
      let report = @core.dry_run_response(plan, alert)
      if has_flag(args, "--json") {
        println(response_json(report, alert))
      } else {
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
}

///|
fn json_escape(value : String) -> String {
  value
  .replace(old="\\", new="\\\\")
  .replace(old="\"", new="\\\"")
  .replace(old="\r", new="\\r")
  .replace(old="\n", new="\\n")
  .replace(old="\t", new="\\t")
}

///|
fn normalized_event_json(event : @core.NormalizedEvent) -> String {
  let security_event = event.event()
  "{\"line_number\":\{event.line_number()},\"event_id\":\"\{json_escape(security_event.id().as_string())}\",\"host_id\":\"\{json_escape(security_event.host_id().as_string())}\",\"hostname\":\"\{json_escape(event.host().hostname())}\",\"platform\":\"\{json_escape(platform_token(event.host().platform()))}\",\"kind\":\"\{kind_token(security_event.kind())}\",\"source\":\"\{json_escape(source_token(security_event.source()))}\",\"severity\":\"\{severity_token(security_event.severity())}\",\"observed_at\":\{security_event.observed_at().unix_seconds()},\"fingerprint\":\"\{json_escape(event.fingerprint())}\"}"
}

///|
fn hunt_json(events : Array[@core.NormalizedEvent]) -> String {
  let items = events.map(normalized_event_json).join(",")
  "[\{items}]"
}

///|
fn response_step_json(step : @core.DryRunStep) -> String {
  "{\"action_id\":\"\{json_escape(step.action_id())}\",\"kind\":\"\{action_kind_token(step.kind())}\",\"target\":\"\{json_escape(step.target())}\",\"reason\":\"\{json_escape(step.reason())}\",\"outcome\":\"\{dry_run_outcome_token(step.outcome())}\"}"
}

///|
fn response_json(report : @core.DryRunReport, alert : @core.Alert) -> String {
  let steps = report.steps().map(response_step_json).join(",")
  "{\"alert_id\":\"\{json_escape(report.alert_id())}\",\"host_id\":\"\{json_escape(report.host_id().as_string())}\",\"risk\":\{alert.score().value()},\"status\":\"\{alert_status_token(alert.status())}\",\"steps\":[\{steps}]}"
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
fn platform_token(platform : @core.HostPlatform) -> String {
  match platform {
    @core.HostPlatform::Windows => "windows"
    @core.HostPlatform::Linux => "linux"
    @core.HostPlatform::MacOS => "macos"
    @core.HostPlatform::Other(value) => value
  }
}

///|
fn source_token(source : @core.EventSource) -> String {
  match source {
    @core.EventSource::Agent => "agent"
    @core.EventSource::Sysmon => "sysmon"
    @core.EventSource::Auditd => "auditd"
    @core.EventSource::WindowsEvent => "windows_event"
    @core.EventSource::Manual => "manual"
    @core.EventSource::Other(value) => value
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
    @core.AlertStatus::Investigating => "investigating"
    @core.AlertStatus::Contained => "contained"
    @core.AlertStatus::Resolved => "resolved"
    @core.AlertStatus::Closed => "closed"
    @core.AlertStatus::Suppressed => "suppressed"
  }
}
