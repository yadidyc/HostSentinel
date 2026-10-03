///|
fn response_alert() -> @hostsentinel.Alert {
  let rule = try! @hostsentinel.Rule::new(
    id="response-process",
    name="Process event",
    description="Matches a process event",
    version=1,
    condition=@hostsentinel.RuleCondition::EventKindIs(
      @hostsentinel.EventKind::Process,
    ),
  )
  let event = try! @hostsentinel.normalize_jsonl(
      "{\"event_id\":\"response-event\",\"host_id\":\"response-host\",\"hostname\":\"response-workstation\",\"platform\":\"linux\",\"kind\":\"process\",\"source\":\"agent\",\"severity\":\"high\",\"observed_at\":100}",
    )[0]
  let observation = @hostsentinel.EventObservation::new(
    event~,
    hits=@hostsentinel.evaluate_rules([rule], event, []),
  )
  let pattern = try! @hostsentinel.CorrelationPattern::new(
    id="response-sequence",
    name="Process detection",
    rule_ids=["response-process"],
    window_seconds=30,
  )
  let detection = @hostsentinel.correlate(pattern, [observation])[0]
  let score = @hostsentinel.score_detection(detection, [observation])
  try! @hostsentinel.Alert::new(
    id="response-alert",
    detection~,
    score~,
    created_at=event.event().observed_at(),
  )
}

///|
test "dry-runs ordered response actions without changing the alert" {
  let alert = response_alert()
  let isolate = try! @hostsentinel.ResponseAction::new(
    id="action-isolate",
    kind=@hostsentinel.ResponseActionKind::IsolateHost,
    target=alert.detection().host_id().as_string(),
    reason="Contain the host while investigating the detection",
  )
  let notify = try! @hostsentinel.ResponseAction::new(
    id="action-notify",
    kind=@hostsentinel.ResponseActionKind::NotifyAnalyst,
    target="on-call",
    reason="Notify the analyst of the simulated containment",
  )
  let plan = try! @hostsentinel.ResponsePlan::new(
    id="plan-contain",
    name="Contain suspicious host",
    actions=[isolate, notify],
  )
  let report = @hostsentinel.dry_run_response(plan, alert)
  assert_eq(report.plan_id(), "plan-contain")
  assert_eq(report.alert_id(), "response-alert")
  assert_eq(report.host_id().as_string(), "response-host")
  assert_eq(report.steps().length(), 2)
  assert_eq(report.steps()[0].action_id(), "action-isolate")
  assert_eq(
    report.steps()[0].kind(),
    @hostsentinel.ResponseActionKind::IsolateHost,
  )
  assert_eq(report.steps()[0].target(), "response-host")
  assert_eq(
    report.steps()[0].outcome(),
    @hostsentinel.DryRunOutcome::WouldExecute,
  )
  assert_eq(report.steps()[1].action_id(), "action-notify")
  assert_eq(report.steps()[1].target(), "on-call")
  assert_eq(alert.status(), @hostsentinel.AlertStatus::Open)
}

///|
test "rejects incomplete and duplicate response plans" {
  try
    @hostsentinel.ResponseAction::new(
      id="",
      kind=@hostsentinel.ResponseActionKind::IsolateHost,
      target="response-host",
      reason="Contain the host",
    )
  catch {
    @hostsentinel.ResponsePlanError::EmptyActionId => ()
    _ => fail("expected empty action id error")
  } noraise {
    _ => fail("expected action construction to fail")
  }

  let action = try! @hostsentinel.ResponseAction::new(
    id="action-duplicate",
    kind=@hostsentinel.ResponseActionKind::CollectArtifact,
    target="/tmp/sample",
    reason="Collect the referenced artifact",
  )
  try
    @hostsentinel.ResponsePlan::new(id="plan-empty", name="Empty plan", actions=[])
  catch {
    @hostsentinel.ResponsePlanError::EmptyActionSequence => ()
    _ => fail("expected empty action sequence error")
  } noraise {
    _ => fail("expected empty response plan to fail")
  }

  try
    @hostsentinel.ResponsePlan::new(
      id="plan-duplicate",
      name="Duplicate actions",
      actions=[action, action],
    )
  catch {
    @hostsentinel.ResponsePlanError::DuplicateActionId => ()
    _ => fail("expected duplicate action id error")
  } noraise {
    _ => fail("expected duplicate response plan to fail")
  }
}
