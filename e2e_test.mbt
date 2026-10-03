///|
fn e2e_rule(
  id : String,
  condition : @hostsentinel.RuleCondition,
) -> @hostsentinel.Rule {
  try! @hostsentinel.Rule::new(
    id~,
    name="End-to-end rule",
    description="Rule used by the end-to-end fixture",
    version=1,
    condition~,
  )
}

///|
test "runs the host security pipeline from fixture to dry-run response" {
  let source =
    #|{"event_id":"e2e-process","host_id":"e2e-host","hostname":"workstation-e2e","platform":"linux","kind":"process","source":"agent","severity":"medium","observed_at":100}
    #|{"event_id":"e2e-network","host_id":"e2e-host","hostname":"workstation-e2e","platform":"linux","kind":"network","source":"agent","severity":"high","observed_at":110}
  let events = try! @hostsentinel.normalize_jsonl(source)
  assert_eq(events.length(), 2)

  let process_rule = e2e_rule(
    "e2e-process",
    @hostsentinel.RuleCondition::EventKindIs(@hostsentinel.EventKind::Process),
  )
  let high_rule = e2e_rule(
    "e2e-high",
    @hostsentinel.RuleCondition::SeverityAtLeast(@hostsentinel.Severity::High),
  )
  let observations = [
    @hostsentinel.EventObservation::new(
      event=events[0],
      hits=@hostsentinel.evaluate_rules([process_rule], events[0], []),
    ),
    @hostsentinel.EventObservation::new(
      event=events[1],
      hits=@hostsentinel.evaluate_rules([high_rule], events[1], []),
    ),
  ]
  assert_eq(observations[0].hits().length(), 1)
  assert_eq(observations[1].hits().length(), 1)

  let pattern = try! @hostsentinel.CorrelationPattern::new(
    id="e2e-sequence",
    name="Process followed by high-severity network activity",
    rule_ids=["e2e-process", "e2e-high"],
    window_seconds=30,
  )
  let detections = @hostsentinel.correlate(pattern, observations)
  assert_eq(detections.length(), 1)
  let detection = detections[0]
  assert_eq(detection.host_id().as_string(), "e2e-host")
  assert_eq(detection.event_fingerprints().length(), 2)

  let score = @hostsentinel.score_detection(detection, observations)
  assert_eq(score.value(), 80)
  assert_eq(score.level(), @hostsentinel.RiskLevel::High)

  let alert = try! @hostsentinel.Alert::new(
    id="e2e-alert",
    detection~,
    score~,
    created_at=events[0].event().observed_at(),
  )
  let investigation = try! @hostsentinel.Case::new(
    id="e2e-case",
    alert~,
    actor="analyst",
    opened_at=events[0].event().observed_at(),
  )
  let with_first_evidence = try! investigation.add_evidence(
    evidence=try! @hostsentinel.Evidence::new(
      id="e2e-evidence-process",
      kind=@hostsentinel.EvidenceKind::Event,
      summary="Process event matched the first rule",
      source="fixture",
      reference=events[0].fingerprint(),
      collected_at=events[0].event().observed_at(),
    ),
    actor="analyst",
  )
  let with_second_evidence = try! with_first_evidence.add_evidence(
    evidence=try! @hostsentinel.Evidence::new(
      id="e2e-evidence-network",
      kind=@hostsentinel.EvidenceKind::Event,
      summary="High-severity network event matched the second rule",
      source="fixture",
      reference=events[1].fingerprint(),
      collected_at=events[1].event().observed_at(),
    ),
    actor="analyst",
  )
  let investigation = try! with_second_evidence.record_audit(
    actor="reviewer",
    action="case.reviewed",
    details="Validated the correlated fixture detection",
    occurred_at=try! @hostsentinel.ObservedAt::from_unix_seconds(
      unix_seconds=120,
    ),
  )
  assert_eq(investigation.evidence().length(), 2)
  assert_eq(investigation.audit_trail().length(), 4)
  assert_eq(investigation.audit_trail()[3].action(), "case.reviewed")

  let isolate = try! @hostsentinel.ResponseAction::new(
    id="e2e-isolate",
    kind=@hostsentinel.ResponseActionKind::IsolateHost,
    target="e2e-host",
    reason="Contain the host while the alert is investigated",
  )
  let notify = try! @hostsentinel.ResponseAction::new(
    id="e2e-notify",
    kind=@hostsentinel.ResponseActionKind::NotifyAnalyst,
    target="on-call",
    reason="Notify the analyst of the simulated containment",
  )
  let plan = try! @hostsentinel.ResponsePlan::new(
    id="e2e-response",
    name="End-to-end containment",
    actions=[isolate, notify],
  )
  let report = @hostsentinel.dry_run_response(plan, alert)
  assert_eq(report.steps().length(), 2)
  assert_eq(report.steps()[0].action_id(), "e2e-isolate")
  assert_eq(report.steps()[1].action_id(), "e2e-notify")
  assert_eq(
    report.steps()[0].outcome(),
    @hostsentinel.DryRunOutcome::WouldExecute,
  )
  assert_eq(alert.status(), @hostsentinel.AlertStatus::Open)

  debug_inspect(events, content=(
    #|[
    #|  {
    #|    line_number: 1,
    #|    raw_line: "{\"event_id\":\"e2e-process\",\"host_id\":\"e2e-host\",\"hostname\":\"workstation-e2e\",\"platform\":\"linux\",\"kind\":\"process\",\"source\":\"agent\",\"severity\":\"medium\",\"observed_at\":100}",
    #|    host: {
    #|      id: { value: "e2e-host" },
    #|      hostname: "workstation-e2e",
    #|      platform: Linux,
    #|      state: Active,
    #|    },
    #|    event: {
    #|      id: { value: "e2e-process" },
    #|      host_id: { value: "e2e-host" },
    #|      kind: Process,
    #|      source: Agent,
    #|      severity: Medium,
    #|      observed_at: { unix_seconds: 100 },
    #|    },
    #|    fingerprint: "11:e2e-process|8:e2e-host|15:workstation-e2e|5:linux|7:process|5:agent|6:medium|3:100",
    #|  },
    #|  {
    #|    line_number: 2,
    #|    raw_line: "{\"event_id\":\"e2e-network\",\"host_id\":\"e2e-host\",\"hostname\":\"workstation-e2e\",\"platform\":\"linux\",\"kind\":\"network\",\"source\":\"agent\",\"severity\":\"high\",\"observed_at\":110}",
    #|    host: {
    #|      id: { value: "e2e-host" },
    #|      hostname: "workstation-e2e",
    #|      platform: Linux,
    #|      state: Active,
    #|    },
    #|    event: {
    #|      id: { value: "e2e-network" },
    #|      host_id: { value: "e2e-host" },
    #|      kind: Network,
    #|      source: Agent,
    #|      severity: High,
    #|      observed_at: { unix_seconds: 110 },
    #|    },
    #|    fingerprint: "11:e2e-network|8:e2e-host|15:workstation-e2e|5:linux|7:network|5:agent|4:high|3:110",
    #|  },
    #|]
  ))
  debug_inspect(investigation, content=(
    #|{
    #|  id: "e2e-case",
    #|  alert: {
    #|    id: "e2e-alert",
    #|    detection: {
    #|      pattern_id: "e2e-sequence",
    #|      host_id: { value: "e2e-host" },
    #|      rule_ids: ["e2e-process", "e2e-high"],
    #|      event_fingerprints: [
    #|        "11:e2e-process|8:e2e-host|15:workstation-e2e|5:linux|7:process|5:agent|6:medium|3:100",
    #|        "11:e2e-network|8:e2e-host|15:workstation-e2e|5:linux|7:network|5:agent|4:high|3:110",
    #|      ],
    #|      started_at: { unix_seconds: 100 },
    #|      ended_at: { unix_seconds: 110 },
    #|      dedup_key: "12:e2e-sequence|8:e2e-host|16:rule:e2e-process|13:rule:e2e-high|91:event:11:e2e-process|8:e2e-host|15:workstation-e2e|5:linux|7:process|5:agent|6:medium|3:100|89:event:11:e2e-network|8:e2e-host|15:workstation-e2e|5:linux|7:network|5:agent|4:high|3:110",
    #|    },
    #|    score: { value: 80, level: High, max_severity: High },
    #|    status: Open,
    #|    created_at: { unix_seconds: 100 },
    #|    updated_at: { unix_seconds: 100 },
    #|  },
    #|  evidence: [
    #|    {
    #|      id: "e2e-evidence-process",
    #|      kind: Event,
    #|      summary: "Process event matched the first rule",
    #|      source: "fixture",
    #|      reference: "11:e2e-process|8:e2e-host|15:workstation-e2e|5:linux|7:process|5:agent|6:medium|3:100",
    #|      collected_at: { unix_seconds: 100 },
    #|    },
    #|    {
    #|      id: "e2e-evidence-network",
    #|      kind: Event,
    #|      summary: "High-severity network event matched the second rule",
    #|      source: "fixture",
    #|      reference: "11:e2e-network|8:e2e-host|15:workstation-e2e|5:linux|7:network|5:agent|4:high|3:110",
    #|      collected_at: { unix_seconds: 110 },
    #|    },
    #|  ],
    #|  audit_trail: [
    #|    {
    #|      sequence: 1,
    #|      actor: "analyst",
    #|      action: "case.created",
    #|      details: "e2e-alert",
    #|      occurred_at: { unix_seconds: 100 },
    #|    },
    #|    {
    #|      sequence: 2,
    #|      actor: "analyst",
    #|      action: "evidence.added",
    #|      details: "e2e-evidence-process",
    #|      occurred_at: { unix_seconds: 100 },
    #|    },
    #|    {
    #|      sequence: 3,
    #|      actor: "analyst",
    #|      action: "evidence.added",
    #|      details: "e2e-evidence-network",
    #|      occurred_at: { unix_seconds: 110 },
    #|    },
    #|    {
    #|      sequence: 4,
    #|      actor: "reviewer",
    #|      action: "case.reviewed",
    #|      details: "Validated the correlated fixture detection",
    #|      occurred_at: { unix_seconds: 120 },
    #|    },
    #|  ],
    #|}
  ))
  debug_inspect(report, content=(
    #|{
    #|  plan_id: "e2e-response",
    #|  alert_id: "e2e-alert",
    #|  host_id: { value: "e2e-host" },
    #|  steps: [
    #|    {
    #|      action_id: "e2e-isolate",
    #|      kind: IsolateHost,
    #|      target: "e2e-host",
    #|      reason: "Contain the host while the alert is investigated",
    #|      outcome: WouldExecute,
    #|    },
    #|    {
    #|      action_id: "e2e-notify",
    #|      kind: NotifyAnalyst,
    #|      target: "on-call",
    #|      reason: "Notify the analyst of the simulated containment",
    #|      outcome: WouldExecute,
    #|    },
    #|  ],
    #|}
  ))
}
