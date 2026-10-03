///|
fn risk_observations() -> Array[@hostsentinel.EventObservation] {
  let first_rule = try! @hostsentinel.Rule::new(
    id="rule-process",
    name="Process event",
    description="Matches process events",
    version=1,
    condition=@hostsentinel.RuleCondition::EventKindIs(
      @hostsentinel.EventKind::Process,
    ),
  )
  let second_rule = try! @hostsentinel.Rule::new(
    id="rule-high",
    name="High severity",
    description="Matches high severity events",
    version=1,
    condition=@hostsentinel.RuleCondition::SeverityAtLeast(
      @hostsentinel.Severity::High,
    ),
  )
  let first = try! @hostsentinel.normalize_jsonl(
      "{\"event_id\":\"risk-event-1\",\"host_id\":\"risk-host\",\"hostname\":\"risk-workstation\",\"platform\":\"linux\",\"kind\":\"process\",\"source\":\"agent\",\"severity\":\"medium\",\"observed_at\":100}",
    )[0]
  let second = try! @hostsentinel.normalize_jsonl(
      "{\"event_id\":\"risk-event-2\",\"host_id\":\"risk-host\",\"hostname\":\"risk-workstation\",\"platform\":\"linux\",\"kind\":\"network\",\"source\":\"agent\",\"severity\":\"high\",\"observed_at\":110}",
    )[0]
  [
    @hostsentinel.EventObservation::new(
      event=first,
      hits=@hostsentinel.evaluate_rules([first_rule], first, []),
    ),
    @hostsentinel.EventObservation::new(
      event=second,
      hits=@hostsentinel.evaluate_rules([second_rule], second, []),
    ),
  ]
}

///|
fn risk_pattern() -> @hostsentinel.CorrelationPattern {
  try! @hostsentinel.CorrelationPattern::new(
    id="risk-sequence",
    name="Process then high severity",
    rule_ids=["rule-process", "rule-high"],
    window_seconds=30,
  )
}

///|
fn risk_detection(
  observations : Array[@hostsentinel.EventObservation],
) -> @hostsentinel.Detection {
  @hostsentinel.correlate(risk_pattern(), observations)[0]
}

///|
test "scores a detection from its strongest event severity" {
  let observations = risk_observations()
  let detection = risk_detection(observations)
  let score = @hostsentinel.score_detection(detection, observations)
  assert_eq(score.value(), 80)
  assert_eq(score.level(), @hostsentinel.RiskLevel::High)
  assert_eq(score.max_severity(), @hostsentinel.Severity::High)
}

///|
test "advances an alert through its lifecycle" {
  let observations = risk_observations()
  let detection = risk_detection(observations)
  let score = @hostsentinel.score_detection(detection, observations)
  let alert = try! @hostsentinel.Alert::new(
    id="alert-001",
    detection~,
    score~,
    created_at=observations[0].event().event().observed_at(),
  )
  assert_eq(alert.status(), @hostsentinel.AlertStatus::Open)
  assert_eq(alert.created_at().unix_seconds(), 100)
  let acknowledged = try! alert.transition(
    status=@hostsentinel.AlertStatus::Acknowledged,
    at=try! @hostsentinel.ObservedAt::from_unix_seconds(unix_seconds=105),
  )
  let investigating = try! acknowledged.transition(
    status=@hostsentinel.AlertStatus::InProgress,
    at=try! @hostsentinel.ObservedAt::from_unix_seconds(unix_seconds=110),
  )
  let resolved = try! investigating.transition(
    status=@hostsentinel.AlertStatus::Resolved,
    at=try! @hostsentinel.ObservedAt::from_unix_seconds(unix_seconds=120),
  )
  assert_eq(resolved.status(), @hostsentinel.AlertStatus::Resolved)
  assert_eq(resolved.updated_at().unix_seconds(), 120)
  assert_eq(resolved.score(), score)
}

///|
test "rejects invalid alert lifecycle changes" {
  let observations = risk_observations()
  let detection = risk_detection(observations)
  let score = @hostsentinel.score_detection(detection, observations)
  try
    @hostsentinel.Alert::new(
      id="",
      detection~,
      score~,
      created_at=observations[0].event().event().observed_at(),
    )
  catch {
    @hostsentinel.AlertError::EmptyAlertId => ()
    _ => fail("expected an empty alert id error")
  } noraise {
    _ => fail("expected alert construction to fail")
  }

  let alert = try! @hostsentinel.Alert::new(
    id="alert-002",
    detection~,
    score~,
    created_at=observations[0].event().event().observed_at(),
  )
  let resolved = try! alert.transition(
    status=@hostsentinel.AlertStatus::Resolved,
    at=try! @hostsentinel.ObservedAt::from_unix_seconds(unix_seconds=120),
  )
  try
    resolved.transition(
      status=@hostsentinel.AlertStatus::Open,
      at=try! @hostsentinel.ObservedAt::from_unix_seconds(unix_seconds=121),
    )
  catch {
    @hostsentinel.AlertError::InvalidTransition(
      from=@hostsentinel.AlertStatus::Resolved,
      to=@hostsentinel.AlertStatus::Open
    ) => ()
    _ => fail("expected a terminal state transition error")
  } noraise {
    _ => fail("expected terminal alert transition to fail")
  }

  try
    alert.transition(
      status=@hostsentinel.AlertStatus::Acknowledged,
      at=try! @hostsentinel.ObservedAt::from_unix_seconds(unix_seconds=99),
    )
  catch {
    @hostsentinel.AlertError::StaleTimestamp => ()
    _ => fail("expected a stale timestamp error")
  } noraise {
    _ => fail("expected stale alert transition to fail")
  }
}
