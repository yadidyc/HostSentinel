///|
fn correlation_event(
  event_id : String,
  kind : String,
  severity : String,
  observed_at : Int64,
) -> @hostsentinel.NormalizedEvent {
  let source = "{\"event_id\":\"\{event_id}\",\"host_id\":\"host-a\",\"hostname\":\"workstation-a\",\"platform\":\"linux\",\"kind\":\"\{kind}\",\"source\":\"agent\",\"severity\":\"\{severity}\",\"observed_at\":\{observed_at}}"
  try! @hostsentinel.normalize_jsonl(source)[0]
}

///|
fn correlation_rule(
  id : String,
  condition : @hostsentinel.RuleCondition,
) -> @hostsentinel.Rule {
  try! @hostsentinel.Rule::new(
    id~,
    name="Correlation rule",
    description="Rule used by correlation tests",
    version=1,
    condition~,
  )
}

///|
suberror CorrelationTestError {
  MissingHit
}

///|
fn required_hit(
  rule : @hostsentinel.Rule,
  event : @hostsentinel.NormalizedEvent,
) -> @hostsentinel.RuleHit raise CorrelationTestError {
  match @hostsentinel.evaluate_rule(rule, event, []) {
    Some(hit) => hit
    None => raise CorrelationTestError::MissingHit
  }
}

///|
test "correlates ordered rule hits within one host window" {
  let rule_a = correlation_rule(
    "rule-a",
    @hostsentinel.RuleCondition::EventKindIs(@hostsentinel.EventKind::Process),
  )
  let rule_b = correlation_rule(
    "rule-b",
    @hostsentinel.RuleCondition::SeverityAtLeast(@hostsentinel.Severity::High),
  )
  let event_a = correlation_event("event-a", "process", "medium", 100)
  let event_b = correlation_event("event-b", "network", "high", 110)
  let pattern = try! @hostsentinel.CorrelationPattern::new(
    id="pattern-a",
    name="Process then high severity",
    rule_ids=["rule-a", "rule-b"],
    window_seconds=30,
  )
  let observations = [
    @hostsentinel.EventObservation::new(event=event_a, hits=[
      try! required_hit(rule_a, event_a),
    ]),
    @hostsentinel.EventObservation::new(event=event_b, hits=[
      try! required_hit(rule_b, event_b),
    ]),
  ]
  let detections = @hostsentinel.correlate(pattern, observations)
  assert_eq(detections.length(), 1)
  assert_eq(detections[0].host_id().as_string(), "host-a")
  assert_eq(detections[0].rule_ids(), ["rule-a", "rule-b"])
  assert_eq(detections[0].event_fingerprints().length(), 2)
  assert_eq(detections[0].started_at().unix_seconds(), 100)
  assert_eq(detections[0].ended_at().unix_seconds(), 110)
}

///|
test "deduplicates repeated correlation evidence" {
  let rule_a = correlation_rule(
    "rule-a",
    @hostsentinel.RuleCondition::EventKindIs(@hostsentinel.EventKind::Process),
  )
  let rule_b = correlation_rule(
    "rule-b",
    @hostsentinel.RuleCondition::SeverityAtLeast(@hostsentinel.Severity::High),
  )
  let event_a = correlation_event("event-a", "process", "medium", 100)
  let event_b = correlation_event("event-b", "network", "high", 110)
  let observation_a = @hostsentinel.EventObservation::new(event=event_a, hits=[
    try! required_hit(rule_a, event_a),
  ])
  let observation_b = @hostsentinel.EventObservation::new(event=event_b, hits=[
    try! required_hit(rule_b, event_b),
  ])
  let pattern = try! @hostsentinel.CorrelationPattern::new(
    id="pattern-a",
    name="Process then high severity",
    rule_ids=["rule-a", "rule-b"],
    window_seconds=30,
  )
  let detections = @hostsentinel.correlate(pattern, [
    observation_a, observation_b, observation_a, observation_b,
  ])
  assert_eq(detections.length(), 1)
  assert_true(detections[0].dedup_key() != "")
}

///|
test "does not correlate events outside the time window" {
  let rule_a = correlation_rule(
    "rule-a",
    @hostsentinel.RuleCondition::EventKindIs(@hostsentinel.EventKind::Process),
  )
  let rule_b = correlation_rule(
    "rule-b",
    @hostsentinel.RuleCondition::SeverityAtLeast(@hostsentinel.Severity::High),
  )
  let event_a = correlation_event("event-a", "process", "medium", 100)
  let event_b = correlation_event("event-b", "network", "high", 110)
  let pattern = try! @hostsentinel.CorrelationPattern::new(
    id="pattern-a",
    name="Process then high severity",
    rule_ids=["rule-a", "rule-b"],
    window_seconds=5,
  )
  let observations = [
    @hostsentinel.EventObservation::new(event=event_a, hits=[
      try! required_hit(rule_a, event_a),
    ]),
    @hostsentinel.EventObservation::new(event=event_b, hits=[
      try! required_hit(rule_b, event_b),
    ]),
  ]
  assert_eq(@hostsentinel.correlate(pattern, observations).length(), 0)
}

///|
test "validates correlation pattern" {
  try
    @hostsentinel.CorrelationPattern::new(
      id="",
      name="pattern",
      rule_ids=["rule-a"],
      window_seconds=10,
    )
  catch {
    @hostsentinel.CorrelationError::EmptyPatternId => ()
    _ => fail("expected an empty pattern id error")
  } noraise {
    _ => fail("expected pattern construction to fail")
  }

  try
    @hostsentinel.CorrelationPattern::new(
      id="pattern",
      name="pattern",
      rule_ids=[],
      window_seconds=10,
    )
  catch {
    @hostsentinel.CorrelationError::EmptyRuleSequence => ()
    _ => fail("expected an empty rule sequence error")
  } noraise {
    _ => fail("expected pattern construction to fail")
  }

  try
    @hostsentinel.CorrelationPattern::new(
      id="pattern",
      name="pattern",
      rule_ids=[""],
      window_seconds=10,
    )
  catch {
    @hostsentinel.CorrelationError::EmptyRuleId => ()
    _ => fail("expected an empty rule id error")
  } noraise {
    _ => fail("expected pattern construction to fail")
  }

  try
    @hostsentinel.CorrelationPattern::new(
      id="pattern",
      name="pattern",
      rule_ids=["rule-a"],
      window_seconds=0,
    )
  catch {
    @hostsentinel.CorrelationError::InvalidWindow => ()
    _ => fail("expected an invalid window error")
  } noraise {
    _ => fail("expected pattern construction to fail")
  }
}
