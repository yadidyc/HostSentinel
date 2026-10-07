///|
fn fixture_rule(
  id : String,
  condition : @hostsentinel.RuleCondition,
) -> @hostsentinel.Rule {
  try! @hostsentinel.Rule::new(
    id~,
    name="Fixture rule",
    description="Rule used by categorized fixture tests",
    version=1,
    condition~,
  )
}

///|
test "normal fixture remains a stable pair of normalized events" {
  let source =
    #|{"event_id":"normal-process-001","host_id":"fixture-normal-host","hostname":"workstation-normal","platform":"linux","kind":"process","source":"agent","severity":"informational","observed_at":1725001000}
    #|{"event_id":"normal-file-001","host_id":"fixture-normal-host","hostname":"workstation-normal","platform":"linux","kind":"file","source":"agent","severity":"low","observed_at":1725001005}
  let events = try! @hostsentinel.normalize_jsonl(source)
  assert_eq(events.length(), 2)
  assert_eq(events[0].event().host_id(), events[1].event().host_id())
  assert_true(events[0].fingerprint() != events[1].fingerprint())
}

///|
test "malicious fixture correlates into a high risk detection" {
  let source =
    #|{"event_id":"malicious-process-001","host_id":"fixture-malicious-host","hostname":"workstation-malicious","platform":"windows","kind":"process","source":"sysmon","severity":"high","observed_at":1725002000}
    #|{"event_id":"malicious-network-001","host_id":"fixture-malicious-host","hostname":"workstation-malicious","platform":"windows","kind":"network","source":"sysmon","severity":"critical","observed_at":1725002010}
  let events = try! @hostsentinel.normalize_jsonl(source)
  let process_rule = fixture_rule(
    "fixture-process",
    @hostsentinel.RuleCondition::EventKindIs(@hostsentinel.EventKind::Process),
  )
  let critical_rule = fixture_rule(
    "fixture-critical",
    @hostsentinel.RuleCondition::SeverityAtLeast(
      @hostsentinel.Severity::Critical,
    ),
  )
  let observations = [
    @hostsentinel.EventObservation::new(
      event=events[0],
      hits=@hostsentinel.evaluate_rules([process_rule], events[0], []),
    ),
    @hostsentinel.EventObservation::new(
      event=events[1],
      hits=@hostsentinel.evaluate_rules([critical_rule], events[1], []),
    ),
  ]
  let pattern = try! @hostsentinel.CorrelationPattern::new(
    id="fixture-malicious-sequence",
    name="Malicious fixture sequence",
    rule_ids=["fixture-process", "fixture-critical"],
    window_seconds=30,
  )
  let detections = @hostsentinel.correlate(pattern, observations)
  assert_eq(detections.length(), 1)
  let score = @hostsentinel.score_detection(detections[0], observations)
  assert_eq(score.value(), 100)
  assert_eq(score.level(), @hostsentinel.RiskLevel::Critical)
}

///|
test "false positive fixture does not match a high severity rule" {
  let source =
    #|{"event_id":"admin-process-001","host_id":"fixture-admin-host","hostname":"workstation-admin","platform":"windows","kind":"process","source":"windows_event","severity":"medium","observed_at":1725003000}
    #|{"event_id":"admin-auth-001","host_id":"fixture-admin-host","hostname":"workstation-admin","platform":"windows","kind":"authentication","source":"windows_event","severity":"informational","observed_at":1725003005}
  let events = try! @hostsentinel.normalize_jsonl(source)
  let rule = fixture_rule(
    "fixture-high",
    @hostsentinel.RuleCondition::SeverityAtLeast(@hostsentinel.Severity::High),
  )
  assert_eq(@hostsentinel.evaluate_rules([rule], events[0], []).length(), 0)
  assert_eq(@hostsentinel.evaluate_rules([rule], events[1], []).length(), 0)
}

///|
test "duplicate fixture preserves identical fingerprints" {
  let source =
    #|{"event_id":"duplicate-process-001","host_id":"fixture-duplicate-host","hostname":"workstation-duplicate","platform":"linux","kind":"process","source":"agent","severity":"medium","observed_at":1725004000}
    #|{"event_id":"duplicate-process-001","host_id":"fixture-duplicate-host","hostname":"workstation-duplicate","platform":"linux","kind":"process","source":"agent","severity":"medium","observed_at":1725004000}
  let events = try! @hostsentinel.normalize_jsonl(source)
  assert_eq(events.length(), 2)
  assert_eq(events[0].fingerprint(), events[1].fingerprint())
}
