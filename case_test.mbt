///|
fn case_alert() -> @hostsentinel.Alert {
  let first_rule = try! @hostsentinel.Rule::new(
    id="case-process",
    name="Process event",
    description="Matches process events",
    version=1,
    condition=@hostsentinel.RuleCondition::EventKindIs(
      @hostsentinel.EventKind::Process,
    ),
  )
  let second_rule = try! @hostsentinel.Rule::new(
    id="case-high",
    name="High severity",
    description="Matches high severity events",
    version=1,
    condition=@hostsentinel.RuleCondition::SeverityAtLeast(
      @hostsentinel.Severity::High,
    ),
  )
  let first = try! @hostsentinel.normalize_jsonl(
      "{\"event_id\":\"case-event-1\",\"host_id\":\"case-host\",\"hostname\":\"case-workstation\",\"platform\":\"linux\",\"kind\":\"process\",\"source\":\"agent\",\"severity\":\"medium\",\"observed_at\":100}",
    )[0]
  let second = try! @hostsentinel.normalize_jsonl(
      "{\"event_id\":\"case-event-2\",\"host_id\":\"case-host\",\"hostname\":\"case-workstation\",\"platform\":\"linux\",\"kind\":\"network\",\"source\":\"agent\",\"severity\":\"high\",\"observed_at\":110}",
    )[0]
  let observations = [
    @hostsentinel.EventObservation::new(
      event=first,
      hits=@hostsentinel.evaluate_rules([first_rule], first, []),
    ),
    @hostsentinel.EventObservation::new(
      event=second,
      hits=@hostsentinel.evaluate_rules([second_rule], second, []),
    ),
  ]
  let pattern = try! @hostsentinel.CorrelationPattern::new(
    id="case-sequence",
    name="Process then high severity",
    rule_ids=["case-process", "case-high"],
    window_seconds=30,
  )
  let detection = @hostsentinel.correlate(pattern, observations)[0]
  let score = @hostsentinel.score_detection(detection, observations)
  try! @hostsentinel.Alert::new(
    id="alert-case-001",
    detection~,
    score~,
    created_at=first.event().observed_at(),
  )
}

///|
fn case_evidence(
  alert : @hostsentinel.Alert,
  id : String,
  collected_at : Int64,
) -> @hostsentinel.Evidence {
  try! @hostsentinel.Evidence::new(
    id~,
    kind=@hostsentinel.EvidenceKind::Event,
    summary="Normalized event supporting the detection",
    source="agent",
    reference=alert.detection().event_fingerprints()[0],
    collected_at=try! @hostsentinel.ObservedAt::from_unix_seconds(
      unix_seconds=collected_at,
    ),
  )
}

///|
test "opens a case and appends evidence to its audit trail" {
  let alert = case_alert()
  let investigation = try! @hostsentinel.Case::new(
    id="case-001",
    alert~,
    actor="analyst",
    opened_at=try! @hostsentinel.ObservedAt::from_unix_seconds(unix_seconds=100),
  )
  assert_eq(investigation.id(), "case-001")
  assert_eq(investigation.evidence().length(), 0)
  assert_eq(investigation.audit_trail().length(), 1)
  assert_eq(investigation.audit_trail()[0].sequence(), 1)
  assert_eq(investigation.audit_trail()[0].action(), "case.created")

  let evidence = case_evidence(alert, "evidence-001", 110)
  let with_evidence = try! investigation.add_evidence(
    evidence~,
    actor="analyst",
  )
  assert_eq(with_evidence.evidence().length(), 1)
  assert_eq(with_evidence.evidence()[0].id(), "evidence-001")
  assert_eq(with_evidence.audit_trail().length(), 2)
  assert_eq(with_evidence.audit_trail()[1].sequence(), 2)
  assert_eq(with_evidence.audit_trail()[1].action(), "evidence.added")
  assert_eq(with_evidence.audit_trail()[1].details(), "evidence-001")
}

///|
test "records manual case audit actions in order" {
  let alert = case_alert()
  let investigation = try! @hostsentinel.Case::new(
    id="case-002",
    alert~,
    actor="analyst",
    opened_at=try! @hostsentinel.ObservedAt::from_unix_seconds(unix_seconds=100),
  )
  let reviewed = try! investigation.record_audit(
    actor="reviewer",
    action="case.reviewed",
    details="Validated the initial detection",
    occurred_at=try! @hostsentinel.ObservedAt::from_unix_seconds(
      unix_seconds=120,
    ),
  )
  assert_eq(reviewed.audit_trail().length(), 2)
  assert_eq(reviewed.audit_trail()[1].sequence(), 2)
  assert_eq(reviewed.audit_trail()[1].actor(), "reviewer")
  assert_eq(
    reviewed.audit_trail()[1].details(),
    "Validated the initial detection",
  )
}

///|
test "rejects invalid evidence and audit mutations" {
  let alert = case_alert()
  let investigation = try! @hostsentinel.Case::new(
    id="case-003",
    alert~,
    actor="analyst",
    opened_at=try! @hostsentinel.ObservedAt::from_unix_seconds(unix_seconds=100),
  )
  let evidence = case_evidence(alert, "evidence-002", 110)
  let with_evidence = try! investigation.add_evidence(
    evidence~,
    actor="analyst",
  )

  try with_evidence.add_evidence(evidence~, actor="analyst") catch {
    @hostsentinel.CaseError::DuplicateEvidenceId => ()
    _ => fail("expected duplicate evidence error")
  } noraise {
    _ => fail("expected duplicate evidence insertion to fail")
  }

  try
    with_evidence.record_audit(
      actor="analyst",
      action="case.reviewed",
      details="Out of order update",
      occurred_at=try! @hostsentinel.ObservedAt::from_unix_seconds(
        unix_seconds=109,
      ),
    )
  catch {
    @hostsentinel.CaseError::StaleTimestamp => ()
    _ => fail("expected stale timestamp error")
  } noraise {
    _ => fail("expected stale audit insertion to fail")
  }

  try
    @hostsentinel.Evidence::new(
      id="",
      kind=@hostsentinel.EvidenceKind::AnalystNote,
      summary="Missing identifier",
      source="analyst",
      reference="note-1",
      collected_at=try! @hostsentinel.ObservedAt::from_unix_seconds(
        unix_seconds=110,
      ),
    )
  catch {
    @hostsentinel.CaseError::EmptyEvidenceId => ()
    _ => fail("expected empty evidence id error")
  } noraise {
    _ => fail("expected invalid evidence creation to fail")
  }
}
