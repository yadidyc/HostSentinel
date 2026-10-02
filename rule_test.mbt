///|
fn rule_event() -> @hostsentinel.NormalizedEvent {
  let source = "{\"event_id\":\"evt-001\",\"host_id\":\"host-001\",\"hostname\":\"workstation-01\",\"platform\":\"linux\",\"kind\":\"process\",\"source\":\"agent\",\"severity\":\"high\",\"observed_at\":1725000000}"
  try! @hostsentinel.normalize_jsonl(source)[0]
}

///|
test "evaluates all conditions and returns ordered evidence" {
  let indicator = try! @hostsentinel.Indicator::new(
    kind=@hostsentinel.IocKind::Domain,
    value="bad.example.com",
  )
  let rule = try! @hostsentinel.Rule::new(
    id="rule-process-domain",
    name="Suspicious process domain",
    description="A high severity process event references a known domain",
    version=2,
    condition=@hostsentinel.RuleCondition::All([
      @hostsentinel.RuleCondition::EventKindIs(@hostsentinel.EventKind::Process),
      @hostsentinel.RuleCondition::SeverityAtLeast(
        @hostsentinel.Severity::Medium,
      ),
      @hostsentinel.RuleCondition::IocIs(indicator),
    ]),
  )
  let hit = @hostsentinel.evaluate_rule(rule, rule_event(), [
    "powershell.exe", "bad.example.com",
  ])
  guard hit is Some(hit) else { fail("expected a rule hit") }
  assert_eq(hit.rule_id(), "rule-process-domain")
  assert_eq(hit.rule_version(), 2)
  assert_eq(hit.evidence(), [
    "event.kind=process", "event.severity>=medium", "ioc.domain=bad.example.com",
  ])
}

///|
test "any conditions select the first matching branch" {
  let rule = try! @hostsentinel.Rule::new(
    id="rule-source-or-platform",
    name="Source or platform",
    description="Matches either the event source or host platform",
    version=1,
    condition=@hostsentinel.RuleCondition::Any([
      @hostsentinel.RuleCondition::SourceIs(@hostsentinel.EventSource::Sysmon),
      @hostsentinel.RuleCondition::HostPlatformIs(
        @hostsentinel.HostPlatform::Linux,
      ),
    ]),
  )
  let hit = @hostsentinel.evaluate_rule(rule, rule_event(), [])
  guard hit is Some(hit) else { fail("expected a rule hit") }
  assert_eq(hit.evidence(), ["host.platform=linux"])

  let no_hit_rule = try! @hostsentinel.Rule::new(
    id="rule-no-hit",
    name="No hit",
    description="Does not match the Linux agent event",
    version=1,
    condition=@hostsentinel.RuleCondition::Any([
      @hostsentinel.RuleCondition::SourceIs(@hostsentinel.EventSource::Sysmon),
      @hostsentinel.RuleCondition::HostPlatformIs(
        @hostsentinel.HostPlatform::Windows,
      ),
    ]),
  )
  let no_hit = @hostsentinel.evaluate_rule(no_hit_rule, rule_event(), [])
  assert_true(no_hit is None)
}

///|
test "evaluates rules in deterministic input order" {
  let first = try! @hostsentinel.Rule::new(
    id="rule-first",
    name="First",
    description="First matching rule",
    version=1,
    condition=@hostsentinel.RuleCondition::SeverityAtLeast(
      @hostsentinel.Severity::High,
    ),
  )
  let second = try! @hostsentinel.Rule::new(
    id="rule-second",
    name="Second",
    description="Second matching rule",
    version=1,
    condition=@hostsentinel.RuleCondition::EventKindIs(
      @hostsentinel.EventKind::Process,
    ),
  )
  let hits = @hostsentinel.evaluate_rules([first, second], rule_event(), [])
  assert_eq(hits.map(hit => hit.rule_id()), ["rule-first", "rule-second"])
}

///|
test "rejects incomplete rules" {
  try
    @hostsentinel.Rule::new(
      id="",
      name="Name",
      description="Description",
      version=1,
      condition=@hostsentinel.RuleCondition::EventKindIs(
        @hostsentinel.EventKind::File,
      ),
    )
  catch {
    @hostsentinel.RuleError::EmptyRuleId => ()
    _ => fail("expected an empty rule id error")
  } noraise {
    _ => fail("expected rule construction to fail")
  }

  try
    @hostsentinel.Rule::new(
      id="rule-empty",
      name="Name",
      description="Description",
      version=1,
      condition=@hostsentinel.RuleCondition::All([]),
    )
  catch {
    @hostsentinel.RuleError::EmptyConditionGroup => ()
    _ => fail("expected an empty condition group error")
  } noraise {
    _ => fail("expected rule construction to fail")
  }
}
