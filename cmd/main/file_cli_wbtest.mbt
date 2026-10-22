///|
#cfg(target="native")
async test "disk rule and event fixtures run through all five CLI scenarios" {
  for
    name in [
      "session-chain", "auth-failures", "process-network", "parent-child", "distinct-destinations",
    ] {
    let dir = "fixtures/correlation/"
    let format = if name == "session-chain" || name == "process-network" {
      "legacy"
    } else {
      "ocsf"
    }
    let rules = load_cli_rules(["--rule-file", "\{dir}\{name}.rules.json"])
    assert_eq(rules.length(), 1)
    let positive = load_cli_events([
      "--events-file",
      "\{dir}\{name}.positive.jsonl",
      "--format",
      format,
    ])
    let negative = load_cli_events([
      "--events-file",
      "\{dir}\{name}.negative.jsonl",
      "--format",
      format,
    ])
    let accepted = @core.correlate_identity_safe(rules[0], positive)
    let rejected = @core.correlate_identity_safe(
      rules[0],
      negative,
      diagnostic=true,
    )
    assert_eq(accepted.results().length(), 1)
    assert_eq(accepted.results()[0].rule_id(), name)
    assert_eq(rejected.results().length(), 0)
    assert_true(rejected.diagnostics().length() > 0)
  }
}

///|
#cfg(target="native")
async test "missing disk rule file fails rather than claiming validity" {
  try
    load_cli_rules(["--rule-file", "fixtures/correlation/not-found.json"])
  catch {
    _ => ()
  } noraise {
    _ => fail("missing file accepted")
  }
}

///|
#cfg(target="native")
async test "YAML rule file has the same process-network correlation" {
  let rules = load_cli_rules([
    "--rule-file", "fixtures/correlation/process-network.rules.yaml",
  ])
  let events = load_cli_events([
    "--events-file", "fixtures/correlation/process-network.positive.jsonl",
  ])
  assert_eq(rules.length(), 1)
  assert_eq(rules[0].id(), "process-network")
  assert_eq(
    @core.correlate_identity_safe(rules[0], events).results().length(),
    1,
  )
}

///|
#cfg(target="native")
async test "native telemetry files pass through CLI adapters" {
  let sysmon = load_cli_events([
    "--events-file", "fixtures/sysmon-process-create.xml", "--format", "sysmon",
  ])
  let windows = load_cli_events([
    "--events-file", "fixtures/windows-security-4624.xml", "--format", "windows",
  ])
  let auditd = load_cli_events([
    "--events-file", "fixtures/auditd-exec-group.log", "--format", "auditd", "--host-id",
    "test-host",
  ])
  assert_eq(sysmon.length(), 1)
  assert_eq(windows.length(), 1)
  assert_eq(auditd.length(), 1)
  assert_eq(sysmon[0].class_name, "process_activity")
  assert_eq(windows[0].class_name, "authentication")
  assert_eq(auditd[0].class_name, "process_activity")
}
