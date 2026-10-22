///|
fn scenario_claim(value : String?) -> @hostsentinel.Identity {
  match value {
    Some(text) => try! @hostsentinel.Identity::unverified(text)
    None => @hostsentinel.Identity::missing()
  }
}

///|
fn scenario_event(
  id : String,
  class_name : String,
  source : @hostsentinel.EventSource,
  source_id : String?,
  time_ms : Int64,
  boot : String,
  session : String?,
  process : String?,
  parent : String?,
  dst_ip : String?,
) -> @hostsentinel.HostEvent {
  {
    id: try! @hostsentinel.EventId::new(value=id),
    source,
    source_id: scenario_claim(source_id),
    time: {
      value: time_ms,
      precision: @hostsentinel.TimePrecision::Milliseconds,
    },
    category: "synthetic",
    class_name,
    activity: "observed",
    ocsf: None,
    identities: {
      host: scenario_claim(Some("host-1")),
      boot: scenario_claim(Some(boot)),
      user: scenario_claim(None),
      session: scenario_claim(session),
      process: scenario_claim(process),
      parent_process: scenario_claim(parent),
    },
    network: {
      src_ip: None,
      src_port: None,
      dst_ip,
      dst_port: None,
      protocol: None,
    },
    original: {
      format: "scenario-fixture",
      record_number: 1,
      record_id: Some(id),
      raw: "synthetic fixture",
    },
    diagnostics: [],
  }
}

///|
fn scenario_rule(name : String) -> @hostsentinel.CompiledCorrelationRule {
  // Mirrors the checked-in external JSON files; file loading belongs to CLI stage 11.
  let source = match name {
    "session-chain" =>
      (
        #|[{"id":"login","version":1,"detection":{"selection":{"class":"authentication"},"condition":"selection"}},{"id":"launch","version":1,"detection":{"selection":{"class":"process"},"condition":"selection"}},{"id":"connect","version":1,"detection":{"selection":{"class":"network"},"condition":"selection"}},{"id":"session-chain","version":1,"correlation":{"type":"temporal_ordered","rules":["login","launch","connect"],"group-by":["host"],"timespan":"90s","identity":{"same":["boot","session"],"same-between":[{"field":"process","rules":["launch","connect"]}],"sources":"different","missing":"reject"}}}]
      )
    "auth-failures" =>
      (
        #|[{"id":"failure","version":1,"detection":{"selection":{"class":"authentication","source_id":"failure-feed"},"condition":"selection"}},{"id":"auth-failures","version":1,"correlation":{"type":"event_count","rules":["failure"],"group-by":["host","session"],"timespan":"60s","condition":{"gte":3},"identity":{"same":["boot","session"],"missing":"reject"}}}]
      )
    "process-network" =>
      (
        #|[{"id":"process","version":1,"detection":{"selection":{"class":"process"},"condition":"selection"}},{"id":"network","version":1,"detection":{"selection":{"class":"network"},"condition":"selection"}},{"id":"process-network","version":1,"correlation":{"type":"temporal_ordered","rules":["process","network"],"group-by":["host"],"timespan":"30s","identity":{"same":["boot","process"],"sources":"different","missing":"reject"}}}]
      )
    "parent-child" =>
      (
        #|[{"id":"parent","version":1,"detection":{"selection":{"class":"process_activity","source_id":"parent-feed"},"condition":"selection"}},{"id":"child","version":1,"detection":{"selection":{"class":"process_activity","source_id":"child-feed"},"condition":"selection"}},{"id":"parent-child","version":1,"correlation":{"type":"temporal_ordered","rules":["parent","child"],"group-by":["host"],"timespan":"30s","identity":{"same":["boot"],"parent-child":[{"parent":"parent","child":"child"}],"missing":"reject"}}}]
      )
    "distinct-destinations" =>
      (
        #|[{"id":"connection","version":1,"detection":{"selection":{"class":"network_activity"},"condition":"selection"}},{"id":"distinct-destinations","version":1,"correlation":{"type":"value_count","rules":["connection"],"group-by":["host"],"timespan":"60s","condition":{"gte":3,"field":"dst_ip"},"identity":{"same":["boot"],"missing":"reject"}}}]
      )
    _ => ""
  }
  try! @hostsentinel.compile_correlation_rules_json(source)[0]
}

///|
fn scenario_assert(
  name : String,
  positive : Array[@hostsentinel.HostEvent],
  negative : Array[@hostsentinel.HostEvent],
  expected_ids : Array[String],
  expected_rejection : String,
) -> Unit raise {
  let rule = scenario_rule(name)
  let accepted = try! @hostsentinel.correlate_identity_safe(
    rule,
    positive,
    diagnostic=true,
  )
  assert_eq(accepted.results().length(), 1)
  assert_eq(accepted.results()[0].rule_id(), name)
  assert_eq(accepted.results()[0].event_ids(), expected_ids)
  assert_eq(
    accepted.results()[0].grade(),
    @hostsentinel.IdentityEvidenceGrade::Claimed,
  )
  let rejected = try! @hostsentinel.correlate_identity_safe(
    rule,
    negative,
    diagnostic=true,
  )
  assert_eq(rejected.results().length(), 0)
  assert_true(rejected.diagnostics().length() > 0)
  assert_true(rejected.diagnostics()[0].reason().contains(expected_rejection))
}

///|
test "scenario 1 session chain rejects reused process instance" {
  let auth = scenario_event(
    "login-1",
    "authentication",
    @hostsentinel.EventSource::WindowsEvent,
    None,
    100000L,
    "boot-1",
    Some("S1"),
    None,
    None,
    None,
  )
  let process = scenario_event(
    "process-1",
    "process",
    @hostsentinel.EventSource::Sysmon,
    None,
    110000L,
    "boot-1",
    Some("S1"),
    Some("proc-42"),
    None,
    None,
  )
  let network = scenario_event(
    "network-1",
    "network",
    @hostsentinel.EventSource::Agent,
    None,
    120000L,
    "boot-1",
    Some("S1"),
    Some("proc-42"),
    None,
    None,
  )
  let reused = scenario_event(
    "network-1",
    "network",
    @hostsentinel.EventSource::Agent,
    None,
    120000L,
    "boot-1",
    Some("S1"),
    Some("proc-reused"),
    None,
    None,
  )
  scenario_assert(
    "session-chain",
    [auth, process, network],
    [auth, process, reused],
    ["login-1", "process-1", "network-1"],
    "process mismatch",
  )
}

///|
test "scenario 2 failure-feed burst rejects reboot collision" {
  let a = scenario_event(
    "failure-1",
    "authentication",
    @hostsentinel.EventSource::Other("ocsf"),
    Some("failure-feed"),
    100000L,
    "boot-1",
    Some("S1"),
    None,
    None,
    None,
  )
  let b = scenario_event(
    "failure-2",
    "authentication",
    @hostsentinel.EventSource::Other("ocsf"),
    Some("failure-feed"),
    110000L,
    "boot-1",
    Some("S1"),
    None,
    None,
    None,
  )
  let c = scenario_event(
    "failure-3",
    "authentication",
    @hostsentinel.EventSource::Other("ocsf"),
    Some("failure-feed"),
    120000L,
    "boot-1",
    Some("S1"),
    None,
    None,
    None,
  )
  let rebooted = scenario_event(
    "failure-3",
    "authentication",
    @hostsentinel.EventSource::Other("ocsf"),
    Some("failure-feed"),
    120000L,
    "boot-2",
    Some("S1"),
    None,
    None,
    None,
  )
  scenario_assert(
    "auth-failures",
    [a, b, c],
    [a, b, rebooted],
    ["failure-1", "failure-2", "failure-3"],
    "boot mismatch",
  )
}

///|
test "scenario 3 process to network rejects PID reuse" {
  let process = scenario_event(
    "process-1",
    "process",
    @hostsentinel.EventSource::Sysmon,
    None,
    100000L,
    "boot-1",
    None,
    Some("proc-42"),
    None,
    None,
  )
  let network = scenario_event(
    "network-1",
    "network",
    @hostsentinel.EventSource::Agent,
    None,
    110000L,
    "boot-1",
    None,
    Some("proc-42"),
    None,
    None,
  )
  let reused = scenario_event(
    "network-1",
    "network",
    @hostsentinel.EventSource::Agent,
    None,
    110000L,
    "boot-1",
    None,
    Some("proc-reused"),
    None,
    None,
  )
  scenario_assert(
    "process-network",
    [process, network],
    [process, reused],
    ["process-1", "network-1"],
    "process mismatch",
  )
}

///|
test "scenario 4 parent-child requires linked process identity" {
  let parent = scenario_event(
    "parent-1",
    "process_activity",
    @hostsentinel.EventSource::Other("ocsf"),
    Some("parent-feed"),
    100000L,
    "boot-1",
    None,
    Some("process-parent"),
    None,
    None,
  )
  let child = scenario_event(
    "child-1",
    "process_activity",
    @hostsentinel.EventSource::Other("ocsf"),
    Some("child-feed"),
    110000L,
    "boot-1",
    None,
    Some("process-child"),
    Some("process-parent"),
    None,
  )
  let unrelated = scenario_event(
    "child-1",
    "process_activity",
    @hostsentinel.EventSource::Other("ocsf"),
    Some("child-feed"),
    110000L,
    "boot-1",
    None,
    Some("process-child"),
    Some("other-parent"),
    None,
  )
  scenario_assert(
    "parent-child",
    [parent, child],
    [parent, unrelated],
    ["parent-1", "child-1"],
    "parent-child mismatch",
  )
}

///|
test "scenario 5 distinct destinations rejects cross-boot count" {
  let a = scenario_event(
    "network-1",
    "network_activity",
    @hostsentinel.EventSource::Other("ocsf"),
    None,
    100000L,
    "boot-1",
    None,
    None,
    None,
    Some("203.0.113.1"),
  )
  let b = scenario_event(
    "network-2",
    "network_activity",
    @hostsentinel.EventSource::Other("ocsf"),
    None,
    110000L,
    "boot-1",
    None,
    None,
    None,
    Some("203.0.113.2"),
  )
  let c = scenario_event(
    "network-3",
    "network_activity",
    @hostsentinel.EventSource::Other("ocsf"),
    None,
    120000L,
    "boot-1",
    None,
    None,
    None,
    Some("203.0.113.3"),
  )
  let rebooted = scenario_event(
    "network-3",
    "network_activity",
    @hostsentinel.EventSource::Other("ocsf"),
    None,
    120000L,
    "boot-2",
    None,
    None,
    None,
    Some("203.0.113.3"),
  )
  scenario_assert(
    "distinct-destinations",
    [a, b, c],
    [a, b, rebooted],
    ["network-1", "network-2", "network-3"],
    "boot mismatch",
  )
}
