///|
fn sigma_test_event(
  id : String,
  host : String,
  class_name : String,
  time_ms : Int64,
  source : @hostsentinel.EventSource,
  src_ip : String?,
  dst_ip : String?,
) -> @hostsentinel.HostEvent {
  {
    id: try! @hostsentinel.EventId::new(value=id),
    source,
    source_id: @hostsentinel.Identity::missing(),
    time: {
      value: time_ms,
      precision: @hostsentinel.TimePrecision::Milliseconds,
    },
    category: "test",
    class_name,
    activity: "observed",
    ocsf: None,
    identities: {
      host: try! @hostsentinel.Identity::unverified(host),
      boot: @hostsentinel.Identity::missing(),
      user: @hostsentinel.Identity::missing(),
      session: @hostsentinel.Identity::missing(),
      process: @hostsentinel.Identity::missing(),
      parent_process: @hostsentinel.Identity::missing(),
    },
    network: { src_ip, src_port: None, dst_ip, dst_port: None, protocol: None, },
    original: {
      format: "test",
      record_number: 1,
      record_id: Some(id),
      raw: id,
    },
    diagnostics: [],
  }
}

///|
test "event_count uses unique events, inclusive windows and host grouping" {
  let source =
    #|[{"id":"a","version":1,"detection":{"selection":{"class":"auth"},"condition":"selection"}},{"id":"c","version":1,"correlation":{"type":"event_count","rules":["a"],"group-by":["host"],"timespan":"10s","condition":{"gte":2}}}]
  let rule = @hostsentinel.compile_correlation_rules_json(source)[0]
  let a = sigma_test_event(
    "a",
    "h1",
    "auth",
    0L,
    @hostsentinel.EventSource::Agent,
    None,
    None,
  )
  let b = sigma_test_event(
    "b",
    "h1",
    "auth",
    10000L,
    @hostsentinel.EventSource::Agent,
    None,
    None,
  )
  let c = sigma_test_event(
    "c",
    "h1",
    "auth",
    20001L,
    @hostsentinel.EventSource::Agent,
    None,
    None,
  )
  let other = sigma_test_event(
    "d",
    "h2",
    "auth",
    5000L,
    @hostsentinel.EventSource::Agent,
    None,
    None,
  )
  let first = @hostsentinel.match_correlation_rule(rule, [c, other, b, a, b])
  let second = @hostsentinel.match_correlation_rule(rule, [a, b, c, other])
  assert_eq(first.length(), 1)
  assert_eq(first[0].event_ids(), ["a", "b"])
  assert_eq(first[0].event_ids(), second[0].event_ids())
  assert_eq(first[0].observed_count(), 2)
  assert_eq(first[0].ended_ms() - first[0].started_ms(), 10000L)
}

///|
test "value_count counts distinct present values rather than events" {
  let source =
    #|[{"id":"n","version":1,"detection":{"selection":{"class":"network"},"condition":"selection"}},{"id":"vc","version":1,"correlation":{"type":"value_count","rules":["n"],"group-by":["host"],"timespan":"1m","condition":{"gte":2,"field":"dst_ip"}}}]
  let rule = @hostsentinel.compile_correlation_rules_json(source)[0]
  let a = sigma_test_event(
    "a",
    "h",
    "network",
    0L,
    @hostsentinel.EventSource::Agent,
    None,
    Some("1.1.1.1"),
  )
  let b = sigma_test_event(
    "b",
    "h",
    "network",
    1000L,
    @hostsentinel.EventSource::Agent,
    None,
    Some("1.1.1.1"),
  )
  let missing = sigma_test_event(
    "m",
    "h",
    "network",
    2000L,
    @hostsentinel.EventSource::Agent,
    None,
    None,
  )
  assert_eq(
    @hostsentinel.match_correlation_rule(rule, [a, b, missing]).length(),
    0,
  )
  let c = sigma_test_event(
    "c",
    "h",
    "network",
    60000L,
    @hostsentinel.EventSource::Auditd,
    None,
    Some("2.2.2.2"),
  )
  let hits = @hostsentinel.match_correlation_rule(rule, [c, missing, b, a, c])
  assert_eq(hits.length(), 2)
  assert_eq(hits[0].event_ids(), ["a", "c"])
  assert_eq(hits[1].event_ids(), ["b", "c"])
  assert_eq(hits[0].observed_count(), 2)
  let far = sigma_test_event(
    "far",
    "h",
    "network",
    61001L,
    @hostsentinel.EventSource::Agent,
    None,
    Some("3.3.3.3"),
  )
  assert_eq(@hostsentinel.match_correlation_rule(rule, [a, b, far]).length(), 0)
}

///|
test "temporal co-occurrence differs from ordered sequence" {
  let source =
    #|[{"id":"auth","version":1,"detection":{"selection":{"class":"auth"},"condition":"selection"}},{"id":"proc","version":1,"detection":{"selection":{"class":"process"},"condition":"selection"}},{"id":"t","version":1,"correlation":{"type":"temporal","rules":["auth","proc"],"group-by":["host"],"timespan":"10s"}},{"id":"o","version":1,"correlation":{"type":"temporal_ordered","rules":["auth","proc"],"group-by":["host"],"timespan":"10s"}}]
  let rules = @hostsentinel.compile_correlation_rules_json(source)
  let proc = sigma_test_event(
    "p",
    "h",
    "process",
    0L,
    @hostsentinel.EventSource::Sysmon,
    None,
    None,
  )
  let auth = sigma_test_event(
    "a",
    "h",
    "auth",
    10000L,
    @hostsentinel.EventSource::WindowsEvent,
    None,
    None,
  )
  assert_true(
    @hostsentinel.match_correlation_rule(rules[0], [auth, proc]).length() > 0,
  )
  assert_eq(
    @hostsentinel.match_correlation_rule(rules[1], [auth, proc]).length(),
    0,
  )
  let later = sigma_test_event(
    "p2",
    "h",
    "process",
    10000L,
    @hostsentinel.EventSource::Sysmon,
    None,
    None,
  )
  let early = sigma_test_event(
    "a2",
    "h",
    "auth",
    0L,
    @hostsentinel.EventSource::WindowsEvent,
    None,
    None,
  )
  let ordered = @hostsentinel.match_correlation_rule(rules[1], [later, early])
  assert_eq(ordered.length(), 1)
  assert_eq(ordered[0].event_ids(), ["a2", "p2"])
  let wrong_host = sigma_test_event(
    "p3",
    "other",
    "process",
    10000L,
    @hostsentinel.EventSource::Sysmon,
    None,
    None,
  )
  assert_eq(
    @hostsentinel.match_correlation_rule(rules[1], [early, wrong_host]).length(),
    0,
  )
  let outside = sigma_test_event(
    "p4",
    "h",
    "process",
    10001L,
    @hostsentinel.EventSource::Sysmon,
    None,
    None,
  )
  assert_eq(
    @hostsentinel.match_correlation_rule(rules[1], [early, outside]).length(),
    0,
  )
}

///|
test "aliases resolve source-specific grouping fields" {
  let source =
    #|[{"id":"a","version":1,"detection":{"selection":{"class":"auth"},"condition":"selection"}},{"id":"b","version":1,"detection":{"selection":{"class":"network"},"condition":"selection"}},{"id":"c","version":1,"correlation":{"type":"temporal_ordered","rules":["a","b"],"group-by":["peer"],"aliases":{"peer":{"a":"src_ip","b":"dst_ip"}},"timespan":"1m"}}]
  let rule = @hostsentinel.compile_correlation_rules_json(source)[0]
  let a = sigma_test_event(
    "a",
    "h",
    "auth",
    0L,
    @hostsentinel.EventSource::Agent,
    Some("10.0.0.1"),
    None,
  )
  let b = sigma_test_event(
    "b",
    "h",
    "network",
    1000L,
    @hostsentinel.EventSource::Auditd,
    None,
    Some("10.0.0.1"),
  )
  assert_eq(@hostsentinel.match_correlation_rule(rule, [b, a]).length(), 1)
  let wrong = sigma_test_event(
    "x",
    "h",
    "network",
    1000L,
    @hostsentinel.EventSource::Auditd,
    None,
    Some("10.0.0.2"),
  )
  assert_eq(@hostsentinel.match_correlation_rule(rule, [a, wrong]).length(), 0)
}

///|
test "temporal finds a distinct-event assignment when filters overlap" {
  let source =
    #|[{"id":"agent","version":1,"detection":{"selection":{"source":"agent"},"condition":"selection"}},{"id":"auth","version":1,"detection":{"selection":{"class":"auth"},"condition":"selection"}},{"id":"t","version":1,"correlation":{"type":"temporal","rules":["agent","auth"],"group-by":["host"],"timespan":"5s"}}]
  let rule = @hostsentinel.compile_correlation_rules_json(source)[0]
  let both = sigma_test_event(
    "both",
    "h",
    "auth",
    0L,
    @hostsentinel.EventSource::Agent,
    None,
    None,
  )
  let only_agent = sigma_test_event(
    "agent",
    "h",
    "process",
    1000L,
    @hostsentinel.EventSource::Agent,
    None,
    None,
  )
  let hits = @hostsentinel.match_correlation_rule(rule, [both, only_agent])
  assert_eq(hits.length(), 1)
  assert_eq(hits[0].event_ids(), ["agent", "both"])
  assert_eq(
    @hostsentinel.match_correlation_rule(rule, [both, both]).length(),
    0,
  )
}

///|
test "conflicting duplicate IDs fail rather than depend on input order" {
  let source =
    #|[{"id":"a","version":1,"detection":{"selection":{"class":"auth"},"condition":"selection"}},{"id":"c","version":1,"correlation":{"type":"event_count","rules":["a"],"timespan":"1m","condition":{"gte":2}}}]
  let rule = @hostsentinel.compile_correlation_rules_json(source)[0]
  let a = sigma_test_event(
    "same",
    "h",
    "auth",
    0L,
    @hostsentinel.EventSource::Agent,
    None,
    None,
  )
  let b = sigma_test_event(
    "same",
    "h",
    "auth",
    1000L,
    @hostsentinel.EventSource::Agent,
    None,
    None,
  )
  try @hostsentinel.match_correlation_rule(rule, [a, b]) catch {
    @hostsentinel.CorrelationRuleError::Invalid(detail~, ..) =>
      assert_true(detail.contains("conflicting duplicate"))
  } noraise {
    _ => fail("conflicting duplicate accepted")
  }
}
