///|
fn identity_test_value(value : String?) -> @hostsentinel.Identity {
  match value {
    Some(text) => try! @hostsentinel.Identity::unverified(text)
    None => @hostsentinel.Identity::missing()
  }
}

///|
fn identity_test_event(
  id : String,
  host : String,
  boot : String?,
  user : String?,
  session : String?,
  process : String?,
  parent : String?,
  class_name : String,
  source : @hostsentinel.EventSource,
  time_ms : Int64,
  trusted~ : Bool = false,
  precision~ : @hostsentinel.TimePrecision = @hostsentinel.TimePrecision::Milliseconds,
) -> @hostsentinel.HostEvent {
  {
    id: try! @hostsentinel.EventId::new(value=id),
    source,
    source_id: @hostsentinel.Identity::missing(),
    time: { value: time_ms, precision, },
    category: "test",
    class_name,
    activity: "observed",
    ocsf: None,
    identities: {
      host: if trusted {
        try! @hostsentinel.Identity::verified(host)
      } else {
        identity_test_value(Some(host))
      },
      boot: identity_test_value(boot),
      user: identity_test_value(user),
      session: identity_test_value(session),
      process: identity_test_value(process),
      parent_process: identity_test_value(parent),
    },
    network: @hostsentinel.NetworkAttributes::empty(),
    original: {
      format: "fixture",
      record_number: 1,
      record_id: Some(id),
      raw: id,
    },
    diagnostics: [],
  }
}

///|
test "identity engine requires host and explicit composite identities" {
  let rule = @hostsentinel.compile_correlation_rules_json(
      (
        #|[{"id":"a","version":1,"detection":{"selection":{"class":"auth"},"condition":"selection"}},{"id":"p","version":1,"detection":{"selection":{"class":"process"},"condition":"selection"}},{"id":"c","version":3,"correlation":{"type":"temporal_ordered","rules":["a","p"],"timespan":"10s","identity":{"same":["boot","user","session"],"sources":"different"}}}]
      ),
    )[0]
  let auth = identity_test_event(
    "a",
    "h",
    Some("b"),
    Some("u"),
    Some("s"),
    None,
    None,
    "auth",
    @hostsentinel.EventSource::WindowsEvent,
    0L,
  )
  let proc = identity_test_event(
    "p",
    "h",
    Some("b"),
    Some("u"),
    Some("s"),
    Some("proc"),
    None,
    "process",
    @hostsentinel.EventSource::Sysmon,
    10000L,
  )
  let report = @hostsentinel.correlate_identity_safe(
    rule,
    [proc, auth],
    diagnostic=true,
  )
  assert_eq(report.results().length(), 1)
  assert_eq(report.results()[0].rule_version(), 3)
  assert_eq(report.results()[0].event_ids(), ["a", "p"])
  assert_eq(
    report.results()[0].grade(),
    @hostsentinel.IdentityEvidenceGrade::Claimed,
  )
  assert_eq(report.results()[0].keys().length(), 4)
  assert_eq(report.results()[0].span_ms(), 10000L)
  assert_true(report.results()[0].mapping()[0].contains("format=fixture"))
  assert_true(report.results()[0].explanation().contains("rule c v3"))
  let other = identity_test_event(
    "p2",
    "other",
    Some("b"),
    Some("u"),
    Some("s"),
    Some("proc"),
    None,
    "process",
    @hostsentinel.EventSource::Sysmon,
    10000L,
  )
  let rejected = @hostsentinel.correlate_identity_safe(
    rule,
    [auth, other],
    diagnostic=true,
  )
  assert_eq(rejected.results().length(), 0)
  assert_true(rejected.diagnostics()[0].reason().contains("host mismatch"))
}

///|
test "missing identity policies reject, expose indeterminate or mark weak" {
  let events = [
    identity_test_event(
      "a",
      "h",
      None,
      None,
      None,
      None,
      None,
      "auth",
      @hostsentinel.EventSource::Agent,
      0L,
    ),
    identity_test_event(
      "b",
      "h",
      None,
      None,
      None,
      None,
      None,
      "process",
      @hostsentinel.EventSource::Auditd,
      1000L,
    ),
  ]
  for policy in ["reject", "indeterminate", "relaxed"] {
    let source =
      $|[{"id":"a","version":1,"detection":{"selection":{"class":"auth"},"condition":"selection"}},{"id":"b","version":1,"detection":{"selection":{"class":"process"},"condition":"selection"}},{"id":"c","version":1,"correlation":{"type":"temporal_ordered","rules":["a","b"],"timespan":"1m","identity":{"same":["boot"],"missing":"\{policy}"}}}]
    let rule = @hostsentinel.compile_correlation_rules_json(source)[0]
    let report = @hostsentinel.correlate_identity_safe(
      rule,
      events,
      diagnostic=true,
    )
    match policy {
      "reject" => {
        assert_eq(report.results().length(), 0)
        assert_true(report.diagnostics()[0].reason().contains("boot missing"))
      }
      "indeterminate" =>
        assert_eq(
          report.results()[0].grade(),
          @hostsentinel.IdentityEvidenceGrade::Indeterminate,
        )
      _ => {
        assert_eq(
          report.results()[0].grade(),
          @hostsentinel.IdentityEvidenceGrade::Weak,
        )
        assert_true(report.results()[0].explanation().contains("boot missing"))
      }
    }
  }
}

///|
test "process instance mismatch and source reuse are explicit rejections" {
  let rule = @hostsentinel.compile_correlation_rules_json(
      (
        #|[{"id":"a","version":1,"detection":{"selection":{"class":"process"},"condition":"selection"}},{"id":"b","version":1,"detection":{"selection":{"class":"network"},"condition":"selection"}},{"id":"c","version":1,"correlation":{"type":"temporal_ordered","rules":["a","b"],"timespan":"1m","identity":{"same":["boot","process"],"sources":"different"}}}]
      ),
    )[0]
  let process = identity_test_event(
    "a",
    "h",
    Some("boot"),
    None,
    None,
    Some("p1"),
    None,
    "process",
    @hostsentinel.EventSource::Sysmon,
    0L,
  )
  let reused = identity_test_event(
    "b",
    "h",
    Some("boot"),
    None,
    None,
    Some("p2"),
    None,
    "network",
    @hostsentinel.EventSource::Auditd,
    1000L,
  )
  let report = @hostsentinel.correlate_identity_safe(
    rule,
    [process, reused],
    diagnostic=true,
  )
  assert_eq(report.results().length(), 0)
  assert_true(report.diagnostics()[0].reason().contains("process mismatch"))
  let same_source = identity_test_event(
    "c",
    "h",
    Some("boot"),
    None,
    None,
    Some("p1"),
    None,
    "network",
    @hostsentinel.EventSource::Sysmon,
    1000L,
  )
  let source_report = @hostsentinel.correlate_identity_safe(
    rule,
    [process, same_source],
    diagnostic=true,
  )
  assert_true(
    source_report.diagnostics()[0].reason().contains("distinct sources"),
  )
}

///|
test "parent-child relationship checks process instance identities" {
  let rule = @hostsentinel.compile_correlation_rules_json(
      (
        #|[{"id":"p","version":1,"detection":{"selection":{"class":"parent"},"condition":"selection"}},{"id":"c","version":1,"detection":{"selection":{"class":"child"},"condition":"selection"}},{"id":"link","version":1,"correlation":{"type":"temporal_ordered","rules":["p","c"],"timespan":"1m","identity":{"parent-child":[{"parent":"p","child":"c"}]}}}]
      ),
    )[0]
  let parent = identity_test_event(
    "p",
    "h",
    None,
    None,
    None,
    Some("guid-1"),
    None,
    "parent",
    @hostsentinel.EventSource::Sysmon,
    0L,
  )
  let child = identity_test_event(
    "c",
    "h",
    None,
    None,
    None,
    Some("guid-2"),
    Some("guid-1"),
    "child",
    @hostsentinel.EventSource::Auditd,
    1000L,
  )
  assert_eq(
    @hostsentinel.correlate_identity_safe(rule, [child, parent])
    .results()
    .length(),
    1,
  )
  let wrong = identity_test_event(
    "x",
    "h",
    None,
    None,
    None,
    Some("guid-2"),
    Some("guid-x"),
    "child",
    @hostsentinel.EventSource::Auditd,
    1000L,
  )
  let report = @hostsentinel.correlate_identity_safe(
    rule,
    [parent, wrong],
    diagnostic=true,
  )
  assert_eq(report.results().length(), 0)
  assert_true(
    report.diagnostics()[0].reason().contains("parent-child mismatch"),
  )
}

///|
test "budgets bound state, candidates, output and diagnostics" {
  let rule = @hostsentinel.compile_correlation_rules_json(
      (
        #|[{"id":"a","version":1,"detection":{"selection":{"class":"auth"},"condition":"selection"}},{"id":"c","version":1,"correlation":{"type":"event_count","rules":["a"],"timespan":"10s","condition":{"gte":1}}}]
      ),
    )[0]
  let a = identity_test_event(
    "a",
    "h",
    None,
    None,
    None,
    None,
    None,
    "auth",
    @hostsentinel.EventSource::Agent,
    0L,
  )
  let b = identity_test_event(
    "b",
    "h",
    None,
    None,
    None,
    None,
    None,
    "auth",
    @hostsentinel.EventSource::Agent,
    1000L,
  )
  try @hostsentinel.correlate_identity_safe(rule, [a, b], max_events=1) catch {
    @hostsentinel.CorrelationRuleError::Invalid(path~, ..) =>
      assert_eq(path, "limits.max_events")
  } noraise {
    _ => fail("state budget ignored")
  }
  try
    @hostsentinel.correlate_identity_safe(rule, [a, b], max_candidates=1)
  catch {
    @hostsentinel.CorrelationRuleError::Invalid(path~, ..) =>
      assert_eq(path, "limits.max_candidates")
  } noraise {
    _ => fail("candidate budget ignored")
  }
  let limited = @hostsentinel.correlate_identity_safe(
    rule,
    [b, a],
    max_results=1,
  )
  assert_eq(limited.results().length(), 1)
  assert_true(limited.results_truncated())
  let other = identity_test_event(
    "x",
    "other",
    None,
    None,
    None,
    None,
    None,
    "auth",
    @hostsentinel.EventSource::Agent,
    1000L,
  )
  let rejected = @hostsentinel.correlate_identity_safe(
    rule,
    [a, b, other],
    max_diagnostics=0,
    diagnostic=true,
  )
  assert_true(rejected.diagnostics_truncated())
}

///|
test "verified identity, composite grouping and same-source constraints" {
  let rule = @hostsentinel.compile_correlation_rules_json(
      (
        #|[{"id":"a","version":1,"detection":{"selection":{"class":"auth"},"condition":"selection"}},{"id":"c","version":1,"correlation":{"type":"event_count","rules":["a"],"group-by":["host","boot"],"timespan":"10s","condition":{"gte":2},"identity":{"sources":"same"}}}]
      ),
    )[0]
  let a = identity_test_event(
    "a",
    "h",
    Some("boot1"),
    None,
    None,
    None,
    None,
    "auth",
    @hostsentinel.EventSource::Agent,
    0L,
    trusted=true,
  )
  let b = identity_test_event(
    "b",
    "h",
    Some("boot1"),
    None,
    None,
    None,
    None,
    "auth",
    @hostsentinel.EventSource::Agent,
    1000L,
    trusted=true,
  )
  let confirmed = @hostsentinel.correlate_identity_safe(rule, [b, a])
  assert_eq(confirmed.results().length(), 1)
  assert_eq(
    confirmed.results()[0].grade(),
    @hostsentinel.IdentityEvidenceGrade::Verified,
  )
  let different_boot = identity_test_event(
    "c",
    "h",
    Some("boot2"),
    None,
    None,
    None,
    None,
    "auth",
    @hostsentinel.EventSource::Agent,
    1000L,
  )
  assert_eq(
    @hostsentinel.correlate_identity_safe(rule, [a, different_boot])
    .results()
    .length(),
    0,
  )
  let different_source = identity_test_event(
    "d",
    "h",
    Some("boot1"),
    None,
    None,
    None,
    None,
    "auth",
    @hostsentinel.EventSource::Auditd,
    1000L,
  )
  let rejected = @hostsentinel.correlate_identity_safe(
    rule,
    [a, different_source],
    diagnostic=true,
  )
  assert_true(rejected.diagnostics()[0].reason().contains("same source"))
}

///|
test "YAML identity extension accepts parent-child map items and validates references" {
  let source =
    #|id: p
    #|version: 1
    #|detection:
    #|  selection:
    #|    class: parent
    #|  condition: selection
    #|---
    #|id: c
    #|version: 1
    #|detection:
    #|  selection:
    #|    class: child
    #|  condition: selection
    #|---
    #|id: link
    #|version: 1
    #|correlation:
    #|  type: temporal_ordered
    #|  rules:
    #|    - p
    #|    - c
    #|  timespan: 1m
    #|  identity:
    #|    parent-child:
    #|      - parent: p
    #|        child: c
    #|    same-between:
    #|      - field: process
    #|        rules:
    #|          - p
    #|          - c
  let rules = @hostsentinel.compile_correlation_rules_yaml(source)
  assert_eq(rules.length(), 1)
  let bad = source.replace(old="child: c", new="child: missing")
  try @hostsentinel.compile_correlation_rules_yaml(bad) catch {
    @hostsentinel.CorrelationRuleError::Invalid(path~, ..) =>
      assert_true(path.contains("parent-child"))
  } noraise {
    _ => fail("unknown parent-child role accepted")
  }
}

///|
test "scoped process identity does not require authentication to have a process" {
  let source =
    #|[{"id":"auth","version":1,"detection":{"selection":{"class":"auth"},"condition":"selection"}},{"id":"proc","version":1,"detection":{"selection":{"class":"process"},"condition":"selection"}},{"id":"net","version":1,"detection":{"selection":{"class":"network"},"condition":"selection"}},{"id":"lead","version":1,"correlation":{"type":"temporal_ordered","rules":["auth","proc","net"],"timespan":"90s","identity":{"same":["boot","session"],"same-between":[{"field":"process","rules":["proc","net"]}],"sources":"different"}}}]
  let rule = @hostsentinel.compile_correlation_rules_json(source)[0]
  let auth = identity_test_event(
    "a",
    "h",
    Some("b"),
    None,
    Some("s"),
    None,
    None,
    "auth",
    @hostsentinel.EventSource::WindowsEvent,
    0L,
  )
  let proc = identity_test_event(
    "p",
    "h",
    Some("b"),
    None,
    Some("s"),
    Some("instance-1"),
    None,
    "process",
    @hostsentinel.EventSource::Sysmon,
    1000L,
  )
  let net = identity_test_event(
    "n",
    "h",
    Some("b"),
    None,
    Some("s"),
    Some("instance-1"),
    None,
    "network",
    @hostsentinel.EventSource::Auditd,
    90000L,
  )
  let result = @hostsentinel.correlate_identity_safe(rule, [net, auth, proc])
  assert_eq(result.results().length(), 1)
  assert_eq(result.results()[0].keys().length(), 4)
  let reused = identity_test_event(
    "r",
    "h",
    Some("b"),
    None,
    Some("s"),
    Some("instance-2"),
    None,
    "network",
    @hostsentinel.EventSource::Auditd,
    90000L,
  )
  let rejected = @hostsentinel.correlate_identity_safe(
    rule,
    [auth, proc, reused],
    diagnostic=true,
  )
  assert_true(rejected.diagnostics()[0].reason().contains("process mismatch"))
}

///|
test "parent-child constraint considers all role witnesses" {
  let rule = @hostsentinel.compile_correlation_rules_json(
      (
        #|[{"id":"p","version":1,"detection":{"selection":{"class":"parent"},"condition":"selection"}},{"id":"c","version":1,"detection":{"selection":{"class":"child"},"condition":"selection"}},{"id":"link","version":1,"correlation":{"type":"event_count","rules":["p","c"],"timespan":"1m","condition":{"gte":3},"identity":{"parent-child":[{"parent":"p","child":"c"}]}}}]
      ),
    )[0]
  let wrong_parent = identity_test_event(
    "p1",
    "h",
    None,
    None,
    None,
    Some("wrong"),
    None,
    "parent",
    @hostsentinel.EventSource::Agent,
    0L,
  )
  let right_parent = identity_test_event(
    "p2",
    "h",
    None,
    None,
    None,
    Some("right"),
    None,
    "parent",
    @hostsentinel.EventSource::Agent,
    1000L,
  )
  let child = identity_test_event(
    "c",
    "h",
    None,
    None,
    None,
    Some("child"),
    Some("right"),
    "child",
    @hostsentinel.EventSource::Agent,
    2000L,
  )
  let result = @hostsentinel.correlate_identity_safe(rule, [
    child, wrong_parent, right_parent,
  ])
  assert_eq(result.results().length(), 1)
  assert_eq(result.results()[0].keys()[1].value, "right")
}

///|
test "seconds and milliseconds normalize to one inclusive window" {
  let rule = @hostsentinel.compile_correlation_rules_json(
      (
        #|[{"id":"a","version":1,"detection":{"selection":{"class":"auth"},"condition":"selection"}},{"id":"c","version":1,"correlation":{"type":"event_count","rules":["a"],"group-by":["host"],"timespan":"1s","condition":{"gte":2}}}]
      ),
    )[0]
  let seconds = identity_test_event(
    "s",
    "h",
    None,
    None,
    None,
    None,
    None,
    "auth",
    @hostsentinel.EventSource::Agent,
    1L,
    precision=@hostsentinel.TimePrecision::Seconds,
  )
  let millis = identity_test_event(
    "m",
    "h",
    None,
    None,
    None,
    None,
    None,
    "auth",
    @hostsentinel.EventSource::Auditd,
    2000L,
  )
  let report = @hostsentinel.correlate_identity_safe(rule, [millis, seconds])
  assert_eq(report.results().length(), 1)
  assert_eq(report.results()[0].span_ms(), 1000L)
}
