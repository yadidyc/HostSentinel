///|
test "JSON rule IR compiles base selectors and all four correlation kinds" {
  let source =
    #|[{"id":"base","name":"process","version":1,"detection":{"selection":{"class":"process","source":"sysmon"},"condition":"selection"}},{"id":"count","version":2,"correlation":{"type":"event_count","rules":["process"],"group-by":["host"],"timespan":"90s","condition":{"gte":2}}},{"id":"distinct","version":1,"correlation":{"type":"value_count","rules":["base"],"timespan":"1m","condition":{"gte":2,"field":"dst_ip"}}},{"id":"t","version":1,"correlation":{"type":"temporal","rules":["process"],"timespan":"1h"}},{"id":"o","version":1,"correlation":{"type":"temporal_ordered","rules":["process"],"timespan":"1d"}}]
  let rules = @hostsentinel.compile_correlation_rules_json(source)
  assert_eq(rules.length(), 4)
  assert_eq(rules[0].id(), "count")
  assert_eq(rules[0].version(), 2)
  assert_eq(rules[0].window_ms(), 90000L)
  assert_eq(rules[0].kind(), @hostsentinel.CorrelationRuleKind::EventCount)
  assert_eq(rules[1].kind(), @hostsentinel.CorrelationRuleKind::ValueCount)
  assert_eq(rules[2].kind(), @hostsentinel.CorrelationRuleKind::Temporal)
  assert_eq(rules[3].kind(), @hostsentinel.CorrelationRuleKind::TemporalOrdered)
}

///|
test "block YAML Sigma subset compiles with aliases" {
  let source =
    #|id: first
    #|version: 1
    #|detection:
    #|  selection:
    #|    class: process
    #|  condition: selection
    #|---
    #|id: second
    #|version: 1
    #|detection:
    #|  selection:
    #|    class: network
    #|  condition: selection
    #|---
    #|id: chain
    #|version: 1
    #|correlation:
    #|  type: temporal_ordered
    #|  rules:
    #|    - first
    #|    - second
    #|  group-by:
    #|    - peer
    #|  aliases:
    #|    peer:
    #|      first: src_ip
    #|      second: dst_ip
    #|  timespan: 5m
  let rules = @hostsentinel.compile_correlation_rules_yaml(source) catch {
    @hostsentinel.CorrelationRuleError::Invalid(path~, detail~) =>
      fail("\{path}: \{detail}")
  }
  assert_eq(rules.length(), 1)
  assert_eq(rules[0].window_ms(), 300000L)
  assert_eq(rules[0].rule_ids(), ["first", "second"])
}

///|
test "unknown rule references and cycles fail before compilation" {
  let unknown =
    #|[{"id":"chain","version":1,"correlation":{"type":"temporal","rules":["missing"],"timespan":"1m"}}]
  try @hostsentinel.compile_correlation_rules_json(unknown) catch {
    @hostsentinel.CorrelationRuleError::Invalid(path~, detail~) => {
      assert_true(path.contains("rules"))
      assert_true(detail.contains("unknown rule reference"))
    }
  } noraise {
    _ => fail("unknown reference accepted")
  }
  let cycle =
    #|[{"id":"a","version":1,"correlation":{"type":"temporal","rules":["b"],"timespan":"1m"}},{"id":"b","version":1,"correlation":{"type":"temporal","rules":["a"],"timespan":"1m"}}]
  try @hostsentinel.compile_correlation_rules_json(cycle) catch {
    @hostsentinel.CorrelationRuleError::Invalid(detail~, ..) =>
      assert_true(detail.contains("cyclic"))
  } noraise {
    _ => fail("cycle accepted")
  }
}

///|
test "strict schema rejects unsupported fields, types and invalid timespans" {
  let bad_field =
    #|[{"id":"b","version":1,"detection":{"selection":{"unknown":"x"},"condition":"selection"}}]
  try @hostsentinel.compile_correlation_rules_json(bad_field) catch {
    @hostsentinel.CorrelationRuleError::Invalid(path~, ..) =>
      assert_true(path.contains("unknown"))
  } noraise {
    _ => fail("unknown event field accepted")
  }
  let bad_type =
    #|[{"id":"b","version":1,"detection":{"selection":{"class":"x"},"condition":"selection"}},{"id":"c","version":1,"correlation":{"type":"value_sum","rules":["b"],"timespan":"1m","condition":{"gte":1,"field":"src_ip"}}}]
  try @hostsentinel.compile_correlation_rules_json(bad_type) catch {
    @hostsentinel.CorrelationRuleError::Invalid(detail~, ..) =>
      assert_true(detail.contains("unsupported correlation type"))
  } noraise {
    _ => fail("unsupported correlation type accepted")
  }
  let bad_window =
    #|[{"id":"b","version":1,"detection":{"selection":{"class":"x"},"condition":"selection"}},{"id":"c","version":1,"correlation":{"type":"event_count","rules":["b"],"timespan":"0m","condition":{"gte":1}}}]
  try @hostsentinel.compile_correlation_rules_json(bad_window) catch {
    @hostsentinel.CorrelationRuleError::Invalid(path~, ..) =>
      assert_true(path.contains("timespan"))
  } noraise {
    _ => fail("zero timespan accepted")
  }
}
