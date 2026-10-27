///|
test "count, group isolation and inclusive window" {
  let rule : @eventcorr.Rule = {
    id: "count",
    kind: @eventcorr.Kind::EventCount,
    roles: ["seen"],
    window_ms: 1000,
    operator: Some(@eventcorr.CountOperator::Gte),
    threshold: Some(2),
  }
  let hits : Array[@eventcorr.Hit] = [
    {
      event_key: "a",
      role: "seen",
      source: "one",
      time_ms: 1000,
      group_key: "A",
      value: None,
    },
    {
      event_key: "b",
      role: "seen",
      source: "two",
      time_ms: 0,
      group_key: "A",
      value: None,
    },
    {
      event_key: "c",
      role: "seen",
      source: "two",
      time_ms: 0,
      group_key: "B",
      value: None,
    },
  ]
  let matches = @eventcorr.correlate(rule, hits)
  assert_eq(matches.length(), 1)
  assert_eq(matches[0].group_key(), "A")
  assert_eq(matches[0].observed_count(), 2)
  assert_eq(matches[0].hit_indices(), [1, 0])
}

///|
test "distinct values and missing values" {
  let rule : @eventcorr.Rule = {
    id: "distinct",
    kind: @eventcorr.Kind::ValueCount,
    roles: ["visit"],
    window_ms: 100,
    operator: Some(@eventcorr.CountOperator::Gte),
    threshold: Some(2),
  }
  let hits : Array[@eventcorr.Hit] = [
    {
      event_key: "a",
      role: "visit",
      source: "web",
      time_ms: 0,
      group_key: "site",
      value: Some("/a"),
    },
    {
      event_key: "b",
      role: "visit",
      source: "web",
      time_ms: 1,
      group_key: "site",
      value: Some("/a"),
    },
    {
      event_key: "c",
      role: "visit",
      source: "web",
      time_ms: 2,
      group_key: "site",
      value: None,
    },
    {
      event_key: "d",
      role: "visit",
      source: "web",
      time_ms: 3,
      group_key: "site",
      value: Some("/b"),
    },
  ]
  let matches = @eventcorr.correlate(rule, hits)
  assert_eq(matches.length(), 2)
  assert_eq(matches[0].hit_indices(), [0, 3])
  assert_eq(matches[1].hit_indices(), [1, 3])
}

///|
test "ordered sequence rejects reverse order and one event reused as two roles" {
  let rule : @eventcorr.Rule = {
    id: "sequence",
    kind: @eventcorr.Kind::TemporalOrdered,
    roles: ["created", "paid"],
    window_ms: 50,
    operator: None,
    threshold: None,
  }
  let same_event : Array[@eventcorr.Hit] = [
    {
      event_key: "a",
      role: "created",
      source: "bus",
      time_ms: 0,
      group_key: "order-1",
      value: None,
    },
    {
      event_key: "a",
      role: "paid",
      source: "bus",
      time_ms: 0,
      group_key: "order-1",
      value: None,
    },
  ]
  assert_eq(@eventcorr.correlate(rule, same_event).length(), 0)
  let reverse : Array[@eventcorr.Hit] = [
    {
      event_key: "a",
      role: "paid",
      source: "payments",
      time_ms: 0,
      group_key: "order-1",
      value: None,
    },
    {
      event_key: "b",
      role: "created",
      source: "orders",
      time_ms: 1,
      group_key: "order-1",
      value: None,
    },
  ]
  assert_eq(@eventcorr.correlate(rule, reverse).length(), 0)
}

///|
test "unordered roles match regardless of event time order" {
  let rule : @eventcorr.Rule = {
    id: "unordered",
    kind: @eventcorr.Kind::Temporal,
    roles: ["created", "paid"],
    window_ms: 20,
    operator: None,
    threshold: None,
  }
  let hits : Array[@eventcorr.Hit] = [
    {
      event_key: "paid-1",
      role: "paid",
      source: "payments",
      time_ms: 10,
      group_key: "order-1",
      value: None,
    },
    {
      event_key: "created-1",
      role: "created",
      source: "orders",
      time_ms: 20,
      group_key: "order-1",
      value: None,
    },
  ]
  let matches = @eventcorr.correlate(rule, hits)
  assert_eq(matches.length(), 1)
  assert_eq(matches[0].roles(), ["created", "paid"])
  assert_eq(matches[0].started_ms(), 10)
  assert_eq(matches[0].ended_ms(), 20)
}

///|
test "invalid rule and candidate budget are explicit" {
  let rule : @eventcorr.Rule = {
    id: "count",
    kind: @eventcorr.Kind::EventCount,
    roles: ["seen"],
    window_ms: 5,
    operator: Some(@eventcorr.CountOperator::Gte),
    threshold: Some(1),
  }
  let hits : Array[@eventcorr.Hit] = [
    {
      event_key: "a",
      role: "seen",
      source: "one",
      time_ms: 0,
      group_key: "x",
      value: None,
    },
    {
      event_key: "b",
      role: "seen",
      source: "one",
      time_ms: 1,
      group_key: "x",
      value: None,
    },
  ]
  try @eventcorr.correlate(rule, hits, max_candidates=1) catch {
    @eventcorr.CorrelationError::Invalid(message) =>
      assert_eq(message, "candidate budget exceeded")
  } noraise {
    _ => fail("expected candidate budget error")
  }
  let invalid = { ..rule, window_ms: 0, }
  try @eventcorr.correlate(invalid, hits) catch {
    @eventcorr.CorrelationError::Invalid(_) => ()
  } noraise {
    _ => fail("expected invalid rule error")
  }
}
