///|
test "retail order and payment correlation without HostEvent" {
  let rule : @eventcorr.Rule = {
    id: "order-paid",
    kind: @eventcorr.Kind::TemporalOrdered,
    roles: ["placed", "paid"],
    window_ms: 60000,
    operator: None,
    threshold: None,
  }
  let records : Array[@eventcorr.Hit] = [
    {
      event_key: "orders:1",
      role: "placed",
      source: "orders-api",
      time_ms: 1000,
      group_key: "order-17",
      value: None,
    },
    {
      event_key: "payments:8",
      role: "paid",
      source: "payments-api",
      time_ms: 2500,
      group_key: "order-17",
      value: None,
    },
    {
      event_key: "payments:9",
      role: "paid",
      source: "payments-api",
      time_ms: 2500,
      group_key: "order-18",
      value: None,
    },
  ]
  let matches = @eventcorr.correlate(rule, records)
  assert_eq(matches.length(), 1)
  assert_eq(matches[0].group_key(), "order-17")
  assert_eq(matches[0].event_keys(), ["orders:1", "payments:8"])
  assert_eq(matches[0].roles(), ["placed", "paid"])
  assert_eq(matches[0].started_ms(), 1000)
  assert_eq(matches[0].ended_ms(), 2500)
}

///|
test "service monitoring alert burst uses a different correlation kind" {
  let rule : @eventcorr.Rule = {
    id: "alert-burst",
    kind: @eventcorr.Kind::EventCount,
    roles: ["alerted"],
    window_ms: 30000,
    operator: Some(@eventcorr.CountOperator::Gte),
    threshold: Some(2),
  }
  let records : Array[@eventcorr.Hit] = [
    {
      event_key: "monitor:1",
      role: "alerted",
      source: "monitoring",
      time_ms: 100,
      group_key: "service-a",
      value: None,
    },
    {
      event_key: "monitor:2",
      role: "alerted",
      source: "monitoring",
      time_ms: 400,
      group_key: "service-a",
      value: None,
    },
    {
      event_key: "monitor:3",
      role: "alerted",
      source: "monitoring",
      time_ms: 400,
      group_key: "service-b",
      value: None,
    },
  ]
  let matches = @eventcorr.correlate(rule, records)
  assert_eq(matches.length(), 1)
  assert_eq(matches[0].group_key(), "service-a")
}
