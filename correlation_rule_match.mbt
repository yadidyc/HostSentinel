///|
priv struct CorrelationRuleHit {
  event : HostEvent
  rule_id : String
  time_ms : Int64
  event_key : String
  group_key : String
}

///|
/// One deterministic witness for a Sigma-subset correlation condition.
pub struct SigmaCorrelationMatch {
  rule_id : String
  rule_version : Int32
  kind : CorrelationRuleKind
  group_key : String
  event_ids : Array[String]
  matched_rule_ids : Array[String]
  sources : Array[String]
  events : Array[HostEvent]
  started_ms : Int64
  ended_ms : Int64
  observed_count : Int32
}

///|
pub fn SigmaCorrelationMatch::rule_id(self : SigmaCorrelationMatch) -> String {
  self.rule_id
}

///|
pub fn SigmaCorrelationMatch::rule_version(
  self : SigmaCorrelationMatch,
) -> Int32 {
  self.rule_version
}

///|
pub fn SigmaCorrelationMatch::kind(
  self : SigmaCorrelationMatch,
) -> CorrelationRuleKind {
  self.kind
}

///|
pub fn SigmaCorrelationMatch::group_key(self : SigmaCorrelationMatch) -> String {
  self.group_key
}

///|
pub fn SigmaCorrelationMatch::event_ids(
  self : SigmaCorrelationMatch,
) -> Array[String] {
  self.event_ids.copy()
}

///|
pub fn SigmaCorrelationMatch::matched_rule_ids(
  self : SigmaCorrelationMatch,
) -> Array[String] {
  self.matched_rule_ids.copy()
}

///|
pub fn SigmaCorrelationMatch::sources(
  self : SigmaCorrelationMatch,
) -> Array[String] {
  self.sources.copy()
}

///|
pub fn SigmaCorrelationMatch::started_ms(self : SigmaCorrelationMatch) -> Int64 {
  self.started_ms
}

///|
pub fn SigmaCorrelationMatch::ended_ms(self : SigmaCorrelationMatch) -> Int64 {
  self.ended_ms
}

///|
pub fn SigmaCorrelationMatch::observed_count(
  self : SigmaCorrelationMatch,
) -> Int32 {
  self.observed_count
}

///|
fn correlation_event_key(event : HostEvent) -> String {
  let host = match event.identities.host.value() {
    Some(value) => value
    None => "?"
  }
  let parts = [host, source_token(event.source), event.id.as_string()]
  parts.map(part => "\{part.length()}:\{part}").join("|")
}

///|
fn correlation_hits(
  rule : CompiledCorrelationRule,
  events : Array[HostEvent],
) -> Map[String, Array[CorrelationRuleHit]] raise CorrelationRuleError {
  let groups : Map[String, Array[CorrelationRuleHit]] = Map([])
  let seen : Map[String, HostEvent] = Map([])
  for index, event in events {
    let key = correlation_event_key(event)
    match seen.get(key) {
      Some(previous) => {
        if previous != event {
          raise rule_invalid(
            "events[\{index}]",
            "conflicting duplicate event identity",
          )
        }
        continue
      }
      None => ()
    }
    seen[key] = event
    let time_ms = correlation_time_ms(event, "events[\{index}].time")
    for rule_id in rule.rule_ids {
      for base in rule.base_rules {
        if base.id == rule_id && correlation_base_matches(base, event) {
          match correlation_group_key(rule, rule_id, event) {
            Some(group_key) => {
              let hits = groups.get_or_init(group_key, () => [])
              hits.push({ event, rule_id, time_ms, event_key: key, group_key, })
            }
            None => ()
          }
        }
      }
    }
  }
  groups
}

///|
fn correlation_hit_order(
  a : CorrelationRuleHit,
  b : CorrelationRuleHit,
) -> Int32 {
  let time_order = a.time_ms.compare(b.time_ms)
  if time_order != 0 {
    return time_order
  }
  let event_order = a.event_key.compare(b.event_key)
  if event_order != 0 {
    return event_order
  }
  a.rule_id.compare(b.rule_id)
}

///|
fn correlation_window_end(start : Int64, duration : Int64) -> Int64 {
  let max : Int64 = 9223372036854775807
  if start > max - duration {
    max
  } else {
    start + duration
  }
}

///|
fn correlation_window(
  hits : Array[CorrelationRuleHit],
  start : Int32,
  duration : Int64,
) -> Array[CorrelationRuleHit] {
  let selected : Array[CorrelationRuleHit] = []
  let end_time = correlation_window_end(hits[start].time_ms, duration)
  for index in start..<hits.length() {
    if hits[index].time_ms > end_time {
      break
    }
    selected.push(hits[index])
  }
  selected
}

///|
fn correlation_count_witness(
  rule : CompiledCorrelationRule,
  window : Array[CorrelationRuleHit],
) -> (Array[CorrelationRuleHit], Int32) {
  let selected : Array[CorrelationRuleHit] = []
  let seen : Map[String, Bool] = Map([])
  for hit in window {
    let key = match rule.kind {
      CorrelationRuleKind::ValueCount => {
        let field = correlation_resolve_field(
          rule,
          hit.rule_id,
          rule.value_field.unwrap(),
        )
        match correlation_event_field(hit.event, field) {
          Some(value) => "\{value.length()}:\{value}"
          None => continue
        }
      }
      _ => hit.event_key
    }
    if !seen.contains(key) {
      seen[key] = true
      selected.push(hit)
    }
  }
  (selected, selected.length())
}

///|
fn correlation_temporal_witness(
  rule : CompiledCorrelationRule,
  window : Array[CorrelationRuleHit],
) -> (Array[CorrelationRuleHit], Int32) {
  if rule.kind == CorrelationRuleKind::Temporal {
    return correlation_unordered_witness(rule, window)
  }
  let selected : Array[CorrelationRuleHit] = []
  let seen_events : Map[String, Bool] = Map([])
  let mut last_time = window[0].time_ms
  for rule_id in rule.rule_ids {
    let mut found : CorrelationRuleHit? = None
    for hit in window {
      if hit.rule_id == rule_id &&
        !seen_events.contains(hit.event_key) &&
        (
          rule.kind != CorrelationRuleKind::TemporalOrdered ||
          hit.time_ms >= last_time
        ) {
        found = Some(hit)
        break
      }
    }
    match found {
      Some(hit) => {
        selected.push(hit)
        seen_events[hit.event_key] = true
        last_time = hit.time_ms
      }
      None => break
    }
  }
  (selected, selected.length())
}

///|
fn correlation_assign_unordered(
  rule_index : Int32,
  rule : CompiledCorrelationRule,
  window : Array[CorrelationRuleHit],
  assigned : Map[String, Int32],
  visited : Map[String, Bool],
) -> Bool {
  for hit in window {
    if hit.rule_id != rule.rule_ids[rule_index] ||
      visited.contains(hit.event_key) {
      continue
    }
    visited[hit.event_key] = true
    let available = match assigned.get(hit.event_key) {
      None => true
      Some(other_rule) =>
        correlation_assign_unordered(
          other_rule, rule, window, assigned, visited,
        )
    }
    if available {
      assigned[hit.event_key] = rule_index
      return true
    }
  }
  false
}

///|
fn correlation_unordered_witness(
  rule : CompiledCorrelationRule,
  window : Array[CorrelationRuleHit],
) -> (Array[CorrelationRuleHit], Int32) {
  let assigned : Map[String, Int32] = Map([])
  for rule_index in 0..<rule.rule_ids.length() {
    let visited : Map[String, Bool] = Map([])
    ignore(
      correlation_assign_unordered(rule_index, rule, window, assigned, visited),
    )
  }
  let selected : Array[CorrelationRuleHit] = []
  for rule_index in 0..<rule.rule_ids.length() {
    for hit in window {
      if hit.rule_id == rule.rule_ids[rule_index] &&
        assigned.get(hit.event_key) == Some(rule_index) {
        selected.push(hit)
        break
      }
    }
  }
  (selected, selected.length())
}

///|
fn correlation_make_match(
  rule : CompiledCorrelationRule,
  selected : Array[CorrelationRuleHit],
  actual : Int32,
) -> SigmaCorrelationMatch {
  let event_ids : Array[String] = []
  let matched_rule_ids : Array[String] = []
  let sources : Array[String] = []
  let events : Array[HostEvent] = []
  let mut started_ms = selected[0].time_ms
  let mut ended_ms = selected[0].time_ms
  for hit in selected {
    event_ids.push(hit.event.id.as_string())
    matched_rule_ids.push(hit.rule_id)
    sources.push(source_token(hit.event.source))
    events.push(hit.event)
    if hit.time_ms < started_ms {
      started_ms = hit.time_ms
    }
    if hit.time_ms > ended_ms {
      ended_ms = hit.time_ms
    }
  }
  {
    rule_id: rule.id,
    rule_version: rule.version,
    kind: rule.kind,
    group_key: selected[0].group_key,
    event_ids,
    matched_rule_ids,
    sources,
    events,
    started_ms,
    ended_ms,
    observed_count: actual,
  }
}

///|
fn correlation_match_key(result : SigmaCorrelationMatch) -> String {
  let parts = [result.rule_id, result.group_key]
  for event in result.events {
    parts.push(correlation_event_key(event))
  }
  parts.map(part => "\{part.length()}:\{part}").join("|")
}

///|
/// Evaluates a compiled Sigma-subset rule against offline `HostEvent` data.
/// Input order does not affect the result. Window endpoints are inclusive.
///
/// # Example
/// ```mbt check
/// test {
///   let rules = @hostsentinel.compile_correlation_rules_json(
///     (
///       #|[{"id":"a","version":1,"detection":{"selection":{"class":"process"},"condition":"selection"}},{"id":"c","version":1,"correlation":{"type":"event_count","rules":["a"],"timespan":"1m","condition":{"gte":1}}}]
///     ),
///   )
///   let raw =
///     #|{"event_id":"e","host_id":"h","hostname":"h","platform":"linux","kind":"process","source":"agent","severity":"low","observed_at":1}
///   let event = @hostsentinel.host_event_from_normalized(
///     @hostsentinel.normalize_jsonl(raw)[0],
///   )
///   assert_eq(@hostsentinel.match_correlation_rule(rules[0], [event]).length(), 1)
/// }
/// ```
pub fn match_correlation_rule(
  rule : CompiledCorrelationRule,
  events : Array[HostEvent],
) -> Array[SigmaCorrelationMatch] raise CorrelationRuleError {
  correlation_match_rule_limited(rule, events, 2147483647)
}

///|
fn correlation_match_rule_limited(
  rule : CompiledCorrelationRule,
  events : Array[HostEvent],
  max_candidates : Int32,
) -> Array[SigmaCorrelationMatch] raise CorrelationRuleError {
  let groups = correlation_hits(rule, events)
  let group_keys = groups.keys().to_array()
  group_keys.sort()
  let matches : Array[SigmaCorrelationMatch] = []
  let seen_matches : Map[String, Bool] = Map([])
  for group_key in group_keys {
    let hits = groups[group_key]
    hits.sort_by(correlation_hit_order)
    for start in 0..<hits.length() {
      if rule.kind == CorrelationRuleKind::TemporalOrdered &&
        hits[start].rule_id != rule.rule_ids[0] {
        continue
      }
      let window = correlation_window(hits, start, rule.window_ms)
      let (selected, actual) = match rule.kind {
        CorrelationRuleKind::EventCount | CorrelationRuleKind::ValueCount =>
          correlation_count_witness(rule, window)
        CorrelationRuleKind::Temporal | CorrelationRuleKind::TemporalOrdered =>
          correlation_temporal_witness(rule, window)
      }
      if selected.is_empty() {
        continue
      }
      let passed = match (rule.operator, rule.threshold) {
        (Some(op), Some(expected)) =>
          correlation_compare_count(op, actual, expected)
        _ => actual == rule.rule_ids.length()
      }
      if passed {
        let result = correlation_make_match(rule, selected, actual)
        let key = correlation_match_key(result)
        if !seen_matches.contains(key) {
          if matches.length() >= max_candidates {
            raise rule_invalid(
              "limits.max_candidates", "candidate budget exceeded",
            )
          }
          seen_matches[key] = true
          matches.push(result)
        }
      }
    }
  }
  matches
}
