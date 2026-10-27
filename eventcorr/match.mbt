///|
priv struct IndexedHit {
  hit : Hit
  index : Int32
}

///|
fn validate_rule(
  rule : Rule,
  max_candidates : Int32,
) -> Unit raise CorrelationError {
  if rule.id == "" ||
    rule.roles.is_empty() ||
    rule.window_ms <= 0 ||
    max_candidates <= 0 {
    raise CorrelationError::Invalid(
      "id, roles, window and budget must be positive",
    )
  }
  let seen : Map[String, Bool] = Map([])
  for role in rule.roles {
    if role == "" || seen.contains(role) {
      raise CorrelationError::Invalid("roles must be nonempty and unique")
    }
    seen[role] = true
  }
  match (rule.operator, rule.threshold) {
    (Some(_), Some(n)) if n > 0 => ()
    (None, None) if rule.kind == Kind::Temporal ||
      rule.kind == Kind::TemporalOrdered => ()
    _ =>
      raise CorrelationError::Invalid("invalid condition for correlation kind")
  }
}

///|
fn hit_order(a : IndexedHit, b : IndexedHit) -> Int32 {
  let time_order = a.hit.time_ms.compare(b.hit.time_ms)
  if time_order != 0 {
    return time_order
  }
  let event_order = a.hit.event_key.compare(b.hit.event_key)
  if event_order != 0 {
    return event_order
  }
  a.hit.role.compare(b.hit.role)
}

///|
fn window_end(start : Int64, duration : Int64) -> Int64 {
  let max : Int64 = 9223372036854775807
  if start > max - duration {
    max
  } else {
    start + duration
  }
}

///|
fn count_witness(
  rule : Rule,
  window : Array[IndexedHit],
) -> (Array[IndexedHit], Int32) {
  let selected : Array[IndexedHit] = []
  let seen : Map[String, Bool] = Map([])
  for item in window {
    let key = match rule.kind {
      Kind::ValueCount =>
        match item.hit.value {
          Some(value) => "\{value.length()}:\{value}"
          None => continue
        }
      _ => item.hit.event_key
    }
    if !seen.contains(key) {
      seen[key] = true
      selected.push(item)
    }
  }
  (selected, selected.length())
}

///|
fn assign_unordered(
  role_index : Int32,
  rule : Rule,
  window : Array[IndexedHit],
  assigned : Map[String, Int32],
  visited : Map[String, Bool],
) -> Bool {
  for item in window {
    if item.hit.role != rule.roles[role_index] ||
      visited.contains(item.hit.event_key) {
      continue
    }
    visited[item.hit.event_key] = true
    let available = match assigned.get(item.hit.event_key) {
      None => true
      Some(other_role) =>
        assign_unordered(other_role, rule, window, assigned, visited)
    }
    if available {
      assigned[item.hit.event_key] = role_index
      return true
    }
  }
  false
}

///|
fn unordered_witness(
  rule : Rule,
  window : Array[IndexedHit],
) -> (Array[IndexedHit], Int32) {
  let assigned : Map[String, Int32] = Map([])
  for role_index in 0..<rule.roles.length() {
    let visited : Map[String, Bool] = Map([])
    ignore(assign_unordered(role_index, rule, window, assigned, visited))
  }
  let selected : Array[IndexedHit] = []
  for role_index in 0..<rule.roles.length() {
    for item in window {
      if item.hit.role == rule.roles[role_index] &&
        assigned.get(item.hit.event_key) == Some(role_index) {
        selected.push(item)
        break
      }
    }
  }
  (selected, selected.length())
}

///|
fn temporal_witness(
  rule : Rule,
  window : Array[IndexedHit],
) -> (Array[IndexedHit], Int32) {
  if rule.kind == Kind::Temporal {
    return unordered_witness(rule, window)
  }
  let selected : Array[IndexedHit] = []
  let seen_events : Map[String, Bool] = Map([])
  let mut last_time = window[0].hit.time_ms
  for role in rule.roles {
    let mut found : IndexedHit? = None
    for item in window {
      if item.hit.role == role &&
        !seen_events.contains(item.hit.event_key) &&
        item.hit.time_ms >= last_time {
        found = Some(item)
        break
      }
    }
    match found {
      Some(item) => {
        selected.push(item)
        seen_events[item.hit.event_key] = true
        last_time = item.hit.time_ms
      }
      None => break
    }
  }
  (selected, selected.length())
}

///|
fn passes(rule : Rule, actual : Int32) -> Bool {
  match (rule.operator, rule.threshold) {
    (Some(op), Some(expected)) =>
      match op {
        CountOperator::Gt => actual > expected
        CountOperator::Gte => actual >= expected
        CountOperator::Lt => actual < expected
        CountOperator::Lte => actual <= expected
        CountOperator::Eq => actual == expected
        CountOperator::Neq => actual != expected
      }
    _ => actual == rule.roles.length()
  }
}

///|
fn candidate_key(rule : Rule, selected : Array[IndexedHit]) -> String {
  let parts = [rule.id, selected[0].hit.group_key]
  for item in selected {
    parts.push(item.hit.event_key)
  }
  parts.map(part => "\{part.length()}:\{part}").join("|")
}

///|
/// Correlate caller-classified events in inclusive sliding windows. Results
/// are deterministic for shuffled input with stable event keys. The package
/// knows no host, OCSF or Sigma fields; callers control role and group mapping.
///
/// # Example
/// ```mbt check
/// test {
///   let rule : @eventcorr.Rule = {
///     id: "order-paid",
///     kind: @eventcorr.Kind::TemporalOrdered,
///     roles: ["order", "payment"],
///     window_ms: 1000,
///     operator: None,
///     threshold: None,
///   }
///   let hits : Array[@eventcorr.Hit] = [
///     {
///       event_key: "o1",
///       role: "order",
///       source: "orders",
///       time_ms: 0,
///       group_key: "order-7",
///       value: None,
///     },
///     {
///       event_key: "p1",
///       role: "payment",
///       source: "payments",
///       time_ms: 20,
///       group_key: "order-7",
///       value: None,
///     },
///   ]
///   assert_eq(@eventcorr.correlate(rule, hits).length(), 1)
/// }
/// ```
pub fn correlate(
  rule : Rule,
  hits : Array[Hit],
  max_candidates~ : Int32 = 10000,
) -> Array[Candidate] raise CorrelationError {
  validate_rule(rule, max_candidates)
  let groups : Map[String, Array[IndexedHit]] = Map([])
  for index, hit in hits {
    if hit.event_key == "" || hit.role == "" || hit.source == "" {
      raise CorrelationError::Invalid(
        "hit identity, role and source are required",
      )
    }
    if !rule.roles.contains(hit.role) {
      continue
    }
    groups.get_or_init(hit.group_key, () => []).push({ hit, index, })
  }
  let keys = groups.keys().to_array()
  keys.sort()
  let results : Array[Candidate] = []
  let seen : Map[String, Bool] = Map([])
  for group_key in keys {
    let group = groups[group_key]
    group.sort_by(hit_order)
    for start in 0..<group.length() {
      if rule.kind == Kind::TemporalOrdered &&
        group[start].hit.role != rule.roles[0] {
        continue
      }
      let end_time = window_end(group[start].hit.time_ms, rule.window_ms)
      let window : Array[IndexedHit] = []
      for index in start..<group.length() {
        if group[index].hit.time_ms > end_time {
          break
        }
        window.push(group[index])
      }
      let (selected, actual) = match rule.kind {
        Kind::EventCount | Kind::ValueCount => count_witness(rule, window)
        Kind::Temporal | Kind::TemporalOrdered => temporal_witness(rule, window)
      }
      if selected.is_empty() || !passes(rule, actual) {
        continue
      }
      let key = candidate_key(rule, selected)
      if !seen.contains(key) {
        if results.length() >= max_candidates {
          raise CorrelationError::Invalid("candidate budget exceeded")
        }
        seen[key] = true
        let mut started_ms = selected[0].hit.time_ms
        let mut ended_ms = selected[0].hit.time_ms
        for item in selected {
          if item.hit.time_ms < started_ms {
            started_ms = item.hit.time_ms
          }
          if item.hit.time_ms > ended_ms {
            ended_ms = item.hit.time_ms
          }
        }
        results.push({
          group_key,
          hit_indices: selected.map(item => item.index),
          event_keys: selected.map(item => item.hit.event_key),
          roles: selected.map(item => item.hit.role),
          sources: selected.map(item => item.hit.source),
          started_ms,
          ended_ms,
          observed_count: actual,
        })
      }
    }
  }
  results
}
