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
  let indexed_hits : Array[CorrelationRuleHit] = []
  let generic_hits : Array[@eventcorr.Hit] = []
  for group_key in group_keys {
    for hit in groups[group_key] {
      let value = match rule.kind {
        CorrelationRuleKind::ValueCount => {
          let field = correlation_resolve_field(
            rule,
            hit.rule_id,
            rule.value_field.unwrap(),
          )
          correlation_event_field(hit.event, field)
        }
        _ => None
      }
      indexed_hits.push(hit)
      generic_hits.push({
        event_key: hit.event_key,
        role: hit.rule_id,
        source: source_token(hit.event.source),
        time_ms: hit.time_ms,
        group_key,
        value,
      })
    }
  }
  let kind = match rule.kind {
    CorrelationRuleKind::EventCount => @eventcorr.Kind::EventCount
    CorrelationRuleKind::ValueCount => @eventcorr.Kind::ValueCount
    CorrelationRuleKind::Temporal => @eventcorr.Kind::Temporal
    CorrelationRuleKind::TemporalOrdered => @eventcorr.Kind::TemporalOrdered
  }
  let operator = rule.operator.map(op => {
    match op {
      CountOperator::Gt => @eventcorr.CountOperator::Gt
      CountOperator::Gte => @eventcorr.CountOperator::Gte
      CountOperator::Lt => @eventcorr.CountOperator::Lt
      CountOperator::Lte => @eventcorr.CountOperator::Lte
      CountOperator::Eq => @eventcorr.CountOperator::Eq
      CountOperator::Neq => @eventcorr.CountOperator::Neq
    }
  })
  let generic_rule : @eventcorr.Rule = {
    id: rule.id,
    kind,
    roles: rule.rule_ids,
    window_ms: rule.window_ms,
    operator,
    threshold: rule.threshold,
  }
  let candidates = @eventcorr.correlate(
    generic_rule,
    generic_hits,
    max_candidates~,
  ) catch {
    @eventcorr.CorrelationError::Invalid(detail) => {
      let path = if detail == "candidate budget exceeded" {
        "limits.max_candidates"
      } else {
        "correlation"
      }
      raise rule_invalid(path, detail)
    }
  }
  let matches : Array[SigmaCorrelationMatch] = []
  let seen_matches : Map[String, Bool] = Map([])
  for candidate in candidates {
    let selected = candidate.hit_indices().map(index => indexed_hits[index])
    let result = correlation_make_match(
      rule,
      selected,
      candidate.observed_count(),
    )
    let key = correlation_match_key(result)
    if !seen_matches.contains(key) {
      seen_matches[key] = true
      matches.push(result)
    }
  }
  matches
}
