///|
/// Errors raised while constructing an event correlation pattern.
pub(all) suberror CorrelationError {
  EmptyPatternId
  EmptyPatternName
  EmptyRuleSequence
  EmptyRuleId
  InvalidWindow
} derive(Debug, Eq)

///|
/// A sequence of rule hits that must occur on one host within a time window.
pub struct CorrelationPattern {
  id : String
  name : String
  rule_ids : Array[String]
  window_seconds : Int64
} derive(Debug, Eq)

///|
/// Creates a validated event correlation pattern.
pub fn CorrelationPattern::new(
  id~ : String,
  name~ : String,
  rule_ids~ : Array[String],
  window_seconds~ : Int64,
) -> CorrelationPattern raise CorrelationError {
  if id.trim() == "" {
    raise CorrelationError::EmptyPatternId
  }
  if name.trim() == "" {
    raise CorrelationError::EmptyPatternName
  }
  if rule_ids.length() == 0 {
    raise CorrelationError::EmptyRuleSequence
  }
  if window_seconds <= 0 {
    raise CorrelationError::InvalidWindow
  }
  let normalized_rule_ids = rule_ids.map(rule_id => {
    if rule_id.trim() == "" {
      raise CorrelationError::EmptyRuleId
    }
    rule_id.trim().to_owned()
  })
  {
    id: id.trim().to_owned(),
    name: name.trim().to_owned(),
    rule_ids: normalized_rule_ids,
    window_seconds,
  }
}

///|
/// Returns the stable correlation pattern identifier.
pub fn CorrelationPattern::id(self : CorrelationPattern) -> String {
  self.id
}

///|
/// Returns the human-readable correlation pattern name.
pub fn CorrelationPattern::name(self : CorrelationPattern) -> String {
  self.name
}

///|
/// Returns the ordered rule identifiers required by the pattern.
pub fn CorrelationPattern::rule_ids(self : CorrelationPattern) -> Array[String] {
  self.rule_ids
}

///|
/// Returns the maximum elapsed time allowed for one detection.
pub fn CorrelationPattern::window_seconds(self : CorrelationPattern) -> Int64 {
  self.window_seconds
}

///|
/// An event together with the rules that matched it.
pub struct EventObservation {
  event : NormalizedEvent
  hits : Array[RuleHit]
} derive(Debug, Eq)

///|
/// Creates an observation for correlation.
pub fn EventObservation::new(
  event~ : NormalizedEvent,
  hits~ : Array[RuleHit],
) -> EventObservation {
  { event, hits, }
}

///|
/// Returns the normalized event in this observation.
pub fn EventObservation::event(self : EventObservation) -> NormalizedEvent {
  self.event
}

///|
/// Returns rule hits associated with the event.
pub fn EventObservation::hits(self : EventObservation) -> Array[RuleHit] {
  self.hits
}

///|
/// A correlated detection assembled from an ordered rule sequence.
pub struct Detection {
  pattern_id : String
  host_id : HostId
  rule_ids : Array[String]
  event_fingerprints : Array[String]
  started_at : ObservedAt
  ended_at : ObservedAt
  dedup_key : String
} derive(Debug, Eq)

///|
/// Returns the pattern that produced the detection.
pub fn Detection::pattern_id(self : Detection) -> String {
  self.pattern_id
}

///|
/// Returns the host involved in the detection.
pub fn Detection::host_id(self : Detection) -> HostId {
  self.host_id
}

///|
/// Returns the ordered rule identifiers that formed the detection.
pub fn Detection::rule_ids(self : Detection) -> Array[String] {
  self.rule_ids
}

///|
/// Returns the ordered event fingerprints that formed the detection.
pub fn Detection::event_fingerprints(self : Detection) -> Array[String] {
  self.event_fingerprints
}

///|
/// Returns the first event time in the detection.
pub fn Detection::started_at(self : Detection) -> ObservedAt {
  self.started_at
}

///|
/// Returns the last event time in the detection.
pub fn Detection::ended_at(self : Detection) -> ObservedAt {
  self.ended_at
}

///|
/// Returns the deterministic key used to deduplicate this detection.
pub fn Detection::dedup_key(self : Detection) -> String {
  self.dedup_key
}

///|
/// Correlates ordered rule hits into detections by host and time window.
pub fn correlate(
  pattern : CorrelationPattern,
  observations : Array[EventObservation],
) -> Array[Detection] {
  let detections : Array[Detection] = []
  let seen : Array[String] = []
  for start_index, _ in observations {
    match find_detection(pattern, observations, start_index) {
      Some(detection) => {
        let key = detection.dedup_key()
        if !seen.contains(key) {
          seen.push(key)
          detections.push(detection)
        }
      }
      None => ()
    }
  }
  detections
}

///|
fn find_detection(
  pattern : CorrelationPattern,
  observations : Array[EventObservation],
  start_index : Int,
) -> Detection? {
  let start_observation = observations[start_index]
  let start_event = start_observation.event()
  let first_rule_id = pattern.rule_ids()[0]
  if !observation_matches_rule(start_observation, first_rule_id) {
    return None
  }
  let matched_rule_ids : Array[String] = [first_rule_id]
  let matched_fingerprints : Array[String] = [start_event.fingerprint()]
  let mut sequence_index = 1
  let mut last_index = start_index
  let mut complete = pattern.rule_ids().length() == 1
  let start_time = start_event.event().observed_at()
  let mut last_time = start_time
  let start_host_id = start_event.event().host_id()
  while last_index + 1 < observations.length() && !complete {
    last_index += 1
    let observation = observations[last_index]
    let event = observation.event()
    let event_time = event.event().observed_at()
    let elapsed = event_time.unix_seconds() - start_time.unix_seconds()
    let same_host = event.event().host_id() == start_host_id
    let in_order = event_time.unix_seconds() >= last_time.unix_seconds()
    let in_window = elapsed <= pattern.window_seconds()
    let expected_rule_id = pattern.rule_ids()[sequence_index]
    if same_host &&
      in_order &&
      in_window &&
      observation_matches_rule(observation, expected_rule_id) {
      matched_rule_ids.push(expected_rule_id)
      matched_fingerprints.push(event.fingerprint())
      last_time = event_time
      sequence_index += 1
      complete = sequence_index == pattern.rule_ids().length()
    }
  }
  if !complete {
    return None
  }
  let dedup_key = make_dedup_key(
    pattern.id(),
    start_host_id,
    matched_rule_ids,
    matched_fingerprints,
  )
  Some({
    pattern_id: pattern.id(),
    host_id: start_host_id,
    rule_ids: matched_rule_ids,
    event_fingerprints: matched_fingerprints,
    started_at: start_time,
    ended_at: last_time,
    dedup_key,
  })
}

///|
fn observation_matches_rule(
  observation : EventObservation,
  rule_id : String,
) -> Bool {
  let fingerprint = observation.event().fingerprint()
  for hit in observation.hits() {
    if hit.rule_id() == rule_id && hit.event_fingerprint() == fingerprint {
      return true
    }
  }
  false
}

///|
fn make_dedup_key(
  pattern_id : String,
  host_id : HostId,
  rule_ids : Array[String],
  fingerprints : Array[String],
) -> String {
  let parts : Array[String] = [pattern_id, host_id.as_string()]
  for rule_id in rule_ids {
    parts.push("rule:\{rule_id}")
  }
  for fingerprint in fingerprints {
    parts.push("event:\{fingerprint}")
  }
  parts.map(part => "\{part.length()}:\{part}").join("|")
}
