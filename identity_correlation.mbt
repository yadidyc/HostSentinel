///|
/// Confidence describes identity evidence, not source authenticity.
pub(all) enum IdentityEvidenceGrade {
  Verified
  Claimed
  Weak
  Indeterminate
} derive(Debug, Eq)

///|
pub extend IdentityEvidenceGrade with Eq::{equal, not_equal}

///|
pub extend IdentityEvidenceGrade with @debug.Debug::{to_repr}

///|
pub(all) struct CorrelationKeyEvidence {
  field : String
  value : String
  status : IdentityStatus
}

///|
/// Explainable candidate that passed all hard constraints.
pub struct IdentityCorrelationResult {
  rule_id : String
  rule_version : Int32
  event_ids : Array[String]
  sources : Array[String]
  group_key : String
  keys : Array[CorrelationKeyEvidence]
  window_ms : Int64
  span_ms : Int64
  grade : IdentityEvidenceGrade
  mapping : Array[String]
  explanation : String
  dedup_key : String
}

///|
pub fn IdentityCorrelationResult::rule_id(
  self : IdentityCorrelationResult,
) -> String {
  self.rule_id
}

///|
pub fn IdentityCorrelationResult::rule_version(
  self : IdentityCorrelationResult,
) -> Int32 {
  self.rule_version
}

///|
pub fn IdentityCorrelationResult::event_ids(
  self : IdentityCorrelationResult,
) -> Array[String] {
  self.event_ids.copy()
}

///|
pub fn IdentityCorrelationResult::sources(
  self : IdentityCorrelationResult,
) -> Array[String] {
  self.sources.copy()
}

///|
pub fn IdentityCorrelationResult::group_key(
  self : IdentityCorrelationResult,
) -> String {
  self.group_key
}

///|
pub fn IdentityCorrelationResult::keys(
  self : IdentityCorrelationResult,
) -> Array[CorrelationKeyEvidence] {
  self.keys.copy()
}

///|
pub fn IdentityCorrelationResult::window_ms(
  self : IdentityCorrelationResult,
) -> Int64 {
  self.window_ms
}

///|
pub fn IdentityCorrelationResult::span_ms(
  self : IdentityCorrelationResult,
) -> Int64 {
  self.span_ms
}

///|
pub fn IdentityCorrelationResult::grade(
  self : IdentityCorrelationResult,
) -> IdentityEvidenceGrade {
  self.grade
}

///|
pub fn IdentityCorrelationResult::mapping(
  self : IdentityCorrelationResult,
) -> Array[String] {
  self.mapping.copy()
}

///|
pub fn IdentityCorrelationResult::explanation(
  self : IdentityCorrelationResult,
) -> String {
  self.explanation
}

///|
pub fn IdentityCorrelationResult::dedup_key(
  self : IdentityCorrelationResult,
) -> String {
  self.dedup_key
}

///|
pub struct IdentityCorrelationDiagnostic {
  event_ids : Array[String]
  reason : String
}

///|
pub fn IdentityCorrelationDiagnostic::event_ids(
  self : IdentityCorrelationDiagnostic,
) -> Array[String] {
  self.event_ids.copy()
}

///|
pub fn IdentityCorrelationDiagnostic::reason(
  self : IdentityCorrelationDiagnostic,
) -> String {
  self.reason
}

///|
pub struct IdentityCorrelationReport {
  results : Array[IdentityCorrelationResult]
  diagnostics : Array[IdentityCorrelationDiagnostic]
  examined_candidates : Int32
  results_truncated : Bool
  diagnostics_truncated : Bool
}

///|
pub fn IdentityCorrelationReport::results(
  self : IdentityCorrelationReport,
) -> Array[IdentityCorrelationResult] {
  self.results.copy()
}

///|
pub fn IdentityCorrelationReport::diagnostics(
  self : IdentityCorrelationReport,
) -> Array[IdentityCorrelationDiagnostic] {
  self.diagnostics.copy()
}

///|
pub fn IdentityCorrelationReport::examined_candidates(
  self : IdentityCorrelationReport,
) -> Int32 {
  self.examined_candidates
}

///|
pub fn IdentityCorrelationReport::results_truncated(
  self : IdentityCorrelationReport,
) -> Bool {
  self.results_truncated
}

///|
pub fn IdentityCorrelationReport::diagnostics_truncated(
  self : IdentityCorrelationReport,
) -> Bool {
  self.diagnostics_truncated
}

///|
fn correlation_identity(event : HostEvent, field : String) -> Identity {
  match field {
    "host" => event.identities.host
    "boot" => event.identities.boot
    "user" => event.identities.user
    "session" => event.identities.session
    "process" => event.identities.process
    "parent_process" => event.identities.parent_process
    "source_id" => event.source_id
    _ => Identity::missing()
  }
}

///|
fn correlation_identity_pair(
  left : Identity,
  right : Identity,
  label : String,
) -> String? {
  match (left.value(), right.value()) {
    (Some(a), Some(b)) if a != b => Some("\{label} mismatch")
    _ => None
  }
}

///|
fn correlation_mapping_details(
  rule : CompiledCorrelationRule,
  candidate : SigmaCorrelationMatch,
) -> Array[String] {
  let details : Array[String] = []
  for index, event in candidate.events {
    let source = source_token(event.source)
    let matched = candidate.matched_rule_ids[index]
    details.push(
      "\{event.id.as_string()}: base_rule=\{matched}, source=\{source}, format=\{event.original.format}, record=\{event.original.record_number}",
    )
    for base in rule.base_rules {
      if base.id == matched {
        for predicate in base.predicates {
          details.push(
            "\{event.id.as_string()}: selection.\{predicate.field}=\{predicate.value}",
          )
        }
      }
    }
    for diagnostic in event.diagnostics {
      details.push(
        "\{event.id.as_string()}: \{diagnostic.path}: \{diagnostic.detail}",
      )
    }
  }
  details
}

///|
fn correlation_check_candidate(
  rule : CompiledCorrelationRule,
  candidate : SigmaCorrelationMatch,
) -> (
  IdentityEvidenceGrade,
  Array[CorrelationKeyEvidence],
  Array[String],
  String?,
) raise CorrelationRuleError {
  let keys : Array[CorrelationKeyEvidence] = []
  let missing : Array[String] = []
  let mut claimed = false
  for field in rule.same_identities {
    let first = correlation_identity(candidate.events[0], field)
    let first_value = first.value()
    if first_value is None {
      missing.push("\{field} missing in \{candidate.events[0].id.as_string()}")
    } else if first.status() != IdentityStatus::Verified {
      claimed = true
    }
    for event in candidate.events[1:] {
      let next = correlation_identity(event, field)
      match correlation_identity_pair(first, next, field) {
        Some(reason) =>
          return (
            IdentityEvidenceGrade::Indeterminate,
            keys,
            missing,
            Some(reason),
          )
        None => ()
      }
      if next.value() is None {
        missing.push("\{field} missing in \{event.id.as_string()}")
      } else if next.status() != IdentityStatus::Verified {
        claimed = true
      }
    }
    match first_value {
      Some(value) if !missing.any(reason => {
          reason.has_prefix("\{field} missing")
        }) => keys.push({ field, value, status: first.status(), })
      _ => ()
    }
  }
  for scoped in rule.same_between {
    for role in scoped.rules {
      if !candidate.matched_rule_ids.contains(role) {
        return (
          IdentityEvidenceGrade::Indeterminate,
          keys,
          missing,
          Some("same-between rule role absent: \{role}"),
        )
      }
    }
    let missing_before = missing.length()
    let mut first : Identity? = None
    for index, role in candidate.matched_rule_ids {
      if scoped.rules.contains(role) {
        let event = candidate.events[index]
        let identity = correlation_identity(event, scoped.field)
        match first {
          None => first = Some(identity)
          Some(reference) =>
            match correlation_identity_pair(reference, identity, scoped.field) {
              Some(reason) =>
                return (
                  IdentityEvidenceGrade::Indeterminate,
                  keys,
                  missing,
                  Some(reason),
                )
              None => ()
            }
        }
        if identity.value() is None {
          missing.push("\{scoped.field} missing in \{event.id.as_string()}")
        } else if identity.status() != IdentityStatus::Verified {
          claimed = true
        }
      }
    }
    match first {
      Some(identity) if missing.length() == missing_before =>
        match identity.value() {
          Some(value) =>
            keys.push({
              field: "\{scoped.field}@\{scoped.rules.join(",")}",
              value,
              status: identity.status(),
            })
          None => ()
        }
      _ => ()
    }
  }
  match rule.source_constraint {
    SourceConstraint::AnySource => ()
    SourceConstraint::SameSource => {
      let source = source_token(candidate.events[0].source)
      for event in candidate.events[1:] {
        if source_token(event.source) != source {
          return (
            IdentityEvidenceGrade::Indeterminate,
            keys,
            missing,
            Some("source mismatch: expected same source"),
          )
        }
      }
    }
    SourceConstraint::DifferentSources => {
      let seen : Map[String, Bool] = Map([])
      for event in candidate.events {
        let source = source_token(event.source)
        if seen.contains(source) {
          return (
            IdentityEvidenceGrade::Indeterminate,
            keys,
            missing,
            Some("source mismatch: expected distinct sources"),
          )
        }
        seen[source] = true
      }
    }
  }
  for link in rule.parent_child {
    let mut has_parent = false
    let mut has_child = false
    let mut has_ordered_pair = false
    let mut has_missing_pair = false
    let mut matched : (String, IdentityStatus)? = None
    for parent_index, parent_role in candidate.matched_rule_ids {
      if parent_role == link.parent {
        has_parent = true
        let parent = candidate.events[parent_index]
        for child_index, child_role in candidate.matched_rule_ids {
          if child_role == link.child {
            has_child = true
            let child = candidate.events[child_index]
            if correlation_time_ms(child, "events.parent-child") <
              correlation_time_ms(parent, "events.parent-child") {
              continue
            }
            has_ordered_pair = true
            let parent_id = parent.identities.process
            let child_parent = child.identities.parent_process
            match (parent_id.value(), child_parent.value()) {
              (Some(a), Some(b)) if a == b => {
                let status = if parent_id.status() == IdentityStatus::Verified &&
                  child_parent.status() == IdentityStatus::Verified {
                  IdentityStatus::Verified
                } else {
                  IdentityStatus::Unverified
                }
                matched = Some((a, status))
              }
              (None, _) | (_, None) => has_missing_pair = true
              _ => ()
            }
          }
        }
      }
    }
    if !has_parent || !has_child {
      return (
        IdentityEvidenceGrade::Indeterminate,
        keys,
        missing,
        Some("parent-child rule role absent"),
      )
    }
    match matched {
      Some((value, status)) => {
        keys.push({ field: "parent-child", value, status, })
        if status != IdentityStatus::Verified {
          claimed = true
        }
      }
      None if has_missing_pair =>
        missing.push(
          "parent-child identity missing: \{link.parent}->\{link.child}",
        )
      None if !has_ordered_pair =>
        return (
          IdentityEvidenceGrade::Indeterminate,
          keys,
          missing,
          Some("parent-child order mismatch"),
        )
      None =>
        return (
          IdentityEvidenceGrade::Indeterminate,
          keys,
          missing,
          Some("parent-child mismatch"),
        )
    }
  }
  if !missing.is_empty() {
    match rule.missing_policy {
      IdentityMissingPolicy::Reject =>
        return (
          IdentityEvidenceGrade::Indeterminate,
          keys,
          missing,
          Some(missing[0]),
        )
      IdentityMissingPolicy::Indeterminate =>
        return (IdentityEvidenceGrade::Indeterminate, keys, missing, None)
      IdentityMissingPolicy::Relaxed =>
        return (IdentityEvidenceGrade::Weak, keys, missing, None)
    }
  }
  if claimed {
    (IdentityEvidenceGrade::Claimed, keys, missing, None)
  } else {
    (IdentityEvidenceGrade::Verified, keys, missing, None)
  }
}

///|
fn correlation_safe_result(
  rule : CompiledCorrelationRule,
  candidate : SigmaCorrelationMatch,
  grade : IdentityEvidenceGrade,
  keys : Array[CorrelationKeyEvidence],
  missing : Array[String],
) -> IdentityCorrelationResult {
  let ids = candidate.event_ids()
  let sources = candidate.sources()
  let span_ms = candidate.ended_ms() - candidate.started_ms()
  let suffix = if missing.is_empty() { "" } else { "; \{missing.join(", ")}" }
  let explanation = "rule \{rule.id} v\{rule.version}: \{candidate.observed_count()} matched; \{ids.length()} evidence events in \{span_ms}ms of \{rule.window_ms}ms window; identity=\{Repr(grade)}\{suffix}"
  let parts : Array[String] = [
    rule.id,
    "\{rule.version}",
    candidate.group_key(),
  ]
  for event in candidate.events {
    parts.push(correlation_event_key(event))
  }
  let dedup_key = parts.map(part => "\{part.length()}:\{part}").join("|")
  {
    rule_id: rule.id,
    rule_version: rule.version,
    event_ids: ids,
    sources,
    group_key: candidate.group_key(),
    keys,
    window_ms: rule.window_ms,
    span_ms,
    grade,
    mapping: correlation_mapping_details(rule, candidate),
    explanation,
    dedup_key,
  }
}

///|
/// Applies identity and source constraints to a bounded offline correlation.
/// Host equality is always required, even if `identity.same` omits `host`.
///
/// # Example
/// ```mbt check
/// test {
///   let rules = @hostsentinel.compile_correlation_rules_json(
///     (
///       #|[{"id":"a","version":1,"detection":{"selection":{"class":"process"},"condition":"selection"}},{"id":"c","version":1,"correlation":{"type":"event_count","rules":["a"],"timespan":"1m","condition":{"gte":1}}}]
///     ),
///   )
///   let report = @hostsentinel.correlate_identity_safe(rules[0], [])
///   assert_eq(report.results().length(), 0)
/// }
/// ```
pub fn correlate_identity_safe(
  rule : CompiledCorrelationRule,
  events : Array[HostEvent],
  max_events~ : Int32 = 10000,
  max_candidates~ : Int32 = 10000,
  max_results~ : Int32 = 1000,
  max_diagnostics~ : Int32 = 100,
  diagnostic~ : Bool = false,
) -> IdentityCorrelationReport raise CorrelationRuleError {
  if max_events <= 0 ||
    max_candidates <= 0 ||
    max_results <= 0 ||
    max_diagnostics < 0 {
    raise rule_invalid(
      "limits", "budgets must be positive (diagnostics may be zero)",
    )
  }
  if events.length() > max_events {
    raise rule_invalid("limits.max_events", "event state budget exceeded")
  }
  let candidates = correlation_match_rule_limited(rule, events, max_candidates)
  let results : Array[IdentityCorrelationResult] = []
  let diagnostics : Array[IdentityCorrelationDiagnostic] = []
  let mut results_truncated = false
  let mut diagnostics_truncated = false
  for candidate in candidates {
    let (grade, keys, missing, rejection) = correlation_check_candidate(
      rule, candidate,
    )
    match rejection {
      Some(reason) =>
        if diagnostic {
          if diagnostics.length() < max_diagnostics {
            diagnostics.push({ event_ids: candidate.event_ids(), reason, })
          } else {
            diagnostics_truncated = true
          }
        }
      None =>
        if results.length() < max_results {
          results.push(
            correlation_safe_result(rule, candidate, grade, keys, missing),
          )
        } else {
          results_truncated = true
        }
    }
  }
  {
    results,
    diagnostics,
    examined_candidates: candidates.length(),
    results_truncated,
    diagnostics_truncated,
  }
}
