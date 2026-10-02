///|
/// Rule predicates supported by the first evaluation engine.
pub(all) enum RuleCondition {
  EventKindIs(EventKind)
  HostPlatformIs(HostPlatform)
  SourceIs(EventSource)
  SeverityAtLeast(Severity)
  IocIs(Indicator)
  All(Array[RuleCondition])
  Any(Array[RuleCondition])
} derive(Debug, Eq)

///|
/// Errors raised while constructing a detection rule.
pub(all) suberror RuleError {
  EmptyRuleId
  EmptyRuleName
  EmptyDescription
  InvalidVersion
  EmptyConditionGroup
} derive(Debug, Eq)

///|
/// Versioned metadata and predicate for one detection rule.
pub struct Rule {
  id : String
  name : String
  description : String
  version : Int
  condition : RuleCondition
} derive(Debug, Eq)

///|
/// Creates a validated versioned detection rule.
pub fn Rule::new(
  id~ : String,
  name~ : String,
  description~ : String,
  version~ : Int,
  condition~ : RuleCondition,
) -> Rule raise RuleError {
  if id.trim() == "" {
    raise RuleError::EmptyRuleId
  }
  if name.trim() == "" {
    raise RuleError::EmptyRuleName
  }
  if description.trim() == "" {
    raise RuleError::EmptyDescription
  }
  if version <= 0 {
    raise RuleError::InvalidVersion
  }
  validate_condition(condition)
  {
    id: id.trim().to_owned(),
    name: name.trim().to_owned(),
    description: description.trim().to_owned(),
    version,
    condition,
  }
}

///|
/// Returns the stable rule identifier.
pub fn Rule::id(self : Rule) -> String {
  self.id
}

///|
/// Returns the human-readable rule name.
pub fn Rule::name(self : Rule) -> String {
  self.name
}

///|
/// Returns the rule explanation.
pub fn Rule::description(self : Rule) -> String {
  self.description
}

///|
/// Returns the rule version.
pub fn Rule::version(self : Rule) -> Int {
  self.version
}

///|
/// Returns the rule predicate tree.
pub fn Rule::condition(self : Rule) -> RuleCondition {
  self.condition
}

///|
/// Evidence produced when a rule matches one event.
pub struct RuleHit {
  rule_id : String
  rule_version : Int
  event_fingerprint : String
  evidence : Array[String]
} derive(Debug, Eq)

///|
/// Returns the matched rule identifier.
pub fn RuleHit::rule_id(self : RuleHit) -> String {
  self.rule_id
}

///|
/// Returns the matched rule version.
pub fn RuleHit::rule_version(self : RuleHit) -> Int {
  self.rule_version
}

///|
/// Returns the fingerprint of the evaluated event.
pub fn RuleHit::event_fingerprint(self : RuleHit) -> String {
  self.event_fingerprint
}

///|
/// Returns ordered evidence for the matched conditions.
pub fn RuleHit::evidence(self : RuleHit) -> Array[String] {
  self.evidence
}

///|
/// Evaluates one rule against one normalized event and its extracted IOC candidates.
pub fn evaluate_rule(
  rule : Rule,
  event : NormalizedEvent,
  ioc_candidates : Array[String],
) -> RuleHit? {
  match evaluate_condition(rule.condition, event, ioc_candidates) {
    Some(evidence) =>
      Some({
        rule_id: rule.id,
        rule_version: rule.version,
        event_fingerprint: event.fingerprint(),
        evidence,
      })
    None => None
  }
}

///|
/// Evaluates rules in input order and returns only matching rules.
pub fn evaluate_rules(
  rules : Array[Rule],
  event : NormalizedEvent,
  ioc_candidates : Array[String],
) -> Array[RuleHit] {
  let hits : Array[RuleHit] = []
  for rule in rules {
    match evaluate_rule(rule, event, ioc_candidates) {
      Some(hit) => hits.push(hit)
      None => ()
    }
  }
  hits
}

///|
fn validate_condition(condition : RuleCondition) -> Unit raise RuleError {
  match condition {
    All(conditions) | Any(conditions) => {
      if conditions.length() == 0 {
        raise RuleError::EmptyConditionGroup
      }
      for child in conditions {
        validate_condition(child)
      }
    }
    _ => ()
  }
}

///|
fn evaluate_condition(
  condition : RuleCondition,
  event : NormalizedEvent,
  ioc_candidates : Array[String],
) -> Array[String]? {
  match condition {
    EventKindIs(expected) =>
      if event.event().kind() == expected {
        Some(["event.kind=\{kind_token(expected)}"])
      } else {
        None
      }
    HostPlatformIs(expected) =>
      if event.host().platform() == expected {
        Some(["host.platform=\{platform_token(expected)}"])
      } else {
        None
      }
    SourceIs(expected) =>
      if event.event().source() == expected {
        Some(["event.source=\{source_token(expected)}"])
      } else {
        None
      }
    SeverityAtLeast(expected) =>
      if severity_rank(event.event().severity()) >= severity_rank(expected) {
        Some(["event.severity>=\{severity_token(expected)}"])
      } else {
        None
      }
    IocIs(indicator) => {
      let matched : Array[String]? = None
      for candidate in ioc_candidates; result = matched {
        match result {
          Some(_) => continue result
          None =>
            if indicator.matches(candidate) {
              continue Some([
                  "ioc.\{ioc_kind_token(indicator.kind())}=\{indicator.value()}",
                ])
            } else {
              continue None
            }
        }
      } nobreak {
        result
      }
    }
    All(conditions) => {
      let evidence : Array[String] = []
      for child in conditions; matched = true {
        if !matched {
          continue matched
        }
        match evaluate_condition(child, event, ioc_candidates) {
          Some(child_evidence) => {
            for item in child_evidence {
              evidence.push(item)
            }
            continue true
          }
          None => continue false
        }
      } nobreak {
        if matched {
          Some(evidence)
        } else {
          None
        }
      }
    }
    Any(conditions) =>
      for child in conditions; selected = None {
        match selected {
          Some(_) => continue selected
          None =>
            match evaluate_condition(child, event, ioc_candidates) {
              Some(child_evidence) => continue Some(child_evidence)
              None => continue None
            }
        }
      } nobreak {
        selected
      }
  }
}

///|
fn severity_rank(severity : Severity) -> Int {
  match severity {
    Severity::Informational => 0
    Severity::Low => 1
    Severity::Medium => 2
    Severity::High => 3
    Severity::Critical => 4
  }
}

///|
fn ioc_kind_token(kind : IocKind) -> String {
  match kind {
    IocKind::IpAddress => "ip_address"
    IocKind::Domain => "domain"
    IocKind::Url => "url"
    IocKind::FileHash => "file_hash"
    IocKind::FilePath => "file_path"
    IocKind::ProcessName => "process_name"
  }
}
