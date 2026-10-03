///|
/// Risk level derived from a normalized numeric risk score.
pub(all) enum RiskLevel {
  Informational
  Low
  Medium
  High
  Critical
} derive(Debug, Eq)

///|
/// A bounded risk score and the strongest event severity used to calculate it.
pub struct RiskScore {
  value : Int
  level : RiskLevel
  max_severity : Severity
} derive(Debug, Eq)

///|
/// Returns the numeric score in the inclusive range 0 to 100.
pub fn RiskScore::value(self : RiskScore) -> Int {
  self.value
}

///|
/// Returns the risk band for this score.
pub fn RiskScore::level(self : RiskScore) -> RiskLevel {
  self.level
}

///|
/// Returns the highest event severity contributing to this score.
pub fn RiskScore::max_severity(self : RiskScore) -> Severity {
  self.max_severity
}

///|
/// Scores the events that formed one detection.
pub fn score_detection(
  detection : Detection,
  observations : Array[EventObservation],
) -> RiskScore {
  let mut max_severity = Severity::Informational
  for observation in observations {
    if detection
      .event_fingerprints()
      .contains(observation.event().fingerprint()) {
      let severity = observation.event().event().severity()
      if severity_rank(severity) > severity_rank(max_severity) {
        max_severity = severity
      }
    }
  }
  let base_score = match max_severity {
    Severity::Informational => 0
    Severity::Low => 25
    Severity::Medium => 50
    Severity::High => 75
    Severity::Critical => 100
  }
  let sequence_bonus = (detection.rule_ids().length() - 1) * 5
  let unbounded_score = base_score + sequence_bonus
  let value = if unbounded_score > 100 { 100 } else { unbounded_score }
  { value, level: risk_level(value), max_severity, }
}

///|
fn risk_level(value : Int) -> RiskLevel {
  if value >= 90 {
    RiskLevel::Critical
  } else if value >= 70 {
    RiskLevel::High
  } else if value >= 40 {
    RiskLevel::Medium
  } else if value >= 20 {
    RiskLevel::Low
  } else {
    RiskLevel::Informational
  }
}

///|
/// Lifecycle states supported by an alert.
pub(all) enum AlertStatus {
  Open
  Acknowledged
  InProgress
  Resolved
  Suppressed
} derive(Debug, Eq)

///|
/// Errors raised while creating or transitioning an alert.
pub(all) suberror AlertError {
  EmptyAlertId
  InvalidTransition(from~ : AlertStatus, to~ : AlertStatus)
  StaleTimestamp
} derive(Debug, Eq)

///|
/// A detection with a risk score and auditable lifecycle timestamps.
pub struct Alert {
  id : String
  detection : Detection
  score : RiskScore
  status : AlertStatus
  created_at : ObservedAt
  updated_at : ObservedAt
} derive(Debug, Eq)

///|
/// Opens a new alert for a detection.
pub fn Alert::new(
  id~ : String,
  detection~ : Detection,
  score~ : RiskScore,
  created_at~ : ObservedAt,
) -> Alert raise AlertError {
  if id.trim() == "" {
    raise AlertError::EmptyAlertId
  }
  {
    id: id.trim().to_owned(),
    detection,
    score,
    status: AlertStatus::Open,
    created_at,
    updated_at: created_at,
  }
}

///|
/// Returns the stable alert identifier.
pub fn Alert::id(self : Alert) -> String {
  self.id
}

///|
/// Returns the detection that produced this alert.
pub fn Alert::detection(self : Alert) -> Detection {
  self.detection
}

///|
/// Returns the current risk score.
pub fn Alert::score(self : Alert) -> RiskScore {
  self.score
}

///|
/// Returns the current lifecycle state.
pub fn Alert::status(self : Alert) -> AlertStatus {
  self.status
}

///|
/// Returns when the alert was opened.
pub fn Alert::created_at(self : Alert) -> ObservedAt {
  self.created_at
}

///|
/// Returns when the alert was last transitioned.
pub fn Alert::updated_at(self : Alert) -> ObservedAt {
  self.updated_at
}

///|
/// Transitions an alert while preserving its detection and risk score.
pub fn Alert::transition(
  self : Alert,
  status~ : AlertStatus,
  at~ : ObservedAt,
) -> Alert raise AlertError {
  if at.unix_seconds() < self.updated_at.unix_seconds() {
    raise AlertError::StaleTimestamp
  }
  if !is_allowed_transition(self.status, status) {
    raise AlertError::InvalidTransition(from=self.status, to=status)
  }
  {
    id: self.id,
    detection: self.detection,
    score: self.score,
    status,
    created_at: self.created_at,
    updated_at: at,
  }
}

///|
fn is_allowed_transition(from : AlertStatus, to : AlertStatus) -> Bool {
  if from == to {
    return true
  }
  match from {
    AlertStatus::Open =>
      match to {
        AlertStatus::Acknowledged
        | AlertStatus::InProgress
        | AlertStatus::Resolved
        | AlertStatus::Suppressed => true
        _ => false
      }
    AlertStatus::Acknowledged =>
      match to {
        AlertStatus::InProgress
        | AlertStatus::Resolved
        | AlertStatus::Suppressed => true
        _ => false
      }
    AlertStatus::InProgress =>
      match to {
        AlertStatus::Resolved | AlertStatus::Suppressed => true
        _ => false
      }
    AlertStatus::Resolved | AlertStatus::Suppressed => false
  }
}
