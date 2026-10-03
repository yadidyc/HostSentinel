///|
/// Evidence categories that can be attached to a security case.
pub(all) enum EvidenceKind {
  Event
  RuleHit
  IocMatch
  AnalystNote
  Artifact
} derive(Debug, Eq)

///|
/// Errors raised while creating or updating a security case.
pub(all) suberror CaseError {
  EmptyCaseId
  EmptyEvidenceId
  EmptyEvidenceSummary
  EmptyEvidenceSource
  EmptyEvidenceReference
  EmptyActor
  EmptyAction
  InvalidSequence
  DuplicateEvidenceId
  StaleTimestamp
} derive(Debug, Eq)

///|
/// A traceable item of evidence attached to a case.
pub struct Evidence {
  id : String
  kind : EvidenceKind
  summary : String
  source : String
  reference : String
  collected_at : ObservedAt
} derive(Debug, Eq)

///|
/// Creates validated case evidence.
pub fn Evidence::new(
  id~ : String,
  kind~ : EvidenceKind,
  summary~ : String,
  source~ : String,
  reference~ : String,
  collected_at~ : ObservedAt,
) -> Evidence raise CaseError {
  if id.trim() == "" {
    raise CaseError::EmptyEvidenceId
  }
  if summary.trim() == "" {
    raise CaseError::EmptyEvidenceSummary
  }
  if source.trim() == "" {
    raise CaseError::EmptyEvidenceSource
  }
  if reference.trim() == "" {
    raise CaseError::EmptyEvidenceReference
  }
  {
    id: id.trim().to_owned(),
    kind,
    summary: summary.trim().to_owned(),
    source: source.trim().to_owned(),
    reference: reference.trim().to_owned(),
    collected_at,
  }
}

///|
/// Returns the stable evidence identifier.
pub fn Evidence::id(self : Evidence) -> String {
  self.id
}

///|
/// Returns the evidence category.
pub fn Evidence::kind(self : Evidence) -> EvidenceKind {
  self.kind
}

///|
/// Returns the analyst-readable evidence summary.
pub fn Evidence::summary(self : Evidence) -> String {
  self.summary
}

///|
/// Returns the system or analyst that supplied the evidence.
pub fn Evidence::source(self : Evidence) -> String {
  self.source
}

///|
/// Returns the source reference, such as an event fingerprint or IOC value.
pub fn Evidence::reference(self : Evidence) -> String {
  self.reference
}

///|
/// Returns when the evidence was collected.
pub fn Evidence::collected_at(self : Evidence) -> ObservedAt {
  self.collected_at
}

///|
/// One immutable entry in a case audit trail.
pub struct AuditEntry {
  sequence : Int
  actor : String
  action : String
  details : String
  occurred_at : ObservedAt
} derive(Debug, Eq)

///|
/// Creates a validated audit entry with an explicit sequence number.
pub fn AuditEntry::new(
  sequence~ : Int,
  actor~ : String,
  action~ : String,
  details~ : String,
  occurred_at~ : ObservedAt,
) -> AuditEntry raise CaseError {
  if sequence <= 0 {
    raise CaseError::InvalidSequence
  }
  if actor.trim() == "" {
    raise CaseError::EmptyActor
  }
  if action.trim() == "" {
    raise CaseError::EmptyAction
  }
  {
    sequence,
    actor: actor.trim().to_owned(),
    action: action.trim().to_owned(),
    details: details.trim().to_owned(),
    occurred_at,
  }
}

///|
/// Returns the one-based position of this entry in a case audit trail.
pub fn AuditEntry::sequence(self : AuditEntry) -> Int {
  self.sequence
}

///|
/// Returns the actor that caused the audited action.
pub fn AuditEntry::actor(self : AuditEntry) -> String {
  self.actor
}

///|
/// Returns the stable action name.
pub fn AuditEntry::action(self : AuditEntry) -> String {
  self.action
}

///|
/// Returns details associated with the action.
pub fn AuditEntry::details(self : AuditEntry) -> String {
  self.details
}

///|
/// Returns when the action occurred.
pub fn AuditEntry::occurred_at(self : AuditEntry) -> ObservedAt {
  self.occurred_at
}

///|
/// A security investigation case bound to one alert.
pub struct Case {
  id : String
  alert : Alert
  evidence : Array[Evidence]
  audit_trail : Array[AuditEntry]
} derive(Debug, Eq)

///|
/// Opens a case and records its creation in the audit trail.
pub fn Case::new(
  id~ : String,
  alert~ : Alert,
  actor~ : String,
  opened_at~ : ObservedAt,
) -> Case raise CaseError {
  if id.trim() == "" {
    raise CaseError::EmptyCaseId
  }
  let created = AuditEntry::new(
    sequence=1,
    actor~,
    action="case.created",
    details=alert.id(),
    occurred_at=opened_at,
  )
  { id: id.trim().to_owned(), alert, evidence: [], audit_trail: [created], }
}

///|
/// Returns the stable case identifier.
pub fn Case::id(self : Case) -> String {
  self.id
}

///|
/// Returns the alert under investigation.
pub fn Case::alert(self : Case) -> Alert {
  self.alert
}

///|
/// Returns evidence in insertion order.
pub fn Case::evidence(self : Case) -> Array[Evidence] {
  self.evidence
}

///|
/// Returns audit entries in sequence order.
pub fn Case::audit_trail(self : Case) -> Array[AuditEntry] {
  self.audit_trail
}

///|
/// Adds evidence and records the corresponding audit event atomically.
pub fn Case::add_evidence(
  self : Case,
  evidence~ : Evidence,
  actor~ : String,
) -> Case raise CaseError {
  if self.evidence_contains(evidence.id()) {
    raise CaseError::DuplicateEvidenceId
  }
  ensure_case_timestamp(self, evidence.collected_at())
  let audit = AuditEntry::new(
    sequence=self.audit_trail.length() + 1,
    actor~,
    action="evidence.added",
    details=evidence.id(),
    occurred_at=evidence.collected_at(),
  )
  let evidence_items = self.evidence
  evidence_items.push(evidence)
  let audit_entries = self.audit_trail
  audit_entries.push(audit)
  {
    id: self.id,
    alert: self.alert,
    evidence: evidence_items,
    audit_trail: audit_entries,
  }
}

///|
/// Appends a manual audit event while preserving sequence and time ordering.
pub fn Case::record_audit(
  self : Case,
  actor~ : String,
  action~ : String,
  details~ : String,
  occurred_at~ : ObservedAt,
) -> Case raise CaseError {
  ensure_case_timestamp(self, occurred_at)
  let audit = AuditEntry::new(
    sequence=self.audit_trail.length() + 1,
    actor~,
    action~,
    details~,
    occurred_at~,
  )
  let audit_entries = self.audit_trail
  audit_entries.push(audit)
  {
    id: self.id,
    alert: self.alert,
    evidence: self.evidence,
    audit_trail: audit_entries,
  }
}

///|
fn Case::evidence_contains(self : Case, evidence_id : String) -> Bool {
  for evidence in self.evidence {
    if evidence.id() == evidence_id {
      return true
    }
  }
  false
}

///|
fn ensure_case_timestamp(
  case : Case,
  occurred_at : ObservedAt,
) -> Unit raise CaseError {
  let last_entry = case.audit_trail()[case.audit_trail().length() - 1]
  if occurred_at.unix_seconds() < last_entry.occurred_at().unix_seconds() {
    raise CaseError::StaleTimestamp
  }
}
