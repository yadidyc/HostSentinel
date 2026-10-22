///|
/// Whether an identity was absent, explicitly unknown, source-claimed, or verified.
pub(all) enum IdentityStatus {
  Missing
  Unknown
  Unverified
  Verified
} derive(Debug, Eq)

///|
pub extend IdentityStatus with Eq::{equal, not_equal}

///|
pub extend IdentityStatus with @debug.Debug::{to_repr}

///|
/// An identity value whose trust state cannot be confused with an empty string.
pub struct Identity {
  status : IdentityStatus
  value : String?
} derive(Debug, Eq)

///|
pub extend Identity with Eq::{equal, not_equal}

///|
pub extend Identity with @debug.Debug::{to_repr}

///|
pub(all) suberror HostEventError {
  EmptyIdentity
} derive(Debug, Eq)

///|
pub extend HostEventError with Eq::{equal, not_equal}

///|
pub extend HostEventError with @debug.Debug::{to_repr}

///|
pub fn Identity::missing() -> Identity {
  { status: IdentityStatus::Missing, value: None, }
}

///|
pub fn Identity::unknown() -> Identity {
  { status: IdentityStatus::Unknown, value: None, }
}

///|
/// Records a non-empty claim from an input source without treating it as proof.
pub fn Identity::unverified(value : String) -> Identity raise HostEventError {
  if value.trim() == "" {
    raise HostEventError::EmptyIdentity
  }
  { status: IdentityStatus::Unverified, value: Some(value), }
}

///|
/// Marks a non-empty value verified by an explicitly trusted caller.
pub fn Identity::verified(value : String) -> Identity raise HostEventError {
  if value.trim() == "" {
    raise HostEventError::EmptyIdentity
  }
  { status: IdentityStatus::Verified, value: Some(value), }
}

///|
pub fn Identity::status(self : Identity) -> IdentityStatus {
  self.status
}

///|
pub fn Identity::value(self : Identity) -> String? {
  self.value
}

///|
/// Units are explicit: legacy JSONL uses seconds; OCSF uses milliseconds.
pub(all) enum TimePrecision {
  Seconds
  Milliseconds
} derive(Debug, Eq)

///|
pub extend TimePrecision with Eq::{equal, not_equal}

///|
pub extend TimePrecision with @debug.Debug::{to_repr}

///|
pub(all) struct EventTime {
  value : Int64
  precision : TimePrecision
} derive(Debug, Eq)

///|
pub extend EventTime with Eq::{equal, not_equal}

///|
pub extend EventTime with @debug.Debug::{to_repr}

///|
/// Host, boot, user, session, process instance, and parent process identities.
pub(all) struct HostIdentities {
  host : Identity
  boot : Identity
  user : Identity
  session : Identity
  process : Identity
  parent_process : Identity
} derive(Debug, Eq)

///|
pub extend HostIdentities with Eq::{equal, not_equal}

///|
pub extend HostIdentities with @debug.Debug::{to_repr}

///|
pub fn HostIdentities::missing() -> HostIdentities {
  {
    host: Identity::missing(),
    boot: Identity::missing(),
    user: Identity::missing(),
    session: Identity::missing(),
    process: Identity::missing(),
    parent_process: Identity::missing(),
  }
}

///|
/// Only explicitly present connection attributes are populated.
pub(all) struct NetworkAttributes {
  src_ip : String?
  src_port : Int32?
  dst_ip : String?
  dst_port : Int32?
  protocol : String?
} derive(Debug, Eq)

///|
pub extend NetworkAttributes with Eq::{equal, not_equal}

///|
pub extend NetworkAttributes with @debug.Debug::{to_repr}

///|
pub fn NetworkAttributes::empty() -> NetworkAttributes {
  {
    src_ip: None,
    src_port: None,
    dst_ip: None,
    dst_port: None,
    protocol: None,
  }
}

///|
/// A pointer to the input record; raw text remains available for evidence.
pub(all) struct OriginalEventReference {
  format : String
  record_number : Int32
  record_id : String?
  raw : String
} derive(Debug, Eq)

///|
pub extend OriginalEventReference with Eq::{equal, not_equal}

///|
pub extend OriginalEventReference with @debug.Debug::{to_repr}

///|
pub(all) enum MappingIssue {
  Missing
  Invalid
  Lossy
  Unverified
} derive(Debug, Eq)

///|
pub extend MappingIssue with Eq::{equal, not_equal}

///|
pub extend MappingIssue with @debug.Debug::{to_repr}

///|
pub(all) struct MappingDiagnostic {
  path : String
  issue : MappingIssue
  detail : String
} derive(Debug, Eq)

///|
pub extend MappingDiagnostic with Eq::{equal, not_equal}

///|
pub extend MappingDiagnostic with @debug.Debug::{to_repr}

///|
/// Numeric OCSF classification, present only after a validated OCSF mapping.
pub(all) struct OcsfClassification {
  category_uid : Int32
  class_uid : Int32
  activity_id : Int32
  type_uid : Int32
  severity_id : Int32
} derive(Debug, Eq)

///|
pub extend OcsfClassification with Eq::{equal, not_equal}

///|
pub extend OcsfClassification with @debug.Debug::{to_repr}

///|
/// Shared event representation; category/class/activity are source-neutral labels,
/// not an assertion that the record conforms to a particular external schema.
pub(all) struct HostEvent {
  id : EventId
  source : EventSource
  source_id : Identity
  time : EventTime
  category : String
  class_name : String
  activity : String
  ocsf : OcsfClassification?
  identities : HostIdentities
  network : NetworkAttributes
  original : OriginalEventReference
  diagnostics : Array[MappingDiagnostic]
} derive(Debug, Eq)

///|
pub extend HostEvent with Eq::{equal, not_equal}

///|
pub extend HostEvent with @debug.Debug::{to_repr}

///|
fn legacy_identity(
  value : Json,
  field : String,
  diagnostics : Array[MappingDiagnostic],
) -> Identity {
  match json_field(value, field) {
    None => Identity::missing()
    Some(Null) => Identity::unknown()
    Some(String(text)) if text.trim() != "" => try! Identity::unverified(text)
    Some(Number(number, ..)) => try! Identity::unverified(number.to_string())
    _ => {
      diagnostics.push({
        path: field,
        issue: MappingIssue::Invalid,
        detail: "expected a non-empty string or number",
      })
      Identity::unknown()
    }
  }
}

///|
fn legacy_process_identity(
  boot : Identity,
  pid : Identity,
  started : Identity,
) -> Identity {
  if boot.status() == IdentityStatus::Missing ||
    pid.status() == IdentityStatus::Missing ||
    started.status() == IdentityStatus::Missing {
    return Identity::missing()
  }
  match (boot.value(), pid.value(), started.value()) {
    (Some(b), Some(p), Some(s)) =>
      try! Identity::unverified(
        [b, p, s].map(part => "\{part.length()}:\{part}").join("|"),
      )
    _ => Identity::unknown()
  }
}

///|
/// Adapts the existing JSONL model without changing its parser or asserting
/// that source-provided identity strings have been independently verified.
///
/// # Example
/// ```mbt check
/// test {
///   let raw =
///     #|{"event_id":"e","host_id":"h","hostname":"h","platform":"linux","kind":"process","source":"agent","severity":"low","observed_at":1}
///   let events = @hostsentinel.normalize_jsonl(raw)
///   assert_eq(
///     @hostsentinel.host_event_from_normalized(events[0]).identities.process.status(),
///     @hostsentinel.IdentityStatus::Missing,
///   )
/// }
/// ```
pub fn host_event_from_normalized(event : NormalizedEvent) -> HostEvent {
  let raw = event.raw_line()
  let value = try! @json.parse(raw)
  let diagnostics : Array[MappingDiagnostic] = []
  let boot = legacy_identity(value, "boot_id", diagnostics)
  let pid = legacy_identity(value, "pid", diagnostics)
  let started = legacy_identity(value, "process_started_at", diagnostics)
  let identities = {
    host: try! Identity::unverified(event.event().host_id().as_string()),
    boot,
    user: legacy_identity(value, "user_id", diagnostics),
    session: legacy_identity(value, "session_id", diagnostics),
    process: legacy_process_identity(boot, pid, started),
    parent_process: legacy_identity(value, "parent_process_id", diagnostics),
  }
  diagnostics.push({
    path: "host_id",
    issue: MappingIssue::Unverified,
    detail: "legacy JSONL host identifier is source-claimed",
  })
  {
    id: event.event().id(),
    source: event.event().source(),
    source_id: Identity::missing(),
    time: {
      value: event.event().observed_at().unix_seconds(),
      precision: TimePrecision::Seconds,
    },
    category: "legacy",
    class_name: kind_token(event.event().kind()),
    activity: "observed",
    ocsf: None,
    identities,
    network: NetworkAttributes::empty(),
    original: {
      format: "hostsentinel-jsonl",
      record_number: event.line_number(),
      record_id: Some(event.event().id().as_string()),
      raw,
    },
    diagnostics,
  }
}
