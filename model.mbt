///|
/// Errors raised while constructing host security domain values.
pub(all) suberror DomainError {
  EmptyHostId
  EmptyEventId
  EmptyHostname
  InvalidTimestamp
} derive(Debug, Eq)

///|
/// A stable identifier for a managed host.
pub struct HostId {
  value : String
} derive(Debug, Eq)

///|
/// Creates a non-empty host identifier.
pub fn HostId::new(value~ : String) -> HostId raise DomainError {
  if value == "" {
    raise DomainError::EmptyHostId
  }
  { value, }
}

///|
/// Returns the identifier text.
pub fn HostId::as_string(self : HostId) -> String {
  self.value
}

///|
/// Operating system family associated with a host.
pub(all) enum HostPlatform {
  Windows
  Linux
  MacOS
  Other(String)
} derive(Debug, Eq)

///|
/// Lifecycle state tracked for a host.
pub(all) enum HostState {
  Active
  Isolated
  Retired
} derive(Debug, Eq)

///|
/// A host known to the platform.
pub struct Host {
  id : HostId
  hostname : String
  platform : HostPlatform
  state : HostState
} derive(Debug, Eq)

///|
/// Creates an active host with a non-empty hostname.
pub fn Host::new(
  id~ : HostId,
  hostname~ : String,
  platform~ : HostPlatform,
) -> Host raise DomainError {
  if hostname == "" {
    raise DomainError::EmptyHostname
  }
  { id, hostname, platform, state: HostState::Active, }
}

///|
/// Returns the host identifier.
pub fn Host::id(self : Host) -> HostId {
  self.id
}

///|
/// Returns the host name reported by the operating system.
pub fn Host::hostname(self : Host) -> String {
  self.hostname
}

///|
/// Returns the host operating system family.
pub fn Host::platform(self : Host) -> HostPlatform {
  self.platform
}

///|
/// Returns the current host lifecycle state.
pub fn Host::state(self : Host) -> HostState {
  self.state
}

///|
/// A stable identifier for one observed security event.
pub struct EventId {
  value : String
} derive(Debug, Eq)

///|
/// Creates a non-empty event identifier.
pub fn EventId::new(value~ : String) -> EventId raise DomainError {
  if value == "" {
    raise DomainError::EmptyEventId
  }
  { value, }
}

///|
/// Returns the identifier text.
pub fn EventId::as_string(self : EventId) -> String {
  self.value
}

///|
/// A timestamp represented as Unix seconds.
pub struct ObservedAt {
  unix_seconds : Int64
} derive(Debug, Eq)

///|
/// Creates a timestamp at or after the Unix epoch.
pub fn ObservedAt::from_unix_seconds(
  unix_seconds~ : Int64,
) -> ObservedAt raise DomainError {
  if unix_seconds < 0 {
    raise DomainError::InvalidTimestamp
  }
  { unix_seconds, }
}

///|
/// Returns the Unix timestamp.
pub fn ObservedAt::unix_seconds(self : ObservedAt) -> Int64 {
  self.unix_seconds
}

///|
/// Broad category of a security event.
pub(all) enum EventKind {
  Process
  File
  Network
  Authentication
  Persistence
} derive(Debug, Eq)

///|
/// Source that produced a security event.
pub(all) enum EventSource {
  Agent
  Sysmon
  Auditd
  WindowsEvent
  Manual
  Other(String)
} derive(Debug, Eq)

///|
/// Severity assigned before detection and correlation enrichments.
pub(all) enum Severity {
  Informational
  Low
  Medium
  High
  Critical
} derive(Debug, Eq)

///|
/// A normalized security event associated with a host.
pub struct SecurityEvent {
  id : EventId
  host_id : HostId
  kind : EventKind
  source : EventSource
  severity : Severity
  observed_at : ObservedAt
} derive(Debug, Eq)

///|
/// Creates a normalized security event from validated domain values.
pub fn SecurityEvent::new(
  id~ : EventId,
  host_id~ : HostId,
  kind~ : EventKind,
  source~ : EventSource,
  severity~ : Severity,
  observed_at~ : ObservedAt,
) -> SecurityEvent {
  { id, host_id, kind, source, severity, observed_at, }
}

///|
/// Returns the event identifier.
pub fn SecurityEvent::id(self : SecurityEvent) -> EventId {
  self.id
}

///|
/// Returns the host associated with the event.
pub fn SecurityEvent::host_id(self : SecurityEvent) -> HostId {
  self.host_id
}

///|
/// Returns the event category.
pub fn SecurityEvent::kind(self : SecurityEvent) -> EventKind {
  self.kind
}

///|
/// Returns the event source.
pub fn SecurityEvent::source(self : SecurityEvent) -> EventSource {
  self.source
}

///|
/// Returns the assigned severity.
pub fn SecurityEvent::severity(self : SecurityEvent) -> Severity {
  self.severity
}

///|
/// Returns the event observation time.
pub fn SecurityEvent::observed_at(self : SecurityEvent) -> ObservedAt {
  self.observed_at
}
