///|
/// Errors raised while converting one JSONL record into the domain model.
pub(all) suberror NormalizationError {
  InvalidJson(line_number~ : Int, line~ : String)
  ExpectedObject(line_number~ : Int, line~ : String)
  MissingField(line_number~ : Int, field~ : String)
  InvalidField(line_number~ : Int, field~ : String, value~ : String)
} derive(Debug, Eq)

///|
/// A normalized event together with its host, source line, and deduplication key.
pub struct NormalizedEvent {
  line_number : Int
  raw_line : String
  host : Host
  event : SecurityEvent
  fingerprint : String
} derive(Debug, Eq)

///|
/// Returns the physical JSONL line number.
pub fn NormalizedEvent::line_number(self : NormalizedEvent) -> Int {
  self.line_number
}

///|
/// Returns the trimmed source line retained for evidence.
pub fn NormalizedEvent::raw_line(self : NormalizedEvent) -> String {
  self.raw_line
}

///|
/// Returns the normalized host.
pub fn NormalizedEvent::host(self : NormalizedEvent) -> Host {
  self.host
}

///|
/// Returns the normalized security event.
pub fn NormalizedEvent::event(self : NormalizedEvent) -> SecurityEvent {
  self.event
}

///|
/// Returns the deterministic fingerprint used to identify duplicate events.
pub fn NormalizedEvent::fingerprint(self : NormalizedEvent) -> String {
  self.fingerprint
}

///|
fn json_field(value : Json, field : String) -> Json? {
  if value is Object(object) {
    object.get(field)
  } else {
    None
  }
}

///|
fn required_text(
  value : Json,
  line_number : Int,
  field : String,
) -> String raise NormalizationError {
  match json_field(value, field) {
    Some(String(text)) => {
      let normalized = text.trim().to_owned()
      if normalized == "" {
        raise NormalizationError::InvalidField(line_number~, field~, value=text)
      }
      normalized
    }
    Some(other) =>
      raise NormalizationError::InvalidField(
        line_number~,
        field~,
        value=other.stringify(),
      )
    None => raise NormalizationError::MissingField(line_number~, field~)
  }
}

///|
fn required_timestamp_text(
  value : Json,
  line_number : Int,
  field : String,
) -> String raise NormalizationError {
  match json_field(value, field) {
    Some(String(text)) => text.trim().to_owned()
    Some(other) => other.stringify()
    None => raise NormalizationError::MissingField(line_number~, field~)
  }
}

///|
fn parse_unix_seconds(
  text : String,
  line_number : Int,
  field : String,
) -> ObservedAt raise NormalizationError {
  let value = text.trim().to_owned()
  if value == "" {
    raise NormalizationError::InvalidField(line_number~, field~, value=text)
  }
  let mut total : Int64 = 0
  for character in value {
    let digit : Int64 = match character {
      '0' => 0
      '1' => 1
      '2' => 2
      '3' => 3
      '4' => 4
      '5' => 5
      '6' => 6
      '7' => 7
      '8' => 8
      '9' => 9
      _ =>
        raise NormalizationError::InvalidField(line_number~, field~, value=text)
    }
    total = total * 10 + digit
  }
  ObservedAt::from_unix_seconds(unix_seconds=total) catch {
    _ =>
      raise NormalizationError::InvalidField(line_number~, field~, value=text)
  }
}

///|
fn canonical_label(value : String) -> String {
  match value.trim() {
    "WINDOWS" | "Windows" | "windows" => "windows"
    "LINUX" | "Linux" | "linux" => "linux"
    "MACOS" | "MacOS" | "macOS" | "macos" => "macos"
    "PROCESS" | "Process" | "process" => "process"
    "FILE" | "File" | "file" => "file"
    "NETWORK" | "Network" | "network" => "network"
    "AUTH"
    | "Auth"
    | "auth"
    | "AUTHENTICATION"
    | "Authentication"
    | "authentication" => "authentication"
    "PERSISTENCE" | "Persistence" | "persistence" => "persistence"
    "INFO"
    | "Info"
    | "info"
    | "INFORMATIONAL"
    | "Informational"
    | "informational" => "informational"
    "LOW" | "Low" | "low" => "low"
    "MEDIUM" | "Medium" | "medium" => "medium"
    "HIGH" | "High" | "high" => "high"
    "CRITICAL" | "Critical" | "critical" => "critical"
    "AGENT" | "Agent" | "agent" => "agent"
    "SYSMON" | "Sysmon" | "sysmon" => "sysmon"
    "AUDITD" | "Auditd" | "auditd" => "auditd"
    "WINDOWS_EVENT" | "WindowsEvent" | "windows_event" | "windows-event" =>
      "windows_event"
    "MANUAL" | "Manual" | "manual" => "manual"
    other => other.to_owned()
  }
}

///|
fn parse_platform(value : String) -> HostPlatform {
  match canonical_label(value) {
    "windows" => HostPlatform::Windows
    "linux" => HostPlatform::Linux
    "macos" => HostPlatform::MacOS
    other => HostPlatform::Other(other)
  }
}

///|
fn parse_kind(
  value : String,
  line_number : Int,
) -> EventKind raise NormalizationError {
  match canonical_label(value) {
    "process" => EventKind::Process
    "file" => EventKind::File
    "network" => EventKind::Network
    "authentication" => EventKind::Authentication
    "persistence" => EventKind::Persistence
    other =>
      raise NormalizationError::InvalidField(
        line_number~,
        field="kind",
        value=other,
      )
  }
}

///|
fn parse_source(value : String) -> EventSource {
  match canonical_label(value) {
    "agent" => EventSource::Agent
    "sysmon" => EventSource::Sysmon
    "auditd" => EventSource::Auditd
    "windows_event" => EventSource::WindowsEvent
    "manual" => EventSource::Manual
    other => EventSource::Other(other)
  }
}

///|
fn parse_severity(
  value : String,
  line_number : Int,
) -> Severity raise NormalizationError {
  match canonical_label(value) {
    "informational" => Severity::Informational
    "low" => Severity::Low
    "medium" => Severity::Medium
    "high" => Severity::High
    "critical" => Severity::Critical
    other =>
      raise NormalizationError::InvalidField(
        line_number~,
        field="severity",
        value=other,
      )
  }
}

///|
fn platform_token(platform : HostPlatform) -> String {
  match platform {
    HostPlatform::Windows => "windows"
    HostPlatform::Linux => "linux"
    HostPlatform::MacOS => "macos"
    HostPlatform::Other(value) => "other:\{value}"
  }
}

///|
fn kind_token(kind : EventKind) -> String {
  match kind {
    EventKind::Process => "process"
    EventKind::File => "file"
    EventKind::Network => "network"
    EventKind::Authentication => "authentication"
    EventKind::Persistence => "persistence"
  }
}

///|
fn source_token(source : EventSource) -> String {
  match source {
    EventSource::Agent => "agent"
    EventSource::Sysmon => "sysmon"
    EventSource::Auditd => "auditd"
    EventSource::WindowsEvent => "windows_event"
    EventSource::Manual => "manual"
    EventSource::Other(value) => "other:\{value}"
  }
}

///|
fn severity_token(severity : Severity) -> String {
  match severity {
    Severity::Informational => "informational"
    Severity::Low => "low"
    Severity::Medium => "medium"
    Severity::High => "high"
    Severity::Critical => "critical"
  }
}

///|
fn fingerprint(host : Host, event : SecurityEvent) -> String {
  let values = [
    event.id().as_string(),
    host.id().as_string(),
    host.hostname(),
    platform_token(host.platform()),
    kind_token(event.kind()),
    source_token(event.source()),
    severity_token(event.severity()),
    "\{event.observed_at().unix_seconds()}",
  ]
  values.map(value => "\{value.length()}:\{value}").join("|")
}

///|
fn normalize_line(
  line : String,
  line_number : Int,
) -> NormalizedEvent raise NormalizationError {
  let value = @json.parse(line) catch {
    _ => raise NormalizationError::InvalidJson(line_number~, line~)
  }
  guard value is { .. } else {
    raise NormalizationError::ExpectedObject(line_number~, line~)
  }
  let event_id_text = required_text(value, line_number, "event_id")
  let event_id = EventId::new(value=event_id_text) catch {
    _ =>
      raise NormalizationError::InvalidField(
        line_number~,
        field="event_id",
        value="",
      )
  }
  let host_id_text = required_text(value, line_number, "host_id")
  let host_id = HostId::new(value=host_id_text) catch {
    _ =>
      raise NormalizationError::InvalidField(
        line_number~,
        field="host_id",
        value="",
      )
  }
  let hostname = required_text(value, line_number, "hostname")
  let platform = parse_platform(required_text(value, line_number, "platform"))
  let kind = parse_kind(required_text(value, line_number, "kind"), line_number)
  let source = parse_source(required_text(value, line_number, "source"))
  let severity = parse_severity(
    required_text(value, line_number, "severity"),
    line_number,
  )
  let observed_at = parse_unix_seconds(
    required_timestamp_text(value, line_number, "observed_at"),
    line_number,
    "observed_at",
  )
  let host = Host::new(id=host_id, hostname~, platform~) catch {
    _ =>
      raise NormalizationError::InvalidField(
        line_number~,
        field="hostname",
        value=hostname,
      )
  }
  let event = SecurityEvent::new(
    id=event_id,
    host_id=host.id(),
    kind~,
    source~,
    severity~,
    observed_at~,
  )
  {
    line_number,
    raw_line: line,
    host,
    event,
    fingerprint: fingerprint(host, event),
  }
}

///|
/// Parses JSONL input, validates required fields, and normalizes each event.
/// Empty and whitespace-only lines are ignored; non-empty lines must be JSON objects.
pub fn normalize_jsonl(
  source : String,
) -> Array[NormalizedEvent] raise NormalizationError {
  let events : Array[NormalizedEvent] = []
  for index, physical_line in source.split("\n") {
    let line = physical_line.trim().to_owned()
    if line != "" {
      events.push(normalize_line(line, index + 1))
    }
  }
  events
}
