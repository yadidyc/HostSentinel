///|
/// A host event with the identity required for session-bound hunting.
priv struct SessionObservation {
  event : NormalizedEvent
  host_event : HostEvent
  boot_id : String
  session_id : String
  pid : Int64?
  process_started_at : Int64?
}

///|
/// Why three events on one host did not form a verified session lead.
pub(all) enum LeadRejectionReason {
  BootMismatch
  SessionMismatch
  ProcessInstanceMismatch
  SourceNotIndependent
  TimeWindowMismatch
  InsufficientSignal
}

///|
/// One rejected authentication, process, and network candidate.
pub struct LeadRejection {
  event_ids : Array[String]
  reason : LeadRejectionReason
}

///|
pub fn LeadRejection::event_ids(self : LeadRejection) -> Array[String] {
  self.event_ids
}

///|
pub fn LeadRejection::reason(self : LeadRejection) -> LeadRejectionReason {
  self.reason
}

///|
/// A candidate behavior chain supported by three independent event sources.
pub struct SessionLead {
  host_id : HostId
  session_id : String
  process_key : String
  evidence : Array[NormalizedEvent]
  dedup_key : String
}

///|
pub fn SessionLead::host_id(self : SessionLead) -> HostId {
  self.host_id
}

///|
pub fn SessionLead::session_id(self : SessionLead) -> String {
  self.session_id
}

///|
pub fn SessionLead::process_key(self : SessionLead) -> String {
  self.process_key
}

///|
/// Evidence is ordered as authentication, process, then network event.
pub fn SessionLead::evidence(self : SessionLead) -> Array[NormalizedEvent] {
  self.evidence
}

///|
pub fn SessionLead::dedup_key(self : SessionLead) -> String {
  self.dedup_key
}

///|
/// Verified leads and explicit candidate rejection reasons.
pub struct SessionLeadReport {
  leads : Array[SessionLead]
  rejections : Array[LeadRejection]
}

///|
pub fn SessionLeadReport::leads(self : SessionLeadReport) -> Array[SessionLead] {
  self.leads
}

///|
pub fn SessionLeadReport::rejections(
  self : SessionLeadReport,
) -> Array[LeadRejection] {
  self.rejections
}

///|
fn session_observation(
  event : NormalizedEvent,
) -> SessionObservation raise NormalizationError {
  let value = try! @json.parse(event.raw_line())
  let line_number = event.line_number()
  let boot_id = required_text(value, line_number, "boot_id")
  let session_id = required_text(value, line_number, "session_id")
  let (pid, process_started_at) = match event.event().kind() {
    EventKind::Authentication => (None, None)
    _ => {
      let pid_text = required_timestamp_text(value, line_number, "pid")
      let pid = parse_unix_seconds(pid_text, line_number, "pid").unix_seconds()
      if pid == 0 {
        raise NormalizationError::InvalidField(
          line_number~,
          field="pid",
          value=pid_text,
        )
      }
      let started_text = required_timestamp_text(
        value, line_number, "process_started_at",
      )
      let started = parse_unix_seconds(
        started_text, line_number, "process_started_at",
      ).unix_seconds()
      if started > event.event().observed_at().unix_seconds() {
        raise NormalizationError::InvalidField(
          line_number~,
          field="process_started_at",
          value=started_text,
        )
      }
      (Some(pid), Some(started))
    }
  }
  {
    event,
    host_event: host_event_from_normalized(event),
    boot_id,
    session_id,
    pid,
    process_started_at,
  }
}

///|
/// The legacy wrapper keeps its input validation and rejection vocabulary;
/// acceptance is decided by the same configurable engine used by new rules.
fn session_lead_rule(window_seconds : Int64) -> CompiledCorrelationRule {
  let source =
    $|[{"id":"session-auth","version":1,"detection":{"selection":{"class":"authentication"},"condition":"selection"}},{"id":"session-process","version":1,"detection":{"selection":{"class":"process"},"condition":"selection"}},{"id":"session-network","version":1,"detection":{"selection":{"class":"network"},"condition":"selection"}},{"id":"session-lead","version":1,"correlation":{"type":"temporal_ordered","rules":["session-auth","session-process","session-network"],"group-by":["host"],"timespan":"\{window_seconds}s","identity":{"same":["boot","session"],"same-between":[{"field":"process","rules":["session-process","session-network"]}],"sources":"different","missing":"reject"}}}]
  try! compile_correlation_rules_json(source)[0]
}

///|
fn session_process_key(observation : SessionObservation) -> String {
  let host = observation.event.event().host_id().as_string()
  let pid = match observation.pid {
    Some(value) => value
    None => 0
  }
  let started = match observation.process_started_at {
    Some(value) => value
    None => 0
  }
  [host, observation.boot_id, "\{pid}", "\{started}"]
  .map(part => "\{part.length()}:\{part}")
  .join("|")
}

///|
fn candidate_reason(
  auth : SessionObservation,
  process : SessionObservation,
  network : SessionObservation,
  window_seconds : Int64,
) -> LeadRejectionReason? {
  if auth.boot_id != process.boot_id || process.boot_id != network.boot_id {
    return Some(LeadRejectionReason::BootMismatch)
  }
  if auth.session_id != process.session_id ||
    process.session_id != network.session_id {
    return Some(LeadRejectionReason::SessionMismatch)
  }
  if process.pid != network.pid ||
    process.process_started_at != network.process_started_at {
    return Some(LeadRejectionReason::ProcessInstanceMismatch)
  }
  let a = source_token(auth.event.event().source())
  let p = source_token(process.event.event().source())
  let n = source_token(network.event.event().source())
  if a == p || a == n || p == n {
    return Some(LeadRejectionReason::SourceNotIndependent)
  }
  let auth_at = auth.event.event().observed_at().unix_seconds()
  let process_at = process.event.event().observed_at().unix_seconds()
  let network_at = network.event.event().observed_at().unix_seconds()
  if process_at < auth_at ||
    network_at < process_at ||
    network_at - auth_at > window_seconds {
    return Some(LeadRejectionReason::TimeWindowMismatch)
  }
  if severity_rank(process.event.event().severity()) < 3 ||
    severity_rank(network.event.event().severity()) < 3 {
    return Some(LeadRejectionReason::InsufficientSignal)
  }
  None
}

///|
/// Builds evidence-bound login→process→network leads from JSONL telemetry.
/// Events need boot_id and session_id; process/network also need a numeric pid
/// and process_started_at. Only distinct sources can corroborate a lead.
pub fn hunt_session_leads(
  source : String,
  window_seconds~ : Int64 = 90,
) -> SessionLeadReport raise NormalizationError {
  if window_seconds <= 0 {
    raise NormalizationError::InvalidField(
      line_number=0,
      field="window_seconds",
      value="\{window_seconds}",
    )
  }
  let events = normalize_jsonl(source)
  let rule = session_lead_rule(window_seconds)
  let auths : Array[SessionObservation] = []
  let processes : Array[SessionObservation] = []
  let networks : Array[SessionObservation] = []
  for event in events {
    match event.event().kind() {
      EventKind::Authentication => auths.push(session_observation(event))
      EventKind::Process => processes.push(session_observation(event))
      EventKind::Network => networks.push(session_observation(event))
      _ => ()
    }
  }
  let leads : Array[SessionLead] = []
  let rejections : Array[LeadRejection] = []
  let seen : Array[String] = []
  for auth in auths {
    for process in processes {
      for network in networks {
        let host_id = auth.event.event().host_id()
        if process.event.event().host_id() != host_id ||
          network.event.event().host_id() != host_id {
          continue
        }
        let event_ids = [
          auth.event.event().id().as_string(),
          process.event.event().id().as_string(),
          network.event.event().id().as_string(),
        ]
        let matched = try! correlate_identity_safe(rule, [
          auth.host_event,
          process.host_event,
          network.host_event,
        ])
        if matched.results().is_empty() {
          match candidate_reason(auth, process, network, window_seconds) {
            Some(reason) => rejections.push({ event_ids, reason, })
            None =>
              rejections.push({
                event_ids,
                reason: LeadRejectionReason::InsufficientSignal,
              })
          }
          continue
        }
        match candidate_reason(auth, process, network, window_seconds) {
          Some(reason) => rejections.push({ event_ids, reason, })
          None => {
            let process_key = session_process_key(process)
            let dedup_key = [
                auth.event.fingerprint(),
                process.event.fingerprint(),
                network.event.fingerprint(),
                auth.session_id,
                process_key,
              ]
              .map(part => "\{part.length()}:\{part}")
              .join("|")
            if !seen.contains(dedup_key) {
              seen.push(dedup_key)
              leads.push({
                host_id,
                session_id: auth.session_id,
                process_key,
                evidence: [auth.event, process.event, network.event],
                dedup_key,
              })
            }
          }
        }
      }
    }
  }
  { leads, rejections, }
}
