///|
fn xml_decode(
  value : String,
  path : String,
  record_number : Int32,
) -> String raise AdapterError {
  let unknown = value
    .replace_all(old="&amp;", new="")
    .replace_all(old="&lt;", new="")
    .replace_all(old="&gt;", new="")
    .replace_all(old="&quot;", new="")
    .replace_all(old="&apos;", new="")
  if unknown.contains("&") {
    raise AdapterError::InvalidField(
      record_number~,
      path~,
      detail="unsupported XML entity",
    )
  }
  let decoded = value
    .replace_all(old="&amp;", new="&")
    .replace_all(old="&lt;", new="<")
    .replace_all(old="&gt;", new=">")
    .replace_all(old="&quot;", new="\"")
    .replace_all(old="&apos;", new="'")
  decoded.trim().to_owned()
}

///|
fn xml_tag(
  raw : String,
  tag : String,
  record_number : Int32,
) -> String raise AdapterError {
  let open = "<\{tag}>"
  let close = "</\{tag}>"
  let parts = raw.split(open).to_array()
  if parts.length() < 2 {
    raise AdapterError::MissingField(record_number~, path="System.\{tag}")
  }
  let tails = parts[1].to_owned().split(close).to_array()
  if tails.length() < 2 {
    raise AdapterError::InvalidField(
      record_number~,
      path="System.\{tag}",
      detail="unclosed XML tag",
    )
  }
  xml_decode(tails[0].to_owned(), "System.\{tag}", record_number)
}

///|
fn xml_attribute(
  raw : String,
  tag : String,
  attribute : String,
  record_number : Int32,
) -> String raise AdapterError {
  let parts = raw.split("<\{tag}").to_array()
  if parts.length() < 2 {
    raise AdapterError::MissingField(record_number~, path="System.\{tag}")
  }
  let head = parts[1].to_owned().split(">").to_array()
  if head.length() < 2 {
    raise AdapterError::InvalidField(
      record_number~,
      path="System.\{tag}",
      detail="unclosed XML tag",
    )
  }
  let marker = "\{attribute}=\""
  let values = head[0].to_owned().split(marker).to_array()
  if values.length() < 2 {
    raise AdapterError::MissingField(
      record_number~,
      path="System.\{tag}.\{attribute}",
    )
  }
  let ends = values[1].to_owned().split("\"").to_array()
  if ends.length() < 2 {
    raise AdapterError::InvalidField(
      record_number~,
      path="System.\{tag}.\{attribute}",
      detail="unclosed XML attribute",
    )
  }
  xml_decode(ends[0].to_owned(), "System.\{tag}.\{attribute}", record_number)
}

///|
fn xml_data(
  raw : String,
  name : String,
  record_number : Int32,
) -> String? raise AdapterError {
  let marker = "<Data Name=\"\{name}\""
  let parts = raw.split(marker).to_array()
  if parts.length() < 2 {
    return None
  }
  let after_marker = parts[1].to_owned()
  let opening_end = match after_marker.find(">") {
    Some(index) => index
    None =>
      raise AdapterError::InvalidField(
        record_number~,
        path="EventData.\{name}",
        detail="unclosed Data tag",
      )
  }
  let tails = after_marker[opening_end + 1:]
    .to_owned()
    .split("</Data>")
    .to_array()
  if tails.length() < 2 {
    raise AdapterError::InvalidField(
      record_number~,
      path="EventData.\{name}",
      detail="unclosed Data value",
    )
  }
  Some(xml_decode(tails[0].to_owned(), "EventData.\{name}", record_number))
}

///|
fn xml_required_data(
  raw : String,
  name : String,
  record_number : Int32,
) -> String raise AdapterError {
  match xml_data(raw, name, record_number) {
    Some(value) if value != "" => value
    _ =>
      raise AdapterError::MissingField(record_number~, path="EventData.\{name}")
  }
}

///|
fn xml_claim(
  raw : String,
  name : String,
  record_number : Int32,
) -> Identity raise AdapterError {
  match xml_data(raw, name, record_number) {
    None => Identity::missing()
    Some("") | Some("-") => Identity::unknown()
    Some(value) => try! Identity::unverified(value)
  }
}

///|
fn xml_port(
  raw : String,
  name : String,
  record_number : Int32,
) -> Int32? raise AdapterError {
  match xml_data(raw, name, record_number) {
    None | Some("") => None
    Some(value) => {
      let port = adapter_parse_unsigned(
        value,
        "EventData.\{name}",
        record_number,
      )
      if port > 65535 {
        raise AdapterError::InvalidField(
          record_number~,
          path="EventData.\{name}",
          detail="port exceeds 65535",
        )
      }
      Some(port.to_int())
    }
  }
}

///|
fn xml_event_header(
  raw : String,
  record_number : Int32,
) -> (String, String, String, String, Int32) raise AdapterError {
  if raw.contains("<!DOCTYPE") || raw.contains("<!ENTITY") {
    raise AdapterError::Unsupported(
      record_number~,
      path="XML",
      value="DTD or entity declaration",
    )
  }
  if !raw.contains("<Event") ||
    !raw.contains("<System>") ||
    !raw.contains("<EventData>") {
    raise AdapterError::InvalidField(
      record_number~,
      path="Event",
      detail="expected Windows Event XML with System and EventData",
    )
  }
  let provider = xml_attribute(raw, "Provider", "Name", record_number)
  let channel = xml_tag(raw, "Channel", record_number)
  let computer = xml_tag(raw, "Computer", record_number)
  let event_record_id = xml_tag(raw, "EventRecordID", record_number)
  ignore(
    adapter_parse_unsigned(
      event_record_id, "System.EventRecordID", record_number,
    ),
  )
  let event_id = adapter_parse_unsigned(
    xml_tag(raw, "EventID", record_number),
    "System.EventID",
    record_number,
  )
  if event_id > 2147483647 {
    raise AdapterError::InvalidField(
      record_number~,
      path="System.EventID",
      detail="event ID out of range",
    )
  }
  (provider, channel, computer, event_record_id, event_id.to_int())
}

///|
/// Parses one Windows Event XML record from Sysmon Operational: Process Create
/// (1) or Network Connect (3). It does not interpret arbitrary XML documents.
///
/// # Example
/// ```mbt check
/// test {
///   let raw =
///     #|<Event><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID><EventRecordID>1</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>demo</Computer></System><EventData><Data Name="UtcTime">2024-01-01 00:00:00.000</Data><Data Name="ProcessGuid">{p1}</Data></EventData></Event>
///   assert_eq(
///     @hostsentinel.normalize_sysmon_xml(raw).identities.process.value(),
///     Some("{p1}"),
///   )
/// }
/// ```
pub fn normalize_sysmon_xml(
  raw : String,
  record_number~ : Int32 = 1,
) -> HostEvent raise AdapterError {
  let (provider, channel, computer, record_id, event_id) = xml_event_header(
    raw, record_number,
  )
  if provider != "Microsoft-Windows-Sysmon" ||
    channel != "Microsoft-Windows-Sysmon/Operational" {
    raise AdapterError::Unsupported(
      record_number~,
      path="System.Provider/Channel",
      value="\{provider}/\{channel}",
    )
  }
  if event_id != 1 && event_id != 3 {
    raise AdapterError::Unsupported(
      record_number~,
      path="System.EventID",
      value="\{event_id}",
    )
  }
  let (time, lossy) = native_utc_millis(
    xml_required_data(raw, "UtcTime", record_number),
    "EventData.UtcTime",
    record_number,
    false,
  )
  let diagnostics : Array[MappingDiagnostic] = []
  if lossy {
    diagnostics.push({
      path: "EventData.UtcTime",
      issue: MappingIssue::Lossy,
      detail: "sub-millisecond precision truncated",
    })
  }
  let process = xml_claim(raw, "ProcessGuid", record_number)
  if process.status() == IdentityStatus::Missing {
    diagnostics.push({
      path: "EventData.ProcessGuid",
      issue: MappingIssue::Missing,
      detail: "ProcessId alone is not a process instance identity",
    })
  }
  let network = if event_id == 3 {
    {
      src_ip: xml_data(raw, "SourceIp", record_number),
      src_port: xml_port(raw, "SourcePort", record_number),
      dst_ip: xml_data(raw, "DestinationIp", record_number),
      dst_port: xml_port(raw, "DestinationPort", record_number),
      protocol: xml_data(raw, "Protocol", record_number),
    }
  } else {
    NetworkAttributes::empty()
  }
  {
    id: try! EventId::new(value="\{computer}:\{channel}:\{record_id}"),
    source: EventSource::Sysmon,
    source_id: try! Identity::unverified("\{computer}:\{channel}"),
    time: { value: time, precision: TimePrecision::Milliseconds, },
    category: "host",
    class_name: if event_id == 1 {
      "process_activity"
    } else {
      "network_activity"
    },
    activity: if event_id == 1 {
      "launch"
    } else {
      "open"
    },
    ocsf: None,
    identities: {
      host: try! Identity::unverified(computer),
      boot: Identity::missing(),
      user: xml_claim(raw, "User", record_number),
      session: xml_claim(raw, "LogonGuid", record_number),
      process,
      parent_process: if event_id == 1 {
        xml_claim(raw, "ParentProcessGuid", record_number)
      } else {
        Identity::missing()
      },
    },
    network,
    original: {
      format: "windows-event-xml",
      record_number,
      record_id: Some(record_id),
      raw,
    },
    diagnostics,
  }
}

///|
/// Parses one Windows Security Event XML record for successful logon 4624.
/// The Subject* fields describe the actor; Target* fields describe the new
/// logon identity and are used here. Neither the logon-process PID nor time
/// proximity is treated as a target process instance.
///
/// # Example
/// ```mbt check
/// test {
///   let raw =
///     #|<Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4624</EventID><TimeCreated SystemTime="2024-01-01T00:00:00Z"/><EventRecordID>2</EventRecordID><Channel>Security</Channel><Computer>demo</Computer></System><EventData><Data Name="TargetUserSid">S-1-5-21-1</Data><Data Name="TargetLogonId">0x1</Data></EventData></Event>
///   assert_eq(
///     @hostsentinel.normalize_windows_security_xml(raw).identities.user.value(),
///     Some("S-1-5-21-1"),
///   )
/// }
/// ```
pub fn normalize_windows_security_xml(
  raw : String,
  record_number~ : Int32 = 1,
) -> HostEvent raise AdapterError {
  let (provider, channel, computer, record_id, event_id) = xml_event_header(
    raw, record_number,
  )
  if provider != "Microsoft-Windows-Security-Auditing" || channel != "Security" {
    raise AdapterError::Unsupported(
      record_number~,
      path="System.Provider/Channel",
      value="\{provider}/\{channel}",
    )
  }
  if event_id != 4624 {
    raise AdapterError::Unsupported(
      record_number~,
      path="System.EventID",
      value="\{event_id}",
    )
  }
  let (time, lossy) = native_utc_millis(
    xml_attribute(raw, "TimeCreated", "SystemTime", record_number),
    "System.TimeCreated.SystemTime",
    record_number,
    true,
  )
  let diagnostics : Array[MappingDiagnostic] = []
  if lossy {
    diagnostics.push({
      path: "System.TimeCreated.SystemTime",
      issue: MappingIssue::Lossy,
      detail: "sub-millisecond precision truncated",
    })
  }
  {
    id: try! EventId::new(value="\{computer}:\{channel}:\{record_id}"),
    source: EventSource::WindowsEvent,
    source_id: try! Identity::unverified("\{computer}:\{channel}"),
    time: { value: time, precision: TimePrecision::Milliseconds, },
    category: "host",
    class_name: "authentication",
    activity: "logon",
    ocsf: None,
    identities: {
      host: try! Identity::unverified(computer),
      boot: Identity::missing(),
      user: xml_claim(raw, "TargetUserSid", record_number),
      session: xml_claim(raw, "TargetLogonId", record_number),
      process: Identity::missing(),
      parent_process: Identity::missing(),
    },
    network: NetworkAttributes::empty(),
    original: {
      format: "windows-event-xml",
      record_number,
      record_id: Some(record_id),
      raw,
    },
    diagnostics,
  }
}
