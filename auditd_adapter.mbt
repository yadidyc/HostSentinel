///|
priv struct AuditExecGroup {
  key : String
  stamp : String
  serial : String
  first_line : Int32
  mut syscall_line : String?
  mut execve_line : String?
  raw_lines : Array[String]
}

///|
fn audit_token(line : String, key : String) -> String? {
  let marker = "\{key}="
  for part in line.split(" ") {
    let token = part.to_owned()
    if token.has_prefix(marker) {
      let pieces = token.split(marker).to_array()
      if pieces.length() >= 2 {
        return Some(pieces[1].to_owned())
      }
    }
  }
  None
}

///|
fn audit_required(
  line : String,
  key : String,
  record_number : Int32,
) -> String raise AdapterError {
  match audit_token(line, key) {
    Some(value) if value != "" => value
    _ => raise AdapterError::MissingField(record_number~, path="auditd.\{key}")
  }
}

///|
fn audit_key(
  line : String,
  record_number : Int32,
) -> (String, String, String) raise AdapterError {
  let message = audit_required(line, "msg", record_number)
  let parts = message.split("audit(").to_array()
  if parts.length() != 2 {
    raise AdapterError::InvalidField(
      record_number~,
      path="auditd.msg",
      detail="expected audit(timestamp:serial)",
    )
  }
  let close = parts[1].to_owned().split(")").to_array()
  if close.length() < 2 {
    raise AdapterError::InvalidField(
      record_number~,
      path="auditd.msg",
      detail="unclosed audit timestamp",
    )
  }
  let key = close[0].to_owned()
  let pieces = key.split(":").to_array()
  if pieces.length() != 2 {
    raise AdapterError::InvalidField(
      record_number~,
      path="auditd.msg",
      detail="expected timestamp:serial",
    )
  }
  let stamp = pieces[0].to_owned()
  let serial = pieces[1].to_owned()
  ignore(adapter_parse_unsigned(serial, "auditd.msg.serial", record_number))
  (key, stamp, serial)
}

///|
fn audit_millis(
  stamp : String,
  record_number : Int32,
) -> (Int64, Bool) raise AdapterError {
  let parts = stamp.split(".").to_array()
  if parts.length() > 2 {
    raise AdapterError::InvalidField(
      record_number~,
      path="auditd.msg.timestamp",
      detail="invalid seconds.fraction",
    )
  }
  let seconds = adapter_parse_unsigned(
    parts[0].to_owned(),
    "auditd.msg.timestamp",
    record_number,
  )
  if seconds > 253402300799 {
    raise AdapterError::InvalidField(
      record_number~,
      path="auditd.msg.timestamp",
      detail="timestamp exceeds year 9999",
    )
  }
  let mut millis : Int64 = 0
  let mut lossy = false
  if parts.length() == 2 {
    let fraction = parts[1].to_owned()
    if fraction == "" || fraction.length() > 9 {
      raise AdapterError::InvalidField(
        record_number~,
        path="auditd.msg.timestamp",
        detail="invalid fractional seconds",
      )
    }
    ignore(
      adapter_parse_unsigned(fraction, "auditd.msg.timestamp", record_number),
    )
    let mut digits = 0
    for character in fraction {
      if digits < 3 {
        millis = millis * 10 +
          adapter_parse_unsigned(
            "\{character}",
            "auditd.msg.timestamp",
            record_number,
          )
      } else {
        lossy = true
      }
      digits += 1
    }
    for _ in digits..<3 {
      millis *= 10
    }
  }
  (seconds * 1000 + millis, lossy)
}

///|
fn audit_claim(
  line : String,
  key : String,
  record_number : Int32,
) -> Identity raise AdapterError {
  match audit_token(line, key) {
    None => Identity::missing()
    Some("4294967295") | Some("-1") | Some("unset") => Identity::unknown()
    Some(value) => {
      ignore(adapter_parse_unsigned(value, "auditd.\{key}", record_number))
      try! Identity::unverified(value)
    }
  }
}

///|
fn audit_exec_event(
  group : AuditExecGroup,
  host_id : String,
) -> HostEvent raise AdapterError {
  let syscall = match group.syscall_line {
    Some(line) => line
    None =>
      raise AdapterError::MissingField(
        record_number=group.first_line,
        path="auditd.SYSCALL",
      )
  }
  let success = audit_required(syscall, "success", group.first_line)
  if success != "yes" {
    raise AdapterError::Unsupported(
      record_number=group.first_line,
      path="auditd.SYSCALL.success",
      value=success,
    )
  }
  let pid = audit_required(syscall, "pid", group.first_line)
  ignore(adapter_parse_unsigned(pid, "auditd.SYSCALL.pid", group.first_line))
  let (time, lossy) = audit_millis(group.stamp, group.first_line)
  let diagnostics : Array[MappingDiagnostic] = [
    {
      path: "auditd.SYSCALL.pid",
      issue: MappingIssue::Missing,
      detail: "PID without process creation identity is not an instance key",
    },
    {
      path: "auditd.boot_id",
      issue: MappingIssue::Missing,
      detail: "audit records do not supply a boot identity",
    },
  ]
  if lossy {
    diagnostics.push({
      path: "auditd.msg.timestamp",
      issue: MappingIssue::Lossy,
      detail: "sub-millisecond precision truncated",
    })
  }
  {
    id: try! EventId::new(value="audit:\{host_id}:\{group.key}"),
    source: EventSource::Auditd,
    source_id: Identity::missing(),
    time: { value: time, precision: TimePrecision::Milliseconds, },
    category: "host",
    class_name: "process_activity",
    activity: "launch",
    ocsf: None,
    identities: {
      host: try! Identity::unverified(host_id),
      boot: Identity::missing(),
      user: audit_claim(syscall, "auid", group.first_line),
      session: audit_claim(syscall, "ses", group.first_line),
      process: Identity::missing(),
      parent_process: Identity::missing(),
    },
    network: NetworkAttributes::empty(),
    original: {
      format: "auditd-record-group",
      record_number: group.first_line,
      record_id: Some(group.serial),
      raw: group.raw_lines.join("\n"),
    },
    diagnostics,
  }
}

///|
/// Groups raw auditd records by their exact `msg=audit(timestamp:serial)` key.
/// Only groups with EXECVE and successful SYSCALL become process launches;
/// unrelated groups are ignored, while incomplete EXECVE groups fail.
/// `host_id` is supplied by the caller because auditd records have no host ID.
///
/// # Example
/// ```mbt check
/// test {
///   let raw =
///     #|type=SYSCALL msg=audit(1704067201.123:1): success=yes pid=42 auid=1000 ses=7
///     #|type=EXECVE msg=audit(1704067201.123:1): argc=1 a0="/bin/echo"
///   assert_eq(@hostsentinel.normalize_auditd_exec(raw, "host-1").length(), 1)
/// }
/// ```
pub fn normalize_auditd_exec(
  source : String,
  host_id : String,
) -> Array[HostEvent] raise AdapterError {
  if host_id.trim() == "" {
    raise AdapterError::InvalidField(
      record_number=0,
      path="host_id",
      detail="caller must supply non-empty host ID",
    )
  }
  let groups : Array[AuditExecGroup] = []
  for index, raw_line in source.split("\n") {
    let line = raw_line.trim().to_owned()
    if line == "" {
      continue
    }
    let record_number = index + 1
    let kind = audit_required(line, "type", record_number)
    let (key, stamp, serial) = audit_key(line, record_number)
    let mut position = None
    for group_index, group in groups {
      if group.key == key {
        position = Some(group_index)
        break
      }
    }
    let group = match position {
      Some(group_index) => groups[group_index]
      None => {
        let created = {
          key,
          stamp,
          serial,
          first_line: record_number,
          syscall_line: None,
          execve_line: None,
          raw_lines: [],
        }
        groups.push(created)
        created
      }
    }
    group.raw_lines.push(line)
    match kind {
      "SYSCALL" => {
        if group.syscall_line is Some(_) {
          raise AdapterError::InvalidField(
            record_number~,
            path="auditd.SYSCALL",
            detail="duplicate record in event group",
          )
        }
        group.syscall_line = Some(line)
      }
      "EXECVE" => {
        if group.execve_line is Some(_) {
          raise AdapterError::InvalidField(
            record_number~,
            path="auditd.EXECVE",
            detail="duplicate record in event group",
          )
        }
        group.execve_line = Some(line)
      }
      _ => ()
    }
  }
  let events : Array[HostEvent] = []
  for group in groups {
    if group.execve_line is Some(_) {
      events.push(audit_exec_event(group, host_id))
    }
  }
  events
}
