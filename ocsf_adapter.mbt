///|
fn ocsf_identity(
  root : Json,
  uid_path : String,
  name_path : String,
  record_number : Int32,
) -> Identity raise AdapterError {
  let uid = adapter_claim(root, uid_path, record_number)
  if uid.status() != IdentityStatus::Missing {
    return uid
  }
  adapter_claim(root, name_path, record_number)
}

///|
fn ocsf_classification(
  root : Json,
  record_number : Int32,
) -> (OcsfClassification, String, String, String) raise AdapterError {
  let category_uid = adapter_int(root, "category_uid", record_number)
  let class_uid = adapter_int(root, "class_uid", record_number)
  let activity_id = adapter_int(root, "activity_id", record_number)
  let type_uid = adapter_int(root, "type_uid", record_number)
  let severity_id = adapter_int(root, "severity_id", record_number)
  if type_uid != class_uid * 100 + activity_id {
    raise AdapterError::InvalidField(
      record_number~,
      path="type_uid",
      detail="must equal class_uid * 100 + activity_id",
    )
  }
  if !(severity_id <= 6 || severity_id == 99) {
    raise AdapterError::Unsupported(
      record_number~,
      path="severity_id",
      value="\{severity_id}",
    )
  }
  if severity_id == 99 {
    ignore(adapter_text(root, "severity", record_number))
  }
  let labels = match (category_uid, class_uid, activity_id) {
    (3, 3002, 1) => ("iam", "authentication", "logon")
    (1, 1007, 1) => ("system", "process_activity", "launch")
    (4, 4001, 1) => ("network", "network_activity", "open")
    _ =>
      raise AdapterError::Unsupported(
        record_number~,
        path="category_uid/class_uid/activity_id",
        value="\{category_uid}/\{class_uid}/\{activity_id}",
      )
  }
  (
    { category_uid, class_uid, activity_id, type_uid, severity_id, },
    labels.0,
    labels.1,
    labels.2,
  )
}

///|
fn ocsf_validate_class(
  root : Json,
  class_uid : Int32,
  record_number : Int32,
) -> Unit raise AdapterError {
  match class_uid {
    3002 => {
      ignore(adapter_object(root, "user", record_number))
      if adapter_field(root, "user.uid") is None &&
        adapter_field(root, "user.name") is None {
        raise AdapterError::MissingField(
          record_number~,
          path="user.uid|user.name",
        )
      }
      if adapter_field(root, "service") is None &&
        adapter_field(root, "dst_endpoint") is None {
        raise AdapterError::MissingField(
          record_number~,
          path="service|dst_endpoint",
        )
      }
      if adapter_field(root, "dst_endpoint") is Some(_) {
        ignore(adapter_object(root, "dst_endpoint", record_number))
      }
    }
    1007 => {
      ignore(adapter_object(root, "actor", record_number))
      ignore(adapter_object(root, "device", record_number))
      ignore(adapter_int(root, "device.type_id", record_number))
      ignore(adapter_object(root, "process", record_number))
      if adapter_field(root, "process.uid") is None &&
        adapter_field(root, "process.pid") is None &&
        adapter_field(root, "process.cpid") is None {
        raise AdapterError::MissingField(
          record_number~,
          path="process.uid|process.pid|process.cpid",
        )
      }
      if adapter_field(root, "process.pid") is Some(_) {
        ignore(adapter_int(root, "process.pid", record_number))
      }
    }
    4001 => {
      if adapter_field(root, "src_endpoint") is None &&
        adapter_field(root, "dst_endpoint") is None {
        raise AdapterError::MissingField(
          record_number~,
          path="src_endpoint|dst_endpoint",
        )
      }
      if adapter_field(root, "src_endpoint") is Some(_) {
        ignore(adapter_object(root, "src_endpoint", record_number))
      }
      if adapter_field(root, "dst_endpoint") is Some(_) {
        ignore(adapter_object(root, "dst_endpoint", record_number))
      }
    }
    _ => ()
  }
}

///|
fn ocsf_event(
  root : Json,
  raw : String,
  record_number : Int32,
) -> HostEvent raise AdapterError {
  let version = adapter_text(root, "metadata.version", record_number)
  if version != "1.9.0" {
    raise AdapterError::Unsupported(
      record_number~,
      path="metadata.version",
      value=version,
    )
  }
  ignore(adapter_object(root, "metadata.product", record_number))
  ignore(adapter_text(root, "metadata.product.name", record_number))
  let (classification, category, class_name, activity) = ocsf_classification(
    root, record_number,
  )
  ocsf_validate_class(root, classification.class_uid, record_number)
  let time = adapter_unsigned(root, "time", record_number)
  let uid = adapter_optional_text(root, "metadata.uid", record_number)
  let original_uid = adapter_optional_text(
    root, "metadata.original_event_uid", record_number,
  )
  let id_text = match (uid, original_uid) {
    (Some(value), _) | (None, Some(value)) => value
    _ =>
      raise AdapterError::MissingField(
        record_number~,
        path="metadata.uid|metadata.original_event_uid",
      )
  }
  let host = ocsf_identity(root, "device.uid", "device.hostname", record_number)
  let process = adapter_claim(root, "process.uid", record_number)
  let user = match classification.class_uid {
    3002 => ocsf_identity(root, "user.uid", "user.name", record_number)
    1007 =>
      ocsf_identity(
        root, "process.user.uid", "process.user.name", record_number,
      )
    _ => Identity::missing()
  }
  let session = match classification.class_uid {
    3002 => adapter_claim(root, "session.uid", record_number)
    1007 => adapter_claim(root, "process.session.uid", record_number)
    _ => Identity::missing()
  }
  let diagnostics : Array[MappingDiagnostic] = []
  if host.status() == IdentityStatus::Missing {
    diagnostics.push({
      path: "device.uid|device.hostname",
      issue: MappingIssue::Missing,
      detail: "host identity not asserted by this record",
    })
  }
  if process.status() == IdentityStatus::Missing &&
    classification.class_uid == 1007 {
    diagnostics.push({
      path: "process.uid",
      issue: MappingIssue::Missing,
      detail: "PID alone is not a process instance identity",
    })
  }
  let source_id = adapter_claim(root, "metadata.log_source", record_number)
  let src_port = adapter_optional_int(root, "src_endpoint.port", record_number)
  let dst_port = adapter_optional_int(root, "dst_endpoint.port", record_number)
  for
    (path, port) in [
      ("src_endpoint.port", src_port),
      ("dst_endpoint.port", dst_port),
    ] {
    if port is Some(number) && number > 65535 {
      raise AdapterError::InvalidField(
        record_number~,
        path~,
        detail="port exceeds 65535",
      )
    }
  }
  {
    id: try! EventId::new(value=id_text),
    source: EventSource::Other("ocsf"),
    source_id,
    time: { value: time, precision: TimePrecision::Milliseconds, },
    category,
    class_name,
    activity,
    ocsf: Some(classification),
    identities: {
      host,
      boot: adapter_claim(root, "device.boot_uid", record_number),
      user,
      session,
      process,
      parent_process: adapter_claim(
        root, "process.parent_process.uid", record_number,
      ),
    },
    network: {
      src_ip: adapter_optional_text(root, "src_endpoint.ip", record_number),
      src_port,
      dst_ip: adapter_optional_text(root, "dst_endpoint.ip", record_number),
      dst_port,
      protocol: None,
    },
    original: {
      format: "ocsf-1.9.0-jsonl",
      record_number,
      record_id: match original_uid {
        Some(value) => Some(value)
        None => uid
      },
      raw,
    },
    diagnostics,
  }
}

///|
/// Normalizes a deliberately limited OCSF 1.9.0 JSONL subset: Authentication
/// Logon, Process Activity Launch, and Network Activity Open. Other class or
/// activity combinations fail explicitly instead of silently changing meaning.
///
/// # Example
/// ```mbt check
/// test {
///   let raw =
///     #|{"category_uid":3,"class_uid":3002,"activity_id":1,"type_uid":300201,"severity_id":1,"time":123000,"metadata":{"version":"1.9.0","uid":"e-1","product":{"name":"demo"}},"user":{"uid":"u-1"},"service":{"name":"login"}}
///   let events = @hostsentinel.normalize_ocsf_jsonl(raw)
///   assert_eq(events[0].class_name, "authentication")
/// }
/// ```
pub fn normalize_ocsf_jsonl(
  source : String,
) -> Array[HostEvent] raise AdapterError {
  let events : Array[HostEvent] = []
  for index, physical_line in source.split("\n") {
    let raw = physical_line.trim().to_owned()
    if raw != "" {
      let record_number = index + 1
      events.push(
        ocsf_event(adapter_parse_object(raw, record_number), raw, record_number),
      )
    }
  }
  events
}
