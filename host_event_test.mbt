///|
test "legacy JSONL maps to a host event without upgrading claimed identities" {
  let source =
    #|{"event_id":"p-1","host_id":"h-1","hostname":"h","platform":"linux","kind":"process","source":"auditd","severity":"high","observed_at":123,"boot_id":"b-1","session_id":"s-1","user_id":"u-1","pid":42,"process_started_at":120}
  let legacy = try! @hostsentinel.normalize_jsonl(source)[0]
  let event = @hostsentinel.host_event_from_normalized(legacy)
  assert_eq(event.id.as_string(), "p-1")
  assert_eq(event.time.value, 123)
  assert_eq(event.time.precision, @hostsentinel.TimePrecision::Seconds)
  assert_eq(event.class_name, "process")
  assert_eq(event.source_id.status(), @hostsentinel.IdentityStatus::Missing)
  assert_eq(
    event.identities.host.status(),
    @hostsentinel.IdentityStatus::Unverified,
  )
  assert_eq(event.identities.boot.value(), Some("b-1"))
  assert_eq(event.identities.session.value(), Some("s-1"))
  assert_eq(
    event.identities.process.status(),
    @hostsentinel.IdentityStatus::Unverified,
  )
  assert_eq(
    event.identities.parent_process.status(),
    @hostsentinel.IdentityStatus::Missing,
  )
  assert_eq(event.original.record_number, 1)
  assert_eq(event.original.raw, source)
}

///|
test "absent, explicit unknown, and invalid identity values stay distinct" {
  let source =
    #|{"event_id":"p-2","host_id":"h-1","hostname":"h","platform":"linux","kind":"process","source":"auditd","severity":"high","observed_at":123,"boot_id":null,"session_id":{},"pid":42,"process_started_at":120}
  let legacy = try! @hostsentinel.normalize_jsonl(source)[0]
  let event = @hostsentinel.host_event_from_normalized(legacy)
  assert_eq(
    event.identities.boot.status(),
    @hostsentinel.IdentityStatus::Unknown,
  )
  assert_eq(
    event.identities.user.status(),
    @hostsentinel.IdentityStatus::Missing,
  )
  assert_eq(
    event.identities.session.status(),
    @hostsentinel.IdentityStatus::Unknown,
  )
  assert_eq(
    event.identities.process.status(),
    @hostsentinel.IdentityStatus::Unknown,
  )
  assert_eq(event.diagnostics[0].path, "session_id")
  assert_eq(event.diagnostics[0].issue, @hostsentinel.MappingIssue::Invalid)
}

///|
test "process identity requires boot and start time, not PID alone" {
  let source =
    #|{"event_id":"p-3","host_id":"h-1","hostname":"h","platform":"linux","kind":"process","source":"auditd","severity":"high","observed_at":123,"pid":42}
  let legacy = try! @hostsentinel.normalize_jsonl(source)[0]
  let event = @hostsentinel.host_event_from_normalized(legacy)
  assert_eq(
    event.identities.process.status(),
    @hostsentinel.IdentityStatus::Missing,
  )
  try @hostsentinel.Identity::unverified("") catch {
    @hostsentinel.HostEventError::EmptyIdentity => ()
  } noraise {
    _ => fail("empty identity must be rejected")
  }
  let trusted = try! @hostsentinel.Identity::verified("trusted-h")
  assert_eq(trusted.status(), @hostsentinel.IdentityStatus::Verified)
}
