///|
test "constructs a host security event" {
  let host_id = try! @hostsentinel.HostId::new(value="host-001")
  let host = try! @hostsentinel.Host::new(
    id=host_id,
    hostname="workstation-01",
    platform=@hostsentinel.HostPlatform::Linux,
  )
  let event_id = try! @hostsentinel.EventId::new(value="event-001")
  let observed_at = try! @hostsentinel.ObservedAt::from_unix_seconds(
    unix_seconds=1_725_000_000,
  )
  let event = @hostsentinel.SecurityEvent::new(
    id=event_id,
    host_id=host.id(),
    kind=@hostsentinel.EventKind::Process,
    source=@hostsentinel.EventSource::Agent,
    severity=@hostsentinel.Severity::High,
    observed_at~,
  )
  assert_eq(host.hostname(), "workstation-01")
  assert_eq(host.state(), @hostsentinel.HostState::Active)
  assert_eq(event.host_id().as_string(), "host-001")
  assert_eq(event.severity(), @hostsentinel.Severity::High)
  assert_eq(event.observed_at().unix_seconds(), 1_725_000_000)
}

///|
test "rejects invalid host event values" {
  try @hostsentinel.HostId::new(value="") catch {
    @hostsentinel.DomainError::EmptyHostId => ()
    _ => fail("unexpected host id error")
  } noraise {
    _ => fail("expected an empty host id error")
  }
  try
    @hostsentinel.Host::new(
      id=try! @hostsentinel.HostId::new(value="host-001"),
      hostname="",
      platform=@hostsentinel.HostPlatform::Windows,
    )
  catch {
    @hostsentinel.DomainError::EmptyHostname => ()
    _ => fail("unexpected hostname error")
  } noraise {
    _ => fail("expected an empty hostname error")
  }
  try @hostsentinel.ObservedAt::from_unix_seconds(unix_seconds=-1) catch {
    @hostsentinel.DomainError::InvalidTimestamp => ()
    _ => fail("unexpected timestamp error")
  } noraise {
    _ => fail("expected an invalid timestamp error")
  }
}
