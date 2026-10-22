///|
fn sysmon_process_fixture() -> String {
  (
    #|<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID><TimeCreated SystemTime="2024-01-01T00:00:01.123Z"/><EventRecordID>101</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>LAB-1</Computer></System><EventData><Data Name="UtcTime">2024-01-01 00:00:01.123</Data><Data Name="ProcessGuid">{proc-42}</Data><Data Name="ProcessId">42</Data><Data Name="ParentProcessGuid">{parent-1}</Data><Data Name="LogonGuid">{logon-7}</Data><Data Name="User">ACME\alice</Data><Data Name="Image">C:\Windows\System32\cmd.exe</Data></EventData></Event>
  )
}

///|
fn sysmon_network_fixture() -> String {
  (
    #|<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>3</EventID><TimeCreated SystemTime="2024-01-01T00:00:02.123Z"/><EventRecordID>102</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>LAB-1</Computer></System><EventData><Data Name="UtcTime">2024-01-01 00:00:02.123</Data><Data Name="ProcessGuid">{proc-42}</Data><Data Name="ProcessId">42</Data><Data Name="SourceIp">10.0.0.1</Data><Data Name="SourcePort">50000</Data><Data Name="DestinationIp">203.0.113.7</Data><Data Name="DestinationPort">443</Data><Data Name="Protocol">tcp</Data></EventData></Event>
  )
}

///|
fn security_logon_fixture() -> String {
  (
    #|<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4624</EventID><TimeCreated SystemTime="2024-01-01T00:00:01.1234567Z"/><EventRecordID>201</EventRecordID><Channel>Security</Channel><Computer>LAB-1</Computer></System><EventData><Data Name="SubjectUserSid">S-1-5-18</Data><Data Name="TargetUserSid">S-1-5-21-7</Data><Data Name="TargetLogonId">0x7</Data><Data Name="LogonType">2</Data><Data Name="ProcessId">0x44c</Data></EventData></Event>
  )
}

///|
fn auditd_exec_fixture() -> String {
  (
    #|type=SYSCALL msg=audit(1704067201.123:100): arch=c000003e syscall=59 success=yes exit=0 pid=42 ppid=1 auid=1000 uid=1000 ses=7 comm="echo" exe="/bin/echo"
    #|type=EXECVE msg=audit(1704067201.123:100): argc=2 a0="/bin/echo" a1="hello"
    #|type=PATH msg=audit(1704067201.123:100): item=0 name="/bin/echo" nametype=NORMAL
    #|type=SYSCALL msg=audit(1704067202.123:101): arch=c000003e syscall=2 success=yes exit=3 pid=42 auid=1000 ses=7
  )
}

///|
test "Sysmon 1 and 3 retain source-claimed process GUID and network fields" {
  let process = @hostsentinel.normalize_sysmon_xml(sysmon_process_fixture())
  let network = @hostsentinel.normalize_sysmon_xml(sysmon_network_fixture())
  assert_eq(process.class_name, "process_activity")
  assert_eq(network.class_name, "network_activity")
  assert_eq(process.time.value, 1_704_067_201_123)
  assert_eq(process.identities.process.value(), Some("{proc-42}"))
  assert_eq(
    network.identities.process.value(),
    process.identities.process.value(),
  )
  assert_eq(
    process.identities.process.status(),
    @hostsentinel.IdentityStatus::Unverified,
  )
  assert_eq(process.identities.parent_process.value(), Some("{parent-1}"))
  assert_eq(
    process.identities.boot.status(),
    @hostsentinel.IdentityStatus::Missing,
  )
  assert_eq(network.network.dst_ip, Some("203.0.113.7"))
  assert_eq(network.network.dst_port, Some(443))
  assert_eq(network.original.record_id, Some("102"))
}

///|
test "Windows Security 4624 uses Target identity, not Subject or logon process" {
  let event = @hostsentinel.normalize_windows_security_xml(
    security_logon_fixture(),
  )
  assert_eq(event.identities.user.value(), Some("S-1-5-21-7"))
  assert_eq(event.identities.session.value(), Some("0x7"))
  assert_eq(
    event.identities.process.status(),
    @hostsentinel.IdentityStatus::Missing,
  )
  assert_eq(event.time.value, 1_704_067_201_123)
  assert_eq(event.diagnostics[0].issue, @hostsentinel.MappingIssue::Lossy)
  assert_eq(event.original.record_id, Some("201"))
}

///|
test "auditd groups SYSCALL and EXECVE by exact serial and ignores non-exec group" {
  let events = @hostsentinel.normalize_auditd_exec(
    auditd_exec_fixture(),
    "linux-1",
  )
  assert_eq(events.length(), 1)
  let event = events[0]
  assert_eq(event.id.as_string(), "audit:linux-1:1704067201.123:100")
  assert_eq(event.time.value, 1_704_067_201_123)
  assert_eq(event.identities.user.value(), Some("1000"))
  assert_eq(event.identities.session.value(), Some("7"))
  assert_eq(
    event.identities.process.status(),
    @hostsentinel.IdentityStatus::Missing,
  )
  assert_eq(
    event.identities.boot.status(),
    @hostsentinel.IdentityStatus::Missing,
  )
  assert_eq(event.original.record_id, Some("100"))
  assert_true(event.original.raw.contains("type=PATH"))
}

///|
test "native adapters reject unsupported IDs, malformed fields and incomplete groups" {
  let unsupported = sysmon_process_fixture().replace(
    old="<EventID>1</EventID>",
    new="<EventID>5</EventID>",
  )
  try @hostsentinel.normalize_sysmon_xml(unsupported, record_number=4) catch {
    @hostsentinel.AdapterError::Unsupported(record_number~, path~, ..) => {
      assert_eq(record_number, 4)
      assert_eq(path, "System.EventID")
    }
    _ => fail("expected unsupported Sysmon ID")
  } noraise {
    _ => fail("expected rejection")
  }
  let bad_port = sysmon_network_fixture().replace(
    old="<Data Name=\"DestinationPort\">443",
    new="<Data Name=\"DestinationPort\">70000",
  )
  try @hostsentinel.normalize_sysmon_xml(bad_port) catch {
    @hostsentinel.AdapterError::InvalidField(path~, ..) =>
      assert_eq(path, "EventData.DestinationPort")
    _ => fail("expected invalid port")
  } noraise {
    _ => fail("expected rejection")
  }
  let incomplete = "type=EXECVE msg=audit(1704067201.123:100): argc=1 a0=\"/bin/echo\""
  try @hostsentinel.normalize_auditd_exec(incomplete, "linux-1") catch {
    @hostsentinel.AdapterError::MissingField(path~, ..) =>
      assert_eq(path, "auditd.SYSCALL")
    _ => fail("expected incomplete group")
  } noraise {
    _ => fail("expected rejection")
  }
}

///|
test "missing Sysmon ProcessGuid does not fall back to matching ProcessId" {
  let without_guid = sysmon_network_fixture().replace(
    old="<Data Name=\"ProcessGuid\">{proc-42}</Data>",
    new="",
  )
  let event = @hostsentinel.normalize_sysmon_xml(without_guid)
  assert_eq(
    event.identities.process.status(),
    @hostsentinel.IdentityStatus::Missing,
  )
  assert_eq(event.diagnostics[0].path, "EventData.ProcessGuid")
}

///|
test "auditd interleaved serials remain isolated and unset auid is unknown" {
  let first = "type=EXECVE msg=audit(1704067201.123:100): argc=1 a0=\"/bin/a\""
  let second = "type=EXECVE msg=audit(1704067201.123:101): argc=1 a0=\"/bin/b\""
  let second_sys = "type=SYSCALL msg=audit(1704067201.123:101): success=yes pid=43 auid=4294967295 ses=8"
  let first_sys = "type=SYSCALL msg=audit(1704067201.123:100): success=yes pid=42 auid=1000 ses=7"
  let events = @hostsentinel.normalize_auditd_exec(
    [first, second, second_sys, first_sys].join("\n"),
    "linux-1",
  )
  assert_eq(events.length(), 2)
  assert_eq(events[0].original.record_id, Some("100"))
  assert_eq(events[0].identities.session.value(), Some("7"))
  assert_eq(events[1].original.record_id, Some("101"))
  assert_eq(
    events[1].identities.user.status(),
    @hostsentinel.IdentityStatus::Unknown,
  )
}
