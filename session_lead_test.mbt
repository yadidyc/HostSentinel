///|
fn session_lead_fixture() -> String {
  (
    #|{"event_id":"login-s7","host_id":"host-h","hostname":"workstation-h","platform":"windows","kind":"authentication","source":"windows_event","severity":"medium","observed_at":100,"boot_id":"boot-1","session_id":"S7"}
    #|{"event_id":"process-p42","host_id":"host-h","hostname":"workstation-h","platform":"windows","kind":"process","source":"sysmon","severity":"high","observed_at":110,"boot_id":"boot-1","session_id":"S7","pid":42,"process_started_at":110}
    #|{"event_id":"network-p42","host_id":"host-h","hostname":"workstation-h","platform":"windows","kind":"network","source":"agent","severity":"high","observed_at":120,"boot_id":"boot-1","session_id":"S7","pid":42,"process_started_at":110}
  )
}

///|
test "three sources yield one evidence-bound session lead" {
  let report = try! @hostsentinel.hunt_session_leads(session_lead_fixture())
  assert_eq(report.leads().length(), 1)
  assert_eq(report.rejections().length(), 0)
  let lead = report.leads()[0]
  assert_eq(lead.host_id().as_string(), "host-h")
  assert_eq(lead.session_id(), "S7")
  assert_eq(lead.process_key(), "6:host-h|6:boot-1|2:42|3:110")
  assert_eq(lead.evidence().length(), 3)
  assert_eq(lead.evidence()[0].line_number(), 1)
  assert_eq(lead.evidence()[1].event().id().as_string(), "process-p42")
  assert_eq(lead.evidence()[2].event().id().as_string(), "network-p42")
}

///|
test "different login session rejects otherwise matching events" {
  let source = session_lead_fixture().replace(
    old="\"source\":\"agent\",\"severity\":\"high\",\"observed_at\":120,\"boot_id\":\"boot-1\",\"session_id\":\"S7\"",
    new="\"source\":\"agent\",\"severity\":\"high\",\"observed_at\":120,\"boot_id\":\"boot-1\",\"session_id\":\"S8\"",
  )
  let report = try! @hostsentinel.hunt_session_leads(source)
  assert_eq(report.leads().length(), 0)
  assert_eq(report.rejections().length(), 1)
  match report.rejections()[0].reason() {
    @hostsentinel.LeadRejectionReason::SessionMismatch => ()
    _ => fail("expected session mismatch")
  }
}

///|
test "reused PID with another start time rejects the chain" {
  let source = session_lead_fixture().replace(
    old="\"observed_at\":120,\"boot_id\":\"boot-1\",\"session_id\":\"S7\",\"pid\":42,\"process_started_at\":110",
    new="\"observed_at\":120,\"boot_id\":\"boot-1\",\"session_id\":\"S7\",\"pid\":42,\"process_started_at\":115",
  )
  let report = try! @hostsentinel.hunt_session_leads(source)
  assert_eq(report.leads().length(), 0)
  match report.rejections()[0].reason() {
    @hostsentinel.LeadRejectionReason::ProcessInstanceMismatch => ()
    _ => fail("expected process instance mismatch")
  }
}

///|
test "same host after reboot does not share a process chain" {
  let source = session_lead_fixture().replace(
    old="\"observed_at\":120,\"boot_id\":\"boot-1\"",
    new="\"observed_at\":120,\"boot_id\":\"boot-2\"",
  )
  let report = try! @hostsentinel.hunt_session_leads(source)
  assert_eq(report.leads().length(), 0)
  match report.rejections()[0].reason() {
    @hostsentinel.LeadRejectionReason::BootMismatch => ()
    _ => fail("expected boot mismatch")
  }
}

///|
test "duplicate telemetry does not create duplicate leads" {
  let source = session_lead_fixture()
  let report = try! @hostsentinel.hunt_session_leads(source + "\n" + source)
  assert_eq(report.leads().length(), 1)
}

///|
test "same source and expired window cannot corroborate" {
  let same_source = session_lead_fixture().replace(
    old="\"source\":\"agent\"",
    new="\"source\":\"sysmon\"",
  )
  let report = try! @hostsentinel.hunt_session_leads(same_source)
  assert_eq(report.leads().length(), 0)
  match report.rejections()[0].reason() {
    @hostsentinel.LeadRejectionReason::SourceNotIndependent => ()
    _ => fail("expected independent sources")
  }
  let expired = try! @hostsentinel.hunt_session_leads(
    session_lead_fixture(),
    window_seconds=10,
  )
  assert_eq(expired.leads().length(), 0)
  match expired.rejections()[0].reason() {
    @hostsentinel.LeadRejectionReason::TimeWindowMismatch => ()
    _ => fail("expected window mismatch")
  }
}

///|
test "ordinary activity is not promoted to a threat lead" {
  let source = session_lead_fixture().replace(
    old="\"severity\":\"high\"",
    new="\"severity\":\"low\"",
  )
  let report = try! @hostsentinel.hunt_session_leads(source)
  assert_eq(report.leads().length(), 0)
  match report.rejections()[0].reason() {
    @hostsentinel.LeadRejectionReason::InsufficientSignal => ()
    _ => fail("expected insufficient signal")
  }
}

///|
test "invalid correlation window is rejected" {
  try
    @hostsentinel.hunt_session_leads(session_lead_fixture(), window_seconds=0)
  catch {
    @hostsentinel.NormalizationError::InvalidField(field~, ..) =>
      assert_eq(field, "window_seconds")
    _ => fail("expected invalid window")
  } noraise {
    _ => fail("expected invalid window")
  }
}

///|
test "missing identity never produces a verified lead" {
  let source = session_lead_fixture().replace(
    old="\"process_started_at\":110",
    new="\"unused\":110",
  )
  try @hostsentinel.hunt_session_leads(source) catch {
    @hostsentinel.NormalizationError::MissingField(field~, ..) =>
      assert_eq(field, "process_started_at")
    _ => fail("expected missing identity field")
  } noraise {
    _ => fail("expected identity validation to fail")
  }
}

///|
test "rule-backed session leads keep valid and PID-reuse candidates separate" {
  let source = session_lead_fixture() +
    "\n" +
    (
      #|{"event_id":"network-reused","host_id":"host-h","hostname":"workstation-h","platform":"windows","kind":"network","source":"agent","severity":"high","observed_at":121,"boot_id":"boot-1","session_id":"S7","pid":42,"process_started_at":115}
    )
  let report = try! @hostsentinel.hunt_session_leads(source)
  assert_eq(report.leads().length(), 1)
  assert_eq(
    report.leads()[0].evidence()[2].event().id().as_string(),
    "network-p42",
  )
  assert_eq(report.rejections().length(), 1)
  assert_eq(report.rejections()[0].event_ids()[2], "network-reused")
  match report.rejections()[0].reason() {
    @hostsentinel.LeadRejectionReason::ProcessInstanceMismatch => ()
    _ => fail("expected process instance mismatch")
  }
}
