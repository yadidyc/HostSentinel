///|
test "normalizes JSONL events and keeps duplicate fingerprints stable" {
  let source =
    #|  {"event_id":"evt-001","host_id":" host-001 ","hostname":" workstation-01 ","platform":"WINDOWS","kind":"PROCESS","source":"Sysmon","severity":"HIGH","observed_at":1725000000}
    #|
    #|{"event_id":"evt-001","host_id":"host-001","hostname":"workstation-01","platform":"windows","kind":"process","source":"sysmon","severity":"high","observed_at":"1725000000"}
  let events = try! @hostsentinel.normalize_jsonl(source)

  assert_eq(events.length(), 2)
  assert_eq(events[0].line_number(), 1)
  assert_eq(events[0].raw_line()[0], '{')
  assert_eq(events[0].host().hostname(), "workstation-01")
  assert_eq(events[0].host().platform(), @hostsentinel.HostPlatform::Windows)
  assert_eq(events[0].event().source(), @hostsentinel.EventSource::Sysmon)
  assert_eq(events[0].event().severity(), @hostsentinel.Severity::High)
  assert_eq(events[0].event().observed_at().unix_seconds(), 1_725_000_000)
  assert_eq(events[0].fingerprint(), events[1].fingerprint())
}

///|
test "normalization reports malformed JSON and missing fields" {
  try
    @hostsentinel.normalize_jsonl("{\"event_id\":\"evt-001\"}\nnot-json\n")
  catch {
    @hostsentinel.NormalizationError::MissingField(line_number~, field~) => {
      assert_eq(line_number, 1)
      assert_eq(field, "host_id")
    }
    _ => fail("expected the first missing field")
  } noraise {
    _ => fail("expected normalization to fail")
  }

  try @hostsentinel.normalize_jsonl("[]\n") catch {
    @hostsentinel.NormalizationError::ExpectedObject(line_number~, line~) => {
      assert_eq(line_number, 1)
      assert_eq(line, "[]")
    }
    _ => fail("expected an object error")
  } noraise {
    _ => fail("expected normalization to fail")
  }
}

///|
test "normalization rejects unsupported categories and timestamps" {
  let base = "{\"event_id\":\"evt-001\",\"host_id\":\"host-001\",\"hostname\":\"workstation-01\",\"platform\":\"linux\",\"kind\":\"unknown\",\"source\":\"custom\",\"severity\":\"high\",\"observed_at\":\"not-a-time\"}"
  try @hostsentinel.normalize_jsonl(base) catch {
    @hostsentinel.NormalizationError::InvalidField(field="kind", ..) => ()
    _ => fail("expected an invalid kind error")
  } noraise {
    _ => fail("expected normalization to fail")
  }

  let invalid_time = base.replace(old="unknown", new="process")
  try @hostsentinel.normalize_jsonl(invalid_time) catch {
    @hostsentinel.NormalizationError::InvalidField(field="observed_at", ..) =>
      ()
    _ => fail("expected an invalid timestamp error")
  } noraise {
    _ => fail("expected normalization to fail")
  }
}
