///|
fn ocsf_supported_fixture() -> String {
  (
    #|{"category_uid":3,"class_uid":3002,"activity_id":1,"type_uid":300201,"severity_id":1,"time":1760000000123,"metadata":{"version":"1.9.0","uid":"ocsf-auth-1","product":{"name":"example-source","version":"1"},"log_source":"auth-feed"},"user":{"uid":"user-7"},"session":{"uid":"session-7"},"service":{"name":"login"},"device":{"uid":"host-7","boot_uid":"boot-7"}}
    #|{"category_uid":1,"class_uid":1007,"activity_id":1,"type_uid":100701,"severity_id":2,"time":1760000001123,"metadata":{"version":"1.9.0","uid":"ocsf-process-1","product":{"name":"example-source","version":"1"}},"actor":{"user":{"uid":"user-7"}},"device":{"uid":"host-7","type_id":2,"boot_uid":"boot-7"},"process":{"uid":"process-guid-7","pid":42,"user":{"uid":"user-7"},"session":{"uid":"session-7"},"parent_process":{"uid":"parent-guid-7"}}}
    #|{"category_uid":4,"class_uid":4001,"activity_id":1,"type_uid":400101,"severity_id":1,"time":1760000002123,"metadata":{"version":"1.9.0","uid":"ocsf-network-1","product":{"name":"example-source","version":"1"}},"device":{"uid":"host-7","boot_uid":"boot-7"},"src_endpoint":{"ip":"10.0.0.7","port":44444},"dst_endpoint":{"ip":"203.0.113.7","port":443}}
  )
}

///|
test "OCSF 1.9.0 supported classes map exact classification and identity" {
  let events = @hostsentinel.normalize_ocsf_jsonl(ocsf_supported_fixture())
  assert_eq(events.length(), 3)
  assert_eq(events[0].ocsf.unwrap().class_uid, 3002)
  assert_eq(events[0].identities.user.value(), Some("user-7"))
  assert_eq(events[0].identities.session.value(), Some("session-7"))
  assert_eq(events[0].source_id.value(), Some("auth-feed"))
  assert_eq(events[1].ocsf.unwrap().class_uid, 1007)
  assert_eq(events[1].time.precision, @hostsentinel.TimePrecision::Milliseconds)
  assert_eq(events[1].time.value, 1_760_000_001_123)
  assert_eq(events[1].identities.process.value(), Some("process-guid-7"))
  assert_eq(events[1].identities.parent_process.value(), Some("parent-guid-7"))
  assert_eq(
    events[1].identities.process.status(),
    @hostsentinel.IdentityStatus::Unverified,
  )
  assert_eq(events[2].ocsf.unwrap().type_uid, 400101)
  assert_eq(events[2].network.dst_ip, Some("203.0.113.7"))
  assert_eq(events[2].network.dst_port, Some(443))
  assert_eq(events[2].original.record_number, 3)
}

///|
test "OCSF rejects unsupported version, activity and mismatched type UID" {
  let fixture = ocsf_supported_fixture().split("\n").to_array()[0].to_owned()
  let wrong_version = fixture.replace(old="1.9.0", new="1.8.0")
  try @hostsentinel.normalize_ocsf_jsonl(wrong_version) catch {
    @hostsentinel.AdapterError::Unsupported(path~, ..) =>
      assert_eq(path, "metadata.version")
    _ => fail("expected unsupported schema version")
  } noraise {
    _ => fail("expected rejection")
  }
  let wrong_type = fixture.replace(old="300201", new="300202")
  try @hostsentinel.normalize_ocsf_jsonl(wrong_type) catch {
    @hostsentinel.AdapterError::InvalidField(path~, ..) =>
      assert_eq(path, "type_uid")
    _ => fail("expected type UID mismatch")
  } noraise {
    _ => fail("expected rejection")
  }
  let unsupported = fixture
    .replace(old="\"activity_id\":1", new="\"activity_id\":2")
    .replace(old="300201", new="300202")
  try @hostsentinel.normalize_ocsf_jsonl(unsupported) catch {
    @hostsentinel.AdapterError::Unsupported(path~, ..) =>
      assert_eq(path, "category_uid/class_uid/activity_id")
    _ => fail("expected unsupported activity")
  } noraise {
    _ => fail("expected rejection")
  }
}

///|
test "OCSF errors identify field and physical record number" {
  let fixture = ocsf_supported_fixture().split("\n").to_array()[0].to_owned()
  let missing_user = fixture.replace(
    old="\"user\":{\"uid\":\"user-7\"}",
    new="\"user\":{}",
  )
  try @hostsentinel.normalize_ocsf_jsonl("\n" + missing_user) catch {
    @hostsentinel.AdapterError::MissingField(record_number~, path~) => {
      assert_eq(record_number, 2)
      assert_eq(path, "user.uid|user.name")
    }
    _ => fail("expected missing user")
  } noraise {
    _ => fail("expected rejection")
  }
  let invalid_time = fixture.replace(old="1760000000123", new="1.5")
  try @hostsentinel.normalize_ocsf_jsonl(invalid_time) catch {
    @hostsentinel.AdapterError::InvalidField(path~, ..) =>
      assert_eq(path, "time")
    _ => fail("expected invalid millisecond time")
  } noraise {
    _ => fail("expected rejection")
  }
}
