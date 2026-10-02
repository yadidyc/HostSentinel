///|
test "bootstrap metadata is stable" {
  assert_eq(@hostsentinel.project_name(), "HostSentinel")
  assert_eq(@hostsentinel.version(), "0.1.0")
}
