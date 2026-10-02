///|
test "normalizes and matches IOC categories" {
  let domain = try! @hostsentinel.Indicator::new(
    kind=@hostsentinel.IocKind::Domain,
    value=" Example.COM ",
  )
  assert_eq(domain.value(), "example.com")
  assert_true(domain.matches("EXAMPLE.com"))
  assert_false(domain.matches("other.example.com"))

  let path = try! @hostsentinel.Indicator::new(
    kind=@hostsentinel.IocKind::FilePath,
    value="C:\\Windows\\Temp\\dropper.exe",
  )
  assert_eq(path.value(), "C:/Windows/Temp/dropper.exe")
  assert_true(path.matches("C:/Windows/Temp/dropper.exe"))

  let hash = try! @hostsentinel.Indicator::new(
    kind=@hostsentinel.IocKind::FileHash,
    value="0123456789ABCDEF0123456789ABCDEF",
  )
  assert_eq(hash.value(), "0123456789abcdef0123456789abcdef")
  assert_true(hash.matches("0123456789abcdef0123456789abcdef"))
}

///|
test "returns ordered IOC matches" {
  let indicators = [
    try! @hostsentinel.Indicator::new(
      kind=@hostsentinel.IocKind::Domain,
      value="example.com",
    ),
    try! @hostsentinel.Indicator::new(
      kind=@hostsentinel.IocKind::ProcessName,
      value="PowerShell.EXE",
    ),
  ]
  let matches = @hostsentinel.match_iocs(indicators, " powershell.exe ")
  assert_eq(matches.length(), 1)
  assert_eq(matches[0].indicator().kind(), @hostsentinel.IocKind::ProcessName)
  assert_eq(matches[0].candidate(), " powershell.exe ")
  assert_true(@hostsentinel.match_ioc(indicators[0], "powershell.exe") is None)
}

///|
test "rejects empty and malformed hash indicators" {
  try
    @hostsentinel.Indicator::new(kind=@hostsentinel.IocKind::Domain, value="  ")
  catch {
    @hostsentinel.IocError::EmptyValue(kind=@hostsentinel.IocKind::Domain) => ()
    _ => fail("expected an empty indicator error")
  } noraise {
    _ => fail("expected indicator creation to fail")
  }

  try
    @hostsentinel.Indicator::new(
      kind=@hostsentinel.IocKind::FileHash,
      value="not-a-hash",
    )
  catch {
    @hostsentinel.IocError::InvalidFileHash(value="not-a-hash") => ()
    _ => fail("expected a malformed hash error")
  } noraise {
    _ => fail("expected indicator creation to fail")
  }
}
