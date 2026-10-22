///|
fn native_digits(
  text : String,
  start : Int32,
  end : Int32,
  path : String,
  record_number : Int32,
) -> Int32 raise AdapterError {
  let mut value = 0
  for index in start..<end {
    let digit = match text[index] {
      '0' => 0
      '1' => 1
      '2' => 2
      '3' => 3
      '4' => 4
      '5' => 5
      '6' => 6
      '7' => 7
      '8' => 8
      '9' => 9
      _ =>
        raise AdapterError::InvalidField(
          record_number~,
          path~,
          detail="timestamp contains a non-digit",
        )
    }
    value = value * 10 + digit
  }
  value
}

///|
fn native_leap_year(year : Int32) -> Bool {
  year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

///|
fn native_month_days(month : Int32, year : Int32) -> Int32 {
  match month {
    2 => if native_leap_year(year) { 29 } else { 28 }
    4 | 6 | 9 | 11 => 30
    _ => 31
  }
}

///|
/// Accepts UTC `YYYY-MM-DDTHH:mm:ss[.fraction]Z` or Sysmon's UTC
/// `YYYY-MM-DD HH:mm:ss[.fraction]`. Fractions beyond milliseconds are
/// truncated only with an explicit lossy diagnostic returned to the caller.
fn native_utc_millis(
  text : String,
  path : String,
  record_number : Int32,
  require_z : Bool,
) -> (Int64, Bool) raise AdapterError {
  let bad = AdapterError::InvalidField(
    record_number~,
    path~,
    detail="expected UTC timestamp YYYY-MM-DDTHH:mm:ss[.fraction]Z",
  )
  if text.length() < 19 ||
    text[4] != '-' ||
    text[7] != '-' ||
    (text[10] != 'T' && text[10] != ' ') ||
    text[13] != ':' ||
    text[16] != ':' {
    raise bad
  }
  if require_z && text[10] != 'T' {
    raise bad
  }
  let year = native_digits(text, 0, 4, path, record_number)
  let month = native_digits(text, 5, 7, path, record_number)
  let day = native_digits(text, 8, 10, path, record_number)
  let hour = native_digits(text, 11, 13, path, record_number)
  let minute = native_digits(text, 14, 16, path, record_number)
  let second = native_digits(text, 17, 19, path, record_number)
  if year < 1970 ||
    year > 9999 ||
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > native_month_days(month, year) ||
    hour > 23 ||
    minute > 59 ||
    second > 59 {
    raise bad
  }
  let mut index = 19
  let mut fraction_digits = 0
  let mut millis = 0
  if index < text.length() && text[index] == '.' {
    index += 1
    let start = index
    for offset in index..<text.length() {
      if text[offset] < '0' || text[offset] > '9' {
        break
      }
      if fraction_digits < 3 {
        millis = millis * 10 +
          native_digits(text, offset, offset + 1, path, record_number)
      }
      fraction_digits += 1
      index = offset + 1
    }
    if index == start || fraction_digits > 9 {
      raise bad
    }
    for _ in fraction_digits..<3 {
      millis *= 10
    }
  }
  if require_z {
    if index + 1 != text.length() || text[index] != 'Z' {
      raise bad
    }
  } else if index != text.length() {
    raise bad
  }
  let mut days : Int64 = 0
  for prior_year in 1970..<year {
    days += if native_leap_year(prior_year) { 366 } else { 365 }
  }
  for prior_month in 1..<month {
    days += native_month_days(prior_month, year).to_int64()
  }
  days += (day - 1).to_int64()
  let seconds = days * 86400 +
    hour.to_int64() * 3600 +
    minute.to_int64() * 60 +
    second.to_int64()
  (seconds * 1000 + millis.to_int64(), fraction_digits > 3)
}
