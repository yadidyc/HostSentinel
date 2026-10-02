///|
/// The supported indicator-of-compromise categories.
pub(all) enum IocKind {
  IpAddress
  Domain
  Url
  FileHash
  FilePath
  ProcessName
} derive(Debug, Eq)

///|
/// Errors raised while constructing an IOC indicator.
pub(all) suberror IocError {
  EmptyValue(kind~ : IocKind)
  InvalidFileHash(value~ : String)
} derive(Debug, Eq)

///|
/// A normalized indicator of compromise.
pub struct Indicator {
  kind : IocKind
  value : String
} derive(Debug, Eq)

///|
/// Creates an indicator after applying its category-specific normalization.
pub fn Indicator::new(
  kind~ : IocKind,
  value~ : String,
) -> Indicator raise IocError {
  let normalized = normalize_ioc_value(kind, value)
  if normalized == "" {
    raise IocError::EmptyValue(kind~)
  }
  if kind is IocKind::FileHash && !is_supported_hash(normalized) {
    raise IocError::InvalidFileHash(value~)
  }
  { kind, value: normalized, }
}

///|
/// Returns the indicator category.
pub fn Indicator::kind(self : Indicator) -> IocKind {
  self.kind
}

///|
/// Returns the normalized indicator value.
pub fn Indicator::value(self : Indicator) -> String {
  self.value
}

///|
/// Reports whether a candidate has the same normalized value and category.
pub fn Indicator::matches(self : Indicator, candidate : String) -> Bool {
  let normalized = normalize_ioc_value(self.kind, candidate)
  normalized != "" && normalized == self.value
}

///|
/// A successful IOC match with the original candidate value retained.
pub struct IocMatch {
  indicator : Indicator
  candidate : String
} derive(Debug, Eq)

///|
/// Returns the matched indicator.
pub fn IocMatch::indicator(self : IocMatch) -> Indicator {
  self.indicator
}

///|
/// Returns the candidate value supplied by the event adapter.
pub fn IocMatch::candidate(self : IocMatch) -> String {
  self.candidate
}

///|
/// Matches one indicator against one candidate value.
pub fn match_ioc(indicator : Indicator, candidate : String) -> IocMatch? {
  if indicator.matches(candidate) {
    Some({ indicator, candidate, })
  } else {
    None
  }
}

///|
/// Matches every indicator against one candidate while preserving indicator order.
pub fn match_iocs(
  indicators : Array[Indicator],
  candidate : String,
) -> Array[IocMatch] {
  let matches : Array[IocMatch] = []
  for indicator in indicators {
    if indicator.matches(candidate) {
      matches.push({ indicator, candidate, })
    }
  }
  matches
}

///|
fn normalize_ioc_value(kind : IocKind, value : String) -> String {
  let trimmed = value.trim().to_owned()
  match kind {
    IocKind::FilePath => trimmed.split("\\").join("/")
    IocKind::IpAddress
    | IocKind::Domain
    | IocKind::Url
    | IocKind::FileHash
    | IocKind::ProcessName => trimmed.to_lower()
  }
}

///|
fn is_supported_hash(value : String) -> Bool {
  let length = value.length()
  if length != 32 && length != 40 && length != 64 {
    false
  } else {
    for character in value; valid = true {
      if !valid {
        continue false
      }
      match character {
        '0'..='9' | 'a'..='f' => continue true
        _ => continue false
      }
    } nobreak {
      valid
    }
  }
}
