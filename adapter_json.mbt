///|
/// Diagnostics for schema-aware input adapters; paths refer to the raw input.
pub(all) suberror AdapterError {
  InvalidJson(record_number~ : Int32, raw~ : String)
  ExpectedObject(record_number~ : Int32)
  MissingField(record_number~ : Int32, path~ : String)
  InvalidField(record_number~ : Int32, path~ : String, detail~ : String)
  Unsupported(record_number~ : Int32, path~ : String, value~ : String)
} derive(Debug, Eq)

///|
pub extend AdapterError with Eq::{equal, not_equal}

///|
pub extend AdapterError with @debug.Debug::{to_repr}

///|
fn adapter_parse_object(
  raw : String,
  record_number : Int32,
) -> Json raise AdapterError {
  let value = @json.parse(raw) catch {
    _ => raise AdapterError::InvalidJson(record_number~, raw~)
  }
  guard value is { .. } else {
    raise AdapterError::ExpectedObject(record_number~)
  }
  value
}

///|
fn adapter_field(root : Json, path : String) -> Json? {
  let mut value = Some(root)
  for part in path.split(".") {
    value = match value {
      Some(parent) => json_field(parent, part.to_owned())
      None => None
    }
  }
  value
}

///|
fn adapter_required(
  root : Json,
  path : String,
  record_number : Int32,
) -> Json raise AdapterError {
  match adapter_field(root, path) {
    Some(Null) | None => raise AdapterError::MissingField(record_number~, path~)
    Some(value) => value
  }
}

///|
fn adapter_object(
  root : Json,
  path : String,
  record_number : Int32,
) -> Json raise AdapterError {
  let value = adapter_required(root, path, record_number)
  match value {
    Object(_) => value
    _ =>
      raise AdapterError::InvalidField(
        record_number~,
        path~,
        detail="expected object",
      )
  }
}

///|
fn adapter_text(
  root : Json,
  path : String,
  record_number : Int32,
) -> String raise AdapterError {
  match adapter_required(root, path, record_number) {
    String(value) if value.trim() != "" => value
    _ =>
      raise AdapterError::InvalidField(
        record_number~,
        path~,
        detail="expected non-empty string",
      )
  }
}

///|
fn adapter_optional_text(
  root : Json,
  path : String,
  record_number : Int32,
) -> String? raise AdapterError {
  match adapter_field(root, path) {
    None | Some(Null) => None
    Some(String(value)) if value.trim() != "" => Some(value)
    _ =>
      raise AdapterError::InvalidField(
        record_number~,
        path~,
        detail="expected non-empty string",
      )
  }
}

///|
fn adapter_parse_unsigned(
  text : String,
  path : String,
  record_number : Int32,
) -> Int64 raise AdapterError {
  if text == "" {
    raise AdapterError::InvalidField(
      record_number~,
      path~,
      detail="expected unsigned integer",
    )
  }
  let max_value : Int64 = 9223372036854775807
  let mut total : Int64 = 0
  for character in text {
    let digit : Int64 = match character {
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
          detail="expected unsigned integer",
        )
    }
    if total > (max_value - digit) / 10 {
      raise AdapterError::InvalidField(
        record_number~,
        path~,
        detail="integer overflow",
      )
    }
    total = total * 10 + digit
  }
  total
}

///|
fn adapter_unsigned(
  root : Json,
  path : String,
  record_number : Int32,
) -> Int64 raise AdapterError {
  match adapter_required(root, path, record_number) {
    Number(_, ..) as value =>
      adapter_parse_unsigned(value.stringify(), path, record_number)
    _ =>
      raise AdapterError::InvalidField(
        record_number~,
        path~,
        detail="expected integer number",
      )
  }
}

///|
fn adapter_int(
  root : Json,
  path : String,
  record_number : Int32,
) -> Int32 raise AdapterError {
  let number = adapter_unsigned(root, path, record_number)
  if number > 2147483647 {
    raise AdapterError::InvalidField(
      record_number~,
      path~,
      detail="integer exceeds Int range",
    )
  }
  number.to_int()
}

///|
fn adapter_optional_int(
  root : Json,
  path : String,
  record_number : Int32,
) -> Int32? raise AdapterError {
  match adapter_field(root, path) {
    None | Some(Null) => None
    Some(_) => Some(adapter_int(root, path, record_number))
  }
}

///|
fn adapter_claim(
  root : Json,
  path : String,
  record_number : Int32,
) -> Identity raise AdapterError {
  match adapter_field(root, path) {
    None => Identity::missing()
    Some(Null) => Identity::unknown()
    Some(String(value)) if value.trim() != "" =>
      try! Identity::unverified(value)
    _ =>
      raise AdapterError::InvalidField(
        record_number~,
        path~,
        detail="expected non-empty identity string",
      )
  }
}
