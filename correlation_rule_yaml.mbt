///|
priv struct RuleYamlLine {
  indent : Int32
  text : String
  number : Int32
}

///|
fn rule_yaml_lines(
  source : String,
) -> Array[RuleYamlLine] raise CorrelationRuleError {
  let lines : Array[RuleYamlLine] = []
  for index, raw_view in source.split("\n") {
    let raw = raw_view.to_owned()
    let text = raw.trim().to_owned()
    if text == "" || text.has_prefix("#") {
      continue
    }
    let mut indent = 0
    while indent < raw.length() && raw[indent] == ' ' {
      indent += 1
    }
    if indent < raw.length() && raw[indent] == '\t' {
      raise rule_invalid("yaml:\{index + 1}", "tabs are not supported")
    }
    lines.push({ indent, text, number: index + 1, })
  }
  lines
}

///|
fn rule_yaml_scalar(
  text : String,
  path : String,
) -> Json raise CorrelationRuleError {
  if text == "" ||
    text.has_prefix("[") ||
    text.has_prefix("{") ||
    text.has_prefix("&") ||
    text.has_prefix("*") ||
    text.has_prefix("!") {
    raise rule_invalid(path, "unsupported YAML scalar")
  }
  if text.has_prefix("\"") {
    let parsed = @json.parse(text) catch {
      _ => raise rule_invalid(path, "invalid quoted scalar")
    }
    guard parsed is String(_) else {
      raise rule_invalid(path, "expected quoted string")
    }
    return parsed
  }
  if text.has_prefix("'") {
    if text.length() < 2 || text[text.length() - 1] != '\'' {
      raise rule_invalid(path, "invalid quoted scalar")
    }
    return Json::string(text[1:text.length() - 1].to_owned())
  }
  let mut all_digits = true
  for character in text {
    if character < '0' || character > '9' {
      all_digits = false
    }
  }
  if all_digits {
    let parsed = @json.parse(text) catch {
      _ => raise rule_invalid(path, "invalid numeric scalar")
    }
    guard parsed is Number(_, ..) else {
      raise rule_invalid(path, "expected numeric scalar")
    }
    return parsed
  }
  if text.contains(" #") {
    raise rule_invalid(path, "inline comments are not supported")
  }
  Json::string(text)
}

///|
fn rule_yaml_key_value(
  text : String,
  path : String,
) -> (String, String) raise CorrelationRuleError {
  let mut colon = -1
  for index in 0..<text.length() {
    if text[index] == ':' {
      colon = index
      break
    }
  }
  if colon <= 0 {
    raise rule_invalid(path, "expected key: value")
  }
  let key = text[:colon].trim().to_owned()
  let value = text[colon + 1:].trim().to_owned()
  if key == "" || key.contains(" ") {
    raise rule_invalid(path, "invalid YAML key")
  }
  (key, value)
}

///|
fn rule_yaml_block(
  lines : Array[RuleYamlLine],
  start : Int32,
) -> (Json, Int32) raise CorrelationRuleError {
  let indent = lines[start].indent
  if lines[start].text.has_prefix("- ") {
    let items : Array[Json] = []
    let mut index = start
    while index < lines.length() && lines[index].indent == indent {
      let line = lines[index]
      if !line.text.has_prefix("- ") {
        raise rule_invalid("yaml:\{line.number}", "mixed sequence and mapping")
      }
      items.push(
        rule_yaml_scalar(line.text[2:].trim().to_owned(), "yaml:\{line.number}"),
      )
      index += 1
    }
    return (Json::array(items), index)
  }
  let fields : Map[String, Json] = Map([])
  let mut index = start
  while index < lines.length() && lines[index].indent == indent {
    let line = lines[index]
    let path = "yaml:\{line.number}"
    let (key, text) = rule_yaml_key_value(line.text, path)
    if fields.contains(key) {
      raise rule_invalid(path, "duplicate YAML key: \{key}")
    }
    index += 1
    if text == "" {
      if index >= lines.length() || lines[index].indent <= indent {
        raise rule_invalid(path, "empty YAML block")
      }
      let (child, next) = rule_yaml_block(lines, index)
      fields[key] = child
      index = next
    } else {
      fields[key] = rule_yaml_scalar(text, path)
    }
  }
  (Json::object(fields), index)
}

///|
/// Converts the documented block-style YAML subset to the JSON rule IR and
/// applies the same schema and semantic validation. `---` separates rules.
pub fn compile_correlation_rules_yaml(
  source : String,
) -> Array[CompiledCorrelationRule] raise CorrelationRuleError {
  let lines = rule_yaml_lines(source)
  let documents : Array[Json] = []
  let mut start = 0
  while start < lines.length() {
    if lines[start].text == "---" {
      start += 1
      continue
    }
    if lines[start].indent != 0 {
      raise rule_invalid(
        "yaml:\{lines[start].number}",
        "document must start at column 1",
      )
    }
    let mut end = start
    while end < lines.length() && lines[end].text != "---" {
      end += 1
    }
    let part = lines[start:end].to_owned()
    let (value, consumed) = rule_yaml_block(part, 0)
    if consumed != part.length() {
      raise rule_invalid("yaml:\{part[consumed].number}", "invalid indentation")
    }
    documents.push(value)
    start = end
  }
  rule_compile_documents(Json::array(documents))
}
