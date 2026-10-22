///|
fn rule_invalid(path : String, detail : String) -> CorrelationRuleError {
  CorrelationRuleError::Invalid(path~, detail~)
}

///|
fn rule_object(
  value : Json,
  path : String,
) -> Map[String, Json] raise CorrelationRuleError {
  match value {
    Object(fields) => fields
    _ => raise rule_invalid(path, "expected object")
  }
}

///|
fn rule_required(
  value : Json,
  key : String,
  path : String,
) -> Json raise CorrelationRuleError {
  match json_field(value, key) {
    Some(found) => found
    None => raise rule_invalid("\{path}.\{key}", "missing field")
  }
}

///|
fn rule_text(value : Json, path : String) -> String raise CorrelationRuleError {
  match value {
    String(text) if text.trim() != "" => text
    _ => raise rule_invalid(path, "expected non-empty string")
  }
}

///|
fn rule_positive_int(
  value : Json,
  path : String,
) -> Int32 raise CorrelationRuleError {
  let text = match value {
    Number(_, ..) => value.stringify()
    _ => raise rule_invalid(path, "expected positive integer")
  }
  let parsed = adapter_parse_unsigned(text, path, 0) catch {
    _ => raise rule_invalid(path, "expected positive integer")
  }
  if parsed == 0 || parsed > 2147483647 {
    raise rule_invalid(path, "expected positive Int32")
  }
  parsed.to_int()
}

///|
fn rule_allowed(
  value : Json,
  path : String,
  allowed : Array[String],
) -> Unit raise CorrelationRuleError {
  for key, _ in rule_object(value, path) {
    if !allowed.contains(key) {
      raise rule_invalid("\{path}.\{key}", "unsupported field")
    }
  }
}

///|
fn rule_string_list(
  value : Json,
  path : String,
) -> Array[String] raise CorrelationRuleError {
  guard value is Array(items) else {
    raise rule_invalid(path, "expected array")
  }
  let result : Array[String] = []
  for index, item in items {
    let text = rule_text(item, "\{path}[\{index}]")
    if result.contains(text) {
      raise rule_invalid(path, "duplicate item: \{text}")
    }
    result.push(text)
  }
  result
}

///|
fn rule_field_known(field : String) -> Bool {
  [
    "host", "boot", "user", "session", "process", "parent_process", "source_id",
    "source", "category", "class", "activity", "src_ip", "dst_ip", "protocol",
  ].contains(field)
}

///|
fn rule_base(
  value : Json,
  path : String,
  id : String,
  version : Int32,
) -> BaseEventRule raise CorrelationRuleError {
  let detection = rule_required(value, "detection", path)
  rule_allowed(detection, "\{path}.detection", ["selection", "condition"])
  let condition = rule_text(
    rule_required(detection, "condition", "\{path}.detection"),
    "\{path}.detection.condition",
  )
  if condition != "selection" {
    raise rule_invalid(
      "\{path}.detection.condition",
      "only the selection condition is supported",
    )
  }
  let selection = rule_required(detection, "selection", "\{path}.detection")
  let fields = rule_object(selection, "\{path}.detection.selection")
  if fields.is_empty() {
    raise rule_invalid("\{path}.detection.selection", "empty selection")
  }
  let predicates : Array[BaseFieldPredicate] = []
  for field, expected in fields {
    if !rule_field_known(field) {
      raise rule_invalid(
        "\{path}.detection.selection.\{field}",
        "unknown event field",
      )
    }
    predicates.push({
      field,
      value: rule_text(expected, "\{path}.detection.selection.\{field}"),
    })
  }
  { id, version, predicates, }
}

///|
fn rule_kind(
  value : Json,
  path : String,
) -> CorrelationRuleKind raise CorrelationRuleError {
  match rule_text(value, path) {
    "event_count" => CorrelationRuleKind::EventCount
    "value_count" => CorrelationRuleKind::ValueCount
    "temporal" => CorrelationRuleKind::Temporal
    "temporal_ordered" => CorrelationRuleKind::TemporalOrdered
    _ => raise rule_invalid(path, "unsupported correlation type")
  }
}

///|
fn rule_window(value : Json, path : String) -> Int64 raise CorrelationRuleError {
  let text = rule_text(value, path)
  if text.length() < 2 {
    raise rule_invalid(path, "invalid timespan")
  }
  let count_text = text[:text.length() - 1].to_owned()
  let count = adapter_parse_unsigned(count_text, path, 0) catch {
    _ => raise rule_invalid(path, "invalid timespan")
  }
  let multiplier : Int64 = match text[text.length() - 1] {
    's' => 1000
    'm' => 60000
    'h' => 3600000
    'd' => 86400000
    'w' => 604800000
    _ => raise rule_invalid(path, "unsupported timespan unit (s/m/h/d/w)")
  }
  if count == 0 || count > 9223372036854775807 / multiplier {
    raise rule_invalid(path, "invalid or overflowing timespan")
  }
  count * multiplier
}

///|
fn rule_condition(
  value : Json,
  path : String,
  kind : CorrelationRuleKind,
  rule_count : Int32,
) -> (CountOperator?, Int32?, String?) raise CorrelationRuleError {
  let raw = json_field(value, "condition")
  if raw is None {
    if kind == CorrelationRuleKind::EventCount ||
      kind == CorrelationRuleKind::ValueCount {
      raise rule_invalid("\{path}.condition", "count condition required")
    }
    return (None, None, None)
  }
  let condition = raw.unwrap()
  let fields = rule_object(condition, "\{path}.condition")
  rule_allowed(condition, "\{path}.condition", [
    "gt", "gte", "lt", "lte", "eq", "neq", "field",
  ])
  let mut operator : CountOperator? = None
  let mut threshold : Int32? = None
  for key, item in fields {
    let parsed : CountOperator? = match key {
      "gt" => Some(CountOperator::Gt)
      "gte" => Some(CountOperator::Gte)
      "lt" => Some(CountOperator::Lt)
      "lte" => Some(CountOperator::Lte)
      "eq" => Some(CountOperator::Eq)
      "neq" => Some(CountOperator::Neq)
      _ => None
    }
    if parsed is Some(op) {
      if operator is Some(_) {
        raise rule_invalid(
          "\{path}.condition",
          "exactly one comparison is required",
        )
      }
      operator = Some(op)
      threshold = Some(rule_positive_int(item, "\{path}.condition.\{key}"))
    }
  }
  if operator is None {
    raise rule_invalid(
      "\{path}.condition",
      "exactly one comparison is required",
    )
  }
  let field = match json_field(condition, "field") {
    Some(item) => Some(rule_text(item, "\{path}.condition.field"))
    None => None
  }
  if kind == CorrelationRuleKind::ValueCount && field is None {
    raise rule_invalid(
      "\{path}.condition.field",
      "value_count requires a field",
    )
  }
  if kind != CorrelationRuleKind::ValueCount && field is Some(_) {
    raise rule_invalid(
      "\{path}.condition.field",
      "field only applies to value_count",
    )
  }
  if kind == CorrelationRuleKind::Temporal ||
    kind == CorrelationRuleKind::TemporalOrdered {
    let n = threshold.unwrap()
    if n > rule_count {
      raise rule_invalid("\{path}.condition", "threshold exceeds rule count")
    }
  }
  (operator, threshold, field)
}

///|
fn rule_aliases(
  value : Json,
  path : String,
  references : Array[String],
) -> Array[FieldAlias] raise CorrelationRuleError {
  let aliases : Array[FieldAlias] = []
  match json_field(value, "aliases") {
    None => return aliases
    Some(raw) =>
      for name, mapping in rule_object(raw, "\{path}.aliases") {
        if name.trim() == "" {
          raise rule_invalid("\{path}.aliases", "empty alias name")
        }
        if rule_field_known(name) {
          raise rule_invalid(
            "\{path}.aliases.\{name}",
            "alias shadows an event field",
          )
        }
        let by_rule : Map[String, String] = Map([])
        for
          reference, field_value in rule_object(
            mapping,
            "\{path}.aliases.\{name}",
          ) {
          if !references.contains(reference) {
            raise rule_invalid(
              "\{path}.aliases.\{name}.\{reference}",
              "unknown rule reference",
            )
          }
          let field = rule_text(
            field_value,
            "\{path}.aliases.\{name}.\{reference}",
          )
          if !rule_field_known(field) {
            raise rule_invalid(
              "\{path}.aliases.\{name}.\{reference}",
              "unknown event field",
            )
          }
          by_rule[reference] = field
        }
        for reference in references {
          if !by_rule.contains(reference) {
            raise rule_invalid(
              "\{path}.aliases.\{name}",
              "missing mapping for \{reference}",
            )
          }
        }
        aliases.push({ name, mappings: by_rule, })
      }
  }
  aliases
}

///|
fn rule_virtual_field_known(
  field : String,
  aliases : Array[FieldAlias],
) -> Bool {
  if rule_field_known(field) {
    return true
  }
  for field_alias in aliases {
    if field_alias.name == field {
      return true
    }
  }
  false
}

///|
fn rule_identity_config(
  corr : Json,
  path : String,
  references : Array[String],
) -> (
  Array[String],
  Array[ScopedIdentityConstraint],
  IdentityMissingPolicy,
  SourceConstraint,
  Array[ParentChildLink],
) raise CorrelationRuleError {
  let raw = match json_field(corr, "identity") {
    Some(value) => value
    None =>
      return (
        ["host"],
        [],
        IdentityMissingPolicy::Reject,
        SourceConstraint::AnySource,
        [],
      )
  }
  rule_allowed(raw, path, [
    "same", "same-between", "missing", "sources", "parent-child",
  ])
  let same = match json_field(raw, "same") {
    Some(value) => rule_string_list(value, "\{path}.same")
    None => []
  }
  for field in same {
    if ![
        "host", "boot", "user", "session", "process", "parent_process", "source_id",
      ].contains(field) {
      raise rule_invalid("\{path}.same", "unknown identity field: \{field}")
    }
  }
  if !same.contains("host") {
    same.insert(0, "host")
  }
  let same_between : Array[ScopedIdentityConstraint] = []
  match json_field(raw, "same-between") {
    None => ()
    Some(Array(items)) =>
      for index, item in items {
        let item_path = "\{path}.same-between[\{index}]"
        rule_allowed(item, item_path, ["field", "rules"])
        let field = rule_text(
          rule_required(item, "field", item_path),
          "\{item_path}.field",
        )
        if ![
            "host", "boot", "user", "session", "process", "parent_process", "source_id",
          ].contains(field) {
          raise rule_invalid("\{item_path}.field", "unknown identity field")
        }
        let roles = rule_string_list(
          rule_required(item, "rules", item_path),
          "\{item_path}.rules",
        )
        if roles.length() < 2 {
          raise rule_invalid(
            "\{item_path}.rules",
            "at least two roles required",
          )
        }
        for role in roles {
          if !references.contains(role) {
            raise rule_invalid(
              "\{item_path}.rules",
              "unknown rule reference: \{role}",
            )
          }
        }
        same_between.push({ field, rules: roles, })
      }
    Some(_) => raise rule_invalid("\{path}.same-between", "expected array")
  }
  let missing_policy = match json_field(raw, "missing") {
    None => IdentityMissingPolicy::Reject
    Some(value) =>
      match rule_text(value, "\{path}.missing") {
        "reject" => IdentityMissingPolicy::Reject
        "indeterminate" => IdentityMissingPolicy::Indeterminate
        "relaxed" => IdentityMissingPolicy::Relaxed
        _ =>
          raise rule_invalid(
            "\{path}.missing",
            "expected reject/indeterminate/relaxed",
          )
      }
  }
  let source_constraint = match json_field(raw, "sources") {
    None => SourceConstraint::AnySource
    Some(value) =>
      match rule_text(value, "\{path}.sources") {
        "any" => SourceConstraint::AnySource
        "same" => SourceConstraint::SameSource
        "different" => SourceConstraint::DifferentSources
        _ =>
          raise rule_invalid("\{path}.sources", "expected any/same/different")
      }
  }
  let links : Array[ParentChildLink] = []
  match json_field(raw, "parent-child") {
    None => ()
    Some(Array(items)) =>
      for index, item in items {
        let item_path = "\{path}.parent-child[\{index}]"
        rule_allowed(item, item_path, ["parent", "child"])
        let parent = rule_text(
          rule_required(item, "parent", item_path),
          "\{item_path}.parent",
        )
        let child = rule_text(
          rule_required(item, "child", item_path),
          "\{item_path}.child",
        )
        if parent == child ||
          !references.contains(parent) ||
          !references.contains(child) {
          raise rule_invalid(
            item_path, "parent and child must be distinct referenced rules",
          )
        }
        links.push({ parent, child, })
      }
    Some(_) => raise rule_invalid("\{path}.parent-child", "expected array")
  }
  (same, same_between, missing_policy, source_constraint, links)
}

///|
fn rule_compile_correlation(
  value : Json,
  path : String,
  base_rules : Array[BaseEventRule],
  names : Map[String, Json],
) -> CompiledCorrelationRule raise CorrelationRuleError {
  let id = rule_text(rule_required(value, "id", path), "\{path}.id")
  let version = rule_positive_int(
    rule_required(value, "version", path),
    "\{path}.version",
  )
  let corr = rule_required(value, "correlation", path)
  rule_allowed(corr, "\{path}.correlation", [
    "type", "rules", "group-by", "timespan", "aliases", "condition", "identity",
  ])
  let kind = rule_kind(
    rule_required(corr, "type", "\{path}.correlation"),
    "\{path}.correlation.type",
  )
  let references = rule_string_list(
    rule_required(corr, "rules", "\{path}.correlation"),
    "\{path}.correlation.rules",
  )
  if references.is_empty() {
    raise rule_invalid(
      "\{path}.correlation.rules",
      "at least one base rule required",
    )
  }
  for reference in references {
    if !names.contains(reference) {
      raise rule_invalid(
        "\{path}.correlation.rules",
        "unknown rule reference: \{reference}",
      )
    }
    if !base_rules.map(item => item.id).contains(reference) {
      raise rule_invalid(
        "\{path}.correlation.rules",
        "chained correlations are not supported: \{reference}",
      )
    }
  }
  let group_by = match json_field(corr, "group-by") {
    None => []
    Some(raw) => rule_string_list(raw, "\{path}.correlation.group-by")
  }
  let aliases = rule_aliases(corr, "\{path}.correlation", references)
  for field in group_by {
    if !rule_virtual_field_known(field, aliases) {
      raise rule_invalid(
        "\{path}.correlation.group-by",
        "unknown event field: \{field}",
      )
    }
  }
  let window_ms = rule_window(
    rule_required(corr, "timespan", "\{path}.correlation"),
    "\{path}.correlation.timespan",
  )
  let (operator, threshold, value_field) = rule_condition(
    corr,
    "\{path}.correlation",
    kind,
    references.length(),
  )
  match value_field {
    Some(field) if !rule_virtual_field_known(field, aliases) =>
      raise rule_invalid(
        "\{path}.correlation.condition.field",
        "unknown event field",
      )
    _ => ()
  }
  let (
    same_identities,
    same_between,
    missing_policy,
    source_constraint,
    parent_child,
  ) = rule_identity_config(corr, "\{path}.correlation.identity", references)
  {
    id,
    version,
    kind,
    rule_ids: references,
    base_rules,
    group_by,
    aliases,
    window_ms,
    operator,
    threshold,
    value_field,
    same_identities,
    same_between,
    missing_policy,
    source_constraint,
    parent_child,
  }
}

///|
fn rule_detect_cycle(
  id : String,
  names : Map[String, Json],
  visiting : Map[String, Bool],
  visited : Map[String, Bool],
) -> Unit raise CorrelationRuleError {
  if visiting.contains(id) {
    raise rule_invalid("rules.\{id}.correlation.rules", "cyclic rule reference")
  }
  if visited.contains(id) {
    return
  }
  visiting[id] = true
  let value = names[id]
  match json_field(value, "correlation") {
    Some(corr) => {
      let refs = rule_string_list(
        rule_required(corr, "rules", "rules.\{id}.correlation"),
        "rules.\{id}.correlation.rules",
      )
      for reference in refs {
        if !names.contains(reference) {
          raise rule_invalid(
            "rules.\{id}.correlation.rules",
            "unknown rule reference: \{reference}",
          )
        }
        rule_detect_cycle(reference, names, visiting, visited)
      }
    }
    None => ()
  }
  visiting.remove(id)
  visited[id] = true
}

///|
/// Parses and compiles a JSON array of Sigma-subset base and correlation rules.
/// All validation runs before any correlation is returned.
///
/// # Example
/// ```mbt check
/// test {
///   let source =
///     #|[{"id":"p","version":1,"detection":{"selection":{"class":"process"},"condition":"selection"}},{"id":"c","version":1,"correlation":{"type":"event_count","rules":["p"],"timespan":"1m","condition":{"gte":2}}}]
///   let rules = @hostsentinel.compile_correlation_rules_json(source)
///   assert_eq(rules[0].id(), "c")
/// }
/// ```
pub fn compile_correlation_rules_json(
  source : String,
) -> Array[CompiledCorrelationRule] raise CorrelationRuleError {
  let value = @json.parse(source) catch {
    _ => raise rule_invalid("$", "invalid JSON")
  }
  rule_compile_documents(value)
}

///|
fn rule_compile_documents(
  value : Json,
) -> Array[CompiledCorrelationRule] raise CorrelationRuleError {
  guard value is Array(documents) else {
    raise rule_invalid("$", "expected array of rule documents")
  }
  let base_rules : Array[BaseEventRule] = []
  let correlations : Array[(Json, String)] = []
  let names : Map[String, Json] = Map([])
  for index, document in documents {
    let path = "$[\{index}]"
    rule_allowed(document, path, [
      "id", "name", "title", "version", "detection", "correlation",
    ])
    let id = rule_text(rule_required(document, "id", path), "\{path}.id")
    let version = rule_positive_int(
      rule_required(document, "version", path),
      "\{path}.version",
    )
    match json_field(document, "title") {
      Some(raw) => ignore(rule_text(raw, "\{path}.title"))
      None => ()
    }
    let reference = match json_field(document, "name") {
      Some(raw) => rule_text(raw, "\{path}.name")
      None => id
    }
    if names.contains(reference) || names.contains(id) {
      raise rule_invalid("\{path}.id", "duplicate rule reference")
    }
    names[reference] = document
    if reference != id {
      names[id] = document
    }
    let has_base = json_field(document, "detection") is Some(_)
    let has_corr = json_field(document, "correlation") is Some(_)
    if has_base == has_corr {
      raise rule_invalid(
        path, "exactly one of detection or correlation is required",
      )
    }
    if has_base {
      base_rules.push(rule_base(document, path, reference, version))
      if reference != id {
        base_rules.push(rule_base(document, path, id, version))
      }
    } else {
      correlations.push((document, path))
    }
  }
  let visiting : Map[String, Bool] = Map([])
  let visited : Map[String, Bool] = Map([])
  for name, _ in names {
    rule_detect_cycle(name, names, visiting, visited)
  }
  let compiled : Array[CompiledCorrelationRule] = []
  for (document, path) in correlations {
    compiled.push(rule_compile_correlation(document, path, base_rules, names))
  }
  compiled
}
