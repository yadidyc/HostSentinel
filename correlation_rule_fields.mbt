///|
fn correlation_event_field(event : HostEvent, field : String) -> String? {
  match field {
    "host" => event.identities.host.value()
    "boot" => event.identities.boot.value()
    "user" => event.identities.user.value()
    "session" => event.identities.session.value()
    "process" => event.identities.process.value()
    "parent_process" => event.identities.parent_process.value()
    "source_id" => event.source_id.value()
    "source" => Some(source_token(event.source))
    "category" => Some(event.category)
    "class" => Some(event.class_name)
    "activity" => Some(event.activity)
    "src_ip" => event.network.src_ip
    "dst_ip" => event.network.dst_ip
    "protocol" => event.network.protocol
    _ => None
  }
}

///|
fn correlation_resolve_field(
  rule : CompiledCorrelationRule,
  rule_id : String,
  field : String,
) -> String {
  for field_alias in rule.aliases {
    if field_alias.name == field {
      match field_alias.mappings.get(rule_id) {
        Some(physical) => return physical
        None => return field
      }
    }
  }
  field
}

///|
fn correlation_group_key(
  rule : CompiledCorrelationRule,
  rule_id : String,
  event : HostEvent,
) -> String? {
  let parts : Array[String] = []
  for field in rule.group_by {
    let physical = correlation_resolve_field(rule, rule_id, field)
    match correlation_event_field(event, physical) {
      Some(value) =>
        parts.push("\{field.length()}:\{field}\{value.length()}:\{value}")
      None => return None
    }
  }
  Some(parts.join("|"))
}

///|
fn correlation_base_matches(base : BaseEventRule, event : HostEvent) -> Bool {
  for predicate in base.predicates {
    if correlation_event_field(event, predicate.field) != Some(predicate.value) {
      return false
    }
  }
  true
}

///|
fn correlation_time_ms(
  event : HostEvent,
  path : String,
) -> Int64 raise CorrelationRuleError {
  match event.time.precision {
    TimePrecision::Milliseconds => event.time.value
    TimePrecision::Seconds => {
      let max : Int64 = 9223372036854775
      let min : Int64 = -9223372036854775
      if event.time.value > max || event.time.value < min {
        raise rule_invalid(path, "seconds timestamp overflows milliseconds")
      }
      event.time.value * 1000
    }
  }
}

///|
fn correlation_compare_count(
  operator : CountOperator,
  actual : Int32,
  expected : Int32,
) -> Bool {
  match operator {
    CountOperator::Gt => actual > expected
    CountOperator::Gte => actual >= expected
    CountOperator::Lt => actual < expected
    CountOperator::Lte => actual <= expected
    CountOperator::Eq => actual == expected
    CountOperator::Neq => actual != expected
  }
}
