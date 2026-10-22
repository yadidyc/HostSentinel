///|
#cfg(target="native")
fn required_file_option(args : Array[String], name : String) -> String raise {
  match option_value(args, name) {
    Some(path) if path.trim() != "" => path
    _ => fail("missing required option \{name}")
  }
}

///|
#cfg(target="native")
async fn read_cli_file(path : String) -> String {
  let file = @fs.open(path, mode=@fs.Mode::ReadOnly) catch {
    _ => fail("cannot read file: \{path}")
  }
  let data = @buffer.Buffer()
  for ;; {
    match file.read_some(max_len=65536) {
      Some(chunk) => data.write_bytes(chunk)
      None => break
    }
  }
  file.close()
  @utf8.decode(data.to_bytes()) catch {
    _ => fail("file is not valid UTF-8: \{path}")
  }
}

///|
#cfg(target="native")
async fn load_cli_rules(
  args : Array[String],
) -> Array[@core.CompiledCorrelationRule] {
  let path = required_file_option(args, "--rule-file")
  let source = read_cli_file(path)
  if !path.has_suffix(".yaml") &&
    !path.has_suffix(".yml") &&
    !path.has_suffix(".json") {
    fail("rule file must end in .json, .yaml or .yml: \{path}")
  }
  let rules = try {
    if path.has_suffix(".yaml") || path.has_suffix(".yml") {
      @core.compile_correlation_rules_yaml(source)
    } else {
      @core.compile_correlation_rules_json(source)
    }
  } catch {
    @core.CorrelationRuleError::Invalid(path=field, detail~) =>
      fail("invalid rule at \{field}: \{detail}")
  }
  if rules.is_empty() {
    fail("rule file has no correlation rules: \{path}")
  }
  rules
}

///|
#cfg(target="native")
async fn load_cli_events(args : Array[String]) -> Array[@core.HostEvent] {
  let path = required_file_option(args, "--events-file")
  let source = read_cli_file(path)
  let format = match option_value(args, "--format") {
    Some(value) => value
    None => "legacy"
  }
  if !["legacy", "ocsf", "sysmon", "windows", "auditd"].contains(format) {
    fail("unsupported event format: \{format}")
  }
  try {
    match format {
      "legacy" => {
        let result : Array[@core.HostEvent] = []
        let normalized = @core.normalize_jsonl(source)
        for event in normalized {
          result.push(@core.host_event_from_normalized(event))
        }
        result
      }
      "ocsf" => @core.normalize_ocsf_jsonl(source)
      "sysmon" => [@core.normalize_sysmon_xml(source)]
      "windows" => [@core.normalize_windows_security_xml(source)]
      "auditd" => {
        let host_id = required_file_option(args, "--host-id")
        @core.normalize_auditd_exec(source, host_id)
      }
      _ => fail("unsupported event format: \{format}")
    }
  } catch {
    @core.NormalizationError::InvalidJson(line_number~, ..) =>
      fail("invalid JSONL on line \{line_number}")
    @core.NormalizationError::ExpectedObject(line_number~, ..) =>
      fail("expected object on line \{line_number}")
    @core.NormalizationError::MissingField(line_number~, field~) =>
      fail("missing \{field} on line \{line_number}")
    @core.NormalizationError::InvalidField(line_number~, field~, ..) =>
      fail("invalid \{field} on line \{line_number}")
    @core.AdapterError::InvalidJson(record_number~, ..) =>
      fail("invalid adapter JSON on record \{record_number}")
    @core.AdapterError::ExpectedObject(record_number~) =>
      fail("expected adapter object on record \{record_number}")
    @core.AdapterError::MissingField(record_number~, path~) =>
      fail("missing \{path} on record \{record_number}")
    @core.AdapterError::InvalidField(record_number~, path~, detail~) =>
      fail("invalid \{path} on record \{record_number}: \{detail}")
    @core.AdapterError::Unsupported(record_number~, path~, value~) =>
      fail("unsupported \{path}=\{value} on record \{record_number}")
    _ => fail("event normalization failed: \{path}")
  }
}

///|
#cfg(target="native")
fn file_json_text(value : String) -> String {
  "\"\{json_escape(value)}\""
}

///|
#cfg(target="native")
fn file_json_optional(value : String?) -> String {
  match value {
    Some(text) => file_json_text(text)
    None => "null"
  }
}

///|
#cfg(target="native")
fn file_event_json(event : @core.HostEvent) -> String {
  let precision = match event.time.precision {
    @core.TimePrecision::Seconds => "seconds"
    @core.TimePrecision::Milliseconds => "milliseconds"
  }
  "{\"event_id\":\{file_json_text(event.id.as_string())},\"source\":\{file_json_text(source_token(event.source))},\"category\":\{file_json_text(event.category)},\"class\":\{file_json_text(event.class_name)},\"activity\":\{file_json_text(event.activity)},\"time\":\{event.time.value},\"precision\":\{file_json_text(precision)},\"host\":\{file_json_optional(event.identities.host.value())},\"boot\":\{file_json_optional(event.identities.boot.value())},\"session\":\{file_json_optional(event.identities.session.value())},\"process\":\{file_json_optional(event.identities.process.value())},\"dst_ip\":\{file_json_optional(event.network.dst_ip)},\"original_format\":\{file_json_text(event.original.format)},\"record_number\":\{event.original.record_number}}"
}

///|
#cfg(target="native")
fn file_grade(grade : @core.IdentityEvidenceGrade) -> String {
  match grade {
    @core.IdentityEvidenceGrade::Verified => "verified"
    @core.IdentityEvidenceGrade::Claimed => "claimed"
    @core.IdentityEvidenceGrade::Weak => "weak"
    @core.IdentityEvidenceGrade::Indeterminate => "indeterminate"
  }
}

///|
#cfg(target="native")
fn file_identity_status(status : @core.IdentityStatus) -> String {
  match status {
    @core.IdentityStatus::Missing => "missing"
    @core.IdentityStatus::Unknown => "unknown"
    @core.IdentityStatus::Unverified => "unverified"
    @core.IdentityStatus::Verified => "verified"
  }
}

///|
#cfg(target="native")
fn file_key_json(key : @core.CorrelationKeyEvidence) -> String {
  "{\"field\":\{file_json_text(key.field)},\"value\":\{file_json_text(key.value)},\"status\":\{file_json_text(file_identity_status(key.status))}}"
}

///|
#cfg(target="native")
fn file_result_json(result : @core.IdentityCorrelationResult) -> String {
  let keys = result.keys().map(file_key_json).join(",")
  "{\"type\":\"result\",\"rule_id\":\{file_json_text(result.rule_id())},\"rule_version\":\{result.rule_version()},\"event_ids\":[\{json_string_array(result.event_ids())}],\"sources\":[\{json_string_array(result.sources())}],\"group_key\":\{file_json_text(result.group_key())},\"keys\":[\{keys}],\"window_ms\":\{result.window_ms()},\"span_ms\":\{result.span_ms()},\"identity_grade\":\{file_json_text(file_grade(result.grade()))},\"mapping\":[\{json_string_array(result.mapping())}],\"explanation\":\{file_json_text(result.explanation())},\"dedup_key\":\{file_json_text(result.dedup_key())}}"
}

///|
#cfg(target="native")
fn file_diagnostic_json(
  rule_id : String,
  diagnostic : @core.IdentityCorrelationDiagnostic,
) -> String {
  "{\"type\":\"diagnostic\",\"rule_id\":\{file_json_text(rule_id)},\"event_ids\":[\{json_string_array(diagnostic.event_ids())}],\"reason\":\{file_json_text(diagnostic.reason())}}"
}

///|
#cfg(target="native")
fn output_mode(args : Array[String]) -> String raise {
  if has_flag(args, "--json") && has_flag(args, "--jsonl") {
    fail("choose either --json or --jsonl")
  }
  if has_flag(args, "--jsonl") {
    "jsonl"
  } else if has_flag(args, "--json") {
    "json"
  } else {
    "text"
  }
}

///|
#cfg(target="native")
async fn run_file_normalize(args : Array[String]) -> Unit {
  let mode = output_mode(args)
  let events = load_cli_events(args)
  let lines = events.map(file_event_json)
  match mode {
    "json" => println("[\{lines.join(",")}]")
    "jsonl" =>
      for line in lines {
        println(line)
      }
    _ => {
      println("normalize: events=\{events.length()}")
      for event in events {
        println(
          "event=\{event.id.as_string()} class=\{event.class_name} source=\{source_token(event.source)}",
        )
      }
    }
  }
}

///|
#cfg(target="native")
async fn run_rule_validate(args : Array[String]) -> Unit {
  let mode = output_mode(args)
  let rules = load_cli_rules(args)
  let ids = rules.map(rule => rule.id())
  if mode == "jsonl" {
    for rule in rules {
      println(
        "{\"rule_id\":\{file_json_text(rule.id())},\"version\":\{rule.version()}}",
      )
    }
  } else if mode == "json" {
    println("{\"valid\":true,\"rule_ids\":[\{json_string_array(ids)}]}")
  } else {
    println("rules validate: valid=\{rules.length()} ids=\{ids.join(",")}")
  }
}

///|
#cfg(target="native")
async fn run_file_correlation(args : Array[String], explain : Bool) -> Unit {
  let mode = output_mode(args)
  let rules = load_cli_rules(args)
  let events = load_cli_events(args)
  let lines : Array[String] = []
  let mut matches = 0
  for rule in rules {
    let report = @core.correlate_identity_safe(
      rule,
      events,
      max_events=if events.length() > 10000 { events.length() } else { 10000 },
      diagnostic=explain || has_flag(args, "--diagnostic"),
    )
    if report.results_truncated() || report.diagnostics_truncated() {
      fail("correlation output budget exceeded for rule \{rule.id()}")
    }
    for result in report.results() {
      matches += 1
      lines.push(file_result_json(result))
    }
    if explain || has_flag(args, "--diagnostic") {
      for diagnostic in report.diagnostics() {
        lines.push(file_diagnostic_json(rule.id(), diagnostic))
      }
    }
    if report.results().is_empty() && report.diagnostics().is_empty() && explain {
      lines.push(
        "{\"type\":\"diagnostic\",\"rule_id\":\{file_json_text(rule.id())},\"event_ids\":[],\"reason\":\"no candidate satisfied selectors and window\"}",
      )
    }
  }
  match mode {
    "json" => println("[\{lines.join(",")}]")
    "jsonl" =>
      for line in lines {
        println(line)
      }
    _ => {
      println(
        "correlate: events=\{events.length()} rules=\{rules.length()} matches=\{matches}",
      )
      for line in lines {
        println(line)
      }
    }
  }
}

///|
#cfg(target="native")
async fn run_file_correlate(args : Array[String]) -> Unit {
  run_file_correlation(args, false)
}

///|
#cfg(target="native")
async fn run_file_explain(args : Array[String]) -> Unit {
  run_file_correlation(args, true)
}

///|
#cfg(target="native")
async fn run_file_benchmark(args : Array[String]) -> Unit {
  let mode = output_mode(args)
  let start = @env.now()
  let rules = load_cli_rules(args)
  let events = load_cli_events(args)
  let mut matches = 0
  for rule in rules {
    let report = @core.correlate_identity_safe(
      rule,
      events,
      max_events=if events.length() > 10000 { events.length() } else { 10000 },
    )
    if report.results_truncated() {
      fail("benchmark result budget exceeded for rule \{rule.id()}")
    }
    matches += report.results().length()
  }
  let elapsed_ms = @env.now() - start
  let divisor = if elapsed_ms == 0 { 1UL } else { elapsed_ms }
  let throughput = events.length().to_double() * 1000.0 / divisor.to_double()
  let json = "{\"events\":\{events.length()},\"rules\":\{rules.length()},\"matches\":\{matches},\"elapsed_ms\":\{elapsed_ms},\"events_per_second\":\{throughput},\"peak_memory_bytes\":null}"
  if mode == "text" {
    println("benchmark: \{json}")
  } else {
    println(json)
  }
}
