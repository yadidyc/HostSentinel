///|
fn benchmark_case(index : Int32) -> Array[String] {
  let host = "bench-\{index}"
  let network_boot = if index == 1 { "boot-2" } else { "boot-1" }
  let network_session = if index == 2 { "S2" } else { "S1" }
  let network_started = if index == 3 { 115 } else { 110 }
  let auth =
    $|{"event_id":"auth-\{index}","host_id":"\{host}","hostname":"\{host}","platform":"windows","kind":"authentication","source":"windows_event","severity":"medium","observed_at":100,"boot_id":"boot-1","session_id":"S1"}
  let process =
    $|{"event_id":"process-\{index}","host_id":"\{host}","hostname":"\{host}","platform":"windows","kind":"process","source":"sysmon","severity":"high","observed_at":110,"boot_id":"boot-1","session_id":"S1","pid":42,"process_started_at":110}
  let network =
    $|{"event_id":"network-\{index}","host_id":"\{host}","hostname":"\{host}","platform":"windows","kind":"network","source":"agent","severity":"high","observed_at":120,"boot_id":"\{network_boot}","session_id":"\{network_session}","pid":42,"process_started_at":\{network_started}}
  [auth, process, network]
}

///|
fn benchmark_source(size : Int32) -> String {
  let lines : Array[String] = []
  for case_index in 0..<4 {
    for line in benchmark_case(case_index) {
      lines.push(line)
    }
  }
  for index in 12..<size {
    let noise =
      $|{"event_id":"noise-\{index}","host_id":"noise-\{index}","hostname":"noise","platform":"linux","kind":"file","source":"agent","severity":"low","observed_at":130}
    lines.push(noise)
  }
  lines.join("\n")
}

///|
fn benchmark_simple(source : String) -> Array[String] {
  let events = try! @hostsentinel.normalize_jsonl(source)
  let auths : Array[@hostsentinel.NormalizedEvent] = []
  let processes : Array[@hostsentinel.NormalizedEvent] = []
  let networks : Array[@hostsentinel.NormalizedEvent] = []
  for event in events {
    match event.event().kind() {
      @hostsentinel.EventKind::Authentication => auths.push(event)
      @hostsentinel.EventKind::Process => processes.push(event)
      @hostsentinel.EventKind::Network => networks.push(event)
      _ => ()
    }
  }
  let hosts : Array[String] = []
  for auth in auths {
    for process in processes {
      for network in networks {
        let host = auth.event().host_id()
        let a = auth.event().observed_at().unix_seconds()
        let p = process.event().observed_at().unix_seconds()
        let n = network.event().observed_at().unix_seconds()
        if process.event().host_id() == host &&
          network.event().host_id() == host &&
          a <= p &&
          p <= n &&
          n - a <= 90 &&
          !hosts.contains(host.as_string()) {
          hosts.push(host.as_string())
        }
      }
    }
  }
  hosts
}

///|
fn benchmark_legacy(source : String) -> Array[String] {
  let report = try! @hostsentinel.hunt_session_leads(source)
  let hosts : Array[String] = []
  for lead in report.leads() {
    let host = lead.host_id().as_string()
    if !hosts.contains(host) {
      hosts.push(host)
    }
  }
  hosts
}

///|
fn benchmark_configurable(source : String, size : Int32) -> Array[String] {
  let rule = scenario_rule("session-chain")
  let events : Array[@hostsentinel.HostEvent] = []
  let normalized = try! @hostsentinel.normalize_jsonl(source)
  for event in normalized {
    events.push(@hostsentinel.host_event_from_normalized(event))
  }
  let report = try! @hostsentinel.correlate_identity_safe(
    rule,
    events,
    max_events=size,
  )
  let hosts : Array[String] = []
  for result in report.results() {
    let ids = result.event_ids()
    if ids.length() == 3 {
      let host = result.group_key()
      if !hosts.contains(host) {
        hosts.push(host)
      }
    }
  }
  hosts
}

///|
fn benchmark_label(predictions : Array[String]) -> (Int32, Int32, Int32) {
  let mut tp = 0
  let mut fp = 0
  for host in predictions {
    if host == "bench-0" || host.contains("bench-0") {
      tp += 1
    } else {
      fp += 1
    }
  }
  let fn_count = if tp == 0 { 1 } else { 0 }
  (tp, fp, fn_count)
}

///|
fn benchmark_emit(
  method_name : String,
  size : Int32,
  elapsed_ms : UInt64,
  predictions : Array[String],
) -> Unit {
  let (tp, fp, fn_count) = benchmark_label(predictions)
  let precision = if tp + fp == 0 {
    0.0
  } else {
    tp.to_double() / (tp + fp).to_double()
  }
  let recall = tp.to_double()
  let duration = if elapsed_ms == 0 { 1UL } else { elapsed_ms }
  let throughput = size.to_double() * 1000.0 / duration.to_double()
  let line =
    $|BENCH_JSON {"method":"\{method_name}","events":\{size},"tp":\{tp},"fp":\{fp},"fn":\{fn_count},"precision":\{precision},"recall":\{recall},"elapsed_ms":\{elapsed_ms},"events_per_second":\{throughput},"peak_memory_bytes":null}
  println(line)
}

///|
test "benchmark comparison on labeled common three-stage cases" {
  let size = match @env.get_env_var("HOSTSENTINEL_BENCH_SIZE") {
    Some("10000") => 10000
    Some("100000") => 100000
    _ => 1000
  }
  let source = benchmark_source(size)
  let start_simple = @env.now()
  let simple = benchmark_simple(source)
  let simple_ms = @env.now() - start_simple
  let start_legacy = @env.now()
  let legacy = benchmark_legacy(source)
  let legacy_ms = @env.now() - start_legacy
  let start_configurable = @env.now()
  let configurable = benchmark_configurable(source, size)
  let configurable_ms = @env.now() - start_configurable
  assert_eq(benchmark_label(simple), (1, 3, 0))
  assert_eq(benchmark_label(legacy), (1, 0, 0))
  assert_eq(benchmark_label(configurable), (1, 0, 0))
  benchmark_emit("simple-host-window", size, simple_ms, simple)
  benchmark_emit("legacy-session-api", size, legacy_ms, legacy)
  benchmark_emit("configurable-identity", size, configurable_ms, configurable)
}

///|
fn benchmark_rule_set(
  count : Int32,
) -> Array[@hostsentinel.CompiledCorrelationRule] {
  let docs : Array[String] = [
    "{\"id\":\"login\",\"version\":1,\"detection\":{\"selection\":{\"class\":\"authentication\"},\"condition\":\"selection\"}}",
    "{\"id\":\"launch\",\"version\":1,\"detection\":{\"selection\":{\"class\":\"process\"},\"condition\":\"selection\"}}",
    "{\"id\":\"connect\",\"version\":1,\"detection\":{\"selection\":{\"class\":\"network\"},\"condition\":\"selection\"}}",
  ]
  for index in 0..<count {
    let rule =
      $|{"id":"scale-\{index}","version":1,"correlation":{"type":"temporal_ordered","rules":["login","launch","connect"],"group-by":["host"],"timespan":"90s","identity":{"same":["boot","session"],"same-between":[{"field":"process","rules":["launch","connect"]}],"sources":"different","missing":"reject"}}}
    docs.push(rule)
  }
  try! @hostsentinel.compile_correlation_rules_json("[" + docs.join(",") + "]")
}

///|
test "benchmark rule count scaling on same 1000-event corpus" {
  let events : Array[@hostsentinel.HostEvent] = []
  let normalized = @hostsentinel.normalize_jsonl(benchmark_source(1000))
  for event in normalized {
    events.push(@hostsentinel.host_event_from_normalized(event))
  }
  for count in [1, 10, 50] {
    let rules = benchmark_rule_set(count)
    assert_eq(rules.length(), count)
    let started = @env.now()
    let mut matches = 0
    for rule in rules {
      let report = @hostsentinel.correlate_identity_safe(rule, events)
      matches += report.results().length()
    }
    let elapsed_ms = @env.now() - started
    assert_eq(matches, count)
    let line =
      $|RULE_JSON {"events":1000,"rules":\{count},"matches":\{matches},"elapsed_ms":\{elapsed_ms},"peak_memory_bytes":null}
    println(line)
  }
}
