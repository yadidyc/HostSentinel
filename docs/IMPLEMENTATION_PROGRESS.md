# HostSentinel 2.0 实施进度

依据本地 `任务说明.md`，按依赖顺序推进。状态仅表示已验证的交付；当前完成阶段 07。当前阶段的提交 ID 可在提交后运行 `git log -1 --format=%H -- identity_correlation.mbt` 查询，避免在提交内容中写入无法自洽的自身哈希。

| 阶段 | 任务 | 状态 | 实际产出与验证 |
| --- | --- | --- | --- |
| 01 | 代码审计与现有测试基线 | Completed | `80c49e3`；[`v2-audit.md`](v2-audit.md)，全后端 40/40 测试通过。 |
| 02 | 通用事件模型与身份语义 | Completed | `9c972d3`；[`host_event.mbt`](../host_event.mbt)、[`host_event_test.mbt`](../host_event_test.mbt)、[`host-event-model.md`](host-event-model.md)；全后端 44/44 测试。 |
| 03 | OCSF 适配器 | Completed | `618670a`；[`ocsf_adapter.mbt`](../ocsf_adapter.mbt)、[`adapter_json.mbt`](../adapter_json.mbt)、[`ocsf_adapter_test.mbt`](../ocsf_adapter_test.mbt)、[`ocsf-1.9.0-supported.jsonl`](../fixtures/ocsf-1.9.0-supported.jsonl)、[`ocsf-mapping.md`](ocsf-mapping.md)；全后端 48/48 测试。 |
| 04 | Sysmon、Windows Event、auditd 适配器 | Completed | [`windows_event_xml.mbt`](../windows_event_xml.mbt)、[`auditd_adapter.mbt`](../auditd_adapter.mbt)、[`native_time.mbt`](../native_time.mbt)、[`native_adapter_test.mbt`](../native_adapter_test.mbt)、原始输入 fixtures、[`native-telemetry.md`](native-telemetry.md)；全后端 57/57 测试及严格检查/构建通过。 |
| 05 | 规则 IR、Schema 与编译器 | Completed | `00f3853`；[`correlation_rule_ir.mbt`](../correlation_rule_ir.mbt)、[`correlation_rule_compile.mbt`](../correlation_rule_compile.mbt)、[`correlation_rule_yaml.mbt`](../correlation_rule_yaml.mbt)、[`correlation_rule_compile_test.mbt`](../correlation_rule_compile_test.mbt)、[Schema](../schema/correlation-rules.schema.json)、[`correlation-rules.md`](correlation-rules.md)；全后端 62/62 测试。 |
| 06 | Sigma 关联语义 | Completed | `ab1fbbf`；[`correlation_rule_fields.mbt`](../correlation_rule_fields.mbt)、[`correlation_rule_match.mbt`](../correlation_rule_match.mbt)、[`correlation_rule_match_test.mbt`](../correlation_rule_match_test.mbt)；全后端 69/69 测试。 |
| 07 | 通用身份安全关联引擎 | Completed | [`identity_correlation.mbt`](../identity_correlation.mbt)、[`identity_correlation_test.mbt`](../identity_correlation_test.mbt)、规则 IR/Schema 扩展及 [`correlation-rules.md`](correlation-rules.md)；主机/启动/用户/会话/进程/父子/来源约束、缺失策略和预算测试。 |
| 08 | 旧版 session lead 迁移 | Pending | — |
| 09 | 五个可配置规则案例 | Pending | — |
| 10 | Benchmark 与实验报告 | Pending | — |
| 11 | CLI、文档与发布验收 | Pending | — |

阶段 07 的设计取舍：通用约束作为已编译规则的第二道判定，默认强制同主机且拒绝缺失身份；对来源声明身份只标记 `Claimed`。批量调用以事件/候选预算界定状态，结果与诊断可截断并显式标记。旧 `session_lead` 尚未迁移，留待阶段 08；原有 API 未删除。
