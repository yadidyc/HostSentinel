# HostSentinel 2.0 实施进度

依据本地 `任务说明.md`，按依赖顺序推进。状态仅表示已验证的交付；当前完成阶段 03。当前阶段的提交 ID 可在提交后运行 `git log -1 --format=%H -- docs/ocsf-mapping.md` 查询，避免在提交内容中写入无法自洽的自身哈希。

| 阶段 | 任务 | 状态 | 实际产出与验证 |
| --- | --- | --- | --- |
| 01 | 代码审计与现有测试基线 | Completed | `80c49e3`；[`v2-audit.md`](v2-audit.md)，全后端 40/40 测试通过。 |
| 02 | 通用事件模型与身份语义 | Completed | `9c972d3`；[`host_event.mbt`](../host_event.mbt)、[`host_event_test.mbt`](../host_event_test.mbt)、[`host-event-model.md`](host-event-model.md)；全后端 44/44 测试。 |
| 03 | OCSF 适配器 | Completed | [`ocsf_adapter.mbt`](../ocsf_adapter.mbt)、[`adapter_json.mbt`](../adapter_json.mbt)、[`ocsf_adapter_test.mbt`](../ocsf_adapter_test.mbt)、[`ocsf-1.9.0-supported.jsonl`](../fixtures/ocsf-1.9.0-supported.jsonl)、[`ocsf-mapping.md`](ocsf-mapping.md)；限定三类活动及结构化错误。 |
| 04 | Sysmon、Windows Event、auditd 适配器 | Pending | — |
| 05 | 规则 IR、Schema 与编译器 | Pending | — |
| 06 | Sigma 关联语义 | Pending | — |
| 07 | 通用身份安全关联引擎 | Pending | — |
| 08 | 旧版 session lead 迁移 | Pending | — |
| 09 | 五个可配置规则案例 | Pending | — |
| 10 | Benchmark 与实验报告 | Pending | — |
| 11 | CLI、文档与发布验收 | Pending | — |

阶段 03 的设计取舍：仅解析和验证明确列出的 OCSF 1.9.0 子集；未实现原生遥测或完整 Schema 校验，也不把来源声称的身份自动升级为已核验身份。
