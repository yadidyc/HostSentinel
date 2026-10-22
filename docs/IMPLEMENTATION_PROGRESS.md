# HostSentinel 2.0 实施进度

依据本地 `任务说明.md`，按依赖顺序推进。状态仅表示已验证的交付；当前完成阶段 02。当前阶段的提交 ID 可在提交后运行 `git log -1 --format=%H -- docs/host-event-model.md` 查询，避免在提交内容中写入无法自洽的自身哈希。

| 阶段 | 任务 | 状态 | 实际产出与验证 |
| --- | --- | --- | --- |
| 01 | 代码审计与现有测试基线 | Completed | `80c49e3`；[`v2-audit.md`](v2-audit.md)，全后端 40/40 测试通过。 |
| 02 | 通用事件模型与身份语义 | Completed | [`host_event.mbt`](../host_event.mbt)、[`host_event_test.mbt`](../host_event_test.mbt)、[`host-event-model.md`](host-event-model.md)；旧 JSONL 兼容转换和缺失/未知/未核验身份测试。 |
| 03 | OCSF 适配器 | Pending | — |
| 04 | Sysmon、Windows Event、auditd 适配器 | Pending | — |
| 05 | 规则 IR、Schema 与编译器 | Pending | — |
| 06 | Sigma 关联语义 | Pending | — |
| 07 | 通用身份安全关联引擎 | Pending | — |
| 08 | 旧版 session lead 迁移 | Pending | — |
| 09 | 五个可配置规则案例 | Pending | — |
| 10 | Benchmark 与实验报告 | Pending | — |
| 11 | CLI、文档与发布验收 | Pending | — |

阶段 02 的设计取舍：新模型与旧接口并存；不把来源声称的身份自动升级为已核验身份，也不提前实现 OCSF 或原生遥测适配。
