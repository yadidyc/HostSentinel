# HostSentinel 2.0 实施进度

依据本地 `任务说明.md`，按依赖顺序推进。状态仅表示已验证的交付；本次只完成阶段 01，其他阶段尚未启动。阶段 01 的提交 ID 可在提交后运行 `git log -1 --format=%H -- docs/v2-audit.md` 查询，避免在提交内容中写入无法自洽的自身哈希。

| 阶段 | 任务 | 状态 | 实际产出与验证 |
| --- | --- | --- | --- |
| 01 | 代码审计与现有测试基线 | Completed | [`v2-audit.md`](v2-audit.md)；`moon fmt --check`、全后端严格检查/构建、全后端 40/40 测试、`moon info` 通过。 |
| 02 | 通用事件模型与身份语义 | Pending | — |
| 03 | OCSF 适配器 | Pending | — |
| 04 | Sysmon、Windows Event、auditd 适配器 | Pending | — |
| 05 | 规则 IR、Schema 与编译器 | Pending | — |
| 06 | Sigma 关联语义 | Pending | — |
| 07 | 通用身份安全关联引擎 | Pending | — |
| 08 | 旧版 session lead 迁移 | Pending | — |
| 09 | 五个可配置规则案例 | Pending | — |
| 10 | Benchmark 与实验报告 | Pending | — |
| 11 | CLI、文档与发布验收 | Pending | — |

阶段 01 的设计取舍：仅冻结和解释现状，不更改 MoonBit 代码、测试快照或公共 API；性能和标准适配缺口如实记录，不以推断数值充当实验结果。
