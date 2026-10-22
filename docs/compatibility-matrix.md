# HostSentinel 2.0 兼容性矩阵

本表仅承诺列明的子集。模块版本仍为 `0.1.0`；“2.0”是任务阶段名称，不是已发布的语义版本或标签。

| 领域 | 可用范围 | 不支持 / 限制 |
| --- | --- | --- |
| 旧事件 JSONL | `normalize_jsonl` 与 CLI `--format legacy` 转为 `HostEvent` | 不自动补造启动、会话或进程实例 ID；见[事件 Schema](event-schema.md) |
| OCSF | `normalize_ocsf_jsonl`，OCSF 1.9.0 的 Authentication Logon `3002/1`、Process Launch `1007/1`、Network Open `4001/1` | 其他版本、类、活动、完整 profile/扩展校验；认证类别本身不代表登录失败；见[字段映射](ocsf-mapping.md) |
| Sysmon | `normalize_sysmon_xml`，单条 Windows Event XML 的 Event ID 1/3 | 其他 Event ID、通用 XML、PID 推断为进程实例；见[原生遥测](native-telemetry.md) |
| Windows Security | `normalize_windows_security_xml`，单条 4624 XML | 4625 及其他事件、从登录记录推断进程实例 |
| auditd | `normalize_auditd_exec`，按完整 timestamp+serial 组装、成功 SYSCALL 对应的 EXECVE；调用者提供 host ID | 其他记录类型、PID 当实例 ID、从原始行推断主机或启动 ID |
| 规则文件 | JSON 文档数组或限定 YAML 文档；`rules validate --rule-file` 以编译器验证 | YAML 锚点、标签、内联集合；不是通用 YAML 或完整 Sigma 解析器 |
| 基础选择 | `detection.selection` 中已列字段的等值合取，`condition: selection` | Sigma 修饰符、嵌套布尔选择器、`logsource`、任意字段路径 |
| 关联 | `event_count`、`value_count`、`temporal`、`temporal_ordered`；`group-by`、字段别名、正整数阈值、`s/m/h/d/w` 时间窗；滑动窗口含端点 | 其他聚合、关联链、月/年窗口；不保证与其他 Sigma 后端固定桶结果相同 |
| 身份安全 | `identity.same`、`same-between`、`parent-child`、`sources`、`missing`；始终同主机；证据等级及拒绝诊断 | 伪造来源鉴别；仅凭相同 PID/用户名称认定同一实例/主体；缺失身份默认拒绝 |
| CLI 文件输入 | `normalize`、`rules validate`、`correlate`、`explain --rule-file`、`benchmark` 从本地文件读取；`--json`/`--jsonl`，错误非零退出 | 远程 URL、流式摄取、数据库/守护进程；`benchmark` 不计算真值准确率 |
| CLI 兼容 | 旧 `ingest/hunt/leads/alerts/case/plan/explain --event/response dry-run` 保留；`leads` 接受判定委托通用引擎 | 旧入口只处理固定会话三段，不是独立于新引擎的性能基线 |
| 库组合接口 | 规范化：`normalize_jsonl`→`host_event_from_normalized`、`normalize_ocsf_jsonl`、三个原生适配器；验证/编译：`compile_correlation_rules_json/yaml`；关联/解释：`correlate_identity_safe` 的结果、`explanation()` 与诊断 | 未另设 `validate_rule`/`explain` 同名包装 API；使用所列可组合入口 |
| 构建与运行 | 核心库 `native/js/wasm/wasm-gc` 检查与测试；CLI 包声明仅支持 native，文件级集成在 native 实测 | CLI 依赖本地异步文件系统，不能在 JS/wasm/wasm-gc 目标运行；不声称浏览器/沙箱具备文件权限 |
| 资源与响应 | 离线批处理，事件/候选/结果/诊断预算；超限报错或显式截断；响应仅 dry-run | 无持久化/流式状态、真实隔离/通知；[实验](benchmark-methodology.md)尚无可靠峰值内存值 |

文件式 `correlate`、`explain` 与 `benchmark` 对结果/诊断截断视为错误，不将部分输出冒充完整输出。详见[规则语义](correlation-rules.md)和[五套场景](correlation-fixtures.md)。
