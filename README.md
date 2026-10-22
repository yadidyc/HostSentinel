# HostSentinel

HostSentinel 是 MoonBit 实现的离线主机遥测规范化与身份安全关联工具。它把多来源事件映射为 `HostEvent`，用外部 JSON/YAML 规则构造关联候选，再核对主机、启动周期、会话、进程实例、父子关系和来源约束，输出可追溯证据与拒绝诊断。线索不等于攻击确认，来源声明身份也不等于独立核验。

仅按相同主机与时间窗口组合事件，可能把重启后的会话、重用的 PID 或不同进程误连。关联引擎要求规则明确约束身份；身份缺失默认拒绝，并标记证据等级。五套合成正反例见[案例说明](docs/correlation-fixtures.md)。

## 开始使用

安装 MoonBit 工具链后，在仓库根目录执行。文件型 CLI 依赖异步文件系统，命令包仅支持 native 目标；核心库仍可在四种后端构建与测试。原有 `hunt`、`ingest`、`leads`、`alerts`、`case`、`plan`、`explain --event` 和 `response dry-run` 在 native CLI 中仍可用：

```sh
moon fmt
moon check --target all --deny-warn
moon test --target all
moon run cmd/main -- --help
moon run cmd/main -- rules validate --rule-file fixtures/correlation/process-network.rules.yaml --json
moon run cmd/main -- normalize --events-file fixtures/correlation/process-network.positive.jsonl --format legacy --jsonl
moon run cmd/main -- correlate --rule-file fixtures/correlation/process-network.rules.yaml --events-file fixtures/correlation/process-network.positive.jsonl --format legacy --json
moon run cmd/main -- explain --rule-file fixtures/correlation/process-network.rules.yaml --events-file fixtures/correlation/process-network.negative.jsonl --format legacy --jsonl
```

此例的正例关联进程与网络事件；反例因 PID 重用导致进程实例不一致，`explain` 输出拒绝原因。命令使用本地文件而非内置规则。`--json` 返回数组或命令摘要，`--jsonl` 逐条输出；非法规则、记录或缺失文件返回诊断及非零退出码。`--format` 可选 `legacy`（默认）、`ocsf`、`sysmon`、`windows`、`auditd`；`sysmon` 和 `windows` 的 XML 输入为单条事件，auditd 还须传 `--host-id`。文件以 UTF-8 读取。

要新增检测场景，复制并修改[规则样例](fixtures/correlation/process-network.rules.yaml)，定义基础选择器、关联类型、分组/窗口及 `correlation.identity` 约束，然后用 `rules validate` 检查，再用 `correlate` 读取新的事件文件；无需修改或重编译 MoonBit 核心。字段、Schema 与限制见[规则指南](docs/correlation-rules.md)。支持 Sigma 风格的 `event_count`、`value_count`、`temporal`、`temporal_ordered` 子集，不是完整 Sigma 实现。OCSF 1.9.0 仅支持认证登录、进程启动、网络连接打开；原生输入仅支持 Sysmon 1/3、Windows Security 4624 和 auditd EXECVE 组。

## 复现实验与边界

按[实验方法](docs/benchmark-methodology.md)运行 1k/10k/100k 合成输入及 1/10/50 规则规模，核对[结果与原始 JSON](docs/benchmark-results.md)。`benchmark --rule-file <path> --events-file <path> --format <format> --json` 可以计时任意受支持的离线文件，但不生成真值标签；准确率对比应使用固定测试驱动。峰值内存尚未可靠采集，结果中的 `null` 不是零。

当前不支持完整 Sigma/OCSF、任意 Windows XML 或 auditd 记录、流式/持久化关联、来源真实性验证及实际主机响应；`response dry-run` 仅输出动作计划。完整输入、语义、输出与后端限制见[兼容性矩阵](docs/compatibility-matrix.md)。另见[架构](docs/ARCHITECTURE.md)、[事件模型](docs/host-event-model.md)、[运维](docs/OPERATIONS.md)及[旧 CLI Demo](demo/README.md)。
