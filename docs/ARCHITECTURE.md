# HostSentinel 架构说明

## 1. 当前定位

HostSentinel 是一个以 MoonBit 核心库为中心的主机威胁狩猎与响应平台原型。当前实现把输入、检测、调查和响应计划组织在同一个进程内，并通过 CLI 暴露三条可验证的工作流：

- `hunt`：把 JSONL 事件规范化并输出狩猎摘要。
- `leads`：对已映射身份字段的登录、进程与网络事件生成跨来源候选线索及拒绝原因。
- `response dry-run`：从事件建立告警上下文，生成响应步骤，但不执行主机操作。

当前版本没有常驻采集器、数据库、网络服务或真实响应执行器。CLI 与领域库之间没有隐式状态，调用方负责提供事件、规则、关联模式和响应计划。

可配置关联另有明确的包边界：`eventcorr` 只执行已分类事件的分组、含端点时间窗、计数及多角色序列匹配；根包将 `HostEvent` 与外部规则映射为通用 `Hit`，消费候选后再做主机身份安全校验。订单和服务监控的[独立消费测试](../examples/reuse/)只依赖 `eventcorr`，证明该内核不以主机字段为前提；契约和限制见[事件关联库说明](event-correlation-library.md)。下文的旧 `correlate`/`leads` 流程仍是兼容入口，不代表通用包自动理解所有原始日志。

## 2. 数据流

```text
JSONL
  -> 事件规范化
  -> IOC 候选匹配 / 规则评估
  -> 规则命中关联
  -> 风险评分与告警生命周期
  -> 案件证据与审计轨迹
  -> 响应计划 dry-run
  -> CLI 摘要或报告
```

每一步都接收明确的领域对象并返回新的结果对象。事件指纹、规则命中证据、检测去重键和审计序号用于保证结果可追踪；响应阶段只产生报告，不改变主机或告警状态。

## 3. 包结构

根包 `yadidyc/hostsentinel` 是领域库，`cmd/main` 是 CLI 可执行包。

`eventcorr` 是独立可导入的纯关联包，`examples/reuse` 是不导入根包的消费测试包。

| 文件 | 职责 |
| --- | --- |
| `model.mbt` | 主机、事件 ID、时间、事件类型、来源和严重性等基础值对象。 |
| `normalization.mbt` | 解析 JSONL，校验必需字段，创建 `NormalizedEvent` 并生成稳定指纹。 |
| `ioc.mbt` | 规范化 IOC 值并提供单个或批量 IOC 匹配。 |
| `rule.mbt` | 定义版本化规则、条件组合和 `RuleHit` 证据。 |
| `correlation.mbt` | 按主机、顺序和时间窗口把规则命中关联为 `Detection`。 |
| `eventcorr/` 与 `correlation_rule_match.mbt` | 通用候选窗口/计数/序列内核及主机事件到内核输入的适配。 |
| `session_lead.mbt` | 按启动周期、登录会话、进程实例及独立来源验证登录→进程→网络候选链。 |
| `risk_alert.mbt` | 根据关联事件严重性计算风险分数，并维护告警状态转换。 |
| `case.mbt` | 将告警绑定到案件，追加证据并记录有序审计轨迹。 |
| `response_plan.mbt` | 定义响应动作和计划，生成 `DryRunReport`。 |
| `cmd/main/main.mbt` | 解析 CLI 参数，组装领域库调用并打印面向操作人员的摘要。 |
| `*_test.mbt` | 黑盒单元测试、领域行为测试和 `e2e_test.mbt` 端到端 fixture/snapshot。 |

## 4. 核心契约

### 4.1 规范化

`normalize_jsonl` 对每个非空 JSONL 行要求以下字段：

`event_id`、`host_id`、`hostname`、`platform`、`kind`、`source`、`severity` 和 `observed_at`。

输出的 `NormalizedEvent` 同时保留源行、行号、主机、`SecurityEvent` 和指纹。指纹由事件身份、主机信息、事件分类、来源、严重性及 Unix 时间组成，可用于规则证据、检测去重和案件引用。

### 4.2 检测

规则条件支持事件类型、主机平台、事件来源、最低严重性、IOC，以及递归的 `All` / `Any` 组合。规则评估接收 IOC 候选值，返回带规则版本、事件指纹和解释性 evidence 的 `RuleHit`。

关联模式声明有序规则 ID 和时间窗口。`correlate` 只把同一主机、时间顺序正确且处于窗口内的命中组合为检测，并为检测生成稳定 `dedup_key`。

独立的 `hunt_session_leads` 接收扩展 JSONL：三种事件都需要 `boot_id`/`session_id`，进程与网络还需要 `pid`/`process_started_at`。只有三种来源互异、实体身份一致且顺序/窗口成立，才输出带三条原始事件引用的候选线索；可比较但不成立的组合返回拒绝原因。这一结果不自动转成告警，也不把时间关系解释为攻击因果。原生事件格式适配与父子进程/持久化关系仍是后续范围。

### 4.3 风险、告警和案件

风险分数取检测内最高事件严重性作为基础分，并按规则序列长度增加 bonus，最终限制在 0 到 100。告警从 `Open` 开始，推荐按 `Investigating`、`Contained`、`Resolved`、`Closed` 流转，并拒绝过期时间戳；`Acknowledged`、`InProgress` 和 `Suppressed` 保留用于兼容现有调用方。

案件以告警为根，证据按插入顺序保存；每次创建案件、追加证据或手动记录动作都会产生递增的审计序号。证据和审计时间不能早于案件已有的最新审计时间。

### 4.4 响应边界

响应计划只描述动作 ID、动作类型、目标和原因。`dry_run_response` 按声明顺序生成 `WouldExecute` 步骤，报告包含计划、告警、主机和动作信息；它不调用操作系统、不发网络请求，也不改变告警状态。

## 5. CLI 边界

CLI 是薄适配层，提供 `ingest`、`hunt`、`leads`、`alerts`、`case`、`plan`、`explain` 和 `response dry-run` 入口：

1. 从参数中取得 JSONL 文本和可选告警 ID。
2. 委托根包完成规范化、检测上下文及 dry-run 组装。
3. 只打印摘要和步骤，不复制领域规则。

`hunt` 会输出输入中的全部规范化事件；`response dry-run` 当前只使用规范化结果中的第一条事件构造单事件告警上下文。这一行为是当前 CLI 原型的明确边界，不代表后续多事件响应编排已经实现。
