# HostSentinel 关联规则子集

依据 [Sigma 官方关联文档](https://sigmahq.io/docs/meta/correlations.html)（2026-10-22 核对）。本实现只承诺所列子集，不声称完整 Sigma 兼容。阶段 05 已实现解析、JSON Schema 和编译期校验；阶段 06 已实现关联执行；阶段 07 已实现可复用的身份安全约束。

## 文件与验证

JSON 输入是规则文档数组，结构见 [`correlation-rules.schema.json`](../schema/correlation-rules.schema.json)。YAML 输入使用同样的文档结构，以独占一行的 `---` 分隔。基础规则使用 `detection.selection` 的字段等值合取及 `condition: selection`；关联规则用 `correlation`，以 `rules` 引用基础规则的 `name` 或 `id`。每个文档必须有非空 `id` 和正整数 `version`。`title` 仅为说明。新增文件不需要改编译器源码；运行时文件加载由后续 CLI 阶段接入。

```yaml
id: process_event
version: 1
detection:
  selection:
    class: process
  condition: selection
---
id: process_burst
version: 1
correlation:
  type: event_count
  rules:
    - process_event
  group-by:
    - host
  timespan: 1m
  condition:
    gte: 2
```

允许的事件字段：`host`、`boot`、`user`、`session`、`process`、`parent_process`、`source_id`、`source`、`category`、`class`、`activity`、`src_ip`、`dst_ip`、`protocol`。`group-by` 支持这些字段及别名；别名写为 `aliases: {virtual: {rule_name: physical_field}}`，每个被引用的基础规则都必须映射。`value_count` 必须在 `condition.field` 指定一个字段，表示不同取值数；其他类型不得指定该字段。计数比较符为 `gt/gte/lt/lte/eq/neq`，恰好一个；`temporal`/`temporal_ordered` 可省略条件，默认要求全部规则。`timespan` 支持正整数加 `s/m/h/d/w`，毫秒精度，拒绝溢出；月份和年份暂不支持。

YAML 适配器用 MoonBit 实现，只支持缩进映射、标量列表、纯标量、单/双引号字符串和整行注释；不支持内联集合、锚点、标签、复杂检测表达式、修饰符、通用 Sigma `logsource`、关联链或其他聚合类型。它不会默默忽略未知字段或将不支持的语义降级：编译器返回带字段路径的 `CorrelationRuleError`。Schema 做结构校验，编译器另查未知字段、类型、引用、循环、别名覆盖、阈值和时间窗。此限定使受支持规则在多来源 `HostEvent` 上有明确而可测试的含义。

## 执行语义（阶段 06）

`match_correlation_rule` 输入批量 `HostEvent`，直接匹配基础规则后按 `group-by` 分组；字段缺失时不生成该组的命中。`event_count` 统计去重事件，`value_count` 统计 `condition.field` 的不同**已出现**取值，`temporal` 要求不同事件分别满足不同基础规则，`temporal_ordered` 进一步要求规则顺序。`gt/gte/lt/lte/eq/neq` 比较窗口内的计数或命中规则数；时间单位统一为毫秒，秒级输入精确换算。对重复的同一事件 ID（同主机、同来源）只计一次；若相同键对应互相矛盾的记录则报错。输入乱序会按事件时间、稳定事件键、规则 ID 排序；等时间由该排序决定顺序。

实现采用**每条命中事件为起点的滑动窗口**，结束时刻包含在内，返回去重后的确定性见证。Sigma 文档中有后端固定时间桶示例；此处滑动窗口是明确的本地执行选择，**不能据此声称跨后端结果完全相同**。未指定 `group-by` 时按 Sigma 配置语义全局分组，可能跨主机；此时应使用阶段 07 的 `correlate_identity_safe`，而不是直接把阶段 06 的基础匹配当作身份安全告警。阈值必须是正整数；零命中窗口不会凭空生成结果。

## 身份安全约束（阶段 07）

在 `correlation.identity` 中配置 `same`（所有证据事件相同的身份字段）、`same-between`（仅指定基础规则角色之间相同）、`parent-child`（指定父规则的进程实例等于子规则的父进程实例，且子事件时间不早于父事件）、`sources`（`any`、`same`、`different`）和 `missing`（`reject`、`indeterminate`、`relaxed`）。`host` 总是加入 `same`，即使配置没有列出。可用身份字段是 `host/boot/user/session/process/parent_process/source_id`。例如登录→进程→网络链中，登录事件没有进程实例，可写 `same: [boot, session]` 与 `same-between: [{field: process, rules: [process_rule, network_rule]}]`；`group-by` 可用 `host + boot + process` 等复合键。进程实例必须由规范化输入显式提供，绝不由相同 PID 或时间接近臆造。

`reject` 是默认策略：缺失/未知身份不出结果，诊断模式可见原因。`indeterminate` 保留不可判定候选，**不是确证检测**；`relaxed` 只在规则明确指定时输出 `Weak` 证据。相等的来源声明身份若未独立核验，结果标记 `Claimed`，不会提升为 `Verified`；后者仅表示所有参与的身份值由调用方显式标记为已核验，**不证明事件来源标签真实**。身份值矛盾、父子关系矛盾和来源约束矛盾始终拒绝，不能靠 relaxed 放行。`group-by` 字段缺失的事件在候选形成前被排除，因此该字段不受缺失策略补救；需要诊断缺失时，应把该字段放入 `identity.same` 并避免同时用它分组。

批量入口 `correlate_identity_safe` 默认限制输入事件 10,000、候选 10,000、输出结果 1,000、拒绝诊断 100 条；可通过命名参数调整。超出事件/候选预算会报错，不静默丢弃；结果/诊断到达上限会标记 `results_truncated` / `diagnostics_truncated`。分组索引和窗口见证只在单次调用存活，调用返回即释放；尚无流式状态或跨调用持久化。结果解释包含规则 ID/版本、事件 ID、原始格式/记录号与来源标签、基础过滤依据、复合分组键、匹配身份键、窗口/实际跨度及证据等级；拒绝理由只在 `diagnostic=true` 时返回。旧 `session_lead` 路径仍独立，迁移属于阶段 08。
