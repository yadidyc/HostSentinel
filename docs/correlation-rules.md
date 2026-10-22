# HostSentinel 关联规则子集

依据 [Sigma 官方关联文档](https://sigmahq.io/docs/meta/correlations.html)（2026-10-22 核对）。本实现只承诺所列子集，不声称完整 Sigma 兼容。阶段 05 已实现解析、JSON Schema 和编译期校验；阶段 06 已实现关联执行；身份安全关联属阶段 07。

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

实现采用**每条命中事件为起点的滑动窗口**，结束时刻包含在内，返回去重后的确定性见证。Sigma 文档中有后端固定时间桶示例；此处滑动窗口是明确的本地执行选择，**不能据此声称跨后端结果完全相同**。未指定 `group-by` 时按 Sigma 配置语义全局分组，可能跨主机；阶段 07 将提供显式主机/身份约束。阶段 06 尚无候选预算和身份可信度门槛，不宜对大批量或高风险告警直接使用。
