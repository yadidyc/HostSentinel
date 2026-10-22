# HostSentinel 关联规则子集

依据 [Sigma 官方关联文档](https://sigmahq.io/docs/meta/correlations.html)（2026-10-22 核对）。本实现只承诺所列子集，不声称完整 Sigma 兼容。阶段 05 已实现解析、JSON Schema 和编译期校验；关联执行、身份安全关联分别属阶段 06、07。

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
