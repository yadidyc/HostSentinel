# HostSentinel 2.0：重构前关联能力审计

审计基准：`fcedc5e`（2026-10-22）；范围为现有 MoonBit 源码、测试、fixtures、CLI、README 与 CI。本文件记录现状和增量边界，不宣称已实现 HostSentinel 2.0。仓库外的申报书及未跟踪的 `任务说明.md` 不属于基准源码。

## 已有功能与可保留接口

| 层 | 已实现行为 | 依据 |
| --- | --- | --- |
| 事件模型 | `EventKind` 有进程、文件、网络、认证、持久化五类；`EventSource` 有 Agent、Sysmon、Auditd、WindowsEvent、Manual 和 Other。事件含主机、来源、严重性和 Unix 秒时间。 | [`model.mbt`](../model.mbt) |
| 规范化 | `normalize_jsonl` 解析非空 JSONL 行，校验 8 个基础字段，保留原始行、物理行号和确定性指纹；会话扩展字段仍留在原始 JSON。 | [`normalization.mbt`](../normalization.mbt)、[`event-schema.md`](event-schema.md) |
| IOC 与规则 | 六类 IOC；`RuleCondition` 支持类型、平台、来源、最低严重性、IOC，以及递归 `All`/`Any`；命中保留规则 ID、版本、事件指纹和条件证据。 | [`ioc.mbt`](../ioc.mbt)、[`rule.mbt`](../rule.mbt) |
| 通用关联 | `CorrelationPattern` 声明有序规则 ID 和正数秒窗口；`correlate` 将同主机的规则命中连接为 `Detection`，保留有序指纹并按键去重。 | [`correlation.mbt`](../correlation.mbt) |
| 会话线索 | `hunt_session_leads` 专门核验认证→进程→网络，输出三条原始事件证据或候选拒绝原因。 | [`session_lead.mbt`](../session_lead.mbt) |
| 下游能力 | 风险评分、告警状态转换、案件证据和审计轨迹、响应计划 dry-run 已有库 API；dry-run 不执行主机操作。 | [`risk_alert.mbt`](../risk_alert.mbt)、[`case.mbt`](../case.mbt)、[`response_plan.mbt`](../response_plan.mbt) |

这些 API、正反例和 CLI 命令是迁移时须保留或明确提供兼容层的现有成果。

## 两套关联逻辑的准确边界

`correlation.mbt` 接收调用方已构造的 `EventObservation`，从**输入数组顺序**的每个起点向后扫描，并贪心取每个后继规则的第一个合格命中。条件是相同 `host_id`、事件时间相对上一命中不倒退、末次相对起点不超过 `window_seconds`；相等时间及窗口终点均被包含。它不排序输入，不读取 `boot_id`、会话或进程身份，也不支持 `group-by`、计数、字段别名、缺失身份策略或外部规则文件。输入乱序时可能漏掉本可在时间排序后成立的序列。

`session_lead.mbt` 则重新解析规范化事件的 `raw_line`，按 `host_id + boot_id + session_id` 对齐会话，以 `host_id + boot_id + pid + process_started_at` 识别进程实例。三类事件的来源**标签**必须两两不同；`auth_at <= process_at <= network_at`，且 `network_at - auth_at <= 90` 秒（默认）；进程与网络严重性至少为 High。代码接受同秒事件和恰好 90 秒的边界，不要求输入行按时间排序。失败原因按启动周期、会话、进程实例、来源、时间、信号的固定优先级返回；身份字段缺失直接中止整批输入。现有测试覆盖正例、会话不符、PID 重用、重启、重复输入、同来源、超窗、低严重性和缺失字段。

两者职责确有交叠：都做同主机、时间窗、顺序和去重，但一个只认规则命中，一个固定三段身份语义，结果类型也不同。不能简单删除任一实现：通用关联尚无身份安全约束，专用线索尚无可配置规则。后续应抽取共享的关联键、时间窗、证据和去重语义，再通过兼容层保留现有 API 与反例行为。

## 局限与风险（按现有代码观察）

| 现状 | 影响或后续需要明确的决策 |
| --- | --- |
| `SecurityEvent` 只有宽泛类别和秒级时间；无来源 ID、用户/父进程身份、时间精度、原始映射诊断。会话字段只存于 JSONL 原文。 | 尚非通用 HostEvent，更不是 OCSF 对象；缺失/未知/无法核验需分开表示。秒级 `process_started_at` 不能消除同秒 PID 重用。 |
| 事件指纹由基础字段构成，不包含 `boot_id`、`session_id`、`pid` 或 `process_started_at`。 | 身份扩展不同的记录可有相同指纹；不宜单凭指纹作身份或原始记录唯一性证明。 |
| `correlate` 逐起点扫描后续数组；`hunt_session_leads` 枚举认证×进程×网络，并为每个同主机失败三元组保留拒绝记录；去重使用线性数组查找。 | 存在规模增长风险；当前无分组索引、候选/诊断预算、状态清理或最大结果限制。这里仅作复杂度观察，**没有实测性能结论**。 |
| `source` 是输入声明的枚举标签，不是来源真实性证明；`leads` 缺一项身份字段即整批报错。 | 弱关联和身份不确定性目前无表示，来源可信度需由适配层/调用方保证。 |
| CLI 从 `--event` 接收内联 JSONL；`alerts`、`case`、`explain`、`plan`/`response dry-run` 只取首条事件并构造固定 `cli-event` 上下文。 | CLI 尚不加载事件/规则文件，也不把 `leads` 自动变成告警；不能把演示链等同于通用关联工作流。 |
| CLI 对无效输入打印诊断后正常返回。 | 实测 `leads --event '{}' --json` 输出缺少 `event_id`，进程退出码仍为 `0`；后续 CLI 阶段须定义非零退出契约。 |

现有错误边界：`NormalizationError` 含行号及字段名（JSON 解析/非对象/缺失/无效字段），`RuleError` 和 `CorrelationError` 校验构造参数，`LeadRejectionReason` 表达可比较三元组的不成立原因；CLI 通常将库错误压缩为短文本。当前无 OCSF 原始字段路径诊断、外部规则语义校验或可配置的候选拒绝预算。

## Sigma 与 OCSF 规范核对（仅确定后续兼容范围）

[Sigma 官方关联文档](https://sigmahq.io/docs/meta/correlations)区分 `event_count`（事件数）、`value_count`（`condition.field` 的不同取值数）、`temporal`（规则命中共现）和 `temporal_ordered`（按规则顺序共现），并定义 `rules`、`group-by`、`timespan`、`aliases` 等配置语义。当前 `CorrelationPattern` 最接近一个**固定有序序列**，但没有 Sigma 文件解析、分组/别名、计数或完整条件校验，不能称为 Sigma 兼容。任务说明拟支持上述四种类型；其余官方类型不在第一版范围内，后续应写明所依据的文档版本和窗口边界语义。

[OCSF 1.9.0 发布版](https://github.com/ocsf/ocsf-schema/releases/tag/1.9.0)提供 [Authentication](https://github.com/ocsf/ocsf-schema/blob/1.9.0/events/iam/authentication.json)、[Process Activity](https://github.com/ocsf/ocsf-schema/blob/1.9.0/events/system/process_activity.json) 和 [Network Activity](https://github.com/ocsf/ocsf-schema/blob/1.9.0/events/network/network_activity.json) 类；[官方 FAQ](https://github.com/ocsf/ocsf-docs/blob/main/faqs/schema-faq.md)说明基础事件的分类字段与 `metadata` 要求。当前 `kind` 枚举与这些类并非一一等价，也没有 OCSF 分类/活动标识及 `metadata`；**尚未实现 OCSF 适配**。后续映射应固定版本、按官方类和对象定义逐字段核验必填性、时间单位、身份来源及信息损失，不根据名称猜测路径。

## 重构前测试、CLI 与性能基线

| 检查 | 结果 |
| --- | --- |
| 工具链 | Windows；隔离安装的 `moon 0.1.20261012` / `moonc 0.10.15`；模块 `yadidyc/hostsentinel`，首选 native。 |
| `moon fmt --check` | 通过，无源码改动。 |
| `moon check --target all --deny-warn` | 通过。 |
| `moon test --target all` | wasm、wasm-gc、js、native 各 40/40 通过。 |
| `moon build --target all --deny-warn` | 通过。 |
| `moon info`、`git diff --check` | 通过；生成的 `.mbti` 无差异。 |

测试文件涵盖模型、规范化、IOC、规则、关联、风险/告警、案件、dry-run、会话线索，以及 fixture 与端到端快照；`fixtures/` 有 normal、malicious、false-positive、duplicate 和三份会话线索正反例。`e2e_test.mbt` 直接调用库 API，不是启动 CLI 的进程级测试。现有测试没有证明乱序输入、精确窗口边界、大批量候选、外部规则、原生遥测或 OCSF 映射的契约。[CI](../.github/workflows/ci.yml)已有格式、默认目标检查/构建、全后端检查/测试及接口 diff；CI 当前没有 `--target all --deny-warn` 的构建步骤。

可复核 CLI 基线：`moon run cmd/main -- leads --event <fixtures/session-lead-positive.jsonl 的全文> --json` 返回 1 条线索、3 条证据、0 个拒绝；错误输入示例及退出码见上表局限。仓库目前没有 benchmark 脚本、固定规模生成器、吞吐/耗时/峰值内存原始结果，故**性能基线未建立**；不能将 40 个功能测试或这份小样例当作性能测量。

## 后续增量顺序（本提交均未实现）

按任务说明的依赖顺序：先建立带身份可信度/缺失语义的 HostEvent 与旧 API 转换；再固定 OCSF 子集版本与字段映射，接入有真实格式依据的 Sysmon、Windows Event、auditd；随后定义外部规则 IR/Schema 并实现四种 Sigma 风格关联；再把身份约束、窗口和证据管理抽成可复用引擎，迁移 `session_lead`；最后补跨场景正反例、可复现实验、文件输入 CLI 与兼容性文档。每一步须保留本基线中的既有接口或记录迁移差异，不提前声称标准全量兼容或真实响应能力。
