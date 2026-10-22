# 通用 HostEvent 模型（阶段 02）

`HostEvent` 与现有 `SecurityEvent` 并存。旧接口 `normalize_jsonl`、规则、关联和会话线索的输入输出均未改变；调用 `host_event_from_normalized` 可将一条既有 `NormalizedEvent` 转成新模型。反向转换尚未定义，后续适配器直接产生 `HostEvent`。

模型保留事件 ID、来源枚举及独立的 Source ID、带单位的事件时间、类别/类/活动标签、主机/启动/用户/会话/进程实例/父进程身份、网络属性、原始记录编号与文本、逐字段映射诊断。`EventTime.precision` 是 `Seconds` 或 `Milliseconds`，不隐式截断或乘算旧秒时间。标签暂非 OCSF UID；阶段 03 才建立规范映射。

身份采用 `Identity`：`Missing` 表示字段不存在，`Unknown` 表示来源明确给出空值或格式不可用，`Unverified(value)` 表示来源声称但未独立核验，`Verified(value)` 只能由明确承担信任判断的调用者构造。两个有值状态拒绝空串；不能用空串或单独 PID 当作匹配证据。

旧 JSONL 的 `host_id`、`boot_id`、`user_id`、`session_id`、`parent_process_id` 都只转成未核验声称。仅当启动 ID、PID 与创建时间均存在时才形成未核验的复合进程键；不把同 PID 推断为同进程。旧数据没有 Source ID 时保持 `Missing`，无网络字段时网络属性为空。原文中的无效身份字段记录 `Invalid` 诊断，不影响既有 `normalize_jsonl` 的解析契约。旧数据中的来源枚举并非来源真实性证明。

阶段 02 不引入 OCSF 或原生输入解析、不修改风险评分或关联行为；其新增类型是后续适配与身份安全关联的共同数据边界。
