# OCSF 1.9.0 → HostEvent 映射（阶段 03）

本适配器读取 JSONL 中的 OCSF **1.9.0 限定子集**，不是通用 OCSF 校验器，也不将旧 `SecurityEvent` 改成 OCSF。官方依据：[类别 UID](https://raw.githubusercontent.com/ocsf/ocsf-schema/1.9.0/categories.json)、[Base Event](https://raw.githubusercontent.com/ocsf/ocsf-schema/1.9.0/events/base_event.json)、[Authentication](https://raw.githubusercontent.com/ocsf/ocsf-schema/1.9.0/events/iam/authentication.json)、[Process Activity](https://raw.githubusercontent.com/ocsf/ocsf-schema/1.9.0/events/system/process_activity.json)、[Network Activity](https://raw.githubusercontent.com/ocsf/ocsf-schema/1.9.0/events/network/network_activity.json) 及相应的 [metadata](https://raw.githubusercontent.com/ocsf/ocsf-schema/1.9.0/objects/metadata.json)、[process](https://raw.githubusercontent.com/ocsf/ocsf-schema/1.9.0/objects/process.json)、[session](https://raw.githubusercontent.com/ocsf/ocsf-schema/1.9.0/objects/session.json)、[user](https://raw.githubusercontent.com/ocsf/ocsf-schema/1.9.0/objects/user.json) 定义。

| 支持类 | `category_uid` | `class_uid` | `activity_id` | `type_uid` | 范围 |
| --- | ---: | ---: | ---: | ---: | --- |
| Authentication Logon | 3 | 3002 | 1 | 300201 | 仅登录请求，不含登出/票据活动 |
| Process Activity Launch | 1 | 1007 | 1 | 100701 | 仅进程启动，不含终止/注入 |
| Network Activity Open | 4 | 4001 | 1 | 400101 | 仅连接打开，不含流量/关闭 |

所有记录要求 `time` 为非负整型 **UTC 毫秒**，保留为 `EventTime::Milliseconds`；`type_uid` 必须等于 `class_uid * 100 + activity_id`。要求 `severity_id` 为官方枚举 0–6 或 99，99 时另要求 `severity` 文本。要求 `metadata.version == "1.9.0"`、`metadata.product.name`，以及 `metadata.uid` 或 `metadata.original_event_uid` 中至少一个可用作内部事件 ID；后两项是当前内部 ID 需要的**额外子集约束**，不是声称 OCSF 全体事件都强制这些字段。Process 还要求 `actor`、`device`、`device.type_id`、`process` 及至少一个 `process.uid/pid/cpid`；Authentication 要求 `user.uid` 或 `user.name` 及 `service` 或 `dst_endpoint`；Network 要求 `src_endpoint` 或 `dst_endpoint`。不支持的版本、类或活动会返回 `AdapterError::Unsupported`，缺失/类型错误返回含物理记录编号与原始字段路径的错误。

| 原始路径 | HostEvent 字段 | 映射与信息损失 |
| --- | --- | --- |
| `metadata.uid`，备选 `metadata.original_event_uid` | `id` | 非空字符串；原始 ID 优先写入 `original.record_id`。若两者都无则拒绝，不合成 ID。 |
| `metadata.log_source` | `source_id` | 有值时标为 `Unverified`；缺失保持 `Missing`，不能把产品名当采集器实例 ID。 |
| `time` | `time.value/precision` | 原样保留毫秒，不降精度到旧秒时间。 |
| `category_uid/class_uid/activity_id/type_uid/severity_id` | `ocsf` 及文字标签 | 五个数字保留；其他 OCSF 分类与可选信息仅保留于原文。 |
| `device.uid`，备选 `device.hostname` | `identities.host` | 来源声称，均为 `Unverified`；不存在则 `Missing` 并诊断。认证/网络中的 `dst_endpoint` 不自动当作发生事件的主机。 |
| `device.boot_uid` | `identities.boot` | 未提供则 `Missing`；不根据事件时间猜测。 |
| `user.uid`/`user.name` 或 `process.user.uid`/`process.user.name` | `identities.user` | 认证取 `user`；进程取 `process.user`；网络默认缺失。名称备选无法证明跨来源同一用户。 |
| `session.uid` 或 `process.session.uid` | `identities.session` | 认证/进程分别映射；其他保持缺失。 |
| `process.uid`、`process.parent_process.uid` | `identities.process/parent_process` | 即使是 UID 也只是来源声称，不自动升级 `Verified`；只有 PID 时进程实例仍缺失并诊断。 |
| `src_endpoint.ip/port`、`dst_endpoint.ip/port` | `network` | 端口限制 0–65535；其他 endpoint 属性不进入结构化字段，仍保留在 `original.raw`。 |
| 整条 JSONL 记录 | `original.raw/record_number` | 保存可定位的原文和物理行号；未知扩展字段未被丢弃，但不参与规则语义。 |

可复核原始输入见 [`fixtures/ocsf-1.9.0-supported.jsonl`](../fixtures/ocsf-1.9.0-supported.jsonl)。对应期望输出依序是 `(authentication, 3002, user-7, session-7)`、`(process_activity, 1007, process-guid-7, parent-guid-7)`、`(network_activity, 4001, 203.0.113.7:443)`；三条记录均以毫秒保存，身份证据是未核验声称。测试还覆盖版本、类别/活动、`type_uid`、缺字段、时间格式和行号错误。不解析外部 OCSF profile、扩展及全部对象约束；调用方不得把本子集适配结果解释为完整 OCSF 合规证明。
