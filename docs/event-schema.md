# 事件 Schema

HostSentinel 的 MVP 交换格式是 JSONL：每个非空行是一个 JSON 对象。规范化入口为 `normalize_jsonl`；检测逻辑只消费规范化后的字段，不直接读取原始 JSON。

## 必填字段

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `event_id` | 非空字符串 | 事件的稳定标识。 |
| `host_id` | 非空字符串 | 产生事件的主机标识。 |
| `hostname` | 非空字符串 | 主机名，保留在规范化主机对象中。 |
| `platform` | 字符串 | `windows`、`linux`、`macos`，其他值归入 `Other`。 |
| `kind` | 字符串 | `process`、`file`、`network`、`authentication` 或 `persistence`。 |
| `source` | 字符串 | `agent`、`sysmon`、`auditd`、`windows_event`、`manual` 或其他来源。 |
| `severity` | 字符串 | `informational`、`low`、`medium`、`high` 或 `critical`。 |
| `observed_at` | Unix 秒或数字字符串 | 不得为负数的观测时间。 |

示例：

```json
{"event_id":"evt-001","host_id":"host-001","hostname":"workstation-01","platform":"linux","kind":"process","source":"agent","severity":"high","observed_at":1725000000}
```

多个对象可以直接按行拼接为 JSONL；空行会被跳过，单行 JSON 数组不会被当作事件批次接受。

## 规范化规则

- 文本字段会去除首尾空白；平台、类型、来源和严重性按不区分大小写的规范标签解析。
- `observed_at` 支持 JSON 数字和只包含数字的字符串，内部统一为 `ObservedAt`。
- `SecurityEvent` 保存事件 ID、主机 ID、类型、来源、严重性和时间；`NormalizedEvent` 另外保留行号、裁剪后的原始行、主机和指纹。
- 指纹由事件身份、主机信息、类型、来源、严重性及观测时间确定，同一规范化事件得到同一指纹，可用于去重和证据引用。
- 原始行只用于追踪和调查引用；不要把密码、令牌、私钥或真实生产数据放入 fixture。

## 错误定位

解析失败会返回带行号的 `NormalizationError`。常见错误包括 JSON 不是对象、缺少必填字段、事件类型或严重性不支持、时间戳无效。CLI 会把这类错误归纳为 `invalid JSONL input`；库调用方可以读取具体错误字段。

## 兼容边界

事件适配器可以先把 Windows Event、Sysmon 或 Linux audit 等来源映射到本 Schema，再调用规范化入口。采集器、文件读取、数据库写入和网络传输不属于当前核心包的职责。

## 会话线索扩展字段

`leads` / `hunt_session_leads` 使用上述基础 Schema，并对 `authentication`、`process`、`network` 事件额外要求：

| 字段 | 适用事件 | 含义 |
| --- | --- | --- |
| `boot_id` | 三类 | 主机启动周期标识；相同主机的不同启动周期不得关联。 |
| `session_id` | 三类 | 登录会话标识；不同会话不得关联。 |
| `pid` | process、network | 正整数进程 ID，可为 JSON 数字或数字字符串。 |
| `process_started_at` | process、network | Unix 秒；与 PID 一起识别进程实例，避免 PID 重用误连。 |

来源适配器负责把原始 Windows Event、Sysmon、auditd 或代理字段转换成这些标准字段；本版本 CLI 接收转换后的 JSONL，不直接解析原生事件格式。认证→进程→网络三段必须来自不同来源，同主机同启动周期、同会话、同进程实例，且时间递增并处于默认 90 秒窗口内。进程和网络事件还须各自至少为 `high` 严重性，避免普通登录/联网活动被当作线索。缺少身份字段会返回带行号和字段名的 `NormalizationError`；启动周期、会话、进程实例、来源、时间或信号不符会作为拒绝原因返回。正反例见 `fixtures/session-lead-*.jsonl`。现阶段不推断父子进程、文件持久化或真实攻击归因；秒级进程启动时间也无法排除同一秒内的 PID 重用，实际来源适配器应提供更细粒度的稳定实例身份。

