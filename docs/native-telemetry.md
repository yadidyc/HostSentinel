# 原生主机遥测适配边界（阶段 04）

本阶段新增三条 MoonBit API：`normalize_sysmon_xml`、`normalize_windows_security_xml` 接收**单条** Windows Event XML；`normalize_auditd_exec` 接收多行 auditd 原始记录及调用者提供的非空 `host_id`，返回 EXECVE 事件组。三者都产出 `HostEvent`，保留原文、原始记录 ID 与可定位诊断；`ocsf` 字段为 `None`，不宣称原生记录本身符合 OCSF。现有 JSONL、规则、关联、CLI 均保持原状。

资料依据：[Microsoft Sysmon 事件说明](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)确认 Event ID 1 为 Process Create、ID 3 为 Network Connect 及两者的 ProcessGuid；[Microsoft Security 4624 事件 XML 和字段说明](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)确认登录的 `TargetUserSid`、`TargetLogonId`、`System.TimeCreated`、`EventRecordID`；[Red Hat Audit 日志格式说明](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)确认同一 audit 事件的多条记录共享 `msg=audit(timestamp:serial)` 键，[记录类型说明](https://docs.redhat.com/it/documentation/red_hat_enterprise_linux/6/html/security_guide/sec-audit_record_types)确认 `EXECVE` 记录和 `EOE` 含义。`fixtures/` 中的输入为按上述真实字段结构构造的**合成示例**，不是实采生产日志。

| 原始来源/路径 | 内部语义 | 约束与不可推断的信息 |
| --- | --- | --- |
| Sysmon XML `System.Provider/Channel/EventID/EventRecordID/Computer` | 来源、活动、事件 ID、主机、原始引用 | 只接收 Sysmon Operational 的 1/3；事件 ID 由主机+通道+记录号形成，不等同跨重启永久唯一 ID。 |
| Sysmon `EventData.UtcTime` | UTC 毫秒事件时间 | 严格 UTC 日历时间；若小数超过毫秒，截断并输出 `Lossy` 诊断。 |
| Sysmon `EventData.ProcessGuid/ParentProcessGuid/LogonGuid/User` | 进程、父进程、会话、用户声称 | `ProcessGuid` 可跨 1/3 对齐，但均标为 `Unverified`；缺失时不以 `ProcessId` 替代。原文 `ProcessId` 仍可追溯。无 `boot_id`。 |
| Sysmon 3 `SourceIp/SourcePort/DestinationIp/DestinationPort/Protocol` | 网络属性 | 端口必须是 0–65535；无连接的其他上下文不结构化提取。 |
| Security 4624 `System.TimeCreated/@SystemTime` | UTC 毫秒事件时间 | 原始 100ns 等更细精度会输出 `Lossy`；不从登录进程字段推断目标进程。 |
| Security 4624 `TargetUserSid/TargetLogonId` | 登录用户/会话声称 | `Subject*` 是操作者而非新登录主体；Logon ID 可重用，缺启动标识，不能单独跨来源确认会话。 |
| auditd `msg=audit(timestamp:serial)` | 同一事件的组装键、事件时间和原始 ID | 按**完整时间戳+serial** 分组，即使记录交错也不串组；仅有 `EXECVE` 且同组 `SYSCALL success=yes` 才生成启动事件。其他组忽略；有 EXECVE 但缺 SYSCALL、重复关键记录或失败状态则解释性报错。 |
| auditd `SYSCALL auid/ses/pid/ppid` | 用户/会话声称、进程诊断 | `4294967295`/`-1` 为未知用户；PID/PPID 不是进程实例 ID；原始 auditd 行没有主机和启动 ID，主机须由采集器提供且仍是未核验声称。 |

样例原始输入及期望：[`sysmon-process-create.xml`](../fixtures/sysmon-process-create.xml) → `process_activity/launch`、进程 `{proc-42}`；[`sysmon-network-connect.xml`](../fixtures/sysmon-network-connect.xml) → `network_activity/open`、相同进程声称及目标 `203.0.113.7:443`；[`windows-security-4624.xml`](../fixtures/windows-security-4624.xml) → `authentication/logon`、用户 `S-1-5-21-7`、会话 `0x7`、进程身份缺失；[`auditd-exec-group.log`](../fixtures/auditd-exec-group.log) → 仅 serial `100` 一条进程事件，serial `101` 的非执行 SYSCALL 被忽略，进程/启动身份缺失。测试还覆盖不支持 Event ID、端口越界、缺失 ProcessGuid、auditd 缺 SYSCALL 与交错 serial。

XML 解析器仅支持 Windows Event XML 的常见未加前缀标签、双引号属性、`<Data Name="…">` 和五种预定义 XML 实体；拒绝 DTD/实体声明，不是通用 XML 处理器。auditd 解析器支持空格分隔的头部及组键，不解码 `EXECVE` 的复杂引号/十六进制参数；原文仍保留。两者都不读取主机文件或联网、不做威胁判定或真实响应。后续阶段如需更多格式、时区、活动或精度，须显式扩展并补反例。
