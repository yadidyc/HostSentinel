# 多来源主机线索的检测语义

## 净核心机制

`hunt_session_leads` 处理的是“同一登录会话中的同一进程是否产生了可疑网络行为”，而不是把三个规则命中简单拼接。输入先经通用 JSONL 规范化，再读取[身份扩展字段](event-schema.md#会话线索扩展字段)：`host_id + boot_id + session_id`约束登录会话，`host_id + boot_id + pid + process_started_at`约束进程实例。三条证据必须分别是认证、进程、网络事件，`source` 标签互不相同，观测时间依次递增并落在默认 90 秒窗口内，进程和网络严重性均至少为 `high`。

这组条件解决两类简单时间关联无法排除的误连：同主机不同登录会话，以及 PID 被操作系统重用。身份、时间或独立来源任一条件不成立，分析器不会输出已核验线索，而会记录 `boot_mismatch`、`session_mismatch`、`process_instance_mismatch`、`source_not_independent`、`time_window_mismatch` 或 `insufficient_signal`。输入缺少关键身份字段时返回带行号与字段名的错误。输出中的证据保留事件 ID、来源、原始行号和指纹，三个证据按“认证→进程→网络”排列；结果是待人工确认的候选关系，不是攻击归因。

## 可复核案例

| 输入 | 实体关系 | 预期结果 |
| --- | --- | --- |
| [`session-lead-positive.jsonl`](../fixtures/session-lead-positive.jsonl) | Windows Event 登录 S7；Sysmon 进程 PID 42、启动时间 110，属于 S7；Agent 20 秒后报告同一进程联网 | 1 条线索，3 条不同来源的证据。 |
| [`session-lead-session-mismatch.jsonl`](../fixtures/session-lead-session-mismatch.jsonl) | 网络事件属于 S8 | 0 条线索，`session_mismatch`。 |
| [`session-lead-pid-reuse.jsonl`](../fixtures/session-lead-pid-reuse.jsonl) | 网络事件 PID 仍为 42，进程启动时间变为 115 | 0 条线索，`process_instance_mismatch`。 |

在仓库根目录运行 `moon run cmd/main -- leads --event "$(cat fixtures/session-lead-positive.jsonl)" --json`；将文件名换成另外两个夹具即可复核反例。`session_lead_test.mbt` 还覆盖重复事件、来源不独立、窗口超时、低严重性和缺失身份字段。

## 与已有项目的边界

[MoonForensics](https://github.com/jjyiiuy/moonforensics) 的申报范围是应用故障材料的通用时间线和候选关系；[Moon PolicyForge](https://mooncakes.io/docs/123123213weqw/moon_policyforge) 提供通用表达式求值与决策。HostSentinel 在主机域内将**会话和进程实例身份**作为关系成立的前提，并给出不能成立的反证。没有复制或移植上述项目代码。

当前输入须由调用方预先映射为标准 JSONL；本版本不直接读取原生 Sysmon XML、Windows Event 或 auditd 日志，不推断父子进程/文件持久化，不把线索自动转换成告警，也不执行响应动作。`source` 是输入声明的来源标签，互异性不等于来源真实性认证。秒级 `process_started_at` 也不能排除同一秒内的 PID 重用，真实适配器应提供更细粒度的进程实例标识。
