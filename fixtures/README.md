# 测试 Fixtures

这些 JSONL 文件只包含固定、脱敏的离线事件，用于手工 demo、规则回放和回归测试：

| 文件 | 用途 | 预期关注点 |
| --- | --- | --- |
| `normal.jsonl` | 常规主机活动 | 可以规范化，不应仅凭输入本身产生恶意结论。 |
| `malicious.jsonl` | 两步高风险事件序列 | 可作为规则命中、时间窗口关联和风险评分的输入。 |
| `false-positive.jsonl` | 管理员活动样例 | 用于验证过宽规则的误报边界。 |
| `duplicate.jsonl` | 完全重复的同一事件 | 两行应产生相同指纹，关联层应保持去重。 |
| `session-lead-positive.jsonl` | Windows 登录、Sysmon 进程、代理网络 | 同会话、同进程实例生成一条线索。 |
| `session-lead-session-mismatch.jsonl` | 网络事件属于另一会话 | 返回 `session_mismatch`，不生成线索。 |
| `session-lead-pid-reuse.jsonl` | 相同 PID 的启动时间不同 | 返回 `process_instance_mismatch`，不生成线索。 |

Fixture 不包含真实主机名、凭据、令牌、私钥或生产数据。新增样例时保持固定时间戳和稳定 ID，避免快照因环境变化而漂移。

