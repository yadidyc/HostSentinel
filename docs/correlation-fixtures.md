# 五个可配置关联场景（阶段 09）

每个场景在 [`fixtures/correlation/`](../fixtures/correlation/) 中有独立的 `*.rules.json`、`*.positive.jsonl` 和 `*.negative.jsonl`。规则使用阶段 05–07 的通用编译器与身份安全引擎，没有按场景新增检测算法。输入是合成遥测，不代表真实攻击或准确率测量。

| 场景 / 独立测试索引 | 输入格式 | 正例期望（规则 ID → 证据事件 ID） | 反例与拒绝原因 |
| --- | --- | --- | --- |
| `session-chain` / 0 | 旧 JSONL | `session-chain` → `login-1`, `process-1`, `network-1` | 相同 PID、不同启动时间的进程实例：`process mismatch` |
| `auth-failures` / 1 | OCSF 1.9.0 | `auth-failures` → `failure-1`, `failure-2`, `failure-3` | 同主机/会话但跨重启：`boot mismatch` |
| `process-network` / 2 | 旧 JSONL | `process-network` → `process-1`, `network-1` | PID 重用：`process mismatch` |
| `parent-child` / 3 | OCSF 1.9.0 | `parent-child` → `parent-1`, `child-1` | 子进程声称的父进程 UID 不同：`parent-child mismatch` |
| `distinct-destinations` / 4 | OCSF 1.9.0 | `distinct-destinations` → `network-1`, `network-2`, `network-3` | 三个不同目标地址中有一个属于另一次启动：`boot mismatch` |

在仓库根目录独立运行任一案例：`moon test multi_scenario_test.mbt --index 0`，将索引换成表中 `0`–`4`；整组运行：`moon test multi_scenario_test.mbt`。该测试通过公共编译与关联 API 构造与输入文件等价的规范化事件，断言规则 ID、证据顺序、`Claimed` 身份等级及反例诊断。测试源码镜像了五份规则文本，不能把该组跨后端测试称作对磁盘文件的直接执行。阶段 11 另有 `cmd/main/file_cli_wbtest.mbt` 的 **native** 文件级集成测试，读取五套正反例与规则；修改规则文件时仍须同步更新镜像测试。

`auth-failures` 只选择 `metadata.log_source = failure-feed` 的认证遥测，**假定上游专用源只输出失败事件**；当前 OCSF 子集未解析认证成功/失败状态，不能凭通用 `authentication/logon` 类别推断失败。`parent-child` 的进程 UID、`session-chain` 的启动/会话/PID 等均是来源声明身份；命中只给 `Claimed`，不证明事件来源真实性。窗口含端点、离线批处理；这五个合成案例不是性能或误报率实验。
