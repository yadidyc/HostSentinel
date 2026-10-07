# HostSentinel 运维手册

## 1. 运行边界与安全约束

当前版本是本地 CLI 原型，不是常驻服务。它不会自动采集主机事件，不会写入数据库，也不会执行隔离主机、终止进程、阻断网络或通知操作。

`response dry-run` 的输出是计划模拟报告。只有在后续实现并明确接入真实执行器后，响应动作才可能产生外部副作用；在当前版本中，报告中的 `would_execute` 只表示该动作通过了计划构造。

## 2. 环境准备

需要可用的 MoonBit 工具链，并在项目目录 `HostSentinel` 下执行命令。建议先确认版本和帮助信息：

```sh
moon run cmd/main -- --version
moon run cmd/main -- --help
```

## 3. 日常验证

提交前执行格式化、静态检查和测试：

```sh
moon fmt
moon check --deny-warn
moon test
moon info
```

端到端测试可以单独运行：

```sh
moon test e2e_test.mbt
```

端到端快照是测试源文件中的 `debug_inspect` 内容。只有确认行为变化是预期结果时，才更新快照：

```sh
moon test e2e_test.mbt --update
```

更新后必须检查 `git diff`，确认快照没有包含随机值、机器路径或无关改动。

## 4. 狩猎工作流

`hunt` 接收 JSONL 文本，不接收文件路径。每行必须是对象，并包含：

| 字段 | 含义 | 示例 |
| --- | --- | --- |
| `event_id` | 事件唯一标识 | `evt-001` |
| `host_id` | 主机标识 | `host-001` |
| `hostname` | 主机名 | `workstation-01` |
| `platform` | `windows`、`linux`、`macos` 或其他值 | `linux` |
| `kind` | `process`、`file`、`network`、`authentication` 或 `persistence` | `process` |
| `source` | `agent`、`sysmon`、`auditd`、`windows_event`、`manual` 或其他值 | `agent` |
| `severity` | `informational`、`low`、`medium`、`high` 或 `critical` | `high` |
| `observed_at` | Unix 秒时间戳，也可传数字字符串 | `1725000000` |

示例：

```sh
moon run cmd/main -- hunt --event '{"event_id":"evt-001","host_id":"host-001","hostname":"workstation-01","platform":"linux","kind":"process","source":"agent","severity":"high","observed_at":1725000000}'
```

输出包括规范化事件数量、事件 ID、主机 ID、事件类型、严重性和指纹。输入错误时 CLI 输出 `hunt: invalid JSONL input`，具体字段诊断由库层的 `NormalizationError` 提供。

## 5. 响应计划 dry-run

`response dry-run` 使用规范化输入的第一条事件生成单事件告警上下文，默认告警 ID 为 `cli-alert`，也可以用 `--alert-id` 指定：

```sh
moon run cmd/main -- response dry-run --alert-id alert-001 --event '{"event_id":"evt-001","host_id":"host-001","hostname":"workstation-01","platform":"linux","kind":"process","source":"agent","severity":"high","observed_at":1725000000}'
```

报告包含告警 ID、主机 ID、风险分数、告警状态以及按计划顺序排列的动作。当前 CLI 会生成隔离主机和通知分析员两个模拟动作；两者均不会执行。

## 6. 故障处理

- `invalid JSONL input`：检查 JSON 是否为对象，确认字段齐全、枚举值受支持、时间戳不是负数。
- `no events supplied`：输入为空或只包含空行；为 dry-run 提供至少一条事件。
- 快照失败：先运行对应的单测确认是行为变化，再使用 `moon test e2e_test.mbt --update`，最后审阅 diff。
- 检查失败：只修复首个相关错误，然后重新运行 `moon fmt`、`moon check --deny-warn` 和受影响测试。

## 7. 发布前检查清单

1. `git status --short` 只包含本次预期改动。
2. `moon fmt` 和 `moon check --deny-warn` 通过。
3. `moon test` 通过，必要时补跑 `moon test e2e_test.mbt`。
4. `moon info` 通过，并确认没有意外的公共 API 变化。
5. 审阅 README、架构文档、运维文档和快照 diff。
6. 提交信息准确描述当前阶段，不把后续真实响应执行器混入本次提交。
