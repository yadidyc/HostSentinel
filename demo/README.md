# HostSentinel Demo

这个 demo 使用仓库内固定的两条 JSONL 事件，展示完整的本地 CLI 入口。它不连接网络、不写入外部系统，也不会执行响应动作。

## PowerShell

在 `HostSentinel` 项目目录执行：

```powershell
$events = Get-Content demo/events.jsonl -Raw
moon run cmd/main -- hunt --event $events
moon run cmd/main -- response dry-run --alert-id demo-alert --event $events
```

## POSIX shell

```sh
events="$(cat demo/events.jsonl)"
moon run cmd/main -- hunt --event "$events"
moon run cmd/main -- response dry-run --alert-id demo-alert --event "$events"
```

## 预期结果

`hunt` 会规范化两条事件并输出两个指纹。`response dry-run` 使用第一条事件建立告警上下文，输出 `demo-alert`、`demo-host`、风险分数 `75`，以及按顺序排列的隔离主机和通知分析员两个 `would_execute` 步骤。

如果需要验证 demo 输入本身，可以直接运行端到端测试：

```sh
moon test e2e_test.mbt
```
