# HostSentinel

主机威胁狩猎与响应平台。当前版本提供事件规范化狩猎摘要，以及不会执行真实操作的响应计划 dry-run CLI。

## 开发

需要已安装 MoonBit 工具链：

```sh
moon fmt
moon check --deny-warn
moon run cmd/main -- --help
```

狩猎单条 JSONL 事件：

```sh
moon run cmd/main -- hunt --event '{"event_id":"evt-001","host_id":"host-001","hostname":"workstation-01","platform":"linux","kind":"process","source":"agent","severity":"high","observed_at":1725000000}'
```

生成响应计划 dry-run 报告：

```sh
moon run cmd/main -- response dry-run --alert-id alert-001 --event '{"event_id":"evt-001","host_id":"host-001","hostname":"workstation-01","platform":"linux","kind":"process","source":"agent","severity":"high","observed_at":1725000000}'
```

dry-run 只输出计划动作，不执行隔离、通知或其他主机操作。
