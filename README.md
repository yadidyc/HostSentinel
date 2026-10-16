# HostSentinel

主机威胁狩猎与响应平台。当前版本提供事件规范化摘要、会话与进程身份约束的多来源候选线索，以及不会执行真实操作的响应计划 dry-run CLI。

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

追加 `--json` 可获得机器可读的规范化事件数组。

离线命令链还提供 `ingest`、`alerts`、`case`、`plan` 和 `explain` 入口；这些命令都从显式传入的 JSONL 重建上下文，不依赖数据库或常驻服务。

`leads` 将 Windows 登录、Sysmon 进程和代理网络事件按会话与进程实例连接为候选线索，并解释被拒绝的组合。输入需要额外的身份字段，格式见[事件 Schema](docs/event-schema.md)。

```sh
events="$(cat fixtures/session-lead-positive.jsonl)"
moon run cmd/main -- leads --event "$events" --json
```

同一组事件将返回 1 条线索；[会话不符](fixtures/session-lead-session-mismatch.jsonl)和 [PID 重用](fixtures/session-lead-pid-reuse.jsonl)样例均返回 0 条线索及具体拒绝原因。线索表示可复核的事件关系，不等同于确认攻击。

生成响应计划 dry-run 报告：

```sh
moon run cmd/main -- response dry-run --alert-id alert-001 --event '{"event_id":"evt-001","host_id":"host-001","hostname":"workstation-01","platform":"linux","kind":"process","source":"agent","severity":"high","observed_at":1725000000}'
```

dry-run 只输出计划动作，不执行隔离、通知或其他主机操作。
追加 `--json` 可获得机器可读的 dry-run 报告。

## Demo

仓库提供了可重复运行的 [CLI Demo](demo/README.md)，输入文件位于 `demo/events.jsonl`。

## 文档

- [架构说明](docs/ARCHITECTURE.md)
- [事件 Schema](docs/event-schema.md)
- [多来源检测语义与正反例](docs/DETECTION_SEMANTICS.md)
- [规则编写指南](docs/rule-authoring.md)
- [运维手册](docs/OPERATIONS.md)
