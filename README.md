# HostSentinel

主机威胁狩猎与响应平台。当前版本只建立 MoonBit 模块、公共根包和最小可运行 CLI，后续功能将在独立提交中逐步加入。

## 开发

需要已安装 MoonBit 工具链：

```sh
moon fmt
moon check --deny-warn
moon run cmd/main
```

运行 CLI 后应输出项目名称和当前版本：

```text
HostSentinel v0.1.0
```
