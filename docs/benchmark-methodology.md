# 关联实验方法（阶段 10）

`benchmark_test.mbt` 是可重复运行的 MoonBit 测试驱动。数据完全合成、生成顺序确定、无随机调用；四组各含登录、进程、网络事件，`bench-0` 为唯一阳性，另三组分别为跨启动、跨会话、PID 重用反例。其余事件均为不会进入三段规则的 file 噪声。各方法在**共同支持的三段场景**使用同一 JSONL 文本及 90 秒窗口；不将另外五个可配置场景并入三方法准确性分母。

方法分别为：`simple-host-window` 只检查主机、顺序和窗口；`legacy-session-api` 调用现有 `hunt_session_leads`；`configurable-identity` 用 `session-chain` 配置调用身份安全引擎。第 8 阶段起旧入口已委托新引擎，故它保留了固定三段输入/输出与拒绝语义，**不是重构前版本的独立性能基线**。三者都包含 JSONL 解析；可配置方法还包含 `HostEvent` 转换与规则编译，报告不把这些耗时剔除。每组只执行一次，不足以推断稳态性能或真实检测准确率。

在仓库根目录以本地工具链运行：

```powershell
$env:HOSTSENTINEL_BENCH_SIZE='1000'
moon test benchmark_test.mbt --index 0 -v --target native
$env:HOSTSENTINEL_BENCH_SIZE='10000'
moon test benchmark_test.mbt --index 0 -v --target native
$env:HOSTSENTINEL_BENCH_SIZE='100000'
moon test benchmark_test.mbt --index 0 -v --target native
moon test benchmark_test.mbt --index 1 -v --target native
```

最后一条在相同 1,000 条预规范化事件上分别评估 1、10、50 条不同 ID、相同语义的规则；编译不计入该项耗时。`BENCH_JSON`/`RULE_JSON` 行是机器可读原始输出，保存在 [`benchmark-results.json`](benchmark-results.json)。总事件数与吞吐按完整 JSONL 计算，耗时用 `@env.now()` 毫秒墙钟读取，零毫秒时吞吐分母按 1 毫秒下限处理。TP/FP/FN 按主机标签计数，Precision = TP/(TP+FP)，Recall = TP/(TP+FN)。

`peak_memory_bytes` 为 `null`：现有跨后端 MoonBit 核心接口没有进程峰值内存计数器，本轮未引入平台专用探针；**内存指标未完成，不得把 null 解读为 0**。对比只覆盖合成数据；未测来源伪造、真实日志分布、不同规则选择性、预热/重复运行、并发与流式状态。精确性能评估仍需进程级峰值内存采集与多次独立运行。
