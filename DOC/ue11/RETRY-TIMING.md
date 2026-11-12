# RTO 超时与 NACK 重传的时间

UE 1.1 §3.5.5、§3.5.12.7 和 §3.5.15.3 规定初始 RTO 可配置在 0～8 秒，
粒度为 128 ns 或更细；真正的 RTO 重试增加指数退避，NACK 则重启已有的 RTO
时长。本实现分别保存发送尝试计数和超时重试计数，避免两者混用。

`Services::rto_ns`、`TX_pkt_meta::retransmission_timeout_ns` 与 `RTOTimer` 的
`duration_ns` 都使用整数纳秒。PDS 使用 `startTimerNanoseconds`，支持 128 ns、
129 ns 等值，不再转换成整毫秒。`PdsHost::configure_retransmission_timeout` 在
建连前配置，并拒绝大于 8 秒的初始值。YAML 的顶层 `rto_ns` 使用同一范围，默认
仍为 1000000 ns。零表示当前发送时刻到期，不表示关闭可靠重传；有限重试上限
会终止没有得到确认的零超时请求。

## 两个计数的作用

| 状态 | 用途 |
|---|---|
| `retry_cnt` | 当前没有启用独立 NACK 上限，故所有 NACK/RTO 重传都计入共同上限。当前上限仍为固定 5，配置完整范围和无限模式待补。 |
| `timeout_retry_count` | 只在真正的 RTO 重传时增加，用于 `initial_rto_ns * 2^timeout_retry_count`。 |
| `RetryCause` | CMS 或资源不足时，保存该待重传由 Timeout 还是 NegativeAcknowledgment 触发；准入恢复后继续使用原原因。 |

例如初始 128 ns，NACK 导致一次重传后仍等待 128 ns；真正超时一次后等待
256 ns；再收到 NACK 后仍等待 256 ns。初始 8 秒的首次 RTO 重传等待 16 秒，
不会受旧毫秒实现的 10 秒上限截断。移位在运算前检查范围；无法表示的截止时刻
会报告 overflow，且保留先前有效的定时器。

兼容的 `RTOTimer::startTimer`/`updateRTO` 接口仍以毫秒为单位，保留原先的
零值拒绝语义；旧 startTimer 的 10 秒上限也仅存在于这一兼容边界。
`TimerItem::rto` 是兼容诊断字段，纳秒值向上取整后饱和到 16 位毫秒；协议不从
它读取时间。虚拟运行时不会读取 wall clock 或创建监控线程。

具备 MAC 时序的端口在首字节发出后启动 RTO。NACK 触发的替换尝试取消旧事件，
在 NIC 队列或 CMS 窗口等待期间不增加重试次数，也不把 NACK 转换成一次新的 RTO。
Probe 的独立计时同样使用纳秒；未变化窗口的再次查询至少间隔 1 ns，避免零时间
轮询。Probe 不占用数据 PSN 或数据重传槽。

`retry_timing_test` 覆盖精确时间边界、零值、8 秒到 16 秒的退避、溢出后的定时器
保持、NACK/RTO 混合序列、实际 MAC 通知、资源/CMS 延迟后的原因保存、共同重试
上限及 Probe 的 128 ns 重试。场景测试在无路由恢复中使用 50 μs RTO，要求在
100 μs 内完成，防止配置被悄悄量化成 1 ms。

按代码分组的 NACK 延迟、ACK 取消与 RUD/ROD 恢复见 [NACK 恢复](NACK-RECOVERY.md)。
完整重试上限配置、无限重试、所有 NACK/READ/TSS 组合及新 Start_PSN 恢复仍待验收。
