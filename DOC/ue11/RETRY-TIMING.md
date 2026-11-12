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
| `retry_cnt` | 当前没有启用独立 NACK 上限，故所有 NACK/RTO 重传都计入共同上限；同时用作本地发送尝试的身份。 |
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
所有 NACK/READ/TSS 组合及新 Start_PSN 恢复仍待验收。

## 重试上限与无限配置

`PdsHost::configure_retry_limit`、`Services::maximum_packet_retries` 和 YAML 顶层
`max_packet_retries` 使用规范 §3.5.5 的范围：0～14 是有限重传次数，15 表示无限，
默认5。0允许初始发送，但第一次需要重传时即失败。没有启用可选的独立 NACK
上限，所以两种重传原因共用预算；它们仍分别决定是否增加 RTO 指数。公共配置在
建连前完成，拒绝16、256等超范围值，不能先截断成窄整数再验证。

本地计数和 NIC `TransmitIdentity::attempt` 使用64位。配置15不会在第15次重试时
关闭，也不会在原16位计数边界回到0，破坏旧通知过滤或 Karn RTT 采样规则。
虚拟时间、指数退避时长或64位身份无法继续表示时，模拟器报告明确的 overflow；
它不会绕回旧时间/旧身份，也不会把表示上限解释为协议规定的失败次数。

Probe 不占用数据 PSN，当前模拟器策略采用同一个配置控制它自己的重试预算；
这是显式模拟策略。单独的诊断 Probe 失败不终止已成功的数据，但阻塞的数据若
一直等不到窗口恢复则会报错。无限设置同时适用于该 Probe 策略。

`retry_limit_test` 覆盖所有有限值0～14、NACK/RTO共同预算、超出15次后继续运行、
65535→65536边界的旧 NIC 通知过滤、计数表示溢出、Probe 配置，以及配置生命周期。
场景测试还检查上限0/1时实际 MAC 数据发送次数分别为1/2。
