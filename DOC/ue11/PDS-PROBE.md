# Probe：在没有新数据 ACK 时获取进度

Clear Command 依 §3.5.16.3 不产生 ACK。若源端已收到全部保证响应并发送 Clear，目的端的
CACK 会前移，但源端可能暂时不知道。这时对端 MP_RANGE 仍可能阻止新的数据 PSN。
`Probe.cpp` 在原 PDC 状态机中解决这个等待，不另建可靠通道。

## 数据 PSN 与 opaque 分开

依据 §3.5.16.5，Probe CP 使用 PSN=0、AR=1，**不分配新 PSN**。`ProbeAttempt` 记录的是
16 位 opaque、所需 SACK 基址、实际提交本次控制包的虚拟时间及重试数；它的定时器不进入
按数据 PSN 索引的 RTO 表。因此数据序号回绕到零时也不会与 Probe 混用。

opaque 由端点 `Services` 分配，跨本地 PDC ID 重用保持计数，零值合法。目的端将它原样复制
到 ACK 的 `ack_psn_offset`，并设置 P=1、REQ=0。这个字段此时是无符号 opaque，即使 C++
线格式容器使用有符号 offset，也必须按原 16 位解释。

源端只有收到当前 PDC 上匹配的 opaque、合法格式及不超出已发送范围的 CACK，才接收该回复。
P=1 时不能用 CACK+offset 当作数据 ACK_PSN。CACK、SACK、MP_RANGE 和识别出的拥塞反馈
仍然有效；SACK 依旧不代表语义成功，CACK 默认响应推断仍遵循严格高于的规则。

## 接收端生成 SACK

Probe 不访问 SES 或 MR，也不改变接收 PSN/CACK。即使是 ROD，也返回含 bitmap 的 ACK_CC。
可置位的状态来自已经完成的请求和保证响应缓存，不包含仍在 SES 处理中的请求。已覆盖的
有效 CACK 本身也可以置位。

本规范有基址规则的内部差异：一般 SACK 文字要求 8 对齐，而 §3.5.16.5 明确规定 Probe 使用
max(Probe.payload, CACK)。后者在 CACK 较大且未对齐时产生未对齐基址。本实现对逐包 ACK 使用
8 对齐规则，对 Probe 使用其专门条款的 max 规则，并按原样解释收到的基址。32 位比较采用模
序号比较。若请求要求的正向 offset 超出 ACK_CC 的有符号 16 位表示范围，目的端丢弃它；正常
MP_RANGE 的最大 32640 不需要这样的 offset。

未匹配已建立 PDC 的合法 Probe 被静默丢弃，不分配连接；这也避免将其 PSN=0 的 NACK 误认为
针对回绕后真实数据包的 NACK。携带非法 SYN 的控制包仍走已有头部错误处理。

## 何时发送与如何停止

默认 `enable_automatic_window_probes=true`。连接已建立、有排队数据且对端窗口阻塞时，原 PDC
调度器发 Probe。对端窗口仍未前移的有效回复，安排一次以基本 RTO 为间隔的后续唤醒，不在同一
虚拟时间循环发送。无回复时指数退避，按已有 `Max_RTO_Retx_Cnt` 限制重试；它是当前仿真策略。

诊断 Probe 失败本身不终止已经顺利完成的数据。若 Probe 耗尽且排队数据仍受窗口阻塞，则连接
以 RetryExhausted 终止。尚未获得 PSN 的排队消息也通过 RequestRejected 事件得到超时完成，
不能仅等待已经消失的连接再发布事件。释放连接会取消 Probe 定时器及迟到回调。

原生主机可对发起端 PDC 调用 `request_connection_probe(local_pdc_id, selective_base)`，返回值
表示是否接收该查询，不是应用消息完成。接收端 PDC 的共同协议内核也能处理 Probe；显式管理
API 当前只暴露发起端查询。

NSCC §3.6.13.7 的初始 base_rtt Probe 是 SHOULD，并允许在有可靠 RTT 配置时省略。目前实验
显式配置 base_rtt；不会声称已经实现自动初始 RTT 探测、尾丢失 EV 迁移或可选 ACK 合并。
匹配 Probe 的有效 NSCC ACK 可更新字节时钟和 RTT，重传样本仍遵循 Karn 过滤。

回归：

```sh
ctest --test-dir build/cmake -R 'pds_probe|pds_feedback|pds_mpr|selective_acknowledgment'
```

覆盖 RUD/ROD bitmap、opaque 的 0/1/0x8000、数据 PSN 零、错误/过期 opaque、未来 CACK、非法
REQ、独立 RTO 与销毁、未知 PDC、不依赖 Clear ACK 的连续 12 次事务、首次回复丢失恢复，以及
所有 Probe 回复永久丢失时排队操作的错误完成和内存不变性。
