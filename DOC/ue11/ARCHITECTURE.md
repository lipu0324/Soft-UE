# 从一次操作理解 Soft-UE 的分层

本实现用于观察 UE 的协议行为。先看应用语义如何经过 PDS，再区分网络事件和
完成事件，能避免把“报文被端口接收”误认为“远端内存已经可见”。完整目标见
[实施计划](ROADMAP.md)，已实现范围及缺口见 [实现状态](IMPLEMENTATION.md)。

```mermaid
flowchart LR
    Application[研究程序或场景] --> Endpoint[SES Endpoint]
    Endpoint --> Manager[PDS Manager]
    Manager --> PDC[IPDC / TPDC]
    PDC --> Codec[标准报文编码]
    Codec --> Port[非阻塞 PacketPort]
    Port --> Fabric[链路 / 队列 / 路由模型]
    Fabric --> Peer[远端 PDS / SES]
    Peer --> Memory[受检 MR / 稀疏内存]
    Memory --> Response[语义响应]
    Response --> Completion[发起端完成队列]
```

图中 CMS、TSS、LLR、CBFC/PFC 和后续 Profile 的完整路径尚未接入；不能由这张
已有路径图推断它们已经实现。UUD 没有图中的可靠返回响应路径。

## 每个模块负责什么

| 模块 | 负责的状态与决策 | 阅读入口 |
|---|---|---|
| 原生 SES | 操作 ID、消息分片、接收缓冲区、内存授权、应用完成 | `UET/src/SES/Endpoint.hpp` |
| 内存注册表 | JobID、PID、key、访问权限、边界、撤销、稀疏存储 | `UET/src/SES/MemoryRegistry.hpp` |
| 资源目录 | 相对 PID 映射、节点范围 PID、独立索引空间、generation 与启用状态 | `UET/src/SES/ResourceDirectory.hpp` |
| PDS Manager | 将报文分发到正确的端点/PDC 元组；分配和回收上下文 | `UET/src/PDS/PDS_Manager/PDSManager.hpp` |
| Initiator/Target PDC | 建连、PSN、ACK/NACK、重复消除、RTO、Clear/Close | `UET/src/PDS/PDC/` |
| Wire codec | 显式位宽、网络字节序、保留位、长度和 CRC；不决定重传 | `UET/src/Network_Layer/UetWireCodec.cpp` |
| PacketPort | 非阻塞发送结果、接收回调、背压解除通知 | `UET/src/Runtime/PacketPort.hpp` |
| Fabric | 串行化、传播延迟、出口队列、丢包、路由和链路状态 | `UET/src/Runtime/Fabric.hpp` |
| EventLoop | 整数纳秒时间、同一时刻事件的稳定顺序、定时器取消 | `UET/src/Runtime/Runtime.hpp` |

`PdsHost` 是运行适配器：把这些模块接到同一个事件循环。它不会代替 PDC 执行
可靠性恢复。仿真网络丢掉一个数据包时，恢复必须来自真实 PDC 的 NACK 或 RTO。

## 顺着 WRITE 的路径读代码

1. `Endpoint::submit()` 校验本地参数，分配操作 ID 与消息 ID，并拆成 SES 请求。
   `som/eom` 表示消息首尾，`message_offset` 表示片段在消息中的位置。
2. `PDS_Manager::SESTxReq()` 选择已有上下文或分配 IPDC。IPDC 为数据包分配 PSN，
   保存重传状态并启动注入的定时器；仿真模式不启动协议线程。
3. `PdsHost::pump()` 取出 PDS 报文，经过标准 codec 和 PacketPort 送入网络模型。
   `WouldBlock` 表示端口没有接收报文，必须等待可写通知；不能靠零时间轮询重试。
4. 远端先校验编码、CRC 和端点/PDC 身份，再由 TPDC 执行对应投递模式。
5. 远端 SES 检查 JobID、MR key、权限和整个操作的地址范围。收到的地址是模型中的
   地址或偏移，不能转换为进程指针。有效片段写入稀疏存储。
6. 全部片段处理后，SES 生成语义响应。保证交付的响应由 PDC 保存，直到对端 Clear。
   发起端收到响应后，才产生可靠操作的应用完成。

PDS 会把响应关联到原始 PSN。收到中间片段的默认响应只确认该片段，不能提前完成
整条消息；EOM 已发送且所有已发送片段都有明确或合法推断的正向语义结果后，才报告成功。
SACK 只证明交付，CACK 严格高于某包 PSN 时才允许推断其 DEFAULT，详见
[PDS-SACK.md](PDS-SACK.md)。RUD 的显式全长响应可能随最后补齐缺口的包返回。应用先收到错误时，消息 ID 仍保持租约，直到
剩余片段发送并被本地 Clear 覆盖，或上下文终止，防止迟到报文混入重用后的消息。

相对寻址先用 JobID 和相对 PID 选择资源；绝对寻址直接选择节点范围 PID。两者的
buffer_offset 都是受检区域内的偏移。注册应用真实缓冲区只发生在本地 API，远端
无法指定主机指针。libfabric 适配器的进程路径见 [PROVIDER.md](PROVIDER.md)。

WRITE immediate 的 `header_data` 随消息保存；全部数据落地后产生单独的远端完成。
普通 WRITE 不消耗 SEND 的接收缓冲区。非取回原子操作经过同一条路径，原子扩展头
位于 SES 基础头与 payload 之间，每个元素在单线程事件循环中不可分割地更新。

## 关键变量与不变量

| 名称 | 含义与约束 |
|---|---|
| `tx_cur_psn` | 下一次发送要分配的 PSN；不是最后已发送的 PSN。 |
| `clear_psn` | 发起端已经收到所需响应、可通知对端清理的连续 PSN 上界。 |
| `rx_cur_psn` | 接收端连续收到的 PSN 上界；RUD 不能因收到更大的 PSN 而跳过缺口。 |
| `cack_psn` | 连续处理完成、且保证交付响应已被 Clear 的 PSN 上界。 |
| `received_rx_psns_` | RUD 接收窗口中的到达记录，用于去重和推进连续接收边界。 |
| `completed_rx_psns_` | 已完成语义处理并允许推进 CACK 的记录，与“收到报文”分开。 |
| `tx_ack_buffer` | 尚未被 Clear 的保证交付响应；重传请求应重放响应，不能重做原子副作用。 |
| `unack_cnt` | 当前未确认包的数量。选择性确认后，数量与 PSN 区间长度可能不同。 |

PSN 是 32 位循环序号。比较使用相对于已知边界的无符号距离，并保持有效窗口小于
半个序号空间；普通整数大小比较无法处理回绕。线上 `clear_psn_off` 是 **有符号**
16 位数，按 §3.5.11.4.3 使用 `CLEAR_PSN = PSN + offset`。

## 三种当前投递路径的差别

| 模式 | 乱序和重复 | 故障恢复 | 完成含义 |
|---|---|---|---|
| ROD | 乱序包触发 go-back-N；重复包不再次交付 SES | 从接收端要求的缺失 PSN 开始重传；另有 RTO | 可靠语义完成 |
| RUD | 窗口内按到达顺序交付；重复包不再次交付 SES | 保留缺口，选择性重传 | 可靠语义完成 |
| UUD | 无连接、无去重、单包 DATAGRAM_SEND | 无 ACK/NACK、无重传 | 发起端 `LocalSuccess` 仅表示本地发送被接收 |

RUDI 与 RODL 不能直接套用这三种路径；它们仍在后续实施范围内。

## 用测试观察协议

- `pds_recovery_test`：丢失中间包。ROD 必须在 1 ms RTO 前由 NACK 恢复；RUD 必须
  将后续包先交给 SES，再恢复缺口，不能偷偷变成有序网络。
- `rud_window_test`：窗口缺口、重复包、保证交付响应、Clear 和 32 位序号回绕。
- `uud_delivery_test`：丢包仍只有本地完成，没有连接分配或重传。
- `pdc_lifecycle_test`：正常关闭、Close Command 丢失、关闭 ACK 丢失和资源清理。
- `native_atomic_test`：整数边界、8 种数据类型、权限拒绝、丢失 ACK 后原子只执行一次，
  以及 WRITE immediate 的远端完成。
- `reference_wire_comparison`：独立链接官方解析器和 CRC 实现，检查 24 组报文。
  这是报文差分，不代表两个协议端点进程已经互通。
- `reference_process_interop`：独立进程中的原样参考 SES/PDS 经过测试 NIC，验证
  WRITE/SEND、返回 SEND 和 Clear；不覆盖 raw NIC 驱动。
- `context_reuse_test`、`message_retirement_test`：上下文重用、旧报文拒绝、SYN 安全
  时间，以及跨越 16 位消息 ID 空间的 66,000 次真实原子更新。
- `message_completion_test`：延迟 EOM，在中间默认响应之后仍不能提前报告成功。
- `resource_lifecycle_test`：小容量上下文池、待分配超时、重调度、资源 NACK 暂停与恢复。
- `addressing_test`：相对/绝对 PID、generation、禁用资源、索引隔离和跨 JobID 权限。

这些测试说明对应行为有证据，不能替代整份 Profile 的规范验收。
