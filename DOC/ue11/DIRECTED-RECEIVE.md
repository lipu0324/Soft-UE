# Directed receive：按 Job 内 rank 选择接收项

UE 1.1 §3.4.2.3.4 把 `ses.initiator` 定义为 Job 内的32位 rank。它可以用于 SEND、
Tagged SEND 和 DATAGRAM_SEND 的接收匹配；它不是 Source PID，也不是接收内存 key。

| 标识 | 作用 |
|---|---|
| peer / 网络 FEP | 将报文送到哪一个网络端点 |
| `source_pid` | 本地进程及可选 PDC 选择的元数据 |
| `initiator_id` | 线上 Job 内 rank；接收方可指定一个 rank 或任意源 |
| 接收注册身份 | 匹配成功后授权本地缓冲区放置，与源筛选独立 |

## 原生接口

`post_receive(...,context,resource_index,initiator)` 的最后一个参数是可选32位 rank。
省略表示任意源；值0仍是指定 rank，不是通配符。Tagged 接收使用已有的
`TaggedReceiveMatch.initiator`。两者共用匹配逻辑，先验证资源空间与源，再比较 tag。
从所有满足条件的投递中选择软件最早的一项。

Rank 只在其 JobID 中有意义。即使使用绝对 PID、MR 又允许任何 Job，Job99 的 rank7
也不能消耗 Job1 投递的“只接收 rank7”缓冲区。任意源投递仍遵循既有绝对寻址及 MR
授权规则。UUD 不匹配时直接丢弃；其源端本地成功不证明目标收到。

## libfabric 协商和地址映射

应用通过 `hints->caps` 或 `hints->rx_attr->caps` 请求 FI_DIRECTED_RECV。发现结果在
endpoint/rx 能力中返回此项，tx 能力不包含它。默认未请求时，`src_addr` 按 libfabric
规则被忽略；请求后，非 FI_ADDR_UNSPEC 的参数必须是有效 AV 项，否则同步返回
FI_EADDRNOTAVAIL，不分配接收注册或消耗投递。

本实验 provider 使用 FI_SOCKADDR_IN 地址。每个端点的 UDP node/port 被用作 Job1
rank 代理，AV 项通过这个代理映射到原生32位匹配条件。这是 provider 的地址映射
策略；原生接口并不把 rank 限制在16位端口范围。FI_ADDR_UNSPEC 始终表示任意源。
RDM 的 SEND/tagged 和 DGRAM 的 UUD 都支持这个选项。

匹配只选择哪一个本地投递，不能授予远端 RMA 权限。自动接收注册依旧是
local-placement-only，放置仍验证精确的存活注册身份。

## 回归

`tagged_message_test` 验证原生 SEND、tagged、UUD 的 rank0/全1、指定/任意源及绝对
寻址中的 Job 隔离。`libfabric_directed_receive_test` 使用两个分别 progress 的真实
协议对端，验证较早的指定源投递不会被另一个源消耗，任意源仍可接收它；同时覆盖
SEND/tagged/UUD、未请求能力时忽略源参数、接收侧能力 hint，以及无效 AV 拒绝。
实际通过结果以对应提交的验证报告为准。这不是完整 Profile 或安全认证声明。
