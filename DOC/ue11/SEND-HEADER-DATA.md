# SEND 的完成数据与 deferrable 兼容接收

UE 1.1 §3.4.2.9 的 `header_data` 是 64 位完成数据。它随 SOM 包到达，不是 payload，也不占用
额外的接收队列项。`Operation::immediate_data` 现在可用于 WRITE、SEND 和 DATAGRAM_SEND；
零值同样有效，不能把数值零当成“没有数据”。

| 操作 | 目标完成所关联的资源 | 源端完成 |
|---|---|---|
| WRITE with data | 无需 SEND posting，生成独立的 RMA 完成 | 可靠语义完成 |
| SEND with data | 使用已匹配 posting 的 context、buffer 和 CQ；只回收该 posting 一次 | 可靠语义完成 |
| DATAGRAM_SEND with data | 目标若成功匹配 posting，在其完成中携带数据 | 本地发送完成，不推断远端收到 |

ROD 的 unexpected 缓冲会保留 SOM 中的完成数据，后投递接收缓冲区时一并交付。IE 导致的
已匹配 SEND 错误完成也保留已收到的 header data。没有匹配 posting 的 SEND 不会因为带有
header data 就生成一条冒充 RMA 的独立完成。内存检查及首错状态仍见 [SES-ERRORS](SES-ERRORS.md)。

## AI Base 不能拒绝所有 deferrable send

§3.3.5 的表 3-4 与 §3.4.4.6.1 要求 AI Base/HPC 将收到的 `UET_DEFERRABLE_SEND` 作为普通 SEND 处理。
当前接收入口对 opcode `0x08` 做兼容解释。代码复制语义头后解释，不修改原始请求和 PCAP；
SOM 会产生 `deferrable_as_send` 轨迹事件。

Deferrable send 的 `buffer_offset` 位置携带重启令牌。按 SEND 处理时，目标使用 posting 的
本地偏移和注册身份，令牌不能变成 RMA 地址、内存 key 或缓冲区偏移。依据 §3.4.4.6.1，
没有 posting 时两种可靠模式均返回 NoMatch、modified_length=0；已有 posting 则接受完整长度。
这与普通 ROD SEND 的 unexpected 缓冲有所区别。后投递 posting 不会复活已拒绝的消息，源端
可以用新消息重试。接收端不会用 OK/0 表示真实 deferral；零长度消息的完整长度本身也是零。
RUD 中 EOM 先于缺口到达时，可以先用 OK/full 表示接受；源端仍须确认每个数据包的语义结果，
不能因此提前报告整个操作成功。

这不是 AI Full 的完整 deferral/RTR/restart 实现，也不表示已支持 deferrable tagged send。
原生源端尚未公布实际 deferrable 操作；能力只单独说明 `deferrable_send_as_send` 接收行为。

## libfabric CQ 的对应关系

实验 provider 支持 `fi_senddata` 以及 `fi_sendmsg(..., FI_REMOTE_CQ_DATA)`，包括 DGRAM；
发现信息中包含 `FI_REMOTE_CQ_DATA`。目标 CQ 项在 SEND 情况下仍标为 `FI_RECV`，携带原
posting 的应用 context、buffer、length 和 data，不消耗另一条 posting。

Provider 内部的 Native receive token 从 1 开始，溢出时拒绝继续分配；零专供无需 posting 的
WRITE-with-data 通知。这样不能仅凭“有 immediate_data”就把 SEND 误归入 `FI_REMOTE_WRITE`。
应用的 context 本身仍可以是空指针。

回归入口：

```sh
ctest --test-dir build/cmake -R 'send_header_data|semantic_error|unexpected_message'
ctest --test-dir build/asan -R 'libfabric_provider_processes|libfabric_datagram_processes|libfabric_recovery_processes'
```

原生测试使用较小的测试 MTU 快速覆盖多片段边界；不把它当作标准规定的生产 MTU 验收。
覆盖 0/UINT64_MAX 完成数据、零长度消息、RUD/ROD/UUD、IPv4/IPv6/native/UDP、迟到 posting、
无匹配 posting、IE、64 位重启令牌以及 UUD 不建立 PDC/不产生 ACK。公开 fi_* 测试同时验证
RMA 与 SEND CQ 数据的区别、SENDMSG 数据、零值数据和原有错误/恢复路径。
