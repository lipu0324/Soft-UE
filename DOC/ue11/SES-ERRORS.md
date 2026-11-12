# SES 错误如何沿协议栈传播

研究协议时，需要分清应用消息、PDS 数据包和连接三个对象。一次 WRITE 可分为很多包；
某个包失败可以使整条消息失败，同时保留 PDC 供其他消息使用。本文对应当前原生
`SES::Endpoint` 的标准报文路径，依据 UE 1.1 §3.4.6；不代表全部错误机制已完成。

## 一条消息的首个错误

`Incoming` 是接收端消息记录。它的 key 包含来源 FEP、目标本地 PDC、JobID、
initiator、Message ID 和该次连接的起始 PSN。同一个 PDCID 或 Message ID 被复用后，
旧连接记录不会匹配新消息。

`first_error` 记录首次遇到的错误，`error_generation` 保存当时应返回的资源代次。
这里的“首次”按处理顺序判断；RUD 允许乱序，因此它可能来自消息中间或最后一个包。
后续包仍需经过 PDS 的接收、去重和确认，但 SES 只重发已经确定的错误，不再匹配
新的接收请求，也不再访问注册内存。当前整数操作没有 informational error；其与
unrecoverable error 的优先级组合仍待实现。

一个重要反例是：SEND 到达时没有 posting，随后应用投递了一个缓冲区。如果只在每个
包上单独报错，这条已失败消息的尾部就可能写进新缓冲区。保留消息级错误状态能阻止
这种错误；`semantic_error_test` 包含延迟尾包和重新投递的回归。

## `ses.ie` 与 `MSG_ERROR`

两者都表示发起端已无法继续正常交付这条消息，但范围不同：

| 机制 | 包的含义 | 接收端处理 |
|---|---|---|
| `ses.ie=1` | 头有效，当前 payload 不可使用 | 当前包不访问内存，消息进入错误状态 |
| `UET_MSG_ERROR` | 提前终止消息；必须设置 EOM | 不访问内存，允许未发送原消息剩余部分 |

如果它们是第一处错误，返回码为 `RC_INITIATOR_ERROR` (`0x23`)。已有首错时保持原码。
RUD 中终止包可能先于 SOM 到达，因此不能以“已见 EOM”为理由立即丢弃记录。
如果 SOM 后来提供 header data，错误 CQ 仍须携带它。

发送端的 `SourceMessage` 持有应用 payload 的读取方式和当前生产偏移。成功时，PDS
逐片接收它产生的拥有型字节副本。错误发生时，SES 先释放 reader，停止对应用缓冲区的
后续读取，再报告应用错误；尚未生产的尾部改为一个 `MSG_ERROR`。已经进入 PDS 的包
继续使用自己的副本完成发送或重传，不需要再读取应用内存。reader 抛出异常也走这条
路径，部分填写的临时 payload 不会上线。

## 应用完成不等于协议状态已经释放

`finish()` 发布应用完成，`message_leases_` 则单独保留线上 Message ID 的使用权。
只有 PDS 发布的发送事实表明 EOM 已发出，且对端 CACK 已覆盖最后一个发送 PSN，
该 ID 才能用于下一条消息。失败消息也遵守此约束。

接收端通过 EOM 和 PDS Clear 共同退休记录：EOM 表明消息不会再产生新片段，Clear
表明发起端已收到并清除了相应响应。连接终止也会清理该连接代次的消息状态。
这些事实来自原 PDS/IPDC/TPDC 内核，没有由 UDP 后端代替可靠性。

标准路径的首次请求也必须等待 SES 决定响应类型。即使它只是中间包，也可能需要
带错误码的 guaranteed response。先发普通 ACK 会过早删除发起端的包关联，使随后
的错误响应失去所属消息；`T_PDC::processOpen2` 因而把标准请求的 ACK 决定留给 SES。

## 截断与资源限制

当前 SEND 截断采用零字节放置策略：消耗匹配的 posting，不改动缓冲区，发起端收到
`UnsupportedSize`，目标端收到 `Truncated`。完成中的 `length` 是已放置长度，
`original_length` 是原消息长度。libfabric 对应 `FI_ETRUNC`，`olen` 是未放置字节数。

错误记录同样消耗资源。默认消息记录上限为 4096；满时，本仿真策略拒绝该 PDC 的新消息，
保留已有记录到正常退休，并在 PDC 关闭后释放拒绝状态。它避免无界增长和不安全驱逐，
但不是 §3.4.4.7 完整的 ordered unexpected-message、资源代次和软件重试机制；这些
仍需继续实现。各 Profile 的符合性声明继续关闭。

## 可重复验证

```sh
cmake --build build/cmake --target semantic_error_test -j2
ctest --test-dir build/cmake -R '^semantic_error_test$' --output-on-failure
```

该测试覆盖首错保留、迟到尾包、新 posting、记录耗尽、IE、提前到达的 MSG_ERROR、
错误 CQ 的 header data、reader 首包/中途异常、停止读取和截断后的后续正常消息。
可选 `libfabric_provider_processes` 进一步通过公开 `fi_*` API 验证目标截断错误 CQ。
