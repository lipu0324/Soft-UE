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

## 首错保证传递与重复错误

UE 1.1 §3.4.4.3 允许一条多包消息返回多个错误，但只允许首个错误响应保证传递。
`Incoming::error_response_generated` 因此独立于 `first_error`：后者选择错误码，前者
记录是否已经生成了持有保证传递状态的错误响应。两者都保存到该消息正常退休。

`reply_error()` 对首错使用 `ResponseDelivery::Guaranteed`，后续错误使用
`BestEffort`，并始终保持显式 `UET_RESPONSE`。保证传递位不能决定语义 opcode；
将后续错误转换成 DEFAULT 会丢失错误，将它转换成 NO_RESPONSE 则会丢失处理结果。
若先前还有一个等待处理的 EOM handle，当前暴露错误的包先获得保证，EOM 再返回
不保证传递的同一错误。晚到 posting 引发的错误也通过同一个 helper。

原 PDS 缓存首错响应，并阻止 CACK 越过它，直到源端 Clear。首错丢失后，有 SACK
收据的源端可以发送 ACK Request；没有收据时可以重传原请求，两者都由 PDS 重放
已缓存结果。后续错误副本丢失时，源端仍会得到保证传递的首错。非保证传递的尾部
不必触发独立 Clear，消息记录可等到下条请求捎带的累计 Clear 后释放。

`guaranteed_error_test` 通过实际网络包检查 RUD/ROD、NSCC 开关、首错丢失、首错
与全部重复错误丢失、SACK 后查询、RUD 非 SOM 先到，以及后续请求清理状态。
同一 PSN 的保证响应重放仍是同一个保证；测试按不同 PSN 检查恰好一个保证归属。
标准请求在消息记录耗尽时现在于PDS接收前返回资源NACK，不再走无记录保证错误
路径；准入、回滚和Clear恢复见[消息记录信用](RECEIVE-ADMISSION.md)。其他格式仍需独立验收。

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

错误记录同样消耗资源。默认消息记录上限为4096；满时用PDS的
`UET_NO_SES_MSG_AVAIL` 拒绝尚未接受的新包，已有消息继续使用其记录。Clear释放
信用后，发送端按原PSN重试即可继续；不驱逐首错，也不要求关闭PDC后才能恢复。
这项记账容量与unexpected payload容量分开。

ROD 的未匹配消息现按接收顺序进入有界缓冲，后投递的 posting 可接收整条或已到达的
前缀。payload 容量耗尽时，SEND index 进入 `DISABLED_GEN` 状态；补充资源后增加
generation 再启用。已经接受的消息保存原选择并继续排空。provider 保留原应用操作，
等待旧尝试的 `transport_pending()` 变为 false 后，使用新 Message ID 和正确代次重试；
后来的操作等待最早操作完成。RUD 返回 NO_MATCH，由调用者或适配层负责退避重试。完整规范与 API
验收尚未完成，各 Profile 的符合性声明继续关闭。

## 可重复验证

```sh
cmake --build build/cmake --target semantic_error_test -j2
ctest --test-dir build/cmake -R '^semantic_error_test$' --output-on-failure
```

该测试覆盖首错保留、迟到尾包、新 posting、记录耗尽、IE、提前到达的 MSG_ERROR、
错误 CQ 的 header data、reader 首包/中途异常、停止读取和截断后的后续正常消息。
可选 `libfabric_provider_processes` 进一步通过公开 `fi_*` API 验证目标截断错误 CQ。
