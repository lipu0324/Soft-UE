# Provider 注入：缓冲区、重试与完成

UE 1.1 §2.2.5.4 的 inject API 要求调用返回后可复用源缓冲区。成功时不生成
本地 CQ entry；可靠端点交付失败仍生成错误 CQ。该规则也适用于 RMA 和原子注入。

当前 `inject_size` 为 256 字节，是 provider 的本地复制上限。它与 Payload MTU、
普通消息上限、原子元素个数分别计量。原子注入按 datatype 宽度把元素个数转换成
字节数，在乘法和复制前检查上限。能力查询和 endpoint 创建也拒绝超过此上限的配置。

| 调用 | 数据所有权 | 成功完成 |
|---|---|---|
| `fi_inject` / `fi_injectdata` | 返回前复制不超过 256 字节 | 不生成本地 CQ；data 仍送到目标 CQ |
| `fi_inject_write` / `fi_inject_writedata` | 返回前复制，不接管应用缓冲区 | 不生成本地 CQ；WRITE IMM 仍产生目标完成数据 |
| `fi_inject_atomic` | 保留自己拥有的操作数，按字节检查注入上限 | 不生成本地 CQ |
| `sendmsg` / `writemsg` / `atomicmsg` 的 `FI_INJECT` | 同样允许立即复用源缓冲区 | 保留通常的 CQ 完成规则 |
| endpoint 默认 `FI_INJECT` | 基础 API 使用相同复制规则 | 保留通常的 CQ 完成规则 |

带显式 flags 的 message API 覆盖 endpoint 的默认操作 flags。测试还验证了显式
零 flags 能在默认 INJECT endpoint 上发送超过 256 字节的普通消息。普通 SEND/WRITE
继续按需读取应用缓冲区；注入能力没有把全部普通消息改为一次性复制。

复制的数据放在 `SES::Operation` 自有 payload 中。PDS 缓存负责包重传，provider
保留的操作副本负责 `NO_MATCH`、generation 等语义重试。这两层都不需要再次读取
已经还给应用的原始缓冲区。注入操作仍占用有上限的待发送队列，直到协议完成。

`ApplicationOperation::suppress_success_completion` 只抑制成功 entry。异步错误
仍通过 `fi_cq_readerr` 报告；无 context 的 inject API 使用空 context/buffer。
key、JobID、权限和地址边界校验继续在目标 MR 注册表执行。

`libfabric_inject_test` 通过公开 API 向原生 SES/PDS 对端发送。它在调用返回后立即
改写源数组，并先让第一条 SEND 产生 NO_MATCH，再投递 receive，验证语义重试使用
保留副本。覆盖 SEND/WRITE/ATOMIC、远端 CQ data、成功 entry 抑制、错误 entry、
零长度、256/257 字节边界、默认/逐调用 flags 及 DGRAM。本地发送完成不推断
DGRAM 已可靠交付。

`FI_INJECT` 与 `FI_INJECT_COMPLETE` 是不同接口语义：前者规定 API 返回后的源
所有权，后者规定 CQ 完成等级。等级映射和更强完成点的选择另见
[完成语义](PROVIDER-COMPLETION.md)，不由复制测试推断。
