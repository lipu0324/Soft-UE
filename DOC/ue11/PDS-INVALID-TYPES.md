# 未知 PDS 类型为什么不能回复 NACK

UE 1.1 §3.5.11.1/.3 要求：未知 PDS type 或 CP ctl_type 必须计数、静默丢弃。
CP 可能使用 PSN=0，不能从未知类型推断可靠请求或向任意连接发送 NACK。

标准入口先检查 Ethernet/IP/UDP 边界及启用的 CRC，再由 `UetWireCodec` 分类。
`PdsDecodeError` 保留错误种类和原始字段值，避免依赖异常字符串。`PdsHost`
只更新主机计数器和 trace；报文不会进入 PDS 队列，不分配 PDC，不学习 peer ID。
直接向协议队列提交的适配器也有独立的未知 CP 防护，位于任何建连处理之前。

| 字段 | 已定义编码 | 未知编码 | 诊断 |
|---|---|---|---|
| `pds.type` | 表3-39的1～15 | 0、16～31 | `PDS_TYPE_INVALID` |
| `pds.ctl_type` | 表3-48的0～9 | 10～15 | `PDS_CTL_TYPE_INVALID` |

“已定义”不表示实现已支持。TSS、RUDI、ACK_CCX、RODL等已知但尚未实现的格式仍被
拒绝，不能计为未知类型，也不能因此公布对应能力。CRC 错误先于类型分类，避免损坏
报文污染类型错误计数。trim 路径没有完整 CRC 时仅按其独立规则处理，不承诺认证。

`PdsHost::pds_error_counters()` 提供每主机只读快照引用，
`clear_pds_error_counters()` 显式清零。两个字段各选用16位饱和计数器；饱和方式是本
仿真的管理策略，规范未指定溢出行为。它们不会因 PDC 关闭或复用而自动清零。
这两个计数器只是管理模型的一部分，其他表3-36事件仍需逐项补齐。

回归 `pds_invalid_type_test` 覆盖所有32个 type 值、全部保留 ctl_type、IPv4/IPv6、
原生/UDP及CRC开关；验证CRC优先、PSN=0、SYN/非SYN、已建连/未建连、
伪造peer ID、直接队列入口、后续合法NOOP、主机隔离、清零和饱和。
修复前独立探针对ctl_type=10、SYN=1记录了一个错误NACK；修复后要求无响应。

规范还有一个需要保留的编码差异：表3-82把PCM Telegram写为`0x10`，但表3-48
定义ctl_type只有4位，且10～15保留。已对照PDF第398页的渲染表格确认原文。
当前不截断`0x10`为NOOP，也不擅自分配其他编码。PCM属于M8后的独立增强，
其线格式须在实现前解决这一差异。
