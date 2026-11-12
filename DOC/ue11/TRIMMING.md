# trimming：保留丢失线索，不交付残留数据

trimming 是交换机在缓冲准入失败时，把允许截短的数据包改成短通知的方法。它依据
UE 1.1 §4.1，接收与恢复依据 §3.5.8.2、§3.5.15.1 和 §3.6.4.4。短通知仍沿网络发往
目的 FEP；目的端用 NACK 告知源端丢失，PDS 使用自己的缓存重传原数据。

这是一条实际改变 Ethernet/IP 帧内容并经过原 PDS 内核的路径。当前支持无 TSS 的
IPv4/IPv6、原生 UET 和 UDP 封装；TSS、扩展 IP/tunnel header、RUDI/RODL 的相应
路径与完整 Profile 验收仍未完成。

## 配置描述的是整张网络的含义

`NetworkLayer::TrimmingOptions` 定义本实验使用的 DSCP 含义。默认值是模拟器策略，
标准没有规定这些数字：

| 名称 | 默认值 | 用途 |
|---|---:|---|
| trimmable DSCP | 0 | 可在缓冲准入失败时截短 |
| trimmed DSCP | 8 | 普通截短通知 |
| last-hop DSCP | 16 | 最后一跳的截短通知；可关闭这一可选区分 |
| control DSCP | 48 | ACK/NACK/CP 使用的控制码点 |
| trimmed traffic class | 1 | 截短通知重新准入的队列 |
| minimum IP payload | 24 字节 | 保留 UDP/entropy 与当前最大的 PDS request header |

MIN_TRIM_SIZE 是 **IP payload** 的长度，不包含 IP/Ethernet 头。24 字节足以保留
UDP 的 8 字节和最多 16 字节 PDS request header；原生封装也使用这个网络共同下界。
选用 TSS 或其他外层封装时必须重新确定该值，当前不会自动假定它们已经受支持。

```cpp
UET::NetworkLayer::TrimmingOptions trimming;
source_host.configure_trimming(trimming);
target_host.configure_trimming(trimming);
UET::Runtime::LinkConfig switch_egress;
switch_egress.trimming = trimming;
fabric.add_link(switch_node, target_node, switch_egress);
```

所有相关 FEP 必须配置同一组 DSCP 含义。端点配置识别规则，交换机出口配置是否在
准入失败时截短。源端为数据和控制包设置相应码点；已截短报文不会再次截短。

## 交换机具体改变什么

`Fabric::forward()` 先检查目标类的字节缓冲。失败且 DSCP 属于 trimmable 时，
`UetWireCodec::trim_packet()`：

1. 确认输入具有有效的已支持 IP 头和长度；无效 IP 不会变成截短通知。
2. 保留至少 MIN_TRIM_SIZE 的 IP payload；原包更短时只改变 DSCP，不增加长度。
3. 改写 IP 长度、DSCP 和 IPv4 header checksum；保留 ECN。
4. 保持 UDP length/checksum、entropy 和保留下来的 PDS/SES 字节原样。
5. 释放被移除 payload 的 vector 分配，再把通知按 trimmed DSCP 重新准入相应队列。

如果通知队列也没有空间，它仍会丢失；端到端 RTO 继续负责这类恢复。每个已配置出口
也会按收到的 DSCP 重新分类已有通知，不依赖发送者提供模拟器内部的流量类元数据。
队列调度和出队 ECN 见 [NSCC](NSCC.md)。链路统计另记录 `trimmed` 和 `trimmed_bytes`。

`IPacketPort` 存储的 Ethernet 帧不包含物理 FCS；当前没有声称验证了实际网卡的
Ethernet FCS 重算。UET CRC 与 Ethernet FCS 是不同的保护层。

## 接收端为何不校验相同的长度和 CRC

正常包继续验证 IP/UDP 长度及按配置验证 UET CRC。按已配置 DSCP 识别出的截短包，
则走另一条受限解析路径：

| 检查或处理 | 截短包行为 |
|---|---|
| IPv4 header checksum | 仍须有效 |
| IP / UDP length | 不验证；内存读取边界使用实际捕获长度 |
| UET CRC | 可以已被截除；当前不验证截短包 CRC |
| SES header / payload | 不解析，也不交付 |
| 完整 PDS request 头 | 仅提取生成 NACK 所需的连接标识、PSN 和 RETX 信息 |
| 截短 ACK/NACK/CP/UUD | 丢弃；不推进确认状态，也不回复另一个 NACK |

交换机检查并更新 IP 长度，FEP 又不验证截短包的 IP/UDP 长度，这两条规则承担不同
职责，不能合并成同一个接收校验。特别是 UDP length 按标准保留原值，不能要求它等于
截短后的 IP payload。

未验证的截短头只能用于生成 NACK。`PDS_Manager` 在正常分流和建连之前处理它：

- 已有且身份完全绑定的 PDC 可以生成 `UET_TRIMMED` 或 `UET_TRIMMED_LASTHOP`。
- 没有匹配 PDC 时，用 SPDCID 0 生成 NACK，**不会创建 PDC** 或学习新的对端 ID。
- 不推进接收 PSN、CACK、Clear、NSCC accepted-byte counter 或任何 SES/MR 状态。

NACK 的 entropy 和 CE/RETX 反馈来自触发的截短通知。源端用已有发送记录确定原包的
名义大小，再执行 NSCC 的丢失处理；它不会把短通知长度当成丢失数据包的大小。
RCCC 尚未启用，因此 last-hop trim 目前仍会触发 NSCC 的相应拥塞响应。

## 验证与实验参数

```sh
ctest --test-dir build/cmake -R 'packet_trimming|nscc|uet_wire' --output-on-failure
```

`packet_trimming_test` 覆盖八种 IP/UDP/CRC 组合的字段保留、实际长度边界、无效 IPv4
checksum、不同 DSCP 与小控制包；还验证未验证的长度字段不被使用、截短 SYN 不能
创建 PDC 或写内存、截短 ACK 不能修改确认状态。拥塞出口测试覆盖 RUD/ROD、IPv4/IPv6、
原生/UDP、普通/last-hop trim 的十六种恢复组合，以及首次 SYN 被截短后的可靠恢复。

拥塞测试的空载 RTT 上界按传播和串行化估算为 6 µs。早期试验误用 100 µs 配置，
造成 NSCC 的目标延迟和增长参数与拓扑不匹配，ROD 耗尽重试。这一失败说明配置本身
也是实验条件，不能通过改变拥塞控制公式使不正确的配置看起来成功。最终测试使用
拓扑一致的参数，默认有限重试上限保持原值。

仍需验证：更多通知/NACK/ACK 丢失组合、通知类耗尽、跨交换机/多流/不对称路径与
TSS 的组合。当前默认使用有独立缓冲的两个流量类，不宣称提供所有交换芯片缓冲策略。
