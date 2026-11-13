# SACK 为什么不能代表应用成功

UE 1.1 的三个确认层次各有用途，代码也分别记录它们：

| 事实 | 代码状态 | 可以做什么 |
|---|---|---|
| 目的端已接收数据 | `TX_pkt_meta::delivery_confirmed` | 丢失响应时发送 ACK Request，避免重复传输已收到的数据 |
| 单包已有正向语义结果 | `semantic_completed_tx_` | 释放该请求的发送缓存，参与前移 Clear |
| 整个应用消息已结束且每包都有正向结果 | `Pending::awaiting_semantic_responses` 为空，并已发送 EOM | 上报一次成功完成 |

这里“正向”指存在明确结果，不仅指成功：显式错误同样结束该包的等待，但立即使应用操作
以错误完成。应用看到错误后，已有副本的传输收尾和 Clear 仍由 PDS 处理，不再读取应用
缓冲区。

## 接收 SACK 与推断 DEFAULT

`processDeliveryAcknowledgment()` 将 ACK_PSN、有效 CACK 和 SACK 的置位合并到交付状态。
零位表示没有信息，不能撤销以前的确认。只遍历本方向仍有效的请求缓存，不能把远端 PSN
当作本地另一方向的保证响应缓存索引。这个处理不依赖 NSCC 是否开启。

`processSemanticAcknowledgment()` 先交付 ACK_PSN 对应的显式语义响应，再检查其他缓存请求。
依据 §3.5.13，**CACK 必须严格高于某包的 PSN**，才能为它推断 DEFAULT_RESPONSE；相等不够，
SACK 位也不够。这一顺序使同一 ACK 携带的错误先于其他推断响应进入 SES。

原生 SES 在中间片段完成权限检查和数据放置后立即返回 DEFAULT，避免额外等待 RTO。
当 RUD 的 EOM 先于缺口到达时，暂时返回 NO_RESPONSE，完整结果由补齐缺口的包触发。

NO_RESPONSE 是 opcode `0x03`、RC_NULL `0x00` 的显式 SES 头（表 3-24）。它说明目的端尚未
给出该包的肯定语义结果。此时确认数据交付，但继续保留请求及定时器。超时后查询语义结果，
不是重新计入数据的在途字节。模拟器目前保留窗口内的完整缓存包，未做收到 SACK 后单独释放
payload 的优化；空间仍受本地发送窗口限制，不随总消息长度增长。

ACK Request 对已经处理的非保证响应请求返回 DEFAULT。依表 3-69，其 JobID、generation、
modified_length 为零，MessageID 来自控制包 payload 高 16 位。源端先按已验证的端点、PDC、
连接起始序号和 PSN 找到原请求，再恢复其 JobID/generation，不仅凭 MessageID 查找应用。
保证错误仍从原保证响应缓存重放；SES 尚在处理则返回 `UET_RCVD_SES_PROCG`。

## 发送 bitmap

当前使用逐包 ACK 模式。RUD 的 ACK_CC 以触发包所在的 8 对齐序号为基址，最低有效位对应
基址。只有 SES 已返回响应的请求能置位；仅出现在接收集合但仍在处理中的请求不能置位。
新保证响应即使尚未插入重放缓存，其触发位也会正确进入本次 ACK。

正文要求基址低三位为零，但图 3-81 使用未对齐的 1842，属于已记录的规范内部差异。
发送端遵循正文；接收端按线上基址解释 bitmap，不增加无依据的整包拒绝规则。
Probe 的专门基址规则及独立 bitmap 回归见 [PDS-PROBE.md](PDS-PROBE.md)。可选的 ACK 合并仍待实现，
不能将逐包或 Probe 测试作为其证据。

## Clear 跨过缺口

§3.5.11.4.3 的空闲 Clear 规则独立于 ACK 的 REQ_CLEAR 位：收到 ACK 后只要
本地 Clear 已前移，且没有待发送请求捎带它，就需要发送 Clear Command。
当前选择规范允许的立即策略；可选 PDS_Clear_Time 延时合并尚未启用。
非保证错误尾包也遵守这条规则，不能把目标消息记录留到下一次应用提交。

`selective_acknowledgment_test` 在 RUD/ROD、序号回绕及有/无待发送请求时检查
这一分支：空闲时生成 PSN=0、AR=0 的 Clear Command，有请求时携带新 Clear。
目的端不为 Clear 再生成 ACK，重复 ACK 不会导致重复 Clear 循环。

Clear Request 只要求源端报告其 Clear，不能充当 ACK，也不能删除发送缓存。源端回报当前
边界，并记住仍未满足的合法请求。Clear Command 只释放目的端已被源端清理的状态，依
§3.5.16.3 不产生 ACK。

消息 ID 的租约跟随本地 `TransmitCleared` 事件回收，而非依赖目的端为 Clear 额外生成 ACK。
即使 ID 在同一 PDC 上再次使用，新请求也携带已经前移的 Clear；目的端 PDS 会先清理旧状态，
再交付新请求。尚未跨过早期缺口时仍保持租约。`PeerCumulativeAcknowledged` 只表示对端交付
进度，不替代本地逐包语义完成的判断。


保证响应可能先于更早包的响应到达。`peer_clear_requests_` 保留其 Clear 请求，直到本地 Clear
实际覆盖对应 PSN。发送过一次尚未覆盖它的 Clear，不代表请求已经满足。这可避免目的端保证
响应和 SES 消息记录一直被保留。

回归入口：

```sh
ctest --test-dir build/cmake -R 'selective_acknowledgment|message_completion|semantic_error|pds_mpr'
```

测试覆盖严格 CACK、SACK 只确认交付、NO_RESPONSE 查询、JobID/generation 恢复、重复抑制、
LSB 位序、处理中的请求不置位、32 位回绕、Clear Request 不删除未完成发送、Clear Command
不生成 ACK，以及 RUD 中 EOM 默认响应不能掩盖中间丢包。丢失的保证错误在后续 SACK 到达后
通过 ACK Request 恢复，验证开启和关闭 NSCC 时均不会重复发送原数据。
