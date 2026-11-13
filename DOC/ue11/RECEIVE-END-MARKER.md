# 字节覆盖、EOM 与状态回收是三个条件

UE 1.1 §3.4.2.14 的 EOM 标记消息结束。目标已经放置所有 payload 字节，并不代表
EOM 已经到达：最后一个数据包可以不带 EOM，随后另发一个零 payload 的末包。
这也是实现完整 deferrable 事务时必须处理的边界。

```mermaid
flowchart LR
    A[字节已经放完] --> B[EOM 已到达后报告应用成功]
    B --> C[真正的 EOM PSN 被 Clear 后回收状态]
```

原代码仅依据 `received == total` 报告目标成功，因此普通 WRITE IMM/SEND/tagged
会在末包之前产生 CQ。ROD unexpected payload 在迟投递时也可能提前完成。修正
要求 `end_seen` 与完整字节覆盖同时成立；这个条件用于普通接收、unexpected 末包
响应保留，以及迟投递后的完成。

零长度标记不占用任何字节区间。若把零 SOM 记作 `[0,0)`，后续零 EOM 也位于偏移0，
旧逻辑会把它当成重复字节区间并提前返回，导致永远没有成功完成或语义响应。
覆盖表现在只保存非空区间；PDS 的 PSN 去重仍负责重复报文，SES 仍处理新的 EOM。

`end_of_message_psn` 只指真正的 EOM，不是最后一次放置的包。完成后还须等 Clear
覆盖它才回收记录，见[乱序退休边界](RECEIVE-EOM-RETIREMENT.md)。这使研究人员可以
分别观察“数据已到”“应用可见成功”“协议资源释放”，不把三者混为同一个事件。

`receive_end_marker_test` 使用真实源 PDS 和目标 SES/PDS 构造报文，不借助第二套
消息通道。它先发送完整 payload、但不带 EOM，确认此时没有目标完成；再发送独立
零长度 EOM，确认一次成功与两个语义响应，并验证 Clear 后释放记录。覆盖0/48 B、
RUD/ROD、WRITE IMM/SEND/tagged，以及 ROD 在 EOM 前迟投递，共16种情形。
基线提前完成和中间版本的零 EOM 丢失均保留失败证据。此回归不包含源应用 API 完成。
