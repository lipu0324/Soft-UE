# Endpoint 替换、消息号与 Host 退休跟踪

一个原生 Endpoint 是 SES 应用状态的拥有者；PdsHost 与 PDS（包交付子层）还可能持有已经复制的请求、
重传定时器、ACK 与 Clear。关闭 Endpoint 不等于这些传输事实已经消失。
应用 operation ID 属于该对象的 CQ；16位线 MID（Message Identifier，消息标识；或优化请求的本地提交 cookie）则必须
在它所属的传输生命周期内保持唯一，不能因为 C++ 对象被替换而重新分配。

## 可复现的问题

先提交 RUD WRITE，在 Host 运行之前关闭源 Endpoint，然后在同一 Host 创建新的 Endpoint。
两者原来都从 MID1 开始。旧请求随后进入 PDS，`RequestTransmitted` 上交给新 Endpoint，
新操作误把旧 PSN 加入自己的等待集合。即使新 WRITE 已到达目标并被确认，丢失的旧请求
仍把新操作拖成 Timeout。负向日志 `/tmp/softue-endpoint-replacement-before-tests.log`
记录 `status=6`，并先验证新字节确实已放置。

这不是线格式携带应用 operation ID 的理由。优化请求仍没有 MID，不能把本地句柄编码
到线上；它们的本地 TX cookie 也要遵守相同的对象生命周期隔离。

## 退休状态放在哪里

Host 的 `Services` 保存消息号游标与 `RetiredSemanticMessages`。当前 Endpoint 分配时排除
自己的 pending/lease 及 Host 上尚未退休的旧消息号。游标回绕跳过0，不绕过仍活跃的租约。
关闭 Endpoint 时把 pending 和完成后尚未 Clear 的租约移交 Host，再清除应用回调。

Host 在分派 PDC 事件给当前 Endpoint 前处理这些旧租约：

- `RequestTransmitted` 用 Job/FEP/源 PDC/incarnation 绑定尚未发送的旧消息，记录 EOM（消息末包）的 PSN。
  target PDC 的响应 token 不能绑定一个源端租约；Job0 是有效 Job，与未知 Job 分开表示。
- `TransmitCleared` 只在同连接且 EOM 已发送、串号前沿覆盖末包时回收。普通接收 CACK
  不能替代真实 Clear；迟到的较早片段重传不能把 EOM 前沿退回。
- `ConnectionClosed` 回收该连接的租约；资源准入拒绝只回收已经移除的整条未发送消息。
- 还缺结果数据的 READ 继续等连接退休，避免正向 Clear 过早复用 MID。Host 请求原连接关闭，
  仍由已有 PDS 状态机完成握手与定时器取消。
- UUD 在原有本地发送结果到来时回收。RUDI 保持独立的持久 packet ID 与取消路径，
  不把它混入 PDC 序号或这套 Clear 生命周期。

这个跟踪器不增加定时器，不读取墙钟，也不猜测包是否送达。无限重试且始终丢失的请求
可以继续占用其 ID，直到传输退休或 Host 关闭；资源耗尽会明确返回失败。
正常完成的 ID 在 Clear 后回收，可以反复复用，不为每次历史操作永久保留一个槽。

同一个 PdsHost 同时只绑定一个活跃的原生 Endpoint。重复绑定在改动现有处理器之前失败；
关闭旧对象后可以创建替代对象。Provider 的不同端点仍各自拥有 PdsHost，domain MR 可以共享。

## 验证与仍开放的范围

独立租约测试覆盖 Job0、错误 Job/FEP、target token、连接 incarnation、32位 PSN 回绕、
EOM、Clear/Close、READ 与 UUD。替换回归覆盖 STD/SMALL/MEDIUM，旧请求丢失和正常退休，
并检查重复活跃绑定不会破坏原 Endpoint。新增14个替换/边界场景还强制游标从65535回绕，
确保旧 ID 被真正跳过；65535个 ID 全部仍被持有时，源端明确返回 ResourceExhausted，且不创建 PDC。

首轮7项普通 CTest 全部通过（14.31s），见 `/tmp/softue-ownership-normal-tests.log`，包括
已有消息号复用、资源生命周期、RUDI、同步组与 Endpoint 回归。7项 ASan/UBSan/泄漏回归也全部通过（173.77s），见 `/tmp/softue-ownership-asan-tests.log`。
扩展后的替换/回绕/耗尽测试普通与 sanitizer 分别通过（0.09s、0.70s），见
`/tmp/softue-ownership-wrap-normal-tests.log`、`/tmp/softue-ownership-wrap-asan-tests.log`。
上述验证不作为性能测量，也不宣告完整 M1 或任何 Profile 完成。

本轮首先保护源端消息号/本地 cookie。目标 Endpoint 替换的接收状态与响应 token、未完成
分片在关闭时的 MSG_ERROR 收尾，以及全部跨对象组合仍需独立的负向、回收与故障验收。
