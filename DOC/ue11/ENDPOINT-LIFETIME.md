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

本轮首先保护源端消息号/本地 cookie。目标 Endpoint 替换的接收状态与响应 token，以及全部跨对象组合仍需独立的负向、回收与故障验收。
未完成分片的源端收尾进展记录于下节。

## 未完成分片的关闭收尾

新增负向 probe 证实：在复制完第一小段后关闭源 Endpoint，原生产者会被清除，目标却
永远等不到 EOM，源端退休表也没有终止 PSN。日志
`/tmp/softue-endpoint-close-before-tests.log` 记录目标消息/源租约未退休。该测试把 PDS
本地包容量与生产者窗口都限制为1，确保真的关闭了一条未完成消息。

关闭路径现在先停止已开始生产者的应用数据读取，将其标为 aborting，再调用已有
`feed_submissions(drain_abort_tails)` 生成一个无 payload 的 STD MSG_ERROR 末包。
只为已送入 PDS、尚未结束的可靠消息生成收尾；RUDI 使用原有取消路径。
收尾只绕过本地 payload 生产者窗口，真实 PDS 窗口、CMS 准入、MAC 首位时间和恢复
仍保持原来的所有权。不能通过直接推进 Clear 或伪造应用成功来释放状态。

从未送入 PDS 的排队操作既不生成幽灵 MSG_ERROR，也不占用 Host 退休 ID；Host 已停止时
不再排队收尾。本地 Host 关闭在停止 PDS 后清空退休表，之后关闭 Endpoint 不会重建它。

首个 WRITE probe 修复后通过，见 `/tmp/softue-endpoint-close-after-tests.log`。
正式回归扩为26场景：WRITE/SEND/tagged/整数原子，RUD/ROD、NSCC 开关、READ 的 ACK/反向
通道，以及未启动操作与先关闭 Host 的边界。检查恰好一个零字节收尾、应用 reader 不再
调用、目标只保留已复制的前缀、SEND 错误 CQ、旧 READ 结果不写回已关闭对象，以及消息槽
可被后续操作复用。6项普通回归全部通过（1.68s），6项 ASan/UBSan/泄漏回归全部通过（13.08s），
日志 `/tmp/softue-close-tail-normal-tests.log`、`/tmp/softue-close-tail-asan-tests.log`，包含已有
Endpoint 替换、RUDI、同步组、rendezvous 与流式 payload 生命周期。

`endpoint_close_tail_fault_test` 再加入4组 RUD/ROD 的 MSG_ERROR 丢失与确切错误 ACK 丢失，
普通（0.02s）和 sanitizer（0.10s）均通过，见
`/tmp/softue-close-tail-fault-normal-tests.log`、`/tmp/softue-close-tail-fault-asan-tests.log`。
检查真实重传、零次额外 reader 调用、没有重复放置、后续消息成功及租约/目标槽正常回收。
这仍是定向功能证据；构建负载下的耗时不作为网络或实现性能结果。

## 目标 READ 的接收句柄与响应 token

两个独立负向用例复现了目标替换的问题：

- `/tmp/softue-target-replacement-before-read-tests.log`：已接受的 READ 仍在等待反向确认，
  关闭目标 Endpoint 后 `read_returns_` 被清空，原 READ 的 PDS RX handle 再也得不到语义终态。
- `/tmp/softue-target-replacement-before-token-tests.log`：把反向窗口限制为1，旧 token2 尚在
  PDS 队列中时替换 Endpoint，新 READ 又分到 token2。旧请求随后发出的本地 TX 事件与旧 ACK
  错误地回收新 READ 的返回状态，尽管新数据还没有被确认。

目标关闭现在先为仍持有 RX handle 的 READ 排队 Undeliverable 终态响应，再销毁原生状态。
这是一项明确的本地关闭策略；它不撤回已经发出的字节，也不直接修改 PDS 的确认前沿。
已复制的返回数据仍由原 PDS 发送队列与重传缓存持有，不能包含旧 Endpoint 的存储指针。

响应 token 使用独立的 Host 游标与退休表，与源 MID/local cookie 是不同的命名空间。
Host 只用 target PDC 范围的事件绑定与回收它们；Source PDC 的相同数字不能退休一个
响应 token。原 PDC/连接代次、FEP/Job、EOM PSN、真实 Clear/Close 仍是回收依据。
旧响应占用的 READ packet credit 计入 Host 的接收预算，不能用反复替换对象绕过上限。

`target_endpoint_replacement_test` 通过真实 READ/反向 PDS 路径覆盖 STD/SMALL/MEDIUM、
RUD/ROD。token 隔离场景只接管源语义回调，以便目标关闭错误不会提前关闭共享 PDC；
实际报文、PSN、返回数据与 ACK 仍走原内核。它检查新 READ 的状态在实际新数据确认前
保持存在，随后解除 NIC 背压，检查正常回收。

首轮5项普通回归全部通过（0.57s），日志 `/tmp/softue-target-lifetime-normal-tests.log`，
包括源端替换、关闭分片收尾、优化 READ 事务及并发。对应5项 ASan/UBSan/泄漏回归也通过（5.52s），见 `/tmp/softue-target-lifetime-asan-tests.log`。
随后扩为20个目标替换场景，加入强制 token 回绕、退休响应占用 READ credit、65534个
旧 token 保留时选择唯一空闲 token5；再用独立角色测试核对 Job0、source/target 相同数字、
错误 FEP/代次、未发送响应与32位 PSN 回绕。两项普通（0.15s）与 sanitizer（0.88s）均通过，
见 `/tmp/softue-target-lifetime-boundary-normal-tests.log`、`/tmp/softue-target-lifetime-boundary-asan-tests.log`。
未完成接收消息的跨对象续包、延迟 SYNC action、私有 MR key 的管理代次及没有活跃 SES 时
的排队事件仍需进一步验收，因此不宣告完整 M1。

目标 READ 关闭策略还通过5项普通（0.48s）和5项 ASan/UBSan/泄漏（4.83s）集成检查，
覆盖 rendezvous 生命周期/源作用域、同步组生命周期、READ ACK-data 与提前接受，日志
`/tmp/softue-target-lifetime-integration-normal-tests.log`、`/tmp/softue-target-lifetime-integration-asan-tests.log`。
另一个独立同步原子关闭 probe 已复现未完成 action 的 RX handle 丢失，正在另行修复；
不把上述 READ 结果推广为全部目标端关闭路径通过。

固定、干净的 `fbbe071c763be9252d52a15222a9d535b17e4b86` 已完成140/140普通
（137.52s）与140/140 ASan/UBSan/泄漏（709.98s）完整本地回归，启用 provider 与参考实现，
停止全部编译后按普通→sanitizer顺序执行。报告 `/tmp/softue-ownership-clean-full-report.json`，
日志 `/tmp/softue-ownership-clean-normal-tests.log`、`/tmp/softue-ownership-clean-asan-tests.log`。
该版本含优化 READ/原子与源端身份退休，尚不含后续关闭分片收尾及目标端替换改动。

## 等待同步组的目标关闭

独立 PDS 源先发送完成型原子操作、故意不发送其余组成员，复现了关闭后没有语义
终态的接收句柄；负向日志 `/tmp/softue-synchronized-target-close-before-tests.log`。
另一个 probe 只发送部分操作数，尚未产生 `SynchronizedTargetAction`，同样遗留句柄，
见 `/tmp/softue-sync-close-boundary-before-tests.log`。测试不依赖原生源端“完成型原子最后
发送”的协调策略，因此确实走到目标等待状态。

关闭现在直接为完整 action 与部分操作数保存的每个 RX handle 排队 Undeliverable，
按 PDC、连接代次、句柄与 PSN 去重。首个错误仍使用保证响应，其余按既有 sticky-error
规则响应。关闭不调用正常的组成员处理函数，避免把“取消”计为已处理成员后意外释放
组屏障。尚未执行的操作数不计为修改字节，目标内存保持不变。

完成型 SYNC_WRITE 的放置已被确认，等待的是组通知。因此取消通知只产生一次本地
Cancelled CQ，保留已写字节和 header data；不对已消费的 RX handle 再发送错误。
`synchronized_target_close_test` 与 `synchronized_target_close_boundary_test` 合计16场景，
覆盖 RUD/ROD、NSCC、单/多片段完整原子、部分原子及已放置 WRITE。
六项普通定向回归通过（0.29s），包括原有目标替换、源端收尾及同步组事务/生命周期，
日志 `/tmp/softue-target-actions-final-normal-tests2.log`。这不是全部 M1 的验收结果；
接收端续包替换与没有活跃 SES 的排队工作仍待独立检查。

同一源码提交 `9b41d7f` 的六项 ASan/UBSan/泄漏定向回归全部通过（3.03s），
日志 `/tmp/softue-target-actions-final-asan-tests2.log`。普通与 sanitizer 构建均冻结
Endpoint 头文件后运行；本次仅为定向功能结果，不替代完整 Profile 回归。

GitHub Actions 对 `fc4fd85bd9d8fe4291eafa7ba53f209b6b85d399` 的 run186
（ID43553700539）三项作业均已成功：simulation OFF、simulation ON（sanitizer）
及 reference-wire。该提交包含源端分片收尾和目标 READ 替换，但不包含随后
`9b41d7f` 的同步目标关闭改动；不能把这次 CI 结果标记为后续源码的完整验证。
