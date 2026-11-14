# SMALL/MEDIUM 同步组

UE 1.1 §3.4.3.6 明确允许同步扩展放在 STD、SMALL 或 MEDIUM 基础头之后。
原生单包 SMALL/MEDIUM `SynchronizedWrite` 和 `SynchronizedAtomic` 共用已有的
`SynchronizedGroup`、源重试/完成状态、目标跨 PDC 屏障和真实 Clear 生命周期。
这条路径使用原 SES/PDS/CMS 内核，不建立另一套组协议。

SMALL 的 RMA 资源索引解析、MEDIUM 的完整 key 选择、Job/PID/RI、权限、整段边界、
精确注册身份和非零资源代次检查均沿用普通 RMA。优化头没有线端 MID，消息按原始
PSN 区分；源完成使用 PDS 的本地 submission handle。同步组身份仍按源 FEP 与
16位 group ID 查找，不能把单包的 PSN 当作 group ID。

每个优化消息不超过一个 Payload MTU。普通同步 WRITE 的 group count 为0；
completing atomic 最大8字节、没有 HD。MEDIUM 支持 HD completing WRITE，
包括值为0的 header data；它使用 offset/header-data 共享槽，因此偏移必须为0。
SMALL 没有 HD 字段，不能表示 completing WRITE。格式检查在消费源组成员前进行，
调用者可用同一个本地组 handle 改为受支持的 STD 请求。

本功能只按同步操作条款开放 MEDIUM 的 completing WRITE。普通优化 RMA WRITE
的 CQ-data 映射仍保持既有范围，不以此推断公开 provider 支持优化 CQ-data 标志。
provider 当前仍自行选择 STD 请求。

目标先对实际注册授权，再保存 completing atomic 的操作数与真实 RX handle。
即使它先于其他 PDC 上的 WRITE 到达，也要等整个组到齐后才执行一次。组屏障期间
撤销并复用数值 key 会使旧操作失败，不会修改新注册。WRITE 的 payload 则按原
RUD/ROD 规则及时放置，只有聚合通知等待屏障。结果丢失和重复继续由 PDS 处理，
不会执行第二次聚合动作。

发送长度记账包含基础头、4字节同步扩展，以及 atomic 的额外4字节扩展，随后才是
payload。这些实际字节参与既有 PDS/CMS 路径。线格式的固定扩展顺序已有
`optimized_header_test` 黄金样例，本次增加实际组事务验证。

新回归入口：

- `optimized_synchronization_test`：48种原生组事务，包含 RUD/ROD、NSCC、非零代次、
  completing 顺序、失败成员、SMALL/MEDIUM atomic 和 MEDIUM WRITE 通知。
- `optimized_synchronization_target_test`：32种独立原 PDS 请求生产者场景，completing
  atomic 先在另一个 PDC 到达，验证跨上下文屏障和撤销/复用 MR。
- `optimized_synchronization_fault_test`：84种 WRITE/completing/ACK/Clear 丢失、
  重复和延迟，检查一个聚合动作、一次通知及资源退休。
- `optimized_synchronization_boundary_test`：8个格式拒绝后复用原组 handle 的场景，
  以及4个零长度 completing atomic WRITE。

基线独立探针在 `a363e23ac6e4bb5ec87c77a4f67edcf568c50622` 的协议库上返回
`Unsupported`，日志 `/tmp/softue-optimized-sync-before-tests.log`。
初始 `be5e049` 的4项优化组回归均复现延迟响应句柄丢失原始线格式的问题：
本地 Standard 投影被误当作 MID0 身份，无法找到原 PSN 消息。共享辅助函数现保留
线格式、原始 PDC/PSN 与头元数据，并命名为 `deferred_receive_handle`，同时供
rendezvous 缺口与同步屏障使用。

固定版本 `38de3e414a1f9aee43feb4bc80e33ba9fb8f1da6` 的17项普通回归全部通过，
5.02秒；17项 ASan/UBSan与泄漏回归全部通过，50.80秒。包括上述176个新场景、
既有 STD 同步组、扩展黄金样例，以及9项公开 provider 回归。日志为
`/tmp/softue-optimized-sync-identity-{normal,asan}-tests.log`。当时共享辅助函数
仍使用旧名称；后续命名整理及整个166项集成版本需要新的完整验证。
不能据此宣告全部 M5 或 HPC 完成。

`5c30b3376768bef76c1175ef1e40e192637ce841` 的完整集成验证已完成：普通166/166，
139.75秒；ASan/UBSan及泄漏检查166/166，751.49秒。包括辅助函数命名整理、
原生/公开 tagged atomics 和前述176个优化同步组场景。公开 provider、独立参考均
启用，源码冻结且运行完整测试时没有编译任务。报告与日志同
`/tmp/softue-optimized-sync-full-report.json`、
`/tmp/softue-optimized-sync-full-{normal,asan}-tests.log`。
组完成后的额外成员/合法复用分类、完整最大组及其他适用条款仍需继续复核。
