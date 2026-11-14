# 原生 RMA 的 Use-once 缓冲区

UE 1.1 §3.4.2.6.1 要求一条消息选中 use-once 缓冲区后，其他消息不能再访问它，
原消息仍能完成所有访问。表3-3要求 HPC 支持 RMA 的这种行为；§3.4.4.1将
use-once/persistent 选择放在每个缓冲区上。

原生 API 通过 `RegionOptions::use_once=true` 注册这种缓冲区，默认仍为 persistent。
`EndpointCapabilities::use_once_rma` 表示这个原生接口能力。公开 libfabric2.0 API
没有提供对应的标准扩展入口，因此这里不宣告 provider 的 use-once 扩展或 HPC 完成。

## 授权如何跨越分片与重执行

目标 SES 第一次处理 RMA 时，先对完整操作范围检查 Job、PID、RI、key、访问来源、
权限和边界，再领取注册表中的授权。`RmaMessageOwnerToken` 是本地逻辑消息能力，
不编码到线上，也不使用来自远端的地址。共享注册域的所有 Endpoint 共用同一张
授权表，所以其他 FEP 上的消息也不能绕过独占规则。

`Incoming::rma_registration` 固定具体注册实例，`rma_owner` 固定消息所有者。
后续 WRITE 分片、整数原子分片以及 READ 访问重新检查这个注册实例；应用撤销后
复用同一数值 key，不会把旧消息重新绑定到新缓冲区。同步原子在组屏障后也使用
原授权。当前原生整数原子操作一并遵守这种独占规则。

RX handle 表示一次接收执行，而非逻辑消息。§3.5.17 的 ACK-data READ 在丢包后
可能再次执行，得到新的 RX handle，并读取原注册中的较新数据。它必须沿用原消息
能力。反向 return-data 和 fetching atomic 继续使用现有 PDS 重传/结果缓存规则。

## 授权何时消耗和回收

只要另一条消息尝试访问已领取缓冲区，即使访问不重叠或长度为零，也会收到
`BadMemoryKey`；内存不会改变。失败的 scope、权限和边界检查不会领取授权。
`IDEMPOTENT_SAFE` 元数据不取消独占要求。无消息所有权的 RUDI 路径不能领取或使用
这种授权，拒绝后缓冲区仍可供可靠 RMA 使用。

缓冲区在最后一次数据 ACK 后仍保留给原消息，直到实际 EOM Clear 或连接关闭。
此时 `finish_rma_registration` 撤销精确注册身份。Endpoint 关闭会立即撤销其持有的
use-once 授权，旧续包由 Host 的退休消息状态拒绝。应用存储对象的生命周期独立于
远端授权，已持有的 `Region::storage` 仍可供应用检查结果。

注册表保留所有者的弱控制块。调用者错误地丢弃所有者而未退休，不会使授权重新可用。
显式撤销注册或移除 Job 会清理对应记录；旧消息退休不会撤销复用 key 的新注册。
这些操作遵循当前单线程注入事件运行时的串行执行约束。

## 回归入口

- `use_once_memory_test`：完整范围、独占、零长度、撤销、key复用、过期所有者、
  Job/PID、权限、persistent行为和 idempotent 元数据。
- `use_once_rma_test`：124种真实 SES/PDS 场景，覆盖 STD 多分片、SMALL/MEDIUM、
  RUD/ROD、NSCC、两种 READ 载体、结果丢失、WRITE/整数原子、零长度及 RUDI 拒绝。
- `use_once_rma_lifetime_test`：16种共享注册域场景。第一条 WRITE 未完成时，
  其他 FEP 的消息被拒绝；随后验证完整执行、源/目标关闭、撤销和注册替换。

最终构建、消毒器和完整回归结果需按具体提交另行记录；本文不作为全部 M5 的验收。

固定版本 `36215503334cbbd6223430a014246315730c8418` 已完成全部158项回归：
普通构建158/158，127.04秒；ASan/UBSan并启用泄漏检查158/158，711.79秒。
完整构建启用公开 provider 和固定独立参考，源码保持干净冻结，测试以 `-j1` 顺序
运行且没有并行编译。报告 `/tmp/softue-use-once-362-full-report.json`，完整日志
`/tmp/softue-use-once-362-full-{normal,asan}-tests.log`。这些结果不覆盖后续 tagged
atomic 或优化同步组增量，也不是整个 M5/Profile 的完成声明。
