# libfabric 大消息与原生 rendezvous

RDM 的普通 `fi_send` / `fi_tsend` 及其 vector/message/data 形式，在长度达到默认
65536字节时选择原生 rendezvous。eager 上限为1024字节。DATAGRAM、WRITE 和
FI_INJECT 使用各自原路径；inject 仍先复制最多256字节。

这些大小是 provider 策略，不是 UE 规范的固定阈值。libfabric 参数
`FI_SOFTUE_RENDEZVOUS_THRESHOLD` 可在创建 endpoint 前配置：0选择普通 SEND，
正值指定阈值。eager 不超过实际消息长度。与只实现普通 SEND 的参考/其他端点
对照时，选择0可明确限定共同支持的路径；本参数不代替 Profile 协商。

## FI_SEND 为什么没有额外授予 FI_REMOTE_READ

provider 没有 FI_MR_LOCAL 要求。它为大消息创建受限的临时源注册，保存到最终
发送 CQ；仅以隐藏 key 保护它是不够的，因为同 Job 的对端可能猜中数字 key。

`RegionOptions.rendezvous_source_only` 与 `MemoryAccessOrigin::RendezvousSource`
把授权限定在本地事务中：

1. 普通远端 READ/WRITE/ATOMIC 不能访问该注册。
2. 本地 receive/result 放置也不能把它当作普通目标注册。
3. 原生 rendezvous 可以固定该注册的精确身份，并创建只读的、绑定 peer/Job/rank
   的临时视图。扩展头只公布视图 key，原私有 key 不进入报文。
4. 原注册撤销或数值 key 重用不能恢复旧视图。最终成功、错误或提交异常均回收
   provider 临时源注册；原生事务另行撤销自己的视图。

已有 `local_placement_only` 继续只服务于 receive/READ/atomic 结果。两种本地策略
不能同时设置；原生 rendezvous 不能提升普通本地放置 MR 的权限。

这与公开 `fi_mr_reg` 的 FI_REMOTE_READ 授权不同。用户缓冲区在发送 CQ 前保持
有效；不需要用户为了实现大消息 SEND 再授予通用远端 RMA 权限。

## 完成、generation 与 FIFO

大消息保留 FI_MSG/FI_TAGGED、原 context、原 buffer、全长和 tag。目标 header data
仍通过接收 CQ 交付，包括值0；内部 READ 不产生用户发送 CQ。

原生事务负责 eager/READ 双完成、资源退避和单一总 deadline。provider 不在其
最终错误后再开启一轮应用重试。SEND 与 tagged 各自缓存对应资源空间的 generation，
不能误用 RMA generation。相同的 SEND ordering flags 选择 RUD/ROD，应用 FIFO
继续等最早操作最终完成才启动后继，从而维持 FI_FENCE。

接收端使用已有的私有放置注册，内部 READ 固定 posting 的精确身份。取消或错误
之后，迟到包仍按原 PDS 规则排空；不发明远端取消消息。

## 回归路径

- `rendezvous_source_scope_test`：专用源授权、直接 RMA 拒绝、Job/PID/范围、撤销复用、
  外 registry handle 和实际私有源事务。
- `libfabric_rendezvous_test`：通过公开 scalar/vector/message API，验证阈值前后、
  SEND/tagged、RUD/ROD、预投递/迟投递和反向 receive/wildcard/CQ data。
- `libfabric_rendezvous_disabled_test` / `libfabric_rendezvous_threshold_test`：真实配置
  是否改变线上 opcode。
- 原有 `libfabric_recovery_processes` / `libfabric_unordered_recovery_processes` 显式
  配置阈值0，继续验证普通 SEND 的 DISABLED_GEN / NO_MATCH 资源恢复。
- 对应的 `libfabric_rendezvous_*recovery_processes` 单独验证两进程的大消息迟投递、
  恰好一次的总超时错误、错误后复用缓冲区和独立 RMA 继续工作。

这些测试需要在没有编译器或其他CPU实验竞争时顺序运行，避免把调度延迟混成
协议错误。原生事务的两种 READ carrier、故障与内存边界见 [RENDEZVOUS.md](RENDEZVOUS.md)。
本功能不声明完整 Profile、完整安全路径或4 GiB公开 rendezvous传输已验收。

冻结的整合版本 b76e340 在干净工作树中重新配置和构建，开启公开provider及固定参考
实现后，顺序通过全部113项普通回归（123.74s）及全部113项ASan/UBSan/泄漏检查
（565.27s）。两轮运行期间没有编译器或其他CPU实验竞争。日志分别为
`/tmp/softue-provider-rendezvous-clean-normal-tests.log` 和
`/tmp/softue-provider-rendezvous-clean-asan-tests.log`；GitHub run43494936490三项作业成功。
先前2c57040的ASan全套曾在旧60s预算内超时；该失败仍保留在RENDEZVOUS.md，
不能用本轮结果抹去原记录。
