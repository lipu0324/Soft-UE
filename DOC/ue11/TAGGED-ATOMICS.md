# Tagged 整数原子操作

UE 1.1 表3-1要求 HPC 支持 tagged atomics。§3.4.2.5.4 将其原子性范围绑定到
`{FA, JobID, PIDonFEP, Resource Index, Matching Criteria}`；表3-23给出
`UET_TSEND_ATOMIC=0x0d` 和 `UET_TSEND_FETCH_ATOMIC=0x0e`。

原生 `OperationType::TaggedAtomic` 与 `TaggedFetchingAtomic` 使用 `Operation::tag`
选择接收 posting，不使用 tag 查找 MR key。整数运算复用既有整数执行函数：非取回
支持8～64位元素及多分片，取回/CAS支持一个8～128位元素和既有32字节双操作数格式。
STD 和单包 MEDIUM 均可使用；表3-21禁止 MEDIUM tagged atomic 的缓冲区内偏移，
SMALL 不携带 tag，因此这两个不合法组合在本地提交时拒绝。

## 缓冲区选择和内存效果

普通 tagged SEND、tagged non-fetching atomic 和 tagged fetching atomic 共用
tagged posting FIFO、64位通配位规则和 Job 范围的 initiator 匹配。一个 posting
只被消费一次。选中后保留精确注册身份；撤销并复用数值 key 不会授权旧消息。
STD 的 `buffer_offset` 是相对于 posting 起点的偏移，再叠加消息分片偏移。
检查 posting 范围和实际原子地址的对齐后才执行内存操作。

RUD 无匹配时返回 `NO_MATCH`。ROD 使用现有有界 unexpected 队列，保存操作数，
待 posting 到达后再执行；fetching 操作保留真实 EOM RX handle。所有匹配种类
共享到达次序。权限仍要求读、写及原子三项。已投递的私有缓冲区通过本地 posting
授权访问，普通远端 RMA 即使知道其数值 key，也不能获得这种权限。

PDS 将 tagged fetching 与普通 fetching 一样视为需要数据 ACK 的操作：结果不能
由 DEFAULT 或累计 ACK 推断，也不能像 READ 一样在丢失后重新执行。唯一旧值缓存
一直保留到真实 Clear。目标接收完成与源返回完成都按实际数据类型宽度报告长度；
CAS 的32字节线端操作数长度单独保存在目标完成的 `original_length`。
零长度 GET 执行一次授权后的零字节读取；零长度 PUT 不调用存储写函数。

## libfabric 映射

`fi_atomicmsg`、`fi_fetch_atomicmsg`、`fi_compare_atomicmsg` 的 `FI_TAGGED` 标志
选择上述原生操作。遵循 libfabric2.0 `fi_atomic(3)`：`rma_iov.key` 是 tag，
`rma_iov.addr` 是 posting 内从零开始的字节偏移。`fi_query_atomic` 支持单独
`FI_TAGGED` 以及与 FETCH/COMPARE 查询标志组合；FETCH 与 COMPARE 同时设置仍拒绝。
其他 API 的允许标志没有因此增加 `FI_TAGGED`。

tagged 接收的私有 MR 允许通过已选 posting 执行原子读写，仍带
`local_placement_only` 来源限制。源 CQ 标志保留 `FI_ATOMIC|FI_READ/WRITE|FI_TAGGED`，
目标 CQ 标志保留其投递操作的 `FI_TAGGED|FI_RECV`。tagged 资源代次与 RMA 资源
代次分开缓存；传输模式继续按原子操作的 R/W ordering 选择，应用 FIFO 仍提供 fence。

## 验证入口与范围

- `tagged_atomic_header_test`：80个 STD/MEDIUM 扩展黄金样例，IPv4/IPv6、native/UDP、
  CRC、片段标志和截断；不使用编码器产生预期扩展字节。
- `tagged_atomic_test`：216个原生事务，包含通配/rank、私有 posting、多分片、
  非零资源代次、延迟投递和丢失后的唯一结果重放。
- `tagged_atomic_boundary_test`：80个拒绝场景、9个零长度场景和6个不支持格式的本地检查。
- `libfabric_tagged_atomic_test`：两个公开 provider 端点，验证 tagged atomic/fetch/CAS、
  inject 副本、普通 tagged SEND、类型查询及私有 key 的 RMA 拒绝。

原生初步普通回归13/13通过；最终提交的消毒器、公开 API 与完整回归结果仍需另行记录。
独立参考尚未声明支持这些操作，本文不宣告 tagged atomic 参考互操作、完整 M5 或 HPC 完成。
