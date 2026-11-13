# libfabric 取回与比较原子

公开入口为 `fi_fetch_atomic`、`fi_compare_atomic`，以及各自的 v/msg形式。所有入口
进入原 `SES::Endpoint`，共用 PDS结果缓存和正常 CMS/网络路径。

| 操作族 | 数据类型 | 元素上限 | 查询 |
|---|---|---:|---|
| 非取回 | 有符号/无符号8～64位整数 | 按16 MiB操作数上限换算 | flags=0 / `fi_atomicvalid` |
| 取回 | 有符号/无符号8～128位整数 | 1 | FI_FETCH_ATOMIC / `fi_fetch_atomicvalid` |
| 比较 | 有符号/无符号8～128位整数 | 1 | FI_COMPARE_ATOMIC / `fi_compare_atomicvalid` |

扩展取回类型不会误报128位非取回或非取回 READ能力。取回允许普通整数运算和
FI_ATOMIC_READ/WRITE；比较允许六种CSWAP条件和FI_MSWAP。不支持的查询清零
size/count，返回 FI_EOPNOTSUPP。两种查询 flags不能同时设置。

`result` 指向一个保持有效直到CQ的应用缓冲区；provider创建私有本地注册，
原生层保存精确注册身份，每次结果放置重新校验。普通原子输入最多复制一个16 B
元素，比较另外保存一个同宽元素，用于语义generation重试。不会把本地指针或
结果注册key发送到网络。v/msg形式最多一个向量、一个远端元素；原子READ可以
省略输入，结果向量仍须明确给出一个元素。

CQ成功等待实际结果放置与正向语义完成。flags为FI_ATOMIC|FI_READ，buf指向结果，
len为datatype的字节数（uint64为8、uint128为16），不是CAS32 B请求长度。错误也保留context、
结果指针与操作flags。私有注册在最终完成/错误时撤销，generation重试继续保留它。

## 掩码转换

libfabric定义 `new=(input & mask)|(old & ~mask)`；UE Table3-27定义
`new=(old & ue_mask)^ue_operand`。provider设置
`ue_mask=~mask`、`ue_operand=input & mask`，逐字节处理整个元素。两个项不相交，
因此按位XOR等价于这里需要的OR。直接复制掩码会使未选中位产生错误。

## 代次与恢复

应用 FIFO在恢复期间保留原队列位置。BAD_GENERATION结果先更新请求代次，等待旧
原生尝试退休后再以新MID重试。成功的数据ACK没有RI-generation字段，所以原生
完成保留获准请求的代次；下一项操作直接使用这个代次。不能在成功后默认为零。

取回ACK丢失由PDS重放已缓存的旧值，不能重新执行SUM/CAS；即使此后目标内存
已被应用改变，原结果也保持不变。FI_FENCE与所有可靠完成等级仍采用已有较强的
串行完成策略。取回/比较拒绝FI_INJECT及远端CQ data，不提供目标原子CQ通知。

`libfabric_atomic_return_test` 经公开fi_*与原生协议对端验证十种整数类型、三种
调用形式、完整整数/比较操作矩阵、128位逐字节掩码、查询边界、错误后继续操作，
以及一次generation恢复后的连续取回与丢失结果恢复。计数按原PSN去重，缓存错误
ACK重放不算新失败。独立的两provider进程也实际执行取回SUM/CAS并检查结果CQ。

当前仍是Linux小端平台的实验provider。浮点/复数、tagged原子、优化头、TSS、RUDI、
RODL以及完整Profile验收独立推进。
