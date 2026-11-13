# 取回原子与 CAS 的职责边界

`OperationType::FetchingAtomic` 是标准 opcode0x04，沿原 SES→PDS→CMS→网络路径
执行，不用第二套可靠传输或直接读取另一端的 C++ 对象。

## 原生提交接口

`atomic_datatype` 选择8/16/32/64/128位有符号或无符号整数；`payload` 是一个本地
小端整数操作数。`atomic_operation` 选择普通运算、原子 READ/WRITE、条件交换或
掩码交换。双操作数交换另外用 `atomic_compare` 提供一个同宽的 compare/mask。
`atomic_result` 是 `AtomicResultBuffer{key,offset,capacity,pid,resource_index}`，
仅指定本地注册结果缓冲区，不进入线格式。提交与每次结果放置都验证本地注册
身份；撤销或重用 key 不会授权旧操作的结果。

原子 READ 可以省略输入 `payload`，入口补一个零元素以符合标准请求格式。
取回操作不能使用惰性 payload reader、immediate data 或多个元素。目标偏移必须
按 datatype 对齐。非取回 `Atomic` 仍使用独立的8～64位多元素能力列表；扩展取回
数据类型不会隐式公布128位非取回能力。Profile 标志保持 false。

## 线格式与内存事件

§3.4.3.5 要求每个取回请求只操作一个元素。普通取回 payload 的长度是 datatype
宽度；所有 CAS/MaskedSwap 固定使用两个16 B字段，compare/mask在前，swap在后，
因此 `request_length` 恒为32。小于128位的数据放在各字段的低位字节，发送端把
其余高位填零。整数在线上为大端，本地模拟内存为小端。

`MemoryRegistry::fetch_atomic_element` 在一个不可分割的事件中完成权限、范围、
对齐检查、读取和更新，返回更新前的一个元素。需要 MR 的 Read、Write、Atomic
权限。128位计算采用逐字节进位、借位与乘法，不依赖宿主对齐、宿主端序或非标准
128位 C++ 类型。原子性范围是这个事件及所选择的注册区域，不提供整消息快照。

条件交换沿 libfabric 操作定义，以 compare 操作数为比较左侧。例如 LT 判断
`compare < target`。UE Table3-27 的掩码交换公式是
`target = (target & mask) ^ operand`，与 libfabric `FI_MSWAP` 的掩码约定不同；
将来映射该 API 时必须转换，不能直接复制掩码。

## 原结果缓存与恢复

§3.5.17 要求取回结果始终进入数据 ACK，独立于 READ 的 `Max_ACK_Data_Size`，并
支持至多16 B结果。PDS 给 ACK 设置 REQ_CLEAR，并保留原结果直到收到 Clear。
收到重复原请求或 ACK Request 后重放缓存的 ACK；目标 MR 即使已改变或撤销，
也不能再次执行原子操作。SES 不保留第二份结果副本。

这与 READ 的无结果缓存重执行策略不同。DEFAULT 或严格更大的 CACK 不能替代
取回数据；源端逐项验证原 PSN、JobID、MID、连接代次、offset、原请求长度和
结果长度。CAS 的 ACK `modified_length` 为32，但 payload与本地完成长度为一个
datatype元素。成功完成还要求 EOM已发出、正向语义结果齐备、本地结果实际放置。

数据 ACK 不携带 RI generation。完成保留原请求获准使用的 generation，避免
provider在非零代次的 READ/取回操作成功后错误地把 peer generation 重置为零。

## 回归范围与未完成项

`fetching_atomic_value_test` 使用独立整数算式、128位边界和固定线格式字节验证
数值处理与 MR 事件。`native_fetching_atomic_test` 经真实原 SES/PDS，覆盖 RUD/ROD、
NSCC、READ ACK阈值为零、各整数宽度、普通取回/CAS/掩码交换、重复和结果 ACK
丢失、错误数据 ACK/DEFAULT、执行后远端修改/撤销、本地结果撤销、远端错误及
非零 RI generation。实际通过结果以生成的验证报告为准。

独立进程的 pinned reference 互通另验证64位取回 SUM和CAS：原值1返回后目标变2，
CAS返回旧值2并把目标变9。参考 SES/PDS/CRC实现未修改，仅使用现有测试 NIC适配器；
128位及更宽操作矩阵不计入这个部分参考实现的互通覆盖。

provider取回/CAS映射、优化头、浮点与复数、tagged原子、RUDI、
TSS及RODL仍需后续各自验收；此接口不代表 AI Full/HPC 已完成。
