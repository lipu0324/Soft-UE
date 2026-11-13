# softue libfabric 实验适配器

`softue` 是可被 libfabric 2.0 动态加载的 provider。它把公开 `fi_*` 调用映射到
原生 `SES::Endpoint`，继续经过已有 PDS/IPDC/TPDC 内核。网络实验使用无特权 UDP
帧隧道：外层 UDP 的 payload 是完整 Ethernet/UE 帧，可靠性来自 PDS。
此适配器不声明任何 UE Profile 已通过验收。

## 构建和独立进程验证

```sh
cmake -S . -B build/provider -DSOFTUE_ENABLE_LIBFABRIC=ON \
  -DSOFTUE_PROVIDER_LIBFABRIC_ROOT=/path/to/libfabric-2.0-prefix
cmake --build build/provider --target libfabric_atomic_return_test libfabric_read_test libfabric_mode_selection_test libfabric_inject_test libfabric_event_queue_test libfabric_provider_peer libfabric_datagram_peer libfabric_recovery_peer -j2
ctest --test-dir build/provider -R 'libfabric_' --output-on-failure
FI_PROVIDER_PATH="$PWD/build/provider" FI_PROVIDER=softue fi_info -p softue
```

安装前缀包含 `include/rdma` 和 `lib/libfabric.so`；也支持使用已经构建的
libfabric 2.0 源码目录（库位于 `src/.libs`）。普通仿真构建不依赖 libfabric。

`libfabric_provider_peer.c` 只包含公开 libfabric 头文件，没有链接原生 SES API。
两进程测试覆盖插件发现、在 endpoint 创建前注册 MR、实际应用缓冲区写入、
多包 WRITE IMM、SEND 往返、READ、取回 SUM/CAS、512 元素的批量整数 SUM、原子能力查询、远端 CQ data、
非法 key 和仅允许本地写的 MR 拒绝远端写。独立的 DGRAM 应用验证 UUD、1 MTU
边界和本地发送完成；不由发送完成推断远端收到。

## 当前接口边界

| 项目 | 当前行为 |
|---|---|
| Endpoint | `FI_EP_RDM` 或 `FI_EP_DGRAM`；每个 domain 一个 endpoint；域间状态独立 |
| 线程和 progress | `FI_THREAD_DOMAIN`、手动 progress；应用串行调用域内 API；`fi_cq_read/readerr` 推进 socket 和协议定时器 |
| 消息 | `fi_send/recv/senddata`、单 iovec 的 `sendv/recvv`、`sendmsg/recvmsg`；SENDMSG 支持逐调用 `FI_REMOTE_CQ_DATA`；ROD 允许后投递接收缓冲区 |
| 长度和缓冲区 | RDM 宣布最大消息为 4 GiB−1；SEND/WRITE 按需读取应用缓冲区，应用须按 libfabric 规则保持其有效且稳定直到完成；原子查询上限单独返回 |
| RMA | `fi_write/writev/writemsg/writedata` 和 `fi_read/readv/readmsg`；实际注册的 host 缓冲区；地址是 MR 内的零基偏移 |
| 原子 | 非取回 `fi_atomic/atomicv/atomicmsg` 支持8～64位整数；`fi_fetch_atomic`、`fi_compare_atomic` 及单 iovec 的v/msg入口支持8～128位整数，限一个元素；查询返回各自上限 |
| DGRAM | SEND/RECV 映射到 UUD；最大 1024 字节；支持 SEND CQ data；仅本地发送完成，无 PDC/确认/重传 |
| 完成 | CONTEXT/MSG/DATA CQ；可靠成功依据整条消息语义完成；WRITE IMM 产生独立远端 CQ data；SEND data 使用原接收 posting 的 CQ/context |
| 访问权限 | `FI_REMOTE_READ/WRITE` 分别授予远端读/写；仅 `FI_READ/WRITE` 不授予远端访问；撤销使 key 立即失效 |
| 地址和 key | `FI_AV_TABLE`、`FI_AV_UNSPEC` 按 TABLE 处理、数值 IPv4 `FI_SOCKADDR_IN`、provider 分配的 64 位 key |
| 消息排序与传输模式 | 按 §2.2.6 / 表 2-29 分别计算 SEND 排序和 R/W 排序；SEND、READ/WRITE/ATOMIC 各自选择 ROD 或 RUD；DGRAM 使用 UUD |
| 注入 | SEND/WRITE/非取回 ATOMIC inject API 和逐调用 `FI_INJECT`；`inject_size=256` 字节；成功抑制与异步错误按 API 规则分别处理 |
| 控制事件 | 非阻塞 EQ 的实际 FIFO/PEEK/背压、endpoint 绑定和父子生命周期；见 [EQ](PROVIDER-EQ.md) |
| 资源生命周期 | 父对象仍有子对象、AV/CQ 仍被 endpoint 绑定、endpoint 仍有未完成发送时，关闭返回 `FI_EBUSY` |

`mr_key_size=6` 表示标准 RKEY 的 48 位范围；`fi_mr_key()` 仍返回完整 64 位 key。
注入的缓冲区所有权、默认 flags、大小上限和语义重试见 [注入路径](PROVIDER-INJECTION.md)。
`FI_MR_PROV_KEY` 模式下会保留请求的 IDEMPOTENT_SAFE 标志，OPTIMIZED 回退为零。

`fi_mr_reg`、`fi_mr_regv` 和 `auth_key_size=0` 的 `fi_mr_regattr` 按 §2.2.4.3.3
注册为 any JobID。当前 endpoint 选用的 JobID=1 不会把 MR 隐式缩窄为只允许 Job1。
目标仍逐次校验 key、权限、边界和撤销状态。非零 auth key、AV auth key 与完整
特权 JobID 配置接口尚未实现。

自动创建的接收/READ/取回结果注册使用 `local_placement_only`：应用提交的本地
posting/operation可授权放置，直接远端RMA访问被拒绝。这不增加线格式key位，
也不扩大公开MR注册授予的远端权限，见[本地放置权限](LOCAL-PLACEMENT.md)。

`fi_getinfo` 保留调用者请求的已支持排序 flags；显式零排序使用 RUD。没有提供
排序 hints 时保留 SAS 默认。SEND 排序 flags 为 RAS/SAR/SAS/SAW/WAS；R/W
排序 flags 按 §2.2.6 的单独列表解释，交叉排序 flag 可以同时参与两种判断。
可用的 READ/WRITE/取回与非取回 ATOMIC 通过源端应用 FIFO 提供整消息的 RAW/WAR/WAW，
三个 `max_order_*_size` 均为 UINT32_MAX。后续 WRITE 必须等待前序 READ 的实际
结果放置及全部正向语义结果，避免丢失数据 ACK 后重执行 READ 读到这个后序 WRITE
的值（§3.4.2.7.1.2）。这不为其他端点的并发写提供整消息快照。源端应用队列串行
等待前操作的语义完成，为跨模式的混合操作提供保守的 fence。`sendmsg`、`readmsg`、`writemsg`、
`atomicmsg` 支持逐调用 `FI_FENCE`，能力查询保留默认 fence flags；DGRAM 的
fence 等待先前的本地发送完成。该队列也等待其他 peer 的在先操作，属于更强的
串行策略，会限制并发度。

`libfabric_mode_selection_test` 通过公开 `fi_*` API 向原生协议对端发起操作，
独立提取实际帧的 PDS type 和 SES opcode，检查四行排序矩阵及交叉排序 flags。
其中的晚到 receive 场景检查 NO_MATCH 语义重试仍在 fenced WRITE/ATOMIC 之前。
同一用例用三个公开 MR 注册入口验证不同 JobID 的绝对寻址授权，同时检查 key 撤销
和缺少远端写权限时内存不变。它补充现有两个公开 libfabric 进程的测试路径。
原生应用 key 的作用域和本地撤销身份见 [MR key 说明](MEMORY-KEYS.md)；provider 的
应用分配 key 模式仍未公布。

外层 socket 的端口号在本适配器内用作该端口存活期间的 FEP 数字 ID，内层地址由
`PdsHost` 生成。这是明确的实验地址映射，不是 UE 地址发现协议。同一实验中的对端
端口号必须唯一；相同 ID 映射到不同 socket 地址会被拒绝。通过 `fi_getname` 获取
实际分配的地址，再加入对端 AV。实验不要求 root 或 raw socket。

READ 使用[原生 READ](READ.md)的两条返回路径。当前 provider 无 FI_MR_LOCAL 要求，
为每个非零结果缓冲区建立私有本地注册，完成/错误时撤销；该 key 不上线，应用仍须
保持缓冲区有效直到 CQ。单 iovec 的 `readv/readmsg` 与 `read` 使用相同入口。
READ 拒绝 FI_INJECT 和 FI_REMOTE_CQ_DATA，DGRAM 不公布 READ。公开 API 回归
`libfabric_read_test` 覆盖 RAW/WAR 链、两种返回载体的丢失恢复、长度边界、远端权限
和边界错误、错误后继续 READ，以及 CQ flags/context/buffer/length。

取回/CAS 使用[缓存原结果的原生路径](FETCHING-ATOMICS.md)。结果缓冲区采用与 READ
相同的私有本地注册与精确身份校验，完成 CQ 为 `FI_ATOMIC|FI_READ`，`buf` 是结果
指针、`len` 是 datatype字节数。CAS的32 B请求不增加本地结果长度。`FI_ATOMIC_READ`
忽略输入 buffer；v/msg入口也允许省略该输入向量。取回与比较拒绝 FI_INJECT及
FI_REMOTE_CQ_DATA，DGRAM不公布原子能力。`FI_MSWAP` 的掩码与操作数逐字节转换为
UE公式，详见[公开原子接口](PROVIDER-FETCHING-ATOMICS.md)。

浮点原子、tagged、directed receive、
多 iovec、自动 progress、等待对象和选择性完成尚未实现，不会在发现结果中宣称这些
能力。未实现的方法返回明确错误。接收截断产生 `FI_ETRUNC`，`len` 表示已放置字节，
`olen` 表示未放置的原消息字节；当前 SEND 截断采用零字节放置策略。独立进程测试同时
验证发送端错误、接收端错误 CQ 和后续消息交付。更多 operation flags、完整 MR key
类别和 API 验收仍属于 M3；当前测试不代替 libfabric 全套一致性验收。

RDM 支持 INJECT_COMPLETE、TRANSMIT_COMPLETE、DELIVERY_COMPLETE，并选择更强的
GO 完成点；DGRAM 支持前两种，采用本地发送完成。完成等级、DC 和 fence 的关系
见 [完成语义](PROVIDER-COMPLETION.md)；完成等级不是最早 CQ 时刻的性能保证。

## Unexpected message 与恢复

原生 SES 默认最多为 ROD unexpected messages 预留 256 KiB 逻辑容量，按接收顺序匹配
随后投递的缓冲区。预留容量包括尚未到达的片段，避免依靠稀疏零数据绕过容量限制。
缓冲耗尽时，SEND Resource Index 被禁用并返回 `RC_DISABLED_GEN`；投递新的接收资源后，
该 index 的 generation 增加，再重新启用。已接受消息可继续排空，RMA index 不受 SEND
index 的禁用影响。RUD 不使用此有序缓冲策略，未匹配时返回 `RC_NO_MATCH`。

provider 对 `BAD_GENERATION`、`DISABLED`、`DISABLED_GEN` 和 `NO_MATCH` 执行最多八次
语义重试；资源错误使用 1～100 ms 的有界指数退避，generation mismatch 可立即重试。
每次必须先等待旧原生尝试的 EOM/Clear 退休，再分配新 Message ID。应用在这期间继续
保留原缓冲区，只收到一次最终 CQ 完成。当前实验适配器串行准入应用操作，保证后来的
有序 SEND 不会越过正在重试的最早消息；PDS 仍独立承担包窗口、确认、重传和去重。
这是一项保守的准入策略，会限制 provider 的并行度；原生多流仿真不使用该策略。

`libfabric_recovery_processes` 显式请求 SAS，使用两个只调用公开 `fi_*` API 的进程，
验证延迟接收的 512 KiB SEND、后续 SEND 的顺序、隐藏中间恢复错误、重试上限，
以及 SEND 资源禁用后仍可完成独立的 RMA。`libfabric_unordered_recovery_processes`
显式使用无排序 hints，验证 RUD 的同一恢复流程；最终错误是 NO_MATCH，ROD 的
资源耗尽则为 DISABLED_GEN。两个用例保留各自准确的错误码检查。
原生测试另验证部分消息已缓冲时投递接收、
generation 返回值、旧尝试的退休约束和 PDC 失败时的部分接收错误 CQ。

## 阅读代码的顺序

1. `get_information()` 描述应用可依赖的能力；不要按函数指针是否非空推断支持范围。
2. `register_memory()` 把本地指针封装为受检存储；线上仍只有 key 和偏移。
3. `submit_operation()` 把 SEND/WRITE 转成原生操作，并保留应用 context。
4. `progress()` 驱动同一协议内核，再把原生完成转换为 CQ entry 或 error entry。
5. `close_object()` 检查父子关系并依次关闭 SES、PDS 和端口，取消其定时器。

整数原子操作目前只在 little-endian 主机平台上公布能力；标准线格式中的操作数逐元素
转换为 network byte order，注册缓冲区中的整数保持本机表示。官方参考进程的 SUM
测试独立验证这一边界；普通 SEND/WRITE 数据不进行这种转换。

`Runtime::Trace` 在 provider 中显式关闭，避免长期应用累积实验轨迹。独立仿真仍保留
有上限的结构化 trace；文本协议诊断可通过 `Services::diagnostic_output` 接入流。

SEND/WRITE 的 CQ data 路由、零值数据和 deferrable 兼容接收见 [SEND-HEADER-DATA](SEND-HEADER-DATA.md)。
