# Scale-out优化语义头

本轮接通显式选择的原生单包事务。§3.4.3.2的SMALL/MEDIUM适用于单包消息，
均用14位request_length替代标准头中的MID；数据返回还可以用Table3-18的优化格式，
通过original_request_psn关联原请求。它们不等同于M8的Unified Local压缩头或消息打包。

| 格式 | 线宽 | 主要差异 |
|---|---:|---|
| REQUEST_SMALL，Figure3-15 | 20B | 不携带MID、matching字段及header data；hd位保留 |
| REQUEST_MEDIUM，Figure3-16 | 32B | 不携带MID，保留initiator及match_bits/memory_key；地址与header data共用一个64位槽 |
| RESPONSE_DATA_SMALL，Table3-18 | 12B | 无MID、modified_length、offset；有原请求PSN；有数据时payload_length也表示modified length |

已直接渲染并核对规范PDF第224与226页（index223/225），图为
`/tmp/ue-optimized-small-header.png`、`/tmp/ue-optimized-medium-header.png`。
不能把MEDIUM误写成SMALL加两个独立的64位地址和header-data字段。

旧占位结构把请求长度位置命名为msg_id，并把JobID拼作jod_id。现在按规范字段命名，
用本地字段容器保存值，再由UetWireCodec显式编码；C++结构体尺寸和位域布局不是线ABI。
MEDIUM的union只表达同一个槽的两种名字，不授权任何内存访问。

原有STD以及新SMALL/MEDIUM共用操作扩展编解码。atomic、synchronized group及其组合
仍按各自规范次序紧跟基础头。原有RNDV/同步/RUDI/legacy codec回归核对该整理没有
改变既有报文；不将“能够编码扩展”当作该操作的优化事务能力。

## 请求、响应与内存授权

`Operation::header_format` 默认 `Standard`，可显式选择 `Small` 或 `Medium`。
当前选择范围如下；能力字段逐项公布，四种 Profile 仍未通过完整验收。

| 原生格式 | 已接通操作 | 约束 |
|---|---|---|
| SMALL | NOOP、WRITE、整数 atomic/fetching atomic | RMA key 必须是 OPTIMIZED 类，低12位索引置于线上 RI |
| MEDIUM | NOOP、WRITE、整数 atomic/fetching atomic、SEND、tagged SEND | 保留完整 key/match_bits；SEND 可携带立即数 |
| 两者 | RUD、ROD；NSCC 开或关 | SOM=EOM=1，消息不超过配置的 Payload MTU（最大8192） |

RMA 立即数、READ、tagged/浮点 atomic、Sync Group、RUDI/UUD 优化请求及反向通道的优化 READ 数据响应尚未接通；fetching atomic 已在 ACK 中使用 DATA_SMALL。
源端拒绝不支持的组合；接收端独立验证格式和操作，不能依赖可信源端的 API 检查。
Table2-14/15 的 RMA 选择条件排除 FI_REMOTE_CQ_DATA，而 §3.4.3.2 正文还讨论立即数；
当前保守关闭该组合，MEDIUM SEND 的 header data 共用槽则实际验证。
Legacy SUP1 端点不公布这些标准格式能力，也不公布标准 RUDI 能力。

一次事务有三种不同身份：

1. 应用 operation ID：关联应用上下文和一次完成事件。
2. 源端本地提交句柄：保存在 PDS 发包元数据中，在线上不存在。PDC 在确切 PSN 的
   ACK 路径上把它带回 SES；线上语义响应 MID 必须为0，不能把本地句柄写进报文。
3. 原请求 PSN：区分目标端同一连接上的多个无 MID 单包消息。目标 SES 的消息键包含
   对端、本地 PDC、Job、initiator、标记后的完整32位 PSN 和连接起始 PSN，避免与 STD MID0 混淆。

`SemanticRequestFields` 是固定字段的内部视图，不是另一套线格式。PDS 准入及上交 SES
时投影字段并保留原格式；原始编码、扩展和 payload 所有权仍走已有协议内核。
源端完成适配只在本地补回提交句柄，再由现有逻辑检查 FEP、PDC incarnation、Job、未完成 PSN。
DEFAULT 推断、重传、恰好一次放置和 Clear 回收继续由现有 PDS 负责。

fetching atomic 的成功结果使用 DATA_SMALL12B。PDS 同时核对 ACK 指向的 PSN 和
`original_request_psn`，然后从该确切请求恢复本地省略字段；双操作数请求为32B，返回
`payload_length` 仍是一个数据类型的宽度（最大16B），不能把32B当作返回值或目标 MR 访问宽度。
SMALL 请求的全尺寸 DATA 响应被拒绝（Table3-21）。所有取回结果保留在原有 PDS 保证交付缓存
直到 Clear，不能因 DEFAULT/CACK 到来而假定数据已交付，重传也不能重新执行非幂等原子。

SMALL 省略 key 的 IDEMPOTENT_SAFE 等元数据。目标先按 Table2-47 的 Job/PID/index
作用域查找实际注册 key，再用原有 WRITE/atomic 授权路径检查权限、存活注册、资源代次及区间。
索引解析不授予访问权限；绝对寻址不能借 Job 在多个相同索引间任意选一个。
应用可注册 OPTIMIZED key，显式 RI 必须等于 key 索引；自动分配优化 key 尚未实现。
收到的地址始终是经过 MR 检查的偏移，不能成为宿主指针。

例如，注册 `MemoryKeyFormat::Optimized | 3`，配置 PID1/RMA RI3 后，SMALL WRITE
可以向该区域写入一个不超过 MTU 的消息。MEDIUM WRITE 则携带完整 key，按通常资源选择规则访问。

## 事务回归范围

- `optimized_transaction_test`：88组零长度、1/73/MTU长度、两种模式、NSCC、idempotent 元数据、
  完成上下文、SEND 立即数及 tagged rank/tag；捕获真实线包核对请求无 MID、响应 MID0。
- `optimized_fault_test`：144组请求/响应丢失、重复、乱序、Clear 丢失，每组同连接8个事务；
  计数实际 MR 写入，核对数据与每次唯一完成，包括不能重复执行的 SUM。乱序延迟发生在实际 MAC 发出之后。
- `optimized_atomic_test`：800组固定算术向量，8种整数类型×12种操作×两种格式/模式/NSCC；
  加上 MTU、零字节 WRITE 与独立接收端权限/对齐/范围/操作控制拒绝。期望结果不调用实现的算术 helper。
- `optimized_fetching_atomic_test`：1664组双格式、RUD/ROD、NSCC、10种整数类型和20种操作，
  另含零字节操作、丢失/重复结果、缓存旧值、目标撤销、源端旧 MR 身份及错误 PSN/Job/DEFAULT。
- `optimized_fetching_concurrency_test`：40组同连接8个独立返回缓冲区；注入结果丢失、重复、
  延迟及不相符原请求 PSN，按实际原子写入次数检查恰好一次执行。
- `optimized_safety_test`：62组 Job/PID/索引、代次、权限、私有注册、撤销、绝对歧义，
  Job/PID/index零及index4095、UINT64_MAX区域末端、8192B与源端拒绝、legacy能力。
- `optimized_malformed_test`：28组绕过 Endpoint 的缺 SOM/EOM、超 MTU、未支持 READ、
  initiator error、长度不符，以及本地 payload reader 抛错后的单次失败和回收。
- `optimized_admission_test`：6组 RUD/ROD 的真实无 MID 准入资源拒绝，以及优化数据响应入口围栏。

源端本地 reader 失败仍用既有 STD MSG_ERROR 终止路径，避免生成半个优化消息。
这些检查不构成通用 Endpoint 替换/关闭安全的全部证据；该生命周期范围需单独验收。

## 证据与参考限制

`optimized_header_test`有120组独立字节向量：SMALL/MEDIUM的WRITE/READ/atomic/fetch/
同步扩展、MEDIUM SEND以及带数据和无数据优化响应，组合IPv4/IPv6、UDP/native、CRC。
另检查0/8192/14位最大值的字段保存、非法编码、保留位、版本及逐字节截断。14位字段
能保存16383不代表原生接口接受超过8192的Payload MTU；语义准入是另外的工作。

线格式阶段七项普通检查全部通过（1.30s），七项ASan/UBSan/泄漏检查全部通过（2.45s），日志为
`/tmp/softue-optimized-wire-tests2.log` 与 `/tmp/softue-optimized-wire-asan-tests.log`。
检查期间另有完整版本构建，因此这里只作为功能证据，不作性能或实时调度结论。

新增事务/故障/权限/准入四项检查普通全部通过（0.53s），ASan/UBSan/泄漏全部通过（3.65s），
日志为 `/tmp/softue-optimized-expanded-normal-tests2.log`、`/tmp/softue-optimized-expanded-asan-tests2.log`。
其后增加的畸形/reader失败28场景普通通过（0.02s），见 `/tmp/softue-optimized-malformed-tests.log`。
这些是开发树的定向证据，提交后的完整普通和 sanitizer 集成检查另行记录。

整数非取回原子扩展的四项定向普通检查通过（1.58s），见 `/tmp/softue-optimized-atomic-tests.log`；
800组独立算术/拒绝场景与扩为144组的故障矩阵均通过。该次检查期间另有构建，只作功能证据；
新增原子路径的 sanitizer 及 STD 原子集成检查尚在执行。

固定5b4e049的 `util/uet_util.c` 在解析next_hdr时，把REQ_SMALL、REQ_MEDIUM和
RSP_DATA_SMALL直接送到err_exit；未修改它的源码或shared library来扩大对照范围。
现有48项独立parser/CRC比较仍通过，用于保护其他已实现格式。这不构成优化头正向
参考解析或事务互通证据，也不构成任何Profile验收声明。

优化 fetching 的首轮四项普通回归通过（5.52s），包括1664个新场景及标准头 fetching 回归，
见 `/tmp/softue-optimized-fetch-tests.log`。并发与 sanitizer 证据待其执行完成后补记；
期间存在其他构建，因此上述耗时只记录测试运行，不作为性能结果。
