# 规范候选的人工复核记录

这是 M0 的逐段复核账本，不是完整要求清单。自动提取的 729 条记录是含规范关键词的
候选段落；一段可能有多个义务，也可能只定义术语。表格、图和算法还可能包含未被
提取的要求。下列分类没有把未实现的条件项当作已通过，也不增加 Profile 声明。

来源固定为 UE 1.1；PDF SHA-256 见 `requirements.json`。候选文本来自
`build/ue11-normative-candidates.json`，对应提取文本 SHA-256 为
`1ba84e30bffb069df9ad8b98ea28cab1ec2a474acf3358359700824a69467a4f`。
这里只记录义务的转述与覆盖缺口，不复制整段规范。

## 第 1～20 个候选

| 候选 ID | 章节与分类 | 拆分后的义务及适用条件 | 当前证据与后续处理 |
|---|---|---|---|
| UE11-p0030-001 | §1.1.2，条件性合规规则 | 选择实现的可选功能也应遵循该功能规范。 | `check_requirements.py` 阻止不完整 Profile 声明；逐功能清单仍未穷尽。 |
| UE11-p0030-002 | §1.2.1，术语规则 | 说明大写规范关键词的解释方式，无独立的运行时操作。 | 不把关键词定义计为一个已实现协议功能。 |
| UE11-p0083-001 | §2.2，部署要求 | 提供执行 JobID、配置或密钥管理等特权操作的内核驱动。 | 真实驱动在 ROADMAP 中明确留给后续系统集成；M7 仍需相应管理行为模型。 |
| UE11-p0085-001 | §2.2.2，条件性要求 | 供应商提供 Profile 以外功能时，应允许选择性启用和关闭。 | 已有显式 NSCC/trim 配置；完整特性开关和能力协商未完成。 |
| UE11-p0085-002 | §2.2.2，表格引用 | 分别支持表 2-4 中各 Profile 标记为必选的参数。 | 需要把表 2-4 各单元及脚注独立建项；`API-FABRIC` 仅为粗粒度部分覆盖。 |
| UE11-p0088-001 | §2.2.2.1，条件性要求 | 两端 Profile 有交集时，按最高公共逻辑优先级选择通信 Profile。 | 未实现；当前仅公布 experimental 能力。 |
| UE11-p0088-002 | §2.2.2.1，跨 Profile 条件项 | AI Full/HPC 互通时：限制在 AI Full 操作集；HPC 把 deferrable send 当 SEND；把 deferrable tagged send 当 tagged SEND。 | 必须拆成三项。`send_header_data_test` 与 `tagged_message_test` 已覆盖两类目标接收兼容（含0x0b、全长或NO_MATCH/0）；跨 Profile 协商和操作集限制仍未实现，不能通过整段。 |
| UE11-p0089-001 | §2.2.4，三个授权义务 | 特权实体分配 JobID；把分配结果交给驱动；对用户态提供的 JobID 在硬件上下文验证。 | 本轮模型要保留分配/验证边界；真实驱动和硬件验证不在当前软件实验的证据范围。固定 JobID=1 的实验 provider 不能满足该部署要求。 |
| UE11-p0089-002 | §2.2.4.1，可选方法的条件项 | 若选择作业初始化时分配，则通过控制 API 配置 OS PID/服务名到 JobID 的映射。 | 方法尚未实现；需 M7 管理模型与 provider 映射共同验收。 |
| UE11-p0090-001 | 表 2-8，字段要求 | JobID 映射 flags 的保留位为零。 | 控制 API 编解码未实现；本候选只覆盖表的一部分，仍需单独复核完整表 2-8。 |
| UE11-p0091-001 | §2.2.4.1，多 JobID 条件项 | 一个 OS PID/服务名绑定多个 JobID 时，用 FI_AV_AUTH_KEY 选择操作的 JobID。 | native 多 JobID MR 隔离不等于该 libfabric API；后者未实现。 |
| UE11-p0092-001 | §2.2.4.1，所选分配方法条件项 | 驱动保存特权实体配置的 JobID 映射供后续使用。 | 真实驱动后续集成；软件管理映射仍缺失。 |
| UE11-p0092-002 | §2.2.4.1，基础项与条件项 | 每个 libfabric endpoint 至少一个 JobID；支持多个时通过 fi_av_insert_auth_key 插入其授权键。 | 当前 provider 只有固定单 JobID 路径；授权来源、可配置 JobID 和多键路径待实现。 |
| UE11-p0092-003 | §2.2.4.1，多个属性条件项 | 多键时 auth_key_size=FI_AV_AUTH_KEY；其他情况为 0 或 3；为 3 时 auth_key 携带 JobID。 | 需要分别验证属性接受/拒绝、默认授权与三字节 JobID；目前不能通过整项。 |
| UE11-p0092-004 | §2.2.4.1，HPC 必选项 | HPC 支持 AV JobID 方法。 | 未实现；HPC 能力保持 false。 |
| UE11-p0092-005 | §2.2.4.1，方法条件项 | AV JobID 方法同时支持插入和查询 auth key 的公开 API。 | 两个 API 均待实现和独立进程测试。 |
| UE11-p0092-006 | §2.2.4.2，未选择的可选方法 | 只有开启 fallback JobID 时，才要求从指定环境变量获取 initiator ID，并在缺失时拒绝建 endpoint。 | 当前未开启或宣称 fallback；将来选择此方法时需补正向及缺失变量测试。 |
| UE11-p0093-001 | §2.2.4.3，绝对寻址条件项 | 绝对寻址必须执行该节授权流程。 | `addressing_test`、`memory_key_test` 覆盖 native MR 授权；尚无完整 provider JobID 方法。 |
| UE11-p0093-002 | §2.2.4.3，两个基础选项 | buffer/MR 可分别暴露给一个准确 JobID 或 any JobID。 | native 注册表已有 exact/any JobID 选择；公开 provider 配置和全节授权联合验收待完成。 |
| UE11-p0093-003 | §2.2.4.3.1，间接 JobID 方法条件项 | 该方法下，未标记消息 buffer 仅授权给 SES JobID 匹配的操作。 | native posted receive/MR 有匹配检查；provider 的特权分配到 SES 字段的完整链条仍缺失。 |

## 第 21～40 个候选

这批同时复核了 §2.2.4.3 的上下文及跨页续文。特别是 `any JobID` 不等于
JobID=0，也不能由 provider 固定使用 JobID=1 来替代。

| 候选 ID | 章节与分类 | 拆分后的义务及适用条件 | 当前证据与后续处理 |
|---|---|---|---|
| UE11-p0093-004 | §2.2.4.3.1，direct JobID 方法条件项 | 未标记 receive buffer 使用 endpoint auth_key 中的 JobID 授权，仅接受 SES JobID 匹配的操作。 | direct endpoint auth_key 路径未实现；native MR 检查不代替该映射。 |
| UE11-p0093-005 | §2.2.4.3.1，AV JobID 方法条件项 | fi_recvmsg 带 FI_AV_AUTH_KEY 时，src_addr 表示插入 AV 得到的源授权键，并限制 SES JobID。 | AV auth key 及带该 flag 的 receive 未实现；与后续 p0093-006 是同一条件分支的两个结果。 |
| UE11-p0093-006 | §2.2.4.3.1，AV 方法的 else 分支 | 使用 AV JobID 方法但未用上述 fi_recvmsg/flag 组合时，posted buffer 授权 any JobID。 | 不是所有 JobID 方法下的通用 receive 规则。AV 方法未实现；跨页续文的 directed receive 是可选行为。 |
| UE11-p0094-001 | §2.2.4.3.3，关联 JobID 的条件项 | 需要把 MR 关联到特定 JobID 时使用 fi_mr_regattr。 | 当前 regattr 只接受 auth_key_size=0；特定 JobID 路径未实现。 |
| UE11-p0094-002 | §2.2.4.3.3，regattr 零长度授权键 | auth_key_size=0 的 MR 授权 any JobID。 | 现已接入 `allow_any_job`；`libfabric_mode_selection_test` 通过公开 regattr 零 auth key 验证跨 Job 绝对寻址，并验证权限/撤销仍生效。完整特权配置与相对 Job 映射仍缺失。 |
| UE11-p0094-003 | §2.2.4.3.3，regattr 三字节授权键 | auth_key_size=3 时，MR 关联 endpoint auth_key 中的 JobID。 | 当前拒绝非零 auth_key_size；需要完成分配/验证及对象关联。 |
| UE11-p0094-004 | §2.2.4.3.3，AV 授权键条件项 | FI_AV_AUTH_KEY 时，attr.auth_key 指向 fi_mr_auth_key，包含 AV 与其中已插入的地址；MR 关联该地址的授权键所代表的 JobID。 | 至少拆成结构解释、AV 归属/有效地址校验和 MR 授权关联三项；均待实现。 |
| UE11-p0094-005 | §2.2.4.3.3，其他注册方法 | 非上述 regattr 特定授权方法的 MR 注册为 any JobID。 | 现由公开 reg/regv 跨 Job 绝对寻址回归覆盖 any Job 授权；与零 auth key regattr 分开调用验证，完整 JobID 管理链仍待完成。 |
| UE11-p0094-006 | §2.2.4.3.3，特定 JobID 的 MR | MR 一旦关联特定 JobID，只允许相同 SES JobID 访问。 | native exact/any MR 检查有回归；provider 所有注册方法的授权联合矩阵仍缺失。 |
| UE11-p0094-007 | §2.2.4.4，direct 发送方法 | SES JobID 从 endpoint auth_key 获取。 | 未实现；当前固定 1 的实验 provider 不满足该映射。 |
| UE11-p0094-008 | §2.2.4.4，AV 发送方法 | 根据操作 dest_addr 所关联的 AV 授权键选择 SES JobID。 | 未实现。需验证同一 endpoint 向不同 JobID 地址发送及非法/撤销键。 |
| UE11-p0098-001 | 表 2-10，UET 地址字段 | 分别校验 flags、capabilities 的各组保留位；根据有效位解释地址、PID、资源范围等字段。 | FI_ADDR_UET 编解码与能力映射未实现；本段仅为跨页表格片段，完整表 2-10 仍须逐字段复核。 |
| UE11-p0100-001 | 表 2-11，fi_getinfo 条件项 | 非空 node 指向 UET 地址；其 FI_SOURCE 过滤建议另建 SHOULD 项。 | 当前使用 socket 地址/端口的实验入口，不能通过；service 描述在下一页继续。 |
| UE11-p0101-001 | 表 2-11，多个 API 义务 | 配置文件中的同名 service 优先；按指定 service 过滤；支持 FI_SOURCE；非 FI_ADDR_UET 不返回 info；返回规定源地址字段并保留 service 识别；不返回目的地址。 | 至少分为配置优先、过滤、flag、地址格式、源地址字段与目的地址六组，不能整体算一项。上游 libfabric 2.0 与固定参考头缺少 FI_ADDR_UET 定义；需显式兼容方案和独立公开 API 验收。 |
| UE11-p0101-002 | §2.2.5.2.2，端点类型条件项 | scalable endpoint 的每个 RX context 获得独立 resource index；普通 endpoint 获得一个 index。 | 本段跨页；scalable endpoint 未实现。当前 native/provider 的固定目标索引不等于完整服务索引分配。 |
| UE11-p0103-001 | §2.2.5.3.2，基础要求 | provider 支持 EQ，且每个 endpoint 至少支持绑定一个。 | 现已实现非阻塞 EQ 的 owned FIFO、PEEK、背压、同 fabric 绑定和生命周期，公开 API 测试通过；阻塞等待和异步管理/错误生产者仍未接入。 |
| UE11-p0103-002 | §2.2.5.3.4，目标内存要求 | 远程 RMA/atomic 的目标 buffer 先注册到资源 domain；本地发送缓冲注册是可选条件。 | provider 和 native 共享受检 MR，非法 key/撤销/越界有回归；完整授权与 domain 绑定仍需联合验收。 |
| UE11-p0104-001 | 表 2-13，多个 key 字段约束 | IDEMPOTENT_SAFE=0 禁止幂等传输；保留位为零；用户 key 的 vendor 位为零；optimized key 的中间保留位为零且使用 12 位 index。 | `memory_key_test` 与 `optimized_safety_test` 验证普通/优化格式和命名空间；原生 RUDI WRITE/READ 重新授权实际幂等 MR，见 RUDI.md。其余幂等操作与完整 Profile 仍待验收。 |
| UE11-p0104-002 | §2.2.5.3.4.1，key API 格式 | 用户和 provider key 都使用标准 64 位格式；API 传递完整 64 位；RKEY 范围由 mr_key_size 决定。 | native 用户 key 与 provider 生成 key 有部分覆盖，公开 provider 仅 FI_MR_PROV_KEY；mr_key_size 约束由下一段续完。 |
| UE11-p0105-001 | §2.2.5.3.4.1，前段续文 | mr_key_size<6 时，把未使用的高位 RKEY 位清零。 | 与 p0104-002 合并追踪位宽义务；当前 provider 固定 6，尚无可选小位宽路径的边界验收。 |

## 第 41～60 个候选

这批复核了表 2-14～2-16 的选择前提、表 2-20 的 Profile 条件及跨页的发送 API 表。
仅支持一个函数入口不表示它的所有必选 flag 或所有 Profile 映射已经实现。

| 候选 ID | 章节与分类 | 拆分后的义务及适用条件 | 当前证据与后续处理 |
|---|---|---|---|
| UE11-p0105-002 | §2.2.5.3.4.1，本地 key 解释 | provider 选择 RKEY 到 MR 的本地映射方法；不要求复制特定 vendor 的 key 编码。 | native registry 已按 key/地址 namespace 查找，并保留注册 identity；`memory_key_test` 有覆盖。 |
| UE11-p0105-003 | §2.2.5.3.4.1，optimized 条件项 | 采用 optimized RMA 头时，把 RKEY/index 放入 ses.resource_index。 | 原生 SMALL WRITE/整数原子把低12位 key/index 放入 RI，并在目标按 Job/PID 解析实际 MR；MEDIUM 保留完整 key。provider 自动格式选择尚未接通，见 OPTIMIZED-HEADERS.md。 |
| UE11-p0105-004 | §2.2.5.3.4.1，small RMA 条件项 | 只有满足表 2-15 的单 MTU 操作、无 remote CQ data 等前提才使用 small RMA 头；优先使用属于 SHOULD。 | small RMA 头未实现。后续必须把“允许使用的条件”和“建议选择”分开。 |
| UE11-p0105-005 | §2.2.5.3.4.1，标准头回退 | 不满足 optimized 与 small RMA 前提时，RMA 使用标准 SES 头。 | 原生默认 STD，显式 SMALL/MEDIUM 只接受已实现子集，非法组合在源端拒绝；provider 仍使用 STD。尚未完整验收自动选择策略。 |
| UE11-p0105-006 | §2.2.5.3.4.1，RUDI 条件项 | RUDI 需要表 2-16 中无 R/W 消息顺序、IDEMPOTENT_SAFE、目标支持等前提；选择使用属于条件性 SHOULD。 | 原生 RUDI WRITE/READ 按操作和真实 MR 幂等权限准入，有重传/拒绝/作用域回归；provider 尚未按 HPC 排序自动选择 RUDI，见 RUDI.md。 |
| UE11-p0106-001 | §2.2.5.3.4.1，绑定限制与选择建议 | IDEMPOTENT_SAFE MR 绑定 completion counter 必须失败；保留 requested metadata、optimized 分配失败回退是 SHOULD 项。 | 已保留 safe bit 和未支持 optimized 时的回退；counter 整体尚不支持，后续实现后仍需专项失败测试，不能靠全部拒绝绑定证明完整 counter 功能。 |
| UE11-p0106-002 | §2.2.5.3.5，特权配置 | JobID 由特权实体编程到硬件。 | 真实硬件/驱动后续系统集成；本轮 M7 仍需管理模型来表示这一授权边界。 |
| UE11-p0106-003 | §2.2.5.3.5，两个基础端点类型 | 同时支持 FI_EP_DGRAM 和 FI_EP_RDM。 | 两种实验端点已有公开 API 独立进程测试；这只证明端点类型入口，不证明标准地址/授权。 |
| UE11-p0108-001 | §2.2.5.3.5.1，多步管理义务 | 地址请求交驱动，含 FEP IP/OS PID/service；驱动转发给特权进程；通过控制 API 返回；Linux 仅接受 root 的响应；未预配置时返回 JobID/地址模式/PID/initiator。 | 需逐步骤、字段和条件拆分。真实驱动留后续；软件管理行为与特权实体模型仍未实现。Netlink 选择为 SHOULD，安全绑定返回为可选。 |
| UE11-p0109-001 | §2.2.5.3.5.1，前段管理流程续文 | 驱动配置 JobID 校验和安全绑定，再给 provider 返回不含安全绑定的地址响应。 | M7/M6 行为模型未实现；不要把需要保留在特权边界内的绑定信息直接交给普通 provider。 |
| UE11-p0109-002 | 表 2-18，地址请求字段 | flags 保留位为零，IP 类型、OS PID 和 service 使用规定字段。 | 控制 API 编解码未实现；完整表格字段/长度应另建条目。 |
| UE11-p0109-003 | 表 2-19，地址响应字段 | flags 保留位为零，并按 JobID/安全绑定有效位解释其字段。 | 未实现；本段与完整 UET 地址表及安全绑定表存在引用依赖。 |
| UE11-p0110-001 | §2.2.5.3.7，基础 CQ 支持 | provider 支持 completion queue。 | 已有公开 fi_cq_* 成功/错误完成路径；其他 CQ 格式、flags 和边界仍按具体 API 单独复核。 |
| UE11-p0111-001 | §2.2.5.3.7，Profile 条件项 | 表 2-20 中需 counter 的 Profile 同时支持按完成数和按字节计数事件。 | AI Base 无 counter 必选项；AI Full 需本地 SEND/RECV/READ/WRITE，HPC 还需 REMOTE_READ/WRITE。当前 cntr_open 未实现；规范字节事件符号拼写须与选定 libfabric 头核对。 |
| UE11-p0111-002 | §2.2.5.3.8，两个 AV 类型义务 | 支持 FI_AV_TABLE；FI_AV_UNSPEC 按 TABLE 处理。 | 代码接受两种类型，公开进程测试主要使用 TABLE；需补 UNSPEC、跨调用顺序索引和非法 AV 生命周期用例。 |
| UE11-p0112-001 | §2.2.5.4.1，两个端点上的消息 API | DGRAM 与 RDM 都支持 fi_msg 系列，具体义务由表 2-21/2-22 展开。 | 两类 SEND/receive 与 CQ data 已有进程覆盖；系列内 inject 和部分 flags 缺失。 |
| UE11-p0112-002 | 表 2-21，三个 receive API 与 flag | fi_recv、fi_recvv、fi_recvmsg，至少 vendor 声明的 scatter-gather 大小；FI_COMPLETION 必选；消息边界/FIFO/JobID 条件分别验证。 | 目前支持单 iovec、普通接收与 FI_COMPLETION；authorization 分支未完成。MULTI_RECV 是 SHOULD，不能和强制基础接收混为一个义务。 |
| UE11-p0112-003 | 表 2-22，fi_send | API 必选；DGRAM 映射 DATAGRAM_SEND，RDM 映射 SEND。 | 已有两种公开进程测试及 wire/CQ 回归。 |
| UE11-p0112-004 | 表 2-22，fi_sendv 与跨页映射 | fi_sendv 必选，iovec 上限由 vendor 声明；AI Full/HPC 的大消息 opcode 选择在下一页展开。 | 公开 scalar/vector/message SEND 已有缓冲区所有权与 CQ 回归；provider RDM 按可配阈值选择普通或 rendezvous（默认65536），deferrable/Profile 选择仍待补全，见 PROVIDER-RENDEZVOUS.md。 |
| UE11-p0113-001 | 表 2-22，多个 send/inject 义务 | fi_sendmsg 支持 CQ data、completion、inject、三种完成级别及 fence；fi_inject 成功不生成 CQ，可靠端点交付失败必须生成错误 CQ。 | CQ data/部分完成语义及 FI_FENCE 已实现；inject API/flag 已有所有权、CQ 与重试回归；三个可靠完成等级采用更强 GO 完成点，标准地址/授权仍不全。需拆成功抑制、错误报告和每个 flag，不能用 sendmsg 基础通过代替。 |

## 第 61～80 个候选

本批复核 §2.2.5.4 的 API 表格及跨页续文。表中的 “all profiles” 使用本章
libfabric 映射范围，不能据此把 Unified Local 强制映射到 libfabric。

| 候选 ID | 章节与分类 | 拆分后的义务及适用条件 | 当前证据与后续处理 |
|---|---|---|---|
| UE11-p0114-001 | 表 2-22，两种携带 CQ data 的 API | fi_senddata 与 fi_injectdata 都必选，远端 CQ data 放在 ses.header_data；inject 继承成功不生成 CQ、可靠交付失败生成错误 CQ 的规则。 | senddata 有公开进程与 header_data 回归；injectdata 已通过公开 API 到原生对端的复制、目标 CQ data、成功 CQ 抑制和错误完成测试。 |
| UE11-p0114-002 | §2.2.5.4.1.1，接收策略与发送兼容 | 目标至少选一种规范 unexpected-message 策略；发起端正确响应所有目标行为。 | 已有 ROD 暂存、RUD 丢弃/查询及晚到 receive 场景；全部目标行为及 deferral/rendezvous 的组合仍未覆盖。 |
| UE11-p0114-003 | §2.2.5.4.1.2，Profile 条件项 | AI Full 支持 deferrable send；HPC 支持 rendezvous。 | 原生 DS 源端、捕获头、RTR、后缀重启与错误清理已有独立真实 PDS 回归；完整 Profile、公开按大小选择及 rendezvous 事务仍未完成。rendezvous 当前仅24字节扩展头基础。 |
| UE11-p0114-004 | §2.2.5.4.1.2，rendezvous 条件项 | RENDEZVOUS_SEND 的 eager 数据不超过配置上限。 | 原生与 provider RDM rendezvous 已接通，含 eager 边界、源 MR 权限和双向恢复；见 RENDEZVOUS.md 及相应源/目标/边界回归。完整 M5 仍未退出。 |
| UE11-p0115-001 | §2.2.5.4.2，Profile 条件项 | AI Full/HPC 支持 tagged API；DGRAM 不支持。 | 原生及公开 scalar/v/msg tagged 已实现，64位精确/通配与 CQ 有回归；DGRAM 不公布 tagged。优化格式、rendezvous 等完整 M5 仍待验收。 |
| UE11-p0115-002 | 表 2-23，接收 API 与匹配 | 支持 trecv/trecvv/trecvmsg，按 posted 顺序搜索；AI Full 至少 exact match，不支持 wildcard 时拒绝非零 ignore；HPC 支持 wildcard。 | 需拆分三个 API、FIFO、exact、ignore 拒绝及 wildcard，当前均缺失。 |
| UE11-p0115-003 | 表 2-24，发送 API 与 opcode | tsend/tsendv 及跨页 tsendmsg/tinject/tsenddata 必选；AI Full/HPC 分别按大小选择 tagged、deferrable tagged 或 rendezvous tagged。 | 公开 tsend/v/msg、tinject/data 及源端大消息 rendezvous tagged 已有回归；原生 deferrable tagged 有重启事务。完整按 Profile/大小选择仍待验收，见 PROVIDER-TAGGED.md 与 PROVIDER-RENDEZVOUS.md。 |
| UE11-p0116-001 | §2.2.5.4.2.1，两个匹配分支 | 指定 src_addr 时同时匹配 tag 与地址中的 Initiator ID；UNSPEC 时不得用 initiator 过滤。 | 原生 Job 内32位 rank 与公开 FI_DIRECTED_RECV 已用两个独立对端验证；未请求能力时忽略 src_addr，UNSPEC 为任意源。provider 使用UDP端点node作为rank代理；其他地址字段不混入强制匹配。 |
| UE11-p0116-002 | §2.2.5.4.2.1，Profile/能力条件项 | AI Full/HPC 支持 UNSPEC；HPC 支持指定源地址。 | 未实现；FI_EXACT_DIRECTED_RECV 例外声明及与前句的关系需在选用该能力时单独复核，当前不宣称该能力。 |
| UE11-p0116-003 | §2.2.5.4.2.2，tagged rendezvous 条件项 | RENDEZVOUS_TSEND 的 eager 数据不超过配置上限。 | 原生与 provider 的 tagged rendezvous 已分别检查 eager 边界、源 MR 只读租约、源 rank/tag 和 CQ；不将普通 rendezvous 的测试直接代用，见 RENDEZVOUS.md。 |
| UE11-p0117-001 | 表 2-25，RMA API 与 flags | AI Full/HPC 支持 read/readv/readmsg；AI Base/Full/HPC 支持 write/writev/writemsg/inject_write/writedata；分别支持表列 flags 与 vendor iovec 上限。 | WRITE/WRITE IMM、单 iovec、CQ data 和部分完成等级已有覆盖；公开 read/v/msg 已有 RAW/WAR、两种结果载体与丢包回归；三个完成等级采用 GO 点，inject 已覆盖复制/CQ/边界，FI_FENCE 已覆盖混合模式/重试。不能用 WRITE 成功证明整张表通过。 |
| UE11-p0118-001 | §2.2.5.4.4，原子数量约束 | 非取回原子支持 bulk；取回原子限制为所选类型的一个单位。 | 非取回 bulk 已在 native/provider 实现并测试，公开 valid/query 返回类型相关数量；公开8～128位整数 fetching 已实现，查询数量1并拒绝多单位；零字节put/get是§3.4.2.12的显式例外。 |
| UE11-p0118-002 | 表 2-26，非取回 API 与 flags | atomic/atomicv/atomicmsg 必选；支持 COMPLETION、INJECT、FENCE，以及下一页续列的 TAGGED。 | bulk 整数操作已有覆盖；FI_FENCE 与 FI_INJECT 已有公开 API 回归；TAGGED 尚缺。“all profiles” 按本章范围解释。 |
| UE11-p0119-001 | 表 2-26，inject 与 fetching | inject_atomic 为基础要求；AI Full/HPC 支持 fetch_atomic/v/msg，flags 继承 atomicmsg。 | inject_atomic 已有公开 API 所有权、字节上限和成功 CQ 抑制回归；公开 fetching/v/msg 的单单位整数路径及查询、错误和旧值缓存已测试；完整表列flags、浮点和tagged原子仍未完成。 |
| UE11-p0119-002 | 表 2-26，CAS 与能力查询 | AI Full/HPC 支持 compare_atomic/v/msg；所有本章 Profile 支持 atomicvalid/fetch_atomicvalid/compare_atomicvalid/query_atomic，返回实际支持类型和操作。 | 公开 fetch/CAS scalar/v/msg 与各 valid/query 已实现8～128位整数，覆盖掩码转换、非零generation和缓存恢复；不支持组合清零size/count并拒绝。浮点、tagged和完整能力矩阵仍未验收。 |
| UE11-p0120-001 | §2.2.5.4.5，选定 INC 后的条件项 | 支持 INC 时公布 FI_COLLECTIVE；不支持时不公布属于 SHOULD。 | INC 留给 M8 后独立增强，当前不公布 FI_COLLECTIVE，不算作已实现 INC。 |
| UE11-p0120-002 | §2.2.5.4.5，选定 INC 后的管理条件项 | 支持 INC 时能与 manager 通信，并解释 PRIMARY/SECONDARY URL 配置。 | 当前未选定 INC；后续增强需正向、fallback 与失效测试。 |
| UE11-p0121-001 | §2.2.5.6，错误 CQ 三项义务 | err 采用相应 libfabric 错误，无对应项时用 FI_EIO；prov_errno 保留 SES 错误码。 | provider 已实现映射、FI_EIO fallback 与 prov_errno；公开错误进程测试仅覆盖部分 SES 错误，完整映射表仍需逐项验证。 |
| UE11-p0121-002 | §2.2.6，DGRAM 模式 | FI_EP_DGRAM 使用 UUD。 | 已有公开 DGRAM 进程与 wire 路径；不能推断为远端可靠交付。 |
| UE11-p0121-003 | §2.2.6，RDM 模式跨页续文 | RDM 使用 RUD/ROD，HPC 可使用 RUDI；AI Base/Full 依操作和排序按表 2-29/30 选择，HPC 按表 2-31。 | provider SEND/tagged 与 RMA/ATOMIC 已按独立排序谓词选择 ROD/RUD；大消息 rendezvous 已接通。原生 RUDI WRITE/READ 有回归，provider 的 HPC RUDI 策略仍缺失。 |

## 第 81～100 个候选

本批同时检查表格和跨页上下文。§2.2.10.4 对 small/medium 头的文字与表题
存在不一致，后续编码依据 §3.4 的正式线格式；不能直接复制 API 映射表题作为类型值。

| 候选 ID | 章节与分类 | 拆分后的义务及适用条件 | 当前证据与后续处理 |
|---|---|---|---|
| UE11-p0121-004 | §2.2.6，前段 RDM 选择的细化 | AI Base/Full 只使用 RUD/ROD，按操作和配置的排序选择。 | 与 p0121-003、后续两张表共享实现差距，不重复算已实现功能。 |
| UE11-p0122-001 | 表 2-29，AI Base 四种组合 | SEND 排序只控制 SEND 的 ROD/RUD；R/W 排序只控制 RMA/ATOMIC 的 ROD/RUD，两者独立。 | `libfabric_mode_selection_test` 检查四行中的 SEND、WRITE、ATOMIC 及实际 PDS type，另覆盖 RAS/SAR/SAW/WAS 交叉 flags；完整 Profile 仍有其他缺口。 |
| UE11-p0122-002 | 表 2-30，AI Full 四种组合 | SEND/TAGGED 与 RMA/ATOMIC 分别遵循各自排序；有 SEND 排序的 deferrable tagged 初始/eager 数据用 ROD，后续数据用 RUD。 | 公开 SEND/tagged 与 RMA/ATOMIC 已分别按排序谓词选择 ROD/RUD；真实线上模式和分空间代次有回归。deferrable 初始/eager与重启跨模式事务仍缺失，不能通过整表。 |
| UE11-p0122-003 | 表 2-31，HPC 组合与策略 | SEND/TAGGED、rendezvous 初始/后续、RMA、ATOMIC 分别选择表列模式；无 R/W 排序的 RMA 可依策略用 RUD 或 RUDI。 | 原生 rendezvous 与独立 RUDI WRITE/READ 已接通；provider rendezvous 有双进程恢复与排序证据。完整表2-31及 provider RUDI 自动选择仍未通过，HPC 能力未宣告。 |
| UE11-p0124-001 | §2.2.8.1，排序端点条件项 | 配置消息排序的 endpoint 操作约束到一个发送队列。 | provider 当前串行应用队列符合这一局部分支；多队列及流量类别映射是 SHOULD，PDC 内 packet window 不等于多个应用发送队列。 |
| UE11-p0126-001 | §2.2.9，选定 TSS 后的条件项 | provider 支持表 2-33 的完整安全绑定参数，并由特权地址分配流程取得。 | M6/M7 管理与 TSS 缺失；真实 kernel driver 后续系统集成。 |
| UE11-p0126-002 | 表 2-33，字段与保留位 | 支持 AES-GCM-256、三种模式、AN/automatic rekey 选择、shift/mask、四种封装及 offset/AN/SDI/SSI；rekey 保留位必须为零。 | 需逐字段、范围、组合和无效保留值建项，当前未实现。AES 库调用本身不代替安全绑定。 |
| UE11-p0126-003 | 表 2-34，rekey 条件项 | 支持 AN/SDI/SSI、16 位 epoch、96 位 IVMASK、raw/wrapped key 类型、长度及 key 参数。 | M6 缺失。后页 C 示例把 IVMASK octet 常数写为 96，与表中 96 bit 不一致，需以正式 TSS 结构/算法交叉复核。 |
| UE11-p0127-001 | §2.2.9，三方管理流程 | driver 发请求；特权进程返回参数；driver 接受主动推送及请求响应并编程安全状态。 | 本轮需 M6/M7 行为模型；真实驱动不在 M0–M8 范围。请求/响应权限与主动推送分别验收。 |
| UE11-p0127-002 | 表 2-35，请求字段 | rekey 请求带 AN、31 位 SDI、32 位 SSI。 | 当前缺失；必须校验安全域与源归属，不能仅把任意 key 写入对象。 |
| UE11-p0131-001 | §2.2.10.4，optimized 原子条件项 | 原子操作使用与 RMA 相同的 optimized 头前提；使用该头的建议另列 SHOULD。 | 原生显式 SMALL/MEDIUM 整数非取回原子复用 RMA 授权与原子执行；fetch/tagged/浮点等优化分支及 provider 自动格式选择仍待接通，见 OPTIMIZED-HEADERS.md。 |
| UE11-p0132-001 | §2.2.10.4，small RMA 原子条件项 | 原子也采用 small RMA 的适用前提。 | 与 SMALL 区分的 MEDIUM32B 保留完整 key；显式非取回整数原子子集有独立算术与故障测试，完整条件矩阵仍待验收。 |
| UE11-p0132-002 | 表 2-43，small RMA 映射 | hd 必须为零，其余 opcode/dc/rel/index/generation/Job/PID/长度/offset/initiator/key 按各自来源映射。 | 未实现；无 CQ data 是必要前提，不能静默丢弃调用者提供的 CQ data 来选择该头。 |
| UE11-p0132-003 | §2.2.10.4，deferrable token | 两个 restart token 替代 buffer_offset，RTR 携带相同 token；发起 FEP 的活跃 token 唯一。 | 原生源/目标 token 使用 FEP Services 的64位游标，32位耗尽拒绝回绕；并发、取消、替换 Endpoint 与迟到 RTR 有回归。实际 reference RTR 互通仍待验；见 DEFERRABLE-TRANSACTIONS.md。 |
| UE11-p0133-001 | 表 2-44，rendezvous 源 MR | 源 buffer 注册 REMOTE_READ；扩展头包含源 PID/index/generation、消息起始 offset、rkey 和受上限约束的 eager 长度。 | 24字节扩展已按 Figure3-21 独立黄金字节编解码；源 MR 远端 READ 授权、撤销、偏移及整个消息 READ 尚未整合，不能由线格式推断。 |
| UE11-p0133-002 | §2.2.10.4，原子映射 | libfabric datatype/op 映射至 SES 对应 mnemonic。 | 当前支持的 8 种整数类型、12 种非取回操作已有 native/wire/provider 回归；fetching/CAS 另有8～128位整数、固定双操作数格式与旧值缓存/公开掩码转换证据；浮点和完整类型矩阵仍未验收。 |
| UE11-p0133-003 | §2.2.10.4，CAS 扩展 | compare/swap 来自 API，每个值尺寸不超过 16 字节，并带正确 opcode/datatype。 | CAS 未实现；后续还需类型允许集、单单位和目标对齐/权限检查。 |
| UE11-p0134-001 | §2.2.11，Linux 控制接口部署项 | Linux UET Control API 使用 UET family 的 Netlink 消息及规定 typed attributes。 | 真实 kernel 接口留后续系统集成；M7 软件管理模型仍需保留相应消息/权限语义，不宣称提供实际 UET Netlink family。 |
| UE11-p0145-001 | §2.3.4.1，verbs 条件项 | UET verbs 设备支持至少一种 UET GID 类型，应用通过 GID 选择 UET。 | UE verbs 按 ROADMAP 在 M8 后独立增强；当前不声明 verbs 设备或 GID 支持。 |
| UE11-p0147-001 | §2.3.5.1.3，verbs 创建授权 | 拒绝 PIDonFEP/resource index 已占用或调用进程未获授权的 QP 创建。 | verbs/kernel 路径未实现；M7 管理资源分配模型可共享授权规则，但不代替真实 QP API 验收。 |

## 第 101～120 个候选

本批涉及 roadmap 明确放在 M8 后的 UE verbs 与 INC。这里记录其条件义务，
不把未选定扩展算成当前 Profile 的已通过功能。INC 表格中九个整数必选操作是
MIN/MAX/SUM/LOR/LAND/BOR/BAND/LXOR/BXOR，不能把其他 vendor 支持的操作也当成必选。

| 候选 ID | 章节与分类 | 拆分后的义务及适用条件 | 当前证据与后续处理 |
|---|---|---|---|
| UE11-p0150-001 | §2.3.6.1，verbs Job 对象 | Job 关联 JobID、port、源 GID；JobID 映射到 SES，GID 决定协议/源网络地址。 | verbs 独立增强未实现；native JobID 检查不代替这些 API 对象。 |
| UE11-p0153-001 | §2.3.11.5，verbs key 格式 | 返回标准格式 64 位 RKey；返回 64 位 RKey 时也返回 64 位 LKey；legacy 32 位 key 可另提供。 | 标题提取误归入前一节。native/provider 64 位 MR key 不能证明 verbs LKey/QP 功能；扩展未选定。 |
| UE11-p0154-001 | §2.4.1，INC 拓扑/传输条件 | 单一逻辑 SEP 行为；FEP 直接连接 SEP 端口，使用 PFC/CBFC 无损网络上的 ROD。 | INC 未选定；普通多跳 fabric/NSCC 不能代替该拓扑与无损保证。 |
| UE11-p0155-001 | §2.4.1，INC 元素与编码 | 元素不跨包、同 communicator 使用相同 Job；payload 小端且不额外 padding。 | INC 未实现；复合 MINLOC/MAXLOC 的内部 padding 按脚注单独处理，不能把“一律无 padding”误用于复合值。 |
| UE11-p0156-001 | §2.4.2，INC 在途上限 | 每 rank 未完成 collective 不超过 SEP 能力，也不超过 4096 个 CSN。 | 未实现；需容量、12 位回绕及迟到响应测试。 |
| UE11-p0156-002 | 表 2-49，INC 操作集 | REDUCE/ALLREDUCE/BARRIER 必选；BCAST 与 SYNCBCAST 至少一个；EXSCAN 可选。 | 未实现；不能以支持任意一种规约宣称整套 collective。 |
| UE11-p0158-001 | 表 2-51，INC INT32 | 支持本表九个整数必选操作。 | 未实现；与 SES 单目标 integer atomic 的已实现操作不属于同一验收项。 |
| UE11-p0158-002 | 表 2-51，INC UINT32 | 支持本表九个整数必选操作。 | 同上；有符号/无符号 MIN/MAX 需分别验证。 |
| UE11-p0158-003 | 表 2-51，INC BF16 | 必选 MIN/MAX/SUM。 | 未实现；浮点舍入规则另由 §2.4.7 约束。 |
| UE11-p0158-004 | 表 2-51，INC FP16 | 必选 MIN/MAX/SUM。 | 未实现；不能用 BF16 或整数结果代替 FP16。 |
| UE11-p0158-005 | §2.4.6，INC 顺序选择 | IM 配置下至少支持无序、同 communicator 一致、跨 communicator 一致、跨 Job 一致、自然 rank 顺序之一。 | 未选定 INC；未来必须公布实际支持模式并拒绝未支持配置，不要求同时实现全部五种。 |
| UE11-p0158-006 | §2.4.7，INC 浮点舍入 | round-to-nearest ties-to-even 必选；其他列出的模式可选。 | 未实现；内部 accumulator 长度的建议不能冒充额外强制位宽。 |
| UE11-p0161-001 | §2.4.9，INC comm_key | 使用 packed 结构大小，version=1，16 字节 unique_id 为选定 communicator ID。 | 未实现；与线头 inc_info.ver=0 是不同字段，不能混用版本常数。 |
| UE11-p0161-002 | §2.4.10，INC switch 能力 | 标准请求/响应、DS/RTR、reserved ROD PDC、ROD_REQ/ACK/NACK/Close CP、CRC。 | 未实现；TFC/TSS 在本节属于可选，但一旦选定仍需遵循各自协议。 |
| UE11-p0163-001 | §2.4.11.1，INC 版本错误 | 未知 inc_info.ver 时忽略其余 inc_info、拒绝消息并返回 RC_UNSUPPORTED_OP。 | 提取的章节候选 0 是错误标题，人工归回本节；INC 未实现。 |
| UE11-p0163-002 | §2.4.11.2，INC reserved PDC | 支持 INC 的 Profile 支持 reserved PDC。 | 未选定 INC；当前动态 PDC ID 池不等于已实现 reserved PDC 生命周期。 |
| UE11-p0167-001 | §2.4.15.1，RPC 注释中的义务 | communicator 创建在资源/能力不足时失败；Join 幂等，所有 rank 加入后建立；Leave 不可逆并销毁 communicator。 | 即使关键词位于代码注释也不能丢弃。INC 管理扩展未实现。 |
| UE11-p0170-001 | §2.4.15.1，Join 字段约束 | 16 字节 UID 在 Job 生命周期不复用、各 rank 一致；required capabilities 缺失时失败；scale_factor 非零。 | 未实现；desired capabilities 是提示而非强制满足项。必须分别校验字段与跨 rank 一致性。 |
| UE11-p0176-001 | §2.4.17.3，管理状态转换 | 所有数据结构初始化后才能将 admin-status 置 UP。 | INC 管理模型未实现；配置事务失败不得留下可发送的半初始化 communicator。 |
| UE11-p0176-002 | §2.4.17.3，运行失败状态 | admin UP 后，无法/拒绝遵循初始化状态的 switch 把 oper-status 置 FAILED。 | 未实现；admin 与 oper 是独立状态，不得只用一个布尔开关替代。 |

## 第 121～140 个候选

本批对照 PDF 第 188～191 页原始表格图像复核列归属，防止纯文本跨列。表 3-1
AI Base 的 READ 操作格为空但 READ 大小行有值，不能由大小行反推 READ 成为其必选操作。
Sync Group 与 MULTI_RECV 在这些 Profile 表中的格也为空；它们仍属于已选择的 roadmap 范围。

| 候选 ID | 章节与分类 | 拆分后的义务及适用条件 | 当前证据与后续处理 |
|---|---|---|---|
| UE11-p0187-001 | §3.3，Profile 表解释规则 | MUST 格为必选，空格允许增强功能；启用增强时跟踪全部依赖，功能可运行时关闭。 | capability 与 Profile 声明已分开，四种 Profile 仍为 false；完整依赖图和运行时协商未完成。 |
| UE11-p0188-001 | §3.3.1，部署 MTU | 多包 WRITE/READ/SEND 使用一致 Payload MTU，通信 FEP 共同配置一致。 | 场景运行器使用共同 payload 配置；native 独立端点的部署一致性/管理校验仍需补全，不能只检查链路 MTU。 |
| UE11-p0188-002 | 表 3-1，多操作/大小矩阵 | NO_OP/WRITE/非取回原子四种均必选；前三种 Profile 还需 SEND/DATAGRAM/WRITE IMM；Full/HPC 需 exact tag/READ/fetch+CAS；HPC 另需 wildcard/tagged atomic/rendezvous；Full 需 DS/DTSEND。 | AI Base native 基础操作有回归，WRITE 已验证 4GiB−1；Full/HPC SEND 上限、M5 扩展及 Unified Local 16383 字节 READ/WRITE 仍缺失。表内每个操作与大小应独立建项，不能算一次测试通过整表。 |
| UE11-p0189-001 | §3.3.2，基础寻址与 key | 遵守基础寻址；WRITE 使用 memory key；支持 RMA READ 时，READ/ATOMIC 也支持 memory key；匹配按 Profile 表。 | native 相对/绝对、key 与权限有回归；Unified Local direct memory 与本段全 Profile key 用语的关系需结合 §3.4 正式格式处理，不能给无 key 的本地头杜撰字段。 |
| UE11-p0189-002 | 表 3-2，相对/绝对与 exact | AI Base/Full/HPC 均需相对和绝对；Full/HPC 需 exact tag。 | native 寻址部分覆盖，provider 标准 UET 地址/授权和 tag 缺失。 |
| UE11-p0189-003 | 表 3-2，wildcard | HPC 需 wildcard tag。 | 原生与 RDM provider 支持64位 ignore mask 的 wildcard tag，FIFO/源 rank 约束有回归；见 TAGGED-MESSAGES.md。完整 HPC 能力尚未验收。 |
| UE11-p0189-004 | 表 3-2，本地直接寻址 | Unified Local 通过 FA/JobID 选择目标内存。 | M8 缺失；禁止把收到的地址直接转换为执行器指针。 |
| UE11-p0189-005 | §3.3.3，四个授权义务 | 所有 Profile 实现 SES 授权、插入 JobID、访问前检查 JobID，每 FEP 至少一个 JobID。 | native Job0/多 Job/exact/any MR 已有测试；特权管理到公开 provider 的链条与 Unified Local 未实现。 |
| UE11-p0189-006 | §3.3.4，表格总要求 | 按表 3-3 各 Profile 支持相应 buffer 行为。 | 这是后续行的总则，不额外记为一个已通过功能。 |
| UE11-p0189-007 | 表 3-3，use-once RMA | HPC 支持 RMA use-once。 | 原生 RMA 已加入每缓冲区配置和共享注册域消息授权；provider 扩展与完整 HPC 验收仍待完成，见 USE-ONCE-RMA.md。 |
| UE11-p0189-008 | 表 3-3，full-range key | AI Base/Full/HPC 支持标准头全范围 memory key。 | native 64 位 API/48 位线 RKEY 已有边界回归；provider 用户 key 与完整授权矩阵仍不全。 |
| UE11-p0189-009 | 表 3-3，limited-range key | HPC 支持 optimized 头有限范围 key。 | M5 optimized 编解码/索引授权缺失。 |
| UE11-p0190-001 | 表 3-3 续，本地与 tag | Unified Local 支持本地头直接内存；Full/HPC exact tag，HPC wildcard。 | M5/M8 缺失；MULTI_RECV/Sync Group 行为空，不把本表当作其所有 Profile 强制依据。 |
| UE11-p0190-002 | §3.3.5，字段总要求 | 必选头的所有字段/flags 都要支持，除非表中明确例外。 | 标准头通过单一字段子集不等于整头通过；当前保留 partial，逐 flag/组合仍需补验收。 |
| UE11-p0190-003 | 表 3-4，标准头 | AI Base/Full/HPC 均需 44 字节标准请求头。 | codec 黄金样例/native/参考互通部分覆盖；尚非全部字段组合通过。 |
| UE11-p0190-004 | 表 3-4，多格式矩阵 | Full 需 DS/RTR；前三 Profile 需 DS-as-SEND；HPC 需 optimized non-matching/small 和 rendezvous；Unified Local 需 local 格式；原子扩展四种必选；CAS 扩展 Full/HPC/Local 必选。 | DS-as-SEND、标准原子扩展已有子集测试，其余 M5/M8 缺失；不能把未选择的 DS/RTR 当作 AI Base 源端必选。 |
| UE11-p0191-001 | 表 3-4，标准响应 | AI Base/Full/HPC 支持标准 response。 | 当前 codec 和 SES 响应有回归；表中 16B 与正式 §3.4.3.7 的长度差异已在 BASELINE-AUDIT 记录，按正式字段布局编码。 |
| UE11-p0191-002 | 表 3-4 续，响应/packing/GO | Full/HPC 支持带数据响应；HPC optimized response；Local compact response 和每包最多 16 消息的接收处理；四种均支持 GO delivery complete。 | STD READ/fetch 及选定 DATA_SMALL fetching 数据响应有回归；Local compact/packing 缺失。native 成功在受检目标内存动作/结果放置后报告，完整 GO/完成等级及本地路径联合证明未完成。 |
| UE11-p0191-003 | §3.3.6，模式总要求 | 各 Profile 支持表 3-5 列出的模式及对应网络行为。 | 不能用一种通用可靠网络后端覆盖所有模式；当前仍由原 PDC 实现 RUD/ROD/UUD。 |
| UE11-p0191-004 | 表 3-5，模式矩阵跨页截断 | AI Base/Full/HPC 都需 RUD/ROD/UUD；HPC 需 RUDI；Unified Local 需 RODL。 | 原图确认本候选遗漏表后两行。RUD/ROD/UUD 及原生 RUDI WRITE/READ 子集已有回归；RODL 缺失，完整 HPC/Unified Local 能力保持 false。 |

## 第 141～160 个候选

本批补完 Profile 模式表的拆行，并复核基础寻址/授权。JobID 授权与 TSS 安全域
授权是两道独立检查；成功定位一个 buffer 不能替代随后检查权限。

| 候选 ID | 章节与分类 | 拆分后的义务及适用条件 | 当前证据与后续处理 |
|---|---|---|---|
| UE11-p0191-005 | 表 3-5，RUDI | HPC 必选幂等操作的 RUDI。 | 原生 source-owned RUDI WRITE/READ 有独立恢复、幂等 MR 授权和无 target PDC/CQ 的回归；其余操作与完整 HPC 验收仍开放，见 RUDI.md。 |
| UE11-p0191-006 | 表 3-5，UUD | AI Base/Full/HPC 必选 UUD。 | native/provider DGRAM 已有回归；不推断远端收到或可靠交付。 |
| UE11-p0192-001 | 表 3-6/3-7，网络条件 | 最佳努力网络中 AI Base/Full/HPC 必选 NSCC；无损表的 NSCC/RCCC 格为空。 | NSCC 已接入发送准入、反馈及真实 trim；尚未全部规范验收。RCCC 虽非此表通用必选，仍按 roadmap 在 M5 实现。 |
| UE11-p0199-001 | §3.4.2.3，key namespace | 两种 namespace 都遵守 key 格式及绑定；未找到或不允许的 MR 映射返回 RC_BAD_MKEY。 | native exact/any/Job/PID/index 优先与 key 格式已有回归；权限错误与映射错误需按标准区分，不能统一报告成功或任意错误。 |
| UE11-p0200-001 | §3.4.2.3，本地直接内存隔离 | 无 PID/index/key/initiator 的本地事务用 JobID 隔离：单一授权 Job，或 Job 对应地址基址。 | M8 未实现；应使用受检模拟地址空间，管理翻译是软件策略，不能直接解引用远端地址。 |
| UE11-p0201-001 | §3.4.2.3.1，Job provisioning | 同一可达网络内同时运行、不可互通的实体使用不同 JobID；可通信实体可共享；应用可用多个 Job。 | native 能表示多 Job，但网络级特权分配/冲突检测与回收生命周期待 M7；单 registry 的集合不代替全局 provisioning。 |
| UE11-p0201-002 | §3.4.2.3.2，进程隔离 | 各 OS 进程有不同 PIDonFEP；同一 OS 进程可有多个，且与 OS PID/PASID 解耦。 | 当前 native 可配置 PID namespace，尚无特权进程分配模型；固定 PID=1 的 provider 不是完整跨进程隔离证明。 |
| UE11-p0202-001 | §3.4.2.3.2，PID scope | PIDonFEP 范围相对于 Job 或 Fabric Address。 | `ResourceDirectory` 支持相对映射和绝对 PID；provider 标准地址入口仍缺失。 |
| UE11-p0202-002 | §3.4.2.3.3，资源空间/optimized | SEND/tag/RMA index 空间独立；optimized RMA 的 index 精确选择一个 RMA resource。 | native SEND/tagged/RMA 有独立 index 空间；SMALL 的优化索引按 Job/PID 解析 MR，并拒绝绝对同索引歧义。自动优化 key 分配及完整资源类仍待验收，见 MEMORY-KEYS.md。 |
| UE11-p0204-001 | §3.4.2.3.5，匹配顺序 | ROD wildcard 在所有匹配的 posted buffers 中按 FIFO 消耗；RUD FIFO 为 SHOULD，网络乱序可导致不同次序。 | tagged_message_test 及 provider directed/tagged 回归覆盖精确/通配、FIFO 与源 rank；RUD 不将网络乱序误写成全局发送顺序，完整组合仍待验收。 |
| UE11-p0204-002 | §3.4.2.3.5，API key 映射 | 采用 RMA memory key 时把 API key 映射到线头 match_bits，保持相应 namespace。 | native/provider 标准头已有 key 到线格式与目标授权回归；optimized 通过 index 选择的无 key 路径另验。 |
| UE11-p0204-003 | §3.4.2.3.7，唯一 buffer 选择 | 未标记 tuple 唯一选择一个 buffer；匹配 tuple+criteria 也唯一选择 buffer，可采用不同内部数据结构。 | native untagged/tagged/RMA 使用受检选择和具体注册身份，有 FIFO/匹配/Job 隔离回归；不把内部 map 容器写成规范要求。 |
| UE11-p0205-001 | §3.4.2.3.7，无 key RMA | 未携 key 时 tuple 唯一选择 buffer；三种操作使用独立 index 空间。 | 原生 SMALL WRITE/整数原子/fetch 的索引路径与 tagged 匹配已有定向回归；索引解析不替代 MR 权限。更多优化组合及 Unified Local 仍待补齐。 |
| UE11-p0206-001 | §3.4.2.4，定位后授权 | buffer 定位后执行 JobID 与适用安全域授权。 | native Job/MR 检查已有负向回归；M6 SDI 检查尚缺。 |
| UE11-p0206-002 | §3.4.2.4.1，源端可信 Job | 由发起节点可信层分配或验证 JobID。 | native 源端检查配置 Job，但任意应用可自行配置的教学 API 不等于特权管理；M7 授权对象/可信边界待实现。 |
| UE11-p0206-003 | §3.4.2.4.1，逐 buffer 授权 | 每次访问确认 Job 可访问该 buffer；至少一个 Job。只确认 Job 属于 FEP 集合不充分。 | exact/any MR 与相对/绝对访问已有回归；provider 固定 Job 和未完成的配置链仍需补全。 |
| UE11-p0207-001 | §3.4.2.4.2，选定 TSS 后的 SDI 授权 | SDI 必须被 endpoint 允许；失败按 TSS 丢弃并报告，不发送 SES response 或 PDS NACK。 | M6 缺失；认证失败不得沿当前普通 semantic error 路径回复。UET_NO_RESPONSE 的提前返回例外不允许最终成功完成。 |
| UE11-p0207-002 | §3.4.2.5，消息大小与分包 | bulk 上限由标准头 32 位长度决定，可分别限制 RMA/send；分包遵循 Payload MTU，紧凑头还有更窄限制。 | streamed WRITE 已验证 UINT32_MAX 和内存有界；其他大消息与紧凑头仍缺失，provider 大小能力不能由 WRITE 单测推广到全部操作。 |
| UE11-p0211-001 | §3.4.2.6.1，use-once 生命周期 | 一条消息独占已匹配 buffer，其他消息不可再用；保留到该消息完成才还给应用。支持 SEND/RECV，支持 tag 时也覆盖 tag。 | native posted receive/tagged 绑定注册身份；原生 RMA 通过逻辑消息授权跨分片和 READ 重执行保留缓冲区，在真实 Clear/Close 时退休。见 USE-ONCE-RMA.md；完整扩展验收仍开放。 |
| UE11-p0212-001 | §3.4.2.6.3，HPC tag 匹配 | HPC 目标支持 tagged；使用 match_bits 和 initiator，是否硬件加速不影响要求。 | 原生与 provider tagged 使用64位 tag/ignore mask 和 Job 内32位 initiator criteria，有通配、FIFO、定向接收回归；完整 HPC 仍未验收，见 TAGGED-MESSAGES.md。 |

## 第 161～180 个候选

本批检查消息顺序、MTU、标准头和 DS 重启规则。协议配置的标准 Payload MTU
与教学测试使用的小片段大小要分开记录，不能把任意小整数称为标准 MTU 配置。

| 候选 ID | 章节与分类 | 拆分后的义务及适用条件 | 当前证据与后续处理 |
|---|---|---|---|
| UE11-p0212-002 | §3.4.2.6.4，目标 memory key | RMA 支持把 match_bits 用作 memory key，并遵循 libfabric 定义的结构。 | native/provider 标准头已有 key 映射及授权回归；不把内部容器选择当作线格式要求。 |
| UE11-p0213-001 | §3.4.2.7.1.1，消息排序条件 | 需要 SEND 顺序时，决定目标 buffer 的初始 SEND/TSEND/rendezvous 请求使用 ROD；DS/rendezvous 后续数据可独立使用 RUD。 | provider 普通 SEND 模式映射已按独立谓词修正并检查实际报文；原生 tagged 与 DS 的 ROD初始/RUD重启已验证；完整跨退避顺序、Sync Group 和 rendezvous 两阶段仍未实现。 |
| UE11-p0213-002 | §3.4.2.7.1.1，混合顺序 | 混合 RMA/messaging 的顺序可由 ROD 保证；未使用 ROD 时用源端 fence 等待前操作完成。 | provider 已支持 FI_FENCE；公开模式用例同时验证 SENDMSG/WRITEMSG/ATOMICMSG 的 flags，以及 NO_MATCH 重试不被后续 fenced 操作越过。 |
| UE11-p0213-003 | §3.4.2.7.1.2，WAR 条件 | 使用 ROD 实现 WAR 时，保留先前 READ 的结果直到 PDS Clear 表明发起端收到；公布相应大小限制。 | 原生 STD READ 已支持 ACK-data 与反向返回，受检数据生命周期见 READ.md/CLEAR-PROCESSING.md；显式 WAR 请求的结果保留与能力大小限制仍需独立验收，不能由普通 READ 成功代替。 |
| UE11-p0214-001 | §3.4.2.7.1.3，消息内连续性 | SOM 首 PSN 与 offset0；后包 PSN 连续、offset=(N−1)×Payload MTU；最后包 EOM；同 PDC 两条消息不交错。 | native FIFO producer、PDC PSN 及大消息分片已有回归；M5 多消息/重启格式仍需各自测试。 |
| UE11-p0214-002 | §3.4.2.7.1.3，线端顺序 | ROD 按 PSN 顺序发往线端；RUD 可任意顺序。 | 初始 FIFO、GoBackN 顺序和回绕已测试；不同 NACK 延迟、NIC 背压与重传组合仍须持续覆盖。 |
| UE11-p0215-001 | §3.4.2.7.3，READ 响应顺序 | 同 PDC 上 ROD/RODL 的带数据 READ 响应按请求接收顺序生成。 | 原生 STD READ 在 ROD 的同一 PDC 内共用既有队列与返回方向；优化 READ 的同连接测试正在补齐。RODL 与完整异步响应排序范围仍待验收，不能只凭同步回调顺序通过。 |
| UE11-p0216-001 | §3.4.2.11，Payload MTU 能力/默认 | 支持 4096；1024/2048/8192 为 SHOULD；规范默认 4096。 | native 可配置并测试 4096/8192；现有入口默认 1024、研究测试还使用非标准小片段，需明确配置策略及后续 Profile 严格模式。 |
| UE11-p0216-002 | §3.4.2.11，分包/路径限制 | 每个非末包恰好 Payload MTU；包适配全路径 Ethernet MTU；IPv4 DF=1；FEP 不再分片。 | codec DF、原生分片及场景 MTU 校验已有覆盖；动态管理路径变化与所有扩展头的容量校验仍需补全。 |
| UE11-p0217-001 | §3.4.2.14，message ID | READ 请求携 ID；其他单包有字段时可用有效 ID 或0；DGRAM=0；同目标 PDC 的在途消息 ID 唯一。 | native ID lease、迟到/复用、DGRAM0 和 READ 原/响应 ID 已有回归；READ 提前确认、失败连接退休有独立策略测试，紧凑无 ID 格式另验。 |
| UE11-p0218-001 | §3.4.3，保留位总规则 | 保留字段发送为零，接收时忽略。 | 复核发现 SES decoder 原先拒绝多处 reserved 值；新 `ses_reserved_fields_test` 覆盖已实现请求/原子/带数据响应的忽略、规范重编码与 CRC，其他格式仍未实现。 |
| UE11-p0218-002 | §3.4.3.1，标准头/完成数据 | AI Base/Full/HPC 的请求支持标准头；多包和完整 key/match 使用该头；completion data 使用标准或 medium 头。 | 当前标准头和 SEND/WRITE CQ data 有回归；扩展 opcode、medium 头及全部字段尚不全。 |
| UE11-p0219-001 | 表 3-9，首部字段 | opcode 六位，前两位 reserved 为零；有效 opcode 按表 3-23。 | encoder 显式字段编码；新增 reserved 接收测试；opcode 支持集仍为子集。 |
| UE11-p0219-002 | 表 3-9，多字段义务 | DC 等到 GO；IE 阻止该包写入并使消息报错；末包 EOM；Job/PID/index/generation 等按位宽解释。 | native IE/错误完成/权限已有测试，完整 DC/所有响应等级和扩展组合仍待完成；不是一个不可拆分的通过项。 |
| UE11-p0220-001 | 表 3-9 续，地址/DS/长度 | buffer base+offset+消息偏移寻址；初始 DS 的 initiator token 唯一、target 半部0；每包都填 request_length，零长度合法。 | native 受检偏移、零长度和重复长度字段已有测试；DS token 与 FI_MR_VIRT_ADDR 未实现，当前不声明 VIRT_ADDR。 |
| UE11-p0221-001 | 表 3-10，非 SOM payload | 十八位 reserved 为零，十四位 payload_length 正确，其余字段继承标准头。 | 显式 codec 和多包 WRITE 有覆盖；新增 reserved 忽略/重编码测试保留有效 payload_length/offset。 |
| UE11-p0222-001 | 表 3-10 续，长度重复 | 非 SOM 也携带完整 request_length 和消息 offset。 | native READ 分片也保留完整总长与 offset，请求 payload_length0；重启消息格式仍另验。 |
| UE11-p0222-002 | §3.4.3.1，RTR 与重启跨页 | target 不分配 token 时置0，可再次 defer；非零 token 对应重启恰好一次且之后不再 defer；重启 SOM=1，offset 0..2^32−2。 | 原生源支持零 token 再次延期、非零 token 一次重启、新 SOM/RUD MID、原 metadata 和请求后缀；拒绝 offset2^32−1，验证2^32−2。真实 PDS 处理网络重传，独立对端检查控制重放。 |
| UE11-p0223-001 | §3.4.3.1，重启字段保持 | 每次 DS 重启保留原请求地址和 header data；request_length 使用 RTR 指定值。 | M5 缺失；重启新 message offset 与目标保留的原始偏移必须分开跟踪。 |
| UE11-p0226-001 | §3.4.3.3，本地 packing 首消息 | 首个 optimized local 头 ac=0；单消息时 ac=0 且 mm=0。 | M8 未实现；不能把多个标准头直接拼接成 local packing。 |

## 第 181～200 个候选

本批检查 packed local、原子、Sync Group 和目标 buffer 选择；Sync Group 的
非 completing/ completing 两种 count 编码按表 3-15 的跨页续文区分。

| 候选 ID | 章节与分类 | 拆分后的义务及适用条件 | 当前证据与后续处理 |
|---|---|---|---|
| UE11-p0228-001 | §3.4.3.3，local packing 链 | 除最后一条外 mm=1，最后一条 mm=0。 | M8 缺失；需要 1/16 条消息及提前/缺失终止标志的负向用例。 |
| UE11-p0229-001 | §3.4.3.3，三种 packing 容量 | 请求 payload 总量、READ/fetch 响应 payload 总量均不超过 Payload MTU；带全部头的包不超过网络 MTU。 | M8 缺失；只检查请求长度不足以保证响应容量和实际网络包大小。 |
| UE11-p0229-002 | §3.4.3.3，packed 响应 | 响应顺序对应请求；响应 payload 超限时返回单条 UNSUPPORTED_SIZE，使整组失败。 | M8 缺失；禁止按异步完成顺序重新排列或把部分条目误报成功。 |
| UE11-p0229-003 | §3.4.3.3，压缩地址依赖 | 首头 ac=0；后续 ac=1 时，地址相对紧邻前一条，扩展大小继承前一个 ac=0 的消息。 | M8 缺失；地址基准与扩展格式基准是两个不同的状态。 |
| UE11-p0232-001 | §3.4.3.5，原子扩展/错误长度 | 每包带原子扩展，不与 rendezvous 扩展组合；元素数按长度/类型宽度；不整倍数长度执行零字节。 | native 对 request_length/packet count/offset 的整倍数检查在原子访问前执行；完整实际线端 malformed-message 与多包错误联合验收仍需补全。 |
| UE11-p0232-002 | §3.4.3.5，fetch 单单位 | fetching 不操作多于一个所选类型元素，并保留旧值用于响应。 | fetching 未实现；非取回 bulk 不受此单单位限制。 |
| UE11-p0233-001 | §3.4.3.6，同步完成类型 | completing SYNC_WRITE 设置 hd；SYNC_ATOMIC 长度至多8、hd=0，只用允许的非取回操作/至多8字节类型，排除 READ/MSWAP/CSWAP。 | 原生 SYNC_WRITE/SYNC_ATOMIC 已逐项检查 hd、类型、操作和总长≤8，源端组事务与目标计数/延迟动作有回归；组完成后额外成员/合法复用分类仍部分，见 SYNCHRONIZED-TRANSACTIONS.md。 |
| UE11-p0233-002 | §3.4.3.6，同步 scope/count | 目标按源 IP+sync_group 查状态；完成操作携包括自身的总消息数，非完成 write 为0。 | M5 缺失；正文“所有 sync write 为0”的宽泛用语需与表 3-15 completing 分支一起解释，不能让 completing write 丢失计数。 |
| UE11-p0233-003 | 表 3-15，字段编码续文 | group/count 各16位；非 completing count=0，completing count=整组消息数。 | 已阅读下一页续表；M5 缺失，还需零/最大计数与重复完成消息回归。 |
| UE11-p0235-001 | §3.4.3.7，带数据响应选择 | 请求长度大于 Payload MTU 时使用完整带数据响应；optimized request 不用此完整格式。 | 完整数据响应头已用于原生多包 READ、ACK/反向请求两种 carrier，响应关联经真实 PDS 测试；optimized 请求/响应仍缺失。 |
| UE11-p0237-001 | §3.4.3.8，packed 非 DEFAULT | 一组请求中任意响应不是 DEFAULT 时，PDS ACK 中每个请求都有对应响应。 | M8 缺失；需整组默认/混合错误/含数据响应的组合测试。 |
| UE11-p0238-001 | 表 3-19，local response | reserved 发送0；mm/opcode/version/code/ehl/payload_length 按本地格式解释。 | M8 缺失；不能由标准 SES reserved 接收测试推广到本地头。 |
| UE11-p0239-001 | 表 3-21，small 合法集跨页 | optimized non-matching 单包，NO_OP payload0，其他允许请求不超过一 Payload MTU。 | M5 格式未实现；需结合下一页完整 opcode 列表与响应头要求。 |
| UE11-p0240-001 | 表 3-21 续，格式/opcode 限制 | 分别校验 small/medium/std/local 的合法 opcode、NO_OP0、单包、offset 和长度约束；local ac0 至多16383、ac1 至多4095且仍受 MTU约束；响应格式与请求匹配。 | 标准头与零长 NO_OP 子集有测试，其余紧凑/packed 与完整响应关联缺失；本候选含多组独立义务，不能整体通过。 |
| UE11-p0241-001 | §3.4.4.1，buffer 集/行为 | relative tuple 和 absolute pair 唯一选择 buffer 集；每个 buffer 可配置 use-once/persistent；direct 按 Job。 | native posted receive/tagged 与每 MR use-once/persistent 选择已有实现；原生 RMA 固定精确注册和共享域消息所有权。直接本地地址仍缺失；见 USE-ONCE-RMA.md。 |
| UE11-p0241-002 | §3.4.4.1.1，untagged 消耗 | ROD 消耗队首，同消息所有包命中同一 buffer；RUD 可按到达次序；无 buffer 时采用规范 unexpected 流程。 | native posting/pinned registration、分片/FIFO、late receive 与 RUD/ROD provider 恢复已有回归；全部 unexpected 扩展行为仍待 M5。 |
| UE11-p0241-003 | §3.4.4.1.2，optimized RMA 唯一性 | small RMA 的 Job/PID/index 精确映射一个 buffer，provider 按规定选择。 | M5 缺失；普通 key MR 表不能代替 index-only 资源绑定。 |
| UE11-p0241-004 | §3.4.4.1.2，标准 RMA 唯一性 | 标准头 RMA 的 Job/PID/index/key 唯一映射一个 buffer。 | native 注册/授权和公开 provider MR 基础测试有覆盖；完整标准地址/授权配置仍未完成。 |
| UE11-p0242-001 | §3.4.4.1.3，exact matching | exact-only 实现可任意次序尝试，但有匹配 buffer 时必须选择；多个匹配时允许任选，否则 unexpected。 | tagged 未实现；不能把 wildcard 的强制 FIFO 规则误套成 exact-only 所有实现的 MUST。 |
| UE11-p0242-002 | §3.4.4.1.3，ROD wildcard 顺序 | 按 posted buffer 次序尝试；同 Job/initiator 在目标 tuple 上按源发送顺序处理头。 | M5 缺失；允许保持可观察顺序的内部优化，不强制某一种容器/搜索算法。 |

## 第 201～220 个候选

本批检查目标授权与响应生成。默认响应、显式响应、保证传递是不同概念；首错的
保证传递例外须与一般显式响应规则一起解释，不能只根据 opcode 决定缓存策略。

| 候选 ID | 章节与分类 | 拆分后的义务及适用条件 | 当前证据与后续处理 |
|---|---|---|---|
| UE11-p0243-001 | §3.4.4.1.4，直接寻址 | Job 选择地址上下文，线端地址从对应基址开始；允许仅一个 Job。 | M8 缺失；不能把收到的地址直接转换成本机指针。 |
| UE11-p0243-002 | §3.4.4.2，buffer 授权 | 每个 buffer 同时支持 exact Job 和 any Job 两种配置。 | native MR 与 provider 默认 any Job 已有回归；不同权限与撤销仍受检查，完整管理配置尚未完成。 |
| UE11-p0243-003 | §3.4.4.3，消息响应 | 每条消息至少一个语义响应；最后收到包的响应等待此前所有包完成语义处理。 | 当前同步 WRITE/原子与延迟接收有覆盖；异步操作/扩展消息组合仍需验收。 |
| UE11-p0244-001 | §3.4.4.3，DEFAULT 与保证传递 | DEFAULT 前完成处理；无法用 DEFAULT 表达的结果保证传递，并结合后述首错例外。 | PDS 区分 delivery/semantic/Clear；普通消息已修正重复 gtd，实际 8 包场景检查单一保证归属；标准请求记录耗尽已改为PDS接收前资源NACK，其他格式仍未完成。 |
| UE11-p0244-002 | Informative Text | 重复说明每条消息需要响应，无新增独立规范义务。 | 归入解释材料，不重复计作 MUST。 |
| UE11-p0244-003 | §3.4.4.3，多响应 | 后续响应保持首响应 opcode/code 或为错误；首个错误保证传递，后续错误不得保证传递；每包至多一个语义响应。 | `reply_error` 独立选择显式错误和保证属性；RUD/ROD、丢失/重放及遇到顺序有针对性覆盖，标准请求容量耗尽通过资源NACK和记录准入处理，其他格式尚未完成。 |
| UE11-p0245-001 | §3.4.4.3，提前 ACK | 未处理包提前 ACK 使用 NO_RESPONSE；DS 首包必须带实际语义响应。 | native RUD 缺口/DS-as-SEND 有回归；真正 DS/RTR M5 缺失。 |
| UE11-p0245-002 | §3.4.4.3，DC | DC 等到整个消息 GO；“最后收到”不等同于带 EOM 的包。 | provider 各完成等级保守选择 GO，原生乱序缺口有回归；完整操作集尚未完成。 |
| UE11-p0245-003 | §3.4.4.3，响应 ID | 回显 request message ID 或 read_request_message_id；请求无 ID 时响应 ID 为0。 | 标准请求与 READ 原/目标响应 ID 回显已有覆盖；紧凑格式仍缺失。 |
| UE11-p0245-004 | §3.4.4.3，响应 Job | 请求有 Job 时响应回显，某些 PDS 控制查询例外。 | 当前 SES response 构造回显，管理/TSS 扩展仍待验收。 |
| UE11-p0245-005 | §3.4.4.3，数据偏移 | SOM 响应 offset0，其余回显请求 offset。 | READ 实际请求/数据 ACK/反向请求已验证每片 offset；fetch、optimized/local 仍缺失。 |
| UE11-p0245-006 | §3.4.4.3，显式响应 | 非 DEFAULT 无数据用 RESPONSE，有数据用 RESPONSE_W_DATA，并遵守保证传递规则及先述重复错误例外。 | 当前无数据显式响应有覆盖；数据响应生命周期与完整保证矩阵未完成。 |
| UE11-p0245-007 | §3.4.4.3，首错优先 | 成功 RC_OK；首错按 SES 实际遇到顺序，非 PSN 顺序。 | native sticky error 与乱序错误测试已有覆盖；保证归属也按实际遇到次序检查，非 SOM 可先持有保证。 |
| UE11-p0246-001 | §3.4.4.3，modified_length | 普通响应为整个接受长度；DS defer 为0，RTR 指定重发量。 | 普通接受/错误长度已实现；完整 DS/RTR 缺失。 |
| UE11-p0246-002 | §3.4.4.3，响应 payload | payload_length 表示本包实际返回字节数。 | 原生 READ 的实际返回长度与放置已验证；fetch 仍缺失，codec round-trip 不构成完整操作验收。 |
| UE11-p0246-003 | §3.4.4.4，local packed 响应 | ACK 中逐项对应请求，READ/fetch 返回数据；错误数据响应触发整组 ACK。 | M8 缺失，不能独立发送部分结果。 |
| UE11-p0246-004 | §3.4.4.4，响应排序/完成 | 原文要求 ROD/RODL 响应有序，本地处理完成后才响应，DC 等待 completion。 | 条文位于 Unified Local 小节，跨 Profile 适用范围需继续核对；当前异步 ROD response 排序尚未声明通过。 |
| UE11-p0247-001 | §3.4.4.5，rendezvous eager | 不超过 eager 长度，末包 EOM；已发送量达到缩短长度时仍发送至少一个 EOM 包；窗口限制为 SHOULD。 | M5 缺失；缩短到0/已发送部分/末包在途需各自测试。 |
| UE11-p0247-002 | §3.4.4.5，unexpected rendezvous | RUD header 耗尽 backoff/retry；ROD 必须 buffer header 并提供资源耗尽处理。 | M5 缺失；普通 SEND unexpected 存储不能证明 rendezvous 流程正确。 |
| UE11-p0247-003 | §3.4.4.5，后续 READ | 原样使用 rendezvous PID/index/match，read_offset 可取整个消息；缓冲 eager 后相应推进偏移。 | M5 缺失；后续 READ 与原请求关联和授权必须完整测试。 |

## 第 221～240 个候选

本批区分 DS defer、NO_MATCH 重试和 ROD index exhaustion；三者的 token、generation
及重试条件不能互换。buffered unexpected 跨页段落已连读，不把段落截断当作义务结束。

| 候选 ID | 章节与分类 | 拆分后的义务及适用条件 | 当前证据与后续处理 |
|---|---|---|---|
| UE11-p0247-004 | §3.4.4.6，DS 初始传输 | OK/length0 后仍发至少一个 EOM 包；OK/full length 发送全部 payload；初始窗口上限为 SHOULD。 | 原生源首包不置 EOM，OK/0 后零 EOM 并等待 RTR，OK/full 后发完；0字节、MTU/多包、NSCC 和丢响应有端到端回归。源首包上限1 MTU为保守策略。 |
| UE11-p0248-001 | §3.4.4.6，DS header 耗尽 | DS 必须实现 header 耗尽时 backoff/retry，buffered header 为 SHOULD。 | 原生源对无捕获 NO_MATCH 退避重试；目标有界头耗尽不发送 RTR。等待 RTR、旧 MID/Clear、资源恢复和总 deadline 分别验证。完整 Sync Group/跨退避顺序仍待验。 |
| UE11-p0248-002 | §3.4.4.6，restart token | 初始 target token0；非零 target token 保证重启可匹配；defer 后等待 RTR，只重发请求部分；backoff 不产生 RTR。 | 原生源与可选捕获目标已有32+32位 token、原始身份/范围验证、陈旧/重复 RTR、零 token 再次延期和保留 MR 撤销/重用回归。目标采用 J=0/非零 token 策略；J>0/零 token 由独立真实 PDS 对端验证。 |
| UE11-p0249-001 | §3.4.4.6.1，DS-as-SEND | 忽略 restart token 时，返回 NO_MATCH/0 或 OK/request length。 | `send_header_data_test` 覆盖目标兼容路径，真正 defer 与 RTR 不在此能力内。 |
| UE11-p0249-002 | §3.4.4.7.1，RUD unexpected | 至少选择 backoff、buffered header、buffered message 中一种，可组合降级。 | native RUD 返回 NO_MATCH；provider 拥有操作副本并重试。原生低层调用者仍需履行重试合同。 |
| UE11-p0250-001 | §3.4.4.7.1.1，NO_MATCH | NO_MATCH modified_length0；initiator 重发整条消息，软件 provider 可承担。 | provider 重试/源缓冲所有权已有回归；native API 当前直接报错误，完整发起端层次合同需继续补全。 |
| UE11-p0250-002 | §3.4.4.7.1.1，RUD backoff | 所有 send/tagged send 支持 backoff/retry。 | 普通 provider SEND 部分实现；tagged/DS/rendezvous M5 缺失。 |
| UE11-p0250-003 | §3.4.4.7.2.1，buffered header | 响应 OK/0；保存头并与新 recv/trecv 比较。 | 真正 DS/rendezvous header buffering 缺失；普通 SEND 不可使用本方案。 |
| UE11-p0250-004 | §3.4.4.7.2.1，匹配后续动作 | rendezvous 保存 READ 所需信息并发 READ；DS 保存 initiator token 并发 RTR。 | M5 缺失；后续操作必须使用已授权资源和原 token。 |
| UE11-p0250-005 | §3.4.4.7.2.1，适用操作 | buffered header 仅用于 rendezvous 或 DS。 | 记录负向约束，禁止普通 SEND 只留头却宣称已接受全部数据。 |
| UE11-p0250-006 | §3.4.4.7.2.2，buffered message | eager 必须保存整个 payload，响应 OK/full request length。 | native ROD 有界 SparseMemory 保存全部 payload；DC 模式等待 posting 放置，完整完成条件还需与该策略联合验收。 |
| UE11-p0251-001 | §3.4.4.7.2.2，晚到 posting | 比较新 posting 并交付缓存 payload；允许降级重试但受 ROD 后述禁令限制。 | `unexpected_message_test` 覆盖完整/部分到达、撤销和截断；不将 RUD 降级许可扩大到 ROD wildcard。 |
| UE11-p0251-002 | §3.4.4.7.2.2，扩展长度 | rendezvous 返回长度≤eager；DS 返回0或全长，0表示 defer。 | M5 缺失；普通 SEND buffer 测试不能证明这些长度规则。 |
| UE11-p0251-003 | §3.4.4.7.3，ROD 禁止 NO_MATCH | ROD untagged/wildcard unexpected 不能使用 backoff/retry，否则会破坏匹配顺序。 | native ROD 使用有界 buffer，耗尽返回 DISABLED_GEN；provider 独立 ROD/RUD 恢复用例检查实际码。 |
| UE11-p0251-004 | §3.4.4.7.3，ROD wildcard 缓存 | 必须提供 buffered message 或 buffered header。 | 普通 untagged buffer 已有实现；M5 wildcard tagged 未实现。 |
| UE11-p0251-005 | §3.4.4.7.3，buffer exhaustion | libfabric/UET 映射必须包含 exhaustion 解决方案。 | 当前 provider 采用 client/server generation 路径；scalable RC_DISABLED 方案未宣称支持。 |
| UE11-p0252-001 | §3.4.4.7.3.1，选定 scalable 时 | tuple disabled 后全部返回 RC_DISABLED；重启前确保线上无旧操作；按原序重发。 | 此可选方案尚未启用，不可只切换返回码而复用 generation 恢复。 |
| UE11-p0252-002 | §3.4.4.7.3.2，generation 配置 | 不用 generation 时为0；收到不匹配 generation 返回 BAD_GENERATION。 | ResourceDirectory 与 provider 已测试部分路径；完整可编程管理与所有 tagged 类型仍缺失。 |
| UE11-p0253-001 | §3.4.4.7.3.2，耗尽/重启 | BAD_GENERATION 回当前代次；ROD 语义耗尽禁用 index 并返回 DISABLED_GEN；有资源且代次递增后启用。 | native resource lifecycle 和 provider process recovery 有覆盖，代次回绕/异步资源组合仍需验收。 |
| UE11-p0253-002 | §3.4.4.7.3.2，发起端恢复 | 必须重发；提前增加 generation 时只发最老消息，成功后再继续；指数退避为 SHOULD。 | provider FIFO 重试并等待旧 PDS 操作排空；native 低层错误回报合同与完整多源顺序仍需补全。 |

## 第 241～260 个候选

本批检查 Sync Group、序列示例与错误范围。Sync Group 的跨页 MUST NOT 及 recoverable
error 后可提前 MSG_ERROR 的续文已连读；示例不能替代完整 opcode 的实现和验收。

| 候选 ID | 章节与分类 | 拆分后的义务及适用条件 | 当前证据与后续处理 |
|---|---|---|---|
| UE11-p0253-003 | §3.4.4.7.3.2，代次不匹配 | 重发并使用响应给出的新 generation，允许立即重发。 | provider 已采用返回代次重试；native 低层完成合同仍需补全。 |
| UE11-p0253-004 | §3.4.4.8，同步组完成 | 每组恰好一个 completing；收到全部 ACK 后才复用 group ID。 | M5 缺失；最多65534个 write 与 completing 的关联及失败释放需测试。 |
| UE11-p0253-005 | §3.4.4.8，目标同步状态跨页 | 跟踪未完成组并遵守排序；RUD 不得为了排在其他 SYNC_WRITE 后而延迟 payload。 | M5 缺失；Job 关联/校验为 SHOULD，不能误作所有实现 MUST。 |
| UE11-p0255-001 | §3.4.5.1.1，单包请求 | 无 ID 的紧凑头以 PSN 关联；SES 处理完成后才响应，DC 等到 GO。 | 标准头子集有覆盖；紧凑头和 tagged 扩展缺失。DEFAULT 是 SHOULD，显式 RESPONSE 允许。 |
| UE11-p0257-001 | §3.4.5.2，标准 READ 序列 | 对数据响应再提供语义响应，可总用 DEFAULT；目标接受错误结果并 Clear 保证响应。 | M5 缺失；请求、反向数据 PDC 和结果缓存生命周期都需验收。 |
| UE11-p0258-001 | §3.4.5.2，READ 接收能力 | 两种 READ 序列均须保证不依靠再次上线交互就可接受所有响应数据。 | M5 缺失；发 READ 前预留接收容量，不能靠收到数据再发信用解决。 |
| UE11-p0261-001 | §3.4.5.4，DS 目标缓冲 | restarted 消息到原匹配 buffer；目标记住已缓存前缀 J，重启头不携带 J。 | M5 缺失；重启偏移与原始地址不可混用。 |
| UE11-p0261-002 | §3.4.5.4，defer 收尾 | 首次 deferred 消息也以 EOM 结束，便于释放该消息状态。 | M5 缺失；RTR 重启不是原消息缺少 EOM 的补救。 |
| UE11-p0262-001 | §3.4.5.4，未预留 token | 已保留 buffer 不得使用 target token0；未预留可重复 defer。 | M5 缺失；Message ID 可以在不再在途后复用，不能假定第三次重启必换 ID。 |
| UE11-p0267-001 | §3.4.5.6，语义重试序号 | NO_MATCH 完成原 PDS 事务，重试分配新 PSN；允许换 Message ID。 | provider 先等待旧 transport_pending 排空再提交新操作，实际 ROD/RUD 恢复已有覆盖。 |
| UE11-p0272-001 | §3.4.6.2，消息错误范围 | 不可恢复的 message error 只影响该消息及事务。 | semantic_error_test 验证错误后同 PDC 可完成新消息；扩展事务尚未实现。 |
| UE11-p0272-002 | §3.4.6.2，PDC 错误范围 | 不可恢复 PDS error 关闭 PDC，所有尚未成功的在途事务向应用报错。 | context event/source/target completion 及 provider timeout 有覆盖；全部错误矩阵尚未完成。 |
| UE11-p0272-003 | §3.4.6.3，有限语义重试 | 可限制 recoverable error 重试，超限必须错误结束。 | provider 有有限重试与错误 CQ；和 PDS 单包重传预算是不同层次。 |
| UE11-p0272-004 | §3.4.6.3.1，选定源端可恢复故障 | 分配 PSN 后可恢复故障 poison FCS，不能设置 IE；分配前本地处理为 SHOULD。 | 此硬件/中间缓冲故障注入尚未实现；payload reader 异常属于当前选择的不可恢复错误，不能混淆。 |
| UE11-p0272-005 | §3.4.6.3.2，目标可恢复错误跨页 | 使用 DS/发送 unexpected 规定流程；多包进行中可用 MSG_ERROR 提前结束。 | 普通 SEND/provider 重试与 abort 有覆盖；tagged/DS/rendezvous 缺失。 |
| UE11-p0273-001 | §3.4.6.4.1，IE | 不访问目标内存，消息非 OK；若首错则 INITIATOR_ERROR；提供 CQ 时保留 header data。 | native malformed/乱序 IE、首错和 CQ data 有覆盖；完整 datatype/opcode 扩展仍待验收。 |
| UE11-p0273-002 | §3.4.6.4.1，MSG_ERROR | 仅一个终止包、EOM=1、有效字段保持原值，payload可缩短；无内存访问；不得依赖 RUD 前包先完成。 | native source 停止 reader/发送 abort、目标提前 EOM 与迟到 SOM 有覆盖；所有头格式仍未完成。 |
| UE11-p0274-001 | §3.4.6.4.2，目标不可恢复错误 | 消息首错传播并保证传递，不影响 PDC；结合重复错误的单一保证规则。 | 普通 tracked message 已修正首错 gtd，后续消息可继续；标准请求不再使用无记录语义错误fallback，资源拒绝与首错路径分开。 |
| UE11-p0274-002 | §3.4.6.4.2，错误数据响应 | 数据响应错误时，不得写入发起端内存。 | M5 READ/fetch 缺失，需要写入前检查 RC。 |
| UE11-p0274-003 | §3.4.6.5，informational 优先级 | 向应用报告（若请求）；informational 内首错，后续 uncorrectable 覆盖且保证传递。 | 当前整数非取回操作无 informational 类型；浮点/完整优先级未实现。 |

## 第 261～280 个候选

本批检查 opcode/返回码、权限边界、内存模型和 PDS 配置。虚拟化、TSS 或保留 PDC
等有条件要求仍记录适用条件，不把“当前未启用”当作这些路线已完成。

| 候选 ID | 章节与分类 | 拆分后的义务及适用条件 | 当前证据与后续处理 |
|---|---|---|---|
| UE11-p0276-001 | 表3-23，操作码多义务 | NO_OP 单包；DATAGRAM仅UUD；MSG_ERROR禁用UUD；各 opcode 与格式/操作一致，保留码不可占用。 | native 支持子集且源端拒绝未实现操作；完整接收端非法组合、M5/M8扩展尚未完成。 |
| UE11-p0278-001 | 表3-25，返回码编码 | 普通无数据响应不得侵占0x38～0x3D响应数据保留空间；各返回码有独立 scope/recovery 含义。 | 当前已实现无数据码属于合法集；完整码表和扩展错误处理仍待完成。 |
| UE11-p0282-001 | §3.4.8.1，Job 权限 | 最高可达权限上下文插入或验证源 Job，应用只能使用已分配 Job。 | native MR检查与provider固定Job不能代替完整授权配置链；M3/M7管理模型待补。 |
| UE11-p0282-002 | §3.4.8.1，源 FA 权限 | 最高权限上下文插入或验证源 FA。 | PdsHost校验frame/packet地址一致不等于应用源地址授权；完整管理边界未完成。 |
| UE11-p0282-003 | §3.4.8.1，虚拟化跨页 | 虚拟化时 Job/FA配置仅HV/VMM可控；OOB provisioning加强隔离是SHOULD。 | 虚拟化行为/管理权限模型未实现，不能由同进程调用者可信假设推广。 |
| UE11-p0283-001 | §3.4.8.2，SDI/Job 配对 | 应用只能使用已分配SDI，源端支持SDI与允许Job的绑定。 | M6缺失；不能只验证AES-GCM密钥长度。 |
| UE11-p0283-002 | §3.4.9.1.1，ROD flow | 至少按源PID到目标PID/index的flow提供message processing顺序，可多个flow共享PDC。 | PDS有序交付及native posted/unexpected FIFO有覆盖；完整flow映射/扩展操作待验。 |
| UE11-p0283-003 | §3.4.9.1.1，目标处理次序 | ROD对目标Job/PID/index按呈现次序处理消息。 | 普通SEND匹配和provider FIFO有覆盖；tagged/rendezvous及跨PDC选择仍未完成。 |
| UE11-p0283-004 | §3.4.9.1.2，目标完成 | 请求目标CQ时在数据放置后通知，DC还需GO。 | 同步稀疏/应用缓冲写入后CQ已有覆盖；不等同于规范未要求的全局有序CQ。 |
| UE11-p0284-001 | §3.4.9.2，原子粒度 | 已支持原子需保证datatype单元素的atomicity。 | 单事件内执行受检整数元素；128位/浮点/fetch缺失，不能扩大能力。 |
| UE11-p0284-002 | §3.4.9.2，并发一致性跨页 | 同地址tuple的并发原子按单元素consistent，包括多源、atomic read/write和fetch。 | 当前整数非取回路径有多操作回归；完整fetch/所有并发组合未完成。 |
| UE11-p0285-001 | §3.4.9.2，普通访问与原子 | 普通send/write/read与原子的交叉一致性不是必需；需要一致性的调用者使用atomic版本。 | 记录用户使用约束；不把普通WRITE和原子执行恰好同一事件循环当作可移植保证。 |
| UE11-p0285-002 | §3.4.9.3，源成功完成 | 成功完成等待全部PDS ACK及语义响应，足以实现transmit complete。 | native逐PSN semantic集合与provider完成等级已有覆盖；错误提前完成仍单独保留PDS/ID状态。 |
| UE11-p0285-003 | §3.4.9.3，DC | DC可明确报不支持，否则语义响应等到目标GO。 | 当前RDM选择GO；ordinary buffered SEND等待posting，完整操作集待验。 |
| UE11-p0286-001 | §3.4.9.4，恰好一次 | ROD/RUD效果恰好一次；fetch保留旧值应对响应丢失。 | 非取回整数/PDS去重有覆盖；M5 fetching返回值缓存与清理缺失。 |
| UE11-p0286-002 | §3.4.9.6，sync完成 | completing WRITE CQ在同组所有payload交付后；相对其他CQ没有额外排序保证。 | M5缺失；避免错误实现成全局CQ barrier。 |
| UE11-p0286-003 | §3.4.9.6，sync atomic | completing ATOMIC在整组WRITE payload交付后执行。 | M5缺失；计数聚合不等于真正延迟执行原子。 |
| UE11-p0302-001 | §3.5.5，配置集合 | 每FEP至少一套PDS配置；支持reserved pool时另有第二套。 | Runtime Services已分host并支持部分参数，reserved pool未启用；完整配置集合仍缺。 |
| UE11-p0303-001 | §3.5.5，参数范围/状态 | 按指定单位及所需范围支持配置，允许更细粒度；表3-36状态也须支持。 | 纳秒RTO/NACK、0～15retry、MPR部分覆盖；新增UDP目的端口4793参考默认与0～65535配置/错端口/trim/stamp回归；表3-35的24个配置字段及表3-36状态已另列PDS-CONFIGURATION.md；Default_MPR编码与本地缓存已拆分，其余条件字段继续验收。 |
| UE11-p0305-001 | 表3-35续，MPR/SYN及注释 | MPR0 override 0～127；丢SYN后关闭遵守安全时间；启用加密时设0为SHOULD；native IP协议号可配置。 | MPR override/MAC-time SYN safety已有回归；Syn范围表格与正文位宽有冲突须记录。已改默认UDP/4793，原生协议号必须显式配置；network_defaults_test覆盖全部256值、缺失配置拒绝、0/17等端到端路径，见NETWORK-DEFAULTS.md。实验253/254只保留在显式测试配置。 |

## 第 281～300 个候选

本批连读 PDC mapping 的具体列表和建连分支。列表引导段不是空义务；在表格和
续页中的条件、错误码、PSN 分配与 TSS 分支均需各自验收。

| 候选 ID | 章节与分类 | 拆分后的义务及适用条件 | 当前证据与后续处理 |
|---|---|---|---|
| UE11-p0310-001 | §3.5.8，PDC 单模式/TC | 每PDC仅一种RUD/ROD/RODL及一种请求TC。 | 已实现RUD/ROD及默认TC；完整TC配置与RODL尚未完成。 |
| UE11-p0310-002 | §3.5.8，双向序号 | 两个独立PSN空间逐包加1；返回数据方向也可靠确认。 | 当前双向控制空间及正向数据有回归；M5 READ反向数据路径未实现。 |
| UE11-p0310-003 | §3.5.8.1，消息/PDC映射 | 一个消息只用一PDC；同PDC不同消息不交错，前消息完整发送后才发送下条。 | native FIFO producer与manager队列已有回归；所有扩展消息仍待验。 |
| UE11-p0310-004 | §3.5.8.1，ROD强制同PDC | 同Job/源FA/目标FA/源PID/目标PID/index/TC流使用同PDC。 | 现有manager映射部分覆盖；完整选择策略与配置尚未完成。 |
| UE11-p0310-005 | §3.5.8.1，最小tuple | 模式独立，所有tuple含目标FA和TC。 | 默认路径有单模式上下文；完整可编程tuple和TC选择未完成。 |
| UE11-p0311-001 | §3.5.8.1，源tuple列表 | 支持基础FA/TC/mode、TSS时SDI；RUD/ROD可任意组合Job/源目标PID/index，三种模式分别默认tuple。 | 已增加独立RUD/ROD策略及Job/源PID/目标PID/RI的全部16种组合，source PID采用本地元数据，与ses.initiator rank区分；全TC组、reserved pool、SDI与RODL仍待M6～M8。见PDC-MAPPING.md。 |
| UE11-p0311-002 | §3.5.8.1，目标tuple列表 | 按源FA/目标FA/SPDCID识别，验证源IP；单FEP目标FA常量可省略，TSS加SDI。 | peer binding和源地址核对已有测试；TSS和RODL未启用。 |
| UE11-p0311-003 | §3.5.8.1，tuple细则 | SPDCID跨mode/TC唯一，不靠mode/TC区分；启用TSS时SDI入key。 | 独立ID池与非法binding过滤部分覆盖，完整TC/TSS组合未完成。 |
| UE11-p0311-004 | §3.5.8.1，CCC tuple列表 | 支持目标FA/DSCP映射；ROD每PDC独立CCC，不能与RUD混合。 | NSCC已有RUD共享/ROD独立CCC回归；完整DSCP映射配置及reserved pool待补。 |
| UE11-p0311-005 | §3.5.8.1，READ返回方向 | READ数据使用原请求所在PDC的返回方向。 | M5缺失，不能另开一个无关WRITE消息模拟READ响应。 |
| UE11-p0312-001 | §3.5.8.1，RUD共享CCC | 同FEP对、同TC的RUD使用同CCC，reserved pool例外。 | NSCC共享状态已实现，保留池未启用；RCCC等其他CMS仍缺失。 |
| UE11-p0312-002 | §3.5.8.1，多PDC | 单消息同PDC；RUD可跨消息分配不同PDC；ROD同flow固定PDC。 | 当前FIFO和mode映射有回归；多RUD策略与完整flow配置待补。 |
| UE11-p0312-003 | §3.5.8.2，ID0 | 不以PDCID0建连；无已分配PDC的NACK使用0。 | ID池排除0，资源NACK与无context NACK部分测试；保留池完整路径仍缺。 |
| UE11-p0312-004 | §3.5.8.2，建立条件 | trim不可建连；NOOP/Negotiation可以建连；源等目标PDCID才established。 | trim无分配、控制建连及peer学习测试已有覆盖，TSS分支未实现。 |
| UE11-p0312-005 | §3.5.8.2，ID与CCC唯一性 | 本地分配使FA对/PDCID唯一，不能靠mode重复ID；RUD可共享CCC，ROD独立。 | pool/context reuse/NSCC部分覆盖；完整保留池和全部TC未完成。 |
| UE11-p0312-006 | §3.5.8.2，SYN持续 | 未收到目标回复前全部包SYN=1；限制SYN包数/控制建连建议为SHOULD。 | 当前SYN持续、重传和MAC安全时间有回归；完整失去所有SYN后的优化控制恢复尚待完善。 |
| UE11-p0312-007 | §3.5.8.2，SYN重载 | SYN时目标PDCID字段编码pdc_info/psn_offset。 | 显式codec、reserved pdc_info和控制建连测试已有覆盖。 |
| UE11-p0312-008 | §3.5.8.2，起点跨页 | plaintext起点随机/伪随机，距本地ID上次末PSN至少2¹⁶；TSS另遵安全起点规则。 | 已接入种子化allocator并保留本地ID记录，跨peer复用/重新设种子/实际建连在普通和sanitizer定向回归通过；删除不适用于明文的retired-peer起点上界，M6另验。 |
| UE11-p0313-001 | §3.5.8.2，建连程序跨页 | 逐分支处理buffer/trim/资源/安全起点/ROD首包/无SYN peer与窗口；返回方向同起点；未标重传的重复包丢弃。 | 多项独立义务，现有回归只覆盖子集；资源准入、完整错误事件和TSS仍待补，不整体标通过。 |
| UE11-p0314-001 | §3.5.8.2，NACK与分配 | 普通NACK不能自行创建PDC；NEW_START_PSN/ROD_OOO仅在原SYN请求触发的规定场景分配。 | 源端不将无context NACK当建连请求，ROD首包乱序已有回归；安全新起点流程缺失。 |

## 第 301～320 个候选

本批检查建连后SYN范围、安全起点、关闭流程和封装。安全起点两种方法的正文及
关闭流程续页已连读；明文PRNG起点和TSS anti-replay不是同一机制。

| 候选 ID | 章节与分类 | 拆分后的义务及适用条件 | 当前证据与后续处理 |
|---|---|---|---|
| UE11-p0315-001 | §3.5.8.2，逐包身份 | 每包验证源FA/SPDCID；tuple不匹配丢弃并记录HDR_MISMATCH。 | manager peer binding已有回归；完整分类管理事件仍未完成。 |
| UE11-p0315-002 | §3.5.8.2，已建连SYN范围 | SYN PSN不超过Start_PSN+MP_RANGE，否则NACK INVALID_SYN。 | 已补充data/control的初始范围检查；native RUD/ROD、相等/超界和回绕在普通及sanitizer定向回归通过，修正前静默丢弃场景保留为失败基线。 |
| UE11-p0315-003 | §3.5.8.2，未分配目标PDC | NACK.spdcid0时暂停非控制流量，到NACK重试时间或收到非零peer ID回复再恢复。 | NACK resource pause、去重计时及恢复有覆盖；安全NEW_START_PSN是独立未实现分支。 |
| UE11-p0315-004 | §3.5.8.2，丢SYN时间跨页 | 保存最近一次被判丢SYN的时间；优先原发送时刻，允许判丢时刻；只需最近一项。 | MAC-time timing、重传与关闭安全等待已有回归，成功重试不延长安全等待。 |
| UE11-p0317-001 | §3.5.8.2.1，TSS建连 | 加密PDC fully established前验证安全起点；两种方法互通，RANDOM_1RTT为必需基础。 | M6缺失；当前明文PRNG不满足加密起点义务。 |
| UE11-p0319-001 | §3.5.8.2.1.4，方法适用 | TSS必须支持target新起点NACK/源采纳并重启；EXPECTED_0RTT为可选优化。 | M6缺失；不能只实现EXPECTED而省略fallback。§3.5.8.2通用步骤与专用方法的NACK.spdcid描述有差别，实施时需明确处理。 |
| UE11-p0320-001 | §3.5.8.2.1.6，pending资源 | New_PDC_Time限制等待，超时递增计数，超过阈值向provider报告NEW_PDC_TIMEOUT_ERR。 | M6/管理事件未实现；普通连接RTO不等于安全PENDING timer。 |
| UE11-p0320-002 | §3.5.8.2.2，加密生命周期 | 到Start_PSN+2³¹必须关闭加密PDC，再建新PDC。 | M6缺失；普通32位序号回绕测试不能代替加密周期限制。 |
| UE11-p0321-001 | §3.5.8.3，关闭后新消息 | 关闭中的PDC不接受新SES消息；RUD可用其他PDC，ROD/RODL延迟到原PDC完全关闭。 | manager quiesce/deferred messages及context reuse有覆盖；RODL未实现。 |
| UE11-p0321-002 | §3.5.8.3，流程引导 | 关闭流程含后续步骤与续页条件，不能把引导句单独标通过。 | 分解见下项，保留完整PDS/READ/TSS矩阵缺口。 |
| UE11-p0321-003 | §3.5.8.3，关闭步骤跨页 | 在消息边界停新请求；排空ACK/Clear/NACK及READ返回；按选定方法等待丢SYN安全时间或传给target；可靠Close后释放，超限报错；target Close隐式Clear。 | 当前普通可靠close、SYN等待、close丢失/错误有覆盖；READ、转移安全时间和TSS仍缺。非idle诊断是SHOULD。 |
| UE11-p0322-001 | §3.5.8.3，Close重复 | Close用下一唯一PSN并重传；目标已关闭时必须NACK，不能重放已退休CP_ACK。 | 当前closed-target NACK路径符合方向；需要持续覆盖普通/丢ACK/迟到复用组合。 |
| UE11-p0322-002 | §3.5.8.3，READ排空 | 发Close前必须收完READ数据；非stateful read不必再等target Clear。 | M5缺失；缓存结果与普通响应的生命周期要分别处理。 |
| UE11-p0332-001 | §3.5.10，标准格式 | 全部UET包使用所定义格式。 | 标准codec与legacy明确分离；RUDI/RODL/UFH等未完成。 |
| UE11-p0332-002 | §3.5.10，PDS保留字段 | 发0、收忽略。 | 已实现格式通过pds_reserved_fields_test；保留码点仍单独拒绝，其他格式不在覆盖范围。 |
| UE11-p0333-001 | §3.5.10.1，IP/UDP能力 | 支持生成/接收IPv4、IPv6、UDP，部署可选择启用集。 | codec及原生场景覆盖四种组合；provider socket地址仍实验IPv4映射。 |
| UE11-p0333-002 | §3.5.10.1，UDP字段 | 源端口作entropy，不带UET entropy头；UDP checksum发0收忽略。 | wire/反馈熵/trimming测试已有覆盖，CRC按规定屏蔽该字段。 |
| UE11-p0333-003 | §3.5.10.1，原生entropy | 原生IP必须带entropy头，允许配置ip.protocol。 | codec/PdsHost可配置；实验IP协议号默认策略仍是已记录符合性缺口。 |
| UE11-p0333-004 | §3.5.10.1，禁分片 | FEP不做IP分片；IPv4 DF1、MF0、fragment_offset0。 | codec显式编码及拒绝分片有回归，网络MTU检查不等于所有扩展头已验收。 |
| UE11-p0333-005 | §3.5.10.2，UFH32 | UFH32带专用entropy头，VLAN/CSIG标签在UET EtherType前。 | M7/M8缺失；普通IP entropy头不能代替UFH格式。 |

## 第 321～340 个候选

本批检查接收错误分类、Clear 总则、MPR 与反向数据限制。Clear 不能仅按保证响应的
REQ_CLEAR 位解释：§3.5.11.4.3 和 PDS_Clear_Time 的定义还要求空闲时推进已更新的边界。

| 候选 ID | 章节与分类 | 拆分后的义务及适用条件 | 当前证据与后续处理 |
|---|---|---|---|
| UE11-p0347-001 | §3.5.11.1，未知type | 未识别PDS type递增PDS_TYPE_INVALID，丢弃且无响应。 | 已补完整性检查后的分类异常与每主机16位计数；已定义但未实现类型另行拒绝，不误标未知。 |
| UE11-p0347-002 | §3.5.11.3，未知控制类型 | 未识别ctl_type递增PDS_CTL_TYPE_INVALID，丢弃且不改变PDC。 | 已补wire及直接队列入口静默丢弃，覆盖SYN/已建连/PSN=0/伪造peer及后续合法请求；见PDS-INVALID-TYPES.md。 |
| UE11-p0348-001 | §3.5.11.4.3，累计Clear | RUD/ROD/RODL支持Clear，表示≤该PSN的ACK均已收到。 | RUD/ROD语义完成与Clear区分已有覆盖；RODL未完成。 |
| UE11-p0348-002 | §3.5.11.4.3，Clear初始化 | 两个方向初始化为Start_PSN−1。 | init与双向控制、回绕有覆盖，反向READ/RODL还需独立验收。 |
| UE11-p0349-001 | §3.5.11.4.3，空闲Clear | 无请求捎带时立即或定时发送Clear Command；使用PDS_Clear_Time计时是SHOULD。 | 已补立即策略；普通及sanitizer定向回归验证req=0默认ACK也推进Clear、无额外应用请求即可释放错误尾部，延时合并未启用。 |
| UE11-p0349-002 | §3.5.11.4.4，CACK表示 | RUD/ROD使用32位CACK，RODL使用规定的缩减格式。 | 普通codec与窗口覆盖，RODL未完成。 |
| UE11-p0349-003 | §3.5.11.4.4，保证结果阻挡 | CACK不能越过未Clear的最低保证响应；不把接收成功当作语义成功。 | selective_acknowledgment_test和首错丢失/查询已有覆盖。 |
| UE11-p0349-004 | §3.5.11.4.4，CACK初始化 | 创建PDC时为Start_PSN−1。 | 明文随机起点、双向控制及回绕已测试；TSS/RODL仍缺。 |
| UE11-p0351-001 | §3.5.11.8.4，RETX | 重传请求设置RETX并触发ACK；优先接收为建议。 | RUD/ROD重传、trigger反馈和资源重试覆盖，RODL未完成。 |
| UE11-p0351-002 | §3.5.11.8.5，ECN回显 | 当且仅当触发响应的包被ECN标记时设置M。 | PDS feedback、MAC时间戳和trim回归检查对应触发包；其他CMS/安全路径待补。 |
| UE11-p0355-001 | §3.5.11.13，MPR解释跨页 | 非零mpr乘128更新发送区间；零按override选择忽略/替代；缩窗不再发区间外新包。 | 初始窗口按Default_MPR×128建立，独立于local_packet_capacity；零override下收到零MPR取消range限制；边界/缩窗和配置见PDS-WINDOWS.md。 |
| UE11-p0355-002 | §3.5.11.13，MPR新鲜度 | 仅严格更新的CACK可更新MPR；override0时一旦非零后不可再发零。 | stale/equal CACK拒绝、非零本地MPR及override有回归；完整动态接收端配置仍待完成。 |
| UE11-p0355-003 | §3.5.11.14，SACK零位 | 零位表示未知，不能推断丢失。 | 当前SACK只标记肯定收据，不直接把零位当丢包；所有早期丢失检测算法仍非完整。 |
| UE11-p0356-001 | §3.5.12.1，返回方向限制 | 非RODL返回方向只支持READ/原子响应数据；SEND/WRITE/READ新请求及RTR走独立发起方向。 | 当前应用操作仅从initiator提交；完整READ返回与非法方向接收检查仍需M5补全，泛型PDS准入单测不构成语义能力声明。 |
| UE11-p0356-002 | §3.5.12.1，READ响应承载 | ≤Max_ACK_Data_Size放ACK，大于阈值用原PDC返回方向的PDS Request。 | M5缺失；不能用无关WRITE模拟返回数据。 |
| UE11-p0356-003 | §3.5.12.1，RODL响应 | 所有响应放ACK，不使用Max_ACK_Data_Size；请求/响应映射不同TC。 | M8缺失，不能复用RUD大READ返回路径。 |
| UE11-p0357-001 | §3.5.12.2，ACK关联 | ACK对应触发请求/CP的PSN，Probe是例外，延迟SES响应允许。 | 当前普通/控制/Probe和缓存重放有对应测试；其他类型仍未完成。 |
| UE11-p0358-001 | §3.5.12.2，ACK处理选择 | 基础ACK状态处理/MPR是SHOULD；RUD coalescing必须处理SACK，逐包模式为SHOULD；Probe ACK必须填SACK。 | 已选择逐包ACK并处理SACK/MPR，Probe另验；coalescing/ACK_CCX与RODL未实现。 |
| UE11-p0359-001 | §3.5.12.2，响应entropy | 从触发包复制原生entropy或UDP源端口。 | native/UDP、重放、ECN/RETX和Probe有回归；未实现封装另验。 |
| UE11-p0359-002 | §3.5.12.2，逐包ACK | 必须支持ACK per packet，可选coalescing。 | 当前逐包策略覆盖，不声明可选coalescing已经实现。 |

## 第 341～360 个候选

这批区分逐包 ACK、可选 ACK 合并和 RODL 的反向累计确认。§3.5.12.2 对 CP 的
`UET_HDR_NONE` 概述还要结合 §3.5.16 的专用 `UET_HDR_CP_ACK` 格式，不能删除
Close/Negotiation 的有效载荷。第 352 个候选的 stateful response 位于 RODL
反向确认上下文，要求单独 ACK，不能仅从“ACK packet”一词推导所有 scale-out 响应类型。

| 候选 ID | 章节与分类 | 拆分后的义务及适用条件 | 当前证据与后续处理 |
|---|---|---|---|
| UE11-p0359-003 | §3.5.12.2，AR触发 | 收到AR=1的请求必须ACK，与ACK-per-packet配置无关。 | 当前逐包SES响应及控制回归覆盖；资源拒绝时按规定返回NACK，未启用合并策略。 |
| UE11-p0359-004 | §3.5.12.2，CP响应 | 普通CP确认不携带SES头；专用CP_ACK按§3.5.16编码。 | Clear无ACK，NOOP/Probe及Close/Negotiation各有测试；未来Credit等仍需分别验证。 |
| UE11-p0359-005 | §3.5.12.2，ACK范围 | ACK_PSN低于有效CACK或高于最高已发送PSN时不得更新PDC。 | I/T_PDC在CMS/交付/语义处理前检查序号；窗口、回绕和未来ACK覆盖仍应集中补强。 |
| UE11-p0359-006 | §3.5.12.3，逐包AR | 启用ACK-per-packet时，每个请求设置AR。 | 当前发送请求强制AR；标准codec/恢复测试检查，其他可靠模式待实现。 |
| UE11-p0359-007 | §3.5.12.3，DEFAULT推断 | 丢失ACK的PSN严格低于CACK时推断DEFAULT。 | selective_acknowledgment_test验证严格高于与SACK不能替代语义结果。 |
| UE11-p0359-008 | §3.5.12.3.1，逐包SACK | 64位；只在实际收到、交给SES且取得响应后置位；零位不携带否定信息。 | 当前从完成集合/响应缓存构造，不使用仅接收集合；异步SES与保证错误测试覆盖，其他模式仍缺。 |
| UE11-p0360-001 | §3.5.12.4，可选合并条件 | 选择合并时依表3-61设置AR，需逐条复核该表。 | 未启用ACK合并；不把逐包策略的通过证据套用到合并。 |
| UE11-p0360-002 | §3.5.12.4，RUD/ROD合并 | 表3-62触发、ACK_CC/CCX、ACK_PSN对应显式响应，其余已确认PSN按DEFAULT处理。 | 合并发送策略未实现；接收端语义推断仍保留严格CACK规则，不能由SACK推断DEFAULT。 |
| UE11-p0360-003 | §3.5.12.4，RODL合并 | 按表3-62及UFH_16/idle例外，可用反向ACK状态替代独立ACK。 | M8缺失；不得复用scale-out的全部触发条件。 |
| UE11-p0360-004 | §3.5.12.4，语义与收据分离 | CACK严格推进才能推断DEFAULT；SACK不能推断DEFAULT。 | processSemanticAcknowledgment与对应回归已分离交付/语义状态。 |
| UE11-p0362-001 | §3.5.12.4.3，合并SACK | 各Profile支持64位SACK；收到并交付SES才置位，零位不是丢失证据。 | RUD逐包接收/发送与Probe部分实现；合并及其他Profile证据仍缺。 |
| UE11-p0364-001 | §3.5.12.4.4，RODL有状态响应 | 非DEFAULT响应必须用ACK传递，不能仅捎带反向CACK。 | M8缺失；候选提取的章节归属跨越小节，按原文上下文归类。 |
| UE11-p0365-001 | §3.5.12.4.4，RODL序号恢复 | 双方维护完整32位CACK，按12/16位低位检测回绕并恢复高位。 | M8缺失；需单独测试多个回绕及低位歧义边界。 |
| UE11-p0365-002 | §3.5.12.4.4，RODL完整状态 | 双方维护完整32位PSN/CLEAR_PSN。 | M8缺失；不能把wire位宽直接作为内部状态位宽。 |
| UE11-p0365-003 | §3.5.12.4.4，RODL空闲推进 | 无SES业务但Clear/CACK待更新时必须发ACK或控制包。 | M8缺失；当前RUD/ROD空闲Clear不构成RODL证据。 |
| UE11-p0365-004 | §3.5.12.5，保证响应阻挡 | 保证响应未Clear前CACK不得推进到或越过该PSN。 | 保证错误缓存、Clear、SACK及回绕已有测试；新READ/fetch模式仍需验收。 |
| UE11-p0365-005 | §3.5.12.5，显式结果优先 | 先处理ACK_PSN携带的非DEFAULT响应，再为允许的其余PSN推断DEFAULT并标记完成。 | processSemanticAcknowledgment先显式后累计，防止错误被后续成功覆盖；对应测试已覆盖。 |
| UE11-p0366-001 | §3.5.12.6，目的ACK窗口 | 仅在允许窗口或Clear到CACK例外区间ACK，≤Clear不再ACK。 | 数据与编号CP按CACK锚点检查窗口，保留Clear..CACK重放例外；静态接收通告、Probe和回绕有定向测试；运行中动态MPR策略仍未选择。 |
| UE11-p0366-002 | §3.5.12.6，源窗口 | 不发高于CACK+MP_RANGE的新包；缩窗后允许重传。 | PeerSequenceWindow独立于本地容量，MPR边界/缩窗/重传已有回归。 |
| UE11-p0367-001 | §3.5.12.7，NACK生成 | 按表3-66；回显触发包RETX与entropy。 | 全码分类、RUD/ROD恢复及反馈触发测试部分覆盖；完整表3-66仍需逐行映射。 |

## 第 361～380 个候选

表3-66的禁发NACK条件不能被一般错误处理覆盖。§3.5.15.3在下一页继续说明
SHOULD采用逐包定时器/时间戳，或选择每PDC定时器；当前每PDC的`RTOTimer`
管理逐PSN事件，按这段续文采用逐包方案，不把第一页的概述解释为必须删除逐包恢复。
本批还发现ROD唯一PSN控制包的TC映射需要独立检查，不能把所有CP都映射到ACK TC。

| 候选 ID | 章节与分类 | 拆分后的义务及适用条件 | 当前证据与后续处理 |
|---|---|---|---|
| UE11-p0368-001 | 表3-66，六类触发 | 本地资源丢弃/trim/未收到的ACK查询/规定UET错误产生NACK；窗口外与网络头无效不得NACK。 | 资源准入、trim、ACK查询和codec部分覆盖；新建窗口拒绝与ACK窗口丢弃需区分，完整逐行证据仍待整理。 |
| UE11-p0369-001 | §3.5.12.7，错误分类 | NORMAL/PDC_ERR/PDC_FATAL分别处理，fatal发送者/接收者关闭PDC。 | negative_acknowledgment_test覆盖所有码的source action；本地fatal生成后关闭的全矩阵仍需补强。 |
| UE11-p0370-001 | §3.5.12.7，配置支持 | 支持表3-67列出的必选变量。 | RTO初始值、1～4组NACK延迟和公共重试预算已配置；独立NACK预算为未选择可选项。 |
| UE11-p0370-002 | 表3-67，多项配置 | RTO_Init_Time、NACK_Retx_Time、Max_RTO_Retx_Cnt及可选Max_NACK_Retx_Cnt分开解释。 | RetryTiming/RetryLimit测试覆盖纳秒范围、零延迟、0～14/15无限及原因保存；新模式仍需接入。 |
| UE11-p0370-003 | §3.5.12.7，跨页RTO算法 | 超时重传、指数增加；NACK等待后重传并重启RTO；Probe允许暂停。 | 逐包MAC启动、timeout_retry_count和NACK不增加退避已有覆盖；Probe采用独立恢复事件，组合矩阵仍部分完成。 |
| UE11-p0371-001 | §3.5.12.7，有效NACK码 | 发送码必须来自表3-68；可按实现资源粒度选择合法码。 | 全256值分类、保留值拒绝和实际资源NACK已有测试；尚无所有合法码的真实生成路径。 |
| UE11-p0371-002 | 表3-68，接收动作 | 每个合法码执行规定source action，不能统一视为重传。 | NORMAL/fatal/New_Start分类已有；New_Start安全建连动作仍缺，不能因分类正确通过全项。 |
| UE11-p0373-001 | §3.5.12.7，NACK保护 | 不可trimmable，trimmed NACK丢弃；越界NACK除计数外不能更新状态。 | trim与全码/未来PSN/未绑定peer回归覆盖；可选trim诊断计数尚不完整。 |
| UE11-p0374-001 | §3.5.13，推断响应 | 推断成功时构造DEFAULT；若支持NO_RESPONSE，需独立状态区分。 | 当前DEFAULT helper与显式NO_RESPONSE恢复分离；未声称所有可选NO_RESPONSE路径完整。 |
| UE11-p0375-001 | §3.5.13，重复/查询响应 | 已完成非保证请求构造表3-69 DEFAULT；SES处理中按规则NACK。 | ACK Request、重复PSN、首错缓存及JobID恢复已有测试；READ缺失时不套用普通DEFAULT。 |
| UE11-p0376-001 | §3.5.15，丢失检测总则 | 必须实现表3-70的必选检测方法。 | trimming/NACK/RTO已接通；新模式与TSS组合仍缺。 |
| UE11-p0376-002 | 表3-70，分层义务 | trimming/NACK/RTO为MUST；请求早期检测和ACK丢失早期检测为SHOULD。 | 三种基础方法已有；SHOULD项需给选择理由及独立实验，不能仅靠RTO通过所有建议。 |
| UE11-p0377-001 | §3.5.15.1，trim识别 | 按DSCP识别；不验证IP/UDP长度；完整性/认证行为按有效载荷保留情况选择。 | IPv4/IPv6/native/UDP无CRC尾部和长度不一致回归已有；TSS解密/ICV路径未实现。 |
| UE11-p0377-002 | 表3-71，未认证trim | 仅按允许字段产生NACK或丢弃；不得用于正常PDC状态更新，CP丢弃。 | 既有identity匹配与无分配/peer学习路径已有测试；RUDI/RODL/TSS仍缺。 |
| UE11-p0377-003 | §3.5.15.3，RTO跨页 | PDC维护RTO；结合下一页采用推荐的逐包timer/timestamp或每PDC替代方案。 | 当前每PDC拥有RTOTimer，逐PSN事件由注入时钟驱动；MAC出队启动及取消/重用已有回归。 |
| UE11-p0386-001 | §3.5.15.5.1，ACK丢失恢复 | 判定ACK丢失后发ACK Request或原请求；建议优先ACK Request，READ数据例外。 | 普通请求SACK后转查询已有覆盖；READ例外留给M5真实READ实现。 |
| UE11-p0386-002 | §3.5.16，CP全集 | 表3-82全部CP类型必须支持，TC按§3.6.4.7。 | NOOP/查询/Clear/Close/Probe/NO_NEG部分完成；Credit/Credit Request及完整Negotiation未完成。 |
| UE11-p0386-003 | §3.5.16，ROD/RODL控制TC | 有唯一PSN的ROD/RODL CP必须用PDS Request TC。 | 已补ROD本地分类元数据及NO_TRIM码点，32种NSCC/trimming/双向Close组合通过普通和sanitizer定向回归；RODL未实现。 |
| UE11-p0387-001 | §3.5.16，CP_ACK格式 | 专用payload使用CP_ACK next header；不能用在ACK_CC/CCX。 | Close/NO_NEG golden及标准codec部分覆盖；更多CP_ACK和非法组合仍需验收。 |
| UE11-p0387-002 | §3.5.16，CP建连限制 | 仅NOOP/Negotiation可带SYN启动，其余必须等待PDC建连。 | control_establishment_test已验证已知其他类型SYN拒绝；未知类型另按静默丢弃规则处理。 |

## 第 381～400 个候选

CP字段义务按表3-82分开，唯一PSN不包括ACK查询、Clear、Probe和Credit。
本批对照PDF确认表3-82的Telegram编码`0x10`不能放入表3-48的4位字段，
暂不自定线格式。reserved PDC是整个小节明确声明的可选功能，其MUST只在选用后适用。

| 候选 ID | 章节与分类 | 拆分后的义务及适用条件 | 当前证据与后续处理 |
|---|---|---|---|
| UE11-p0387-003 | §3.5.16，CP trimming | CP不得标trimmable；收到trimmed CP丢弃，建议计数。 | 当前CP走控制DSCP且trimmed CP丢弃；将ROD唯一PSN CP改到请求TC时仍须使用NO_TRIM，诊断计数尚部分完成。 |
| UE11-p0388-001 | §3.5.16.1，NOOP字段 | 新唯一PSN、AR=1、正确pdc_type、payload=0并触发ACK。 | RUD/ROD建连、重传、类型和golden已有回归；RODL另验，isrod旧名称按正式两位pdc_type解释。 |
| UE11-p0388-002 | §3.5.16.1，NOOP启动 | NOOP/Negotiation可用SYN建连，其余不可。 | control_establishment_test及初始SYN窗口/模式测试已有覆盖。 |
| UE11-p0388-003 | §3.5.16.2，查询字段 | ACK Request使用被查询PSN，AR=1。 | SACK查询与定时恢复已有检查；不得为查询额外分配新PSN。 |
| UE11-p0389-001 | §3.5.16.2，小READ恢复 | 小READ的ACK数据丢失时重发原READ，不查询不保存的数据。 | M5缺失；未来READ必须保留请求并重新读取目标内存。 |
| UE11-p0389-002 | §3.5.16.2，陈旧查询 | 查询PSN小于Clear时静默丢弃，可计诊断。 | receiveAckRequest已有Clear边界处理；相等及跨回绕仍应集中加强。 |
| UE11-p0390-001 | §3.5.16.3，Clear字段 | Clear/Clear Request的PSN=0、AR=0，不触发ACK。 | 空闲Clear、显式Clear Request及回绕已有回归。 |
| UE11-p0390-002 | §3.5.16.4，关闭权限与超时 | 仅initiator正式关闭；target请求未及时确认时必须错误关闭。 | target_close_test覆盖双向握手与超时；迟到包/新模式矩阵仍部分完成。 |
| UE11-p0390-003 | §3.5.16.4，Close字段 | Close Command/Request分配下一PSN且AR=1。 | 两个方向共用发送追踪/计时器，Close回归已有覆盖；RODL未实现。 |
| UE11-p0392-001 | §3.5.16.5，Probe字段 | PSN=0、AR=1；opaque回显到ACK offset；payload选择SACK基址。 | pds_probe_test覆盖opaque、查询基址、回绕和超时，不占新业务PSN。 |
| UE11-p0392-002 | §3.5.16.5，Probe ACK | P=1，REQ_CLEAR/REQ_CLOSE均不可设置。 | Probe独立收发与普通ACK隔离已有回归；TSS/RODL适用范围另验。 |
| UE11-p0392-003 | §3.5.16.6，Credit字段 | RCCC/TFC下Credit及Credit Request的PSN=0、AR=0，由CMS请求。 | M5缺失；旧生成函数占位不算已实现信用协议。 |
| UE11-p0394-001 | §3.5.16.7，Negotiation字段 | 新唯一PSN、AR=1、PDC类型正确；启动时用SYN状态机。 | NO_NEG建连、丢失/重复和正确类型已有回归；完整ON_OFF与安全协商未实现。 |
| UE11-p0395-001 | 表3-78，NO_NEG与ON_OFF | NO_NEG长度=0且其余32字节为零，用普通ACK格式；ON_OFF携带功能位。 | NO_NEG独立字节检查已有；ON_OFF未实现，保留类型不能启用未知功能。 |
| UE11-p0397-001 | §3.5.16.8，PCM条件项 | Telegram唯一PSN、AR=1、仅建连后双向发送；交付PCM或返回规定NACK。 | PCM是M8后增强且未启用；编码表存在4位/0x10差异，见PDS-INVALID-TYPES.md。 |
| UE11-p0397-002 | §3.5.16.9，RODL CP范围 | Close双向生成必选，接受NOOP/查询/Clear；其余列出类型可不支持。 | M8缺失；不能把scale-out所有CP生成要求直接套用RODL。 |
| UE11-p0398-001 | §3.5.17，保证响应状态 | 保证响应设置REQ_CLEAR并保留重放状态，READ数据例外。 | 首错缓存/查询/丢失已有覆盖；READ/fetch保证响应路径仍缺。 |
| UE11-p0398-002 | §3.5.17，保证响应寿命 | 保留到Clear；窗口内重复/查询重发保证响应或构造合适DEFAULT。 | SES错误、SACK和Clear已有回归；READ特殊规则不得被通用缓存掩盖。 |
| UE11-p0398-003 | §3.5.17，fetch响应 | fetch数据总放ACK，至少16字节能力；保存结果供重放，超长建议专用NACK。 | M5缺失；现有非fetch原子不能满足此要求。 |
| UE11-p0399-001 | §3.5.18，可选reserved PDC | 选用时配置保留PDC/CCC数量，建议至少16；后续表3-83另验。 | 未选择该可选服务；资源池上限不等于保留池，不公布此能力。 |

## 第 401～420 个候选

这批把一个段落的RUD/ROD服务列表拆开列出，段落通过与否不能只取决于基本WRITE
测试。ROD消息不可交织、ACK/READ响应顺序需要异步SES负载验收；固定entropy仅证明
路径选择。§3.5.21.1的“CACK相等或更高”措辞还需结合§3.5.12.5对保证响应阻挡的
规则，不能把相等CACK无条件解释成已经收到非DEFAULT语义结果。

| 候选 ID | 章节与分类 | 拆分后的义务及适用条件 | 当前证据与后续处理 |
|---|---|---|---|
| UE11-p0399-002 | §3.5.18，保留池条件项 | reserved PDC由软件分配/销毁，不因资源压力动态关闭。 | 未启用可选reserved服务，普通PDC的生命周期不能作为该项证据。 |
| UE11-p0399-003 | §3.5.18，保留句柄条件项 | 句柄固定PDC/CCC、禁止混用，启动时设置use_rsvd_pdc。 | 未启用；未来需独立句柄类型与线上标志测试。 |
| UE11-p0399-004 | §3.5.18，保留池分配条件项 | 新SYN按use_rsvd_pdc选择池，普通分配不得占用保留资源。 | 未启用，现有一般资源上限不是双池实现。 |
| UE11-p0401-001 | §3.5.20.1，RUD九组服务 | 发送/选择性重传/恰好一次；SES响应交付、缓存或DEFAULT；Clear携带/处理/释放；同消息READ同向。 | 基础RUD、重试预算、重复、首错、Clear及原包重传刷新已有证据；READ例外和返回方向仍缺，整段不能通过。 |
| UE11-p0415-001 | §3.5.21，ROD消息边界 | 同消息共用一个PDC，消息不可交织；可跨PID/队列共享上下文。 | 新增SEND加两个分片WRITE的线上FIFO/无交织检查通过；多队列共享及READ仍需独立验收。 |
| UE11-p0415-002 | §3.5.21.1，ROD发送顺序 | 单路径、消息内顺序、同send queue提交顺序。 | 固定entropy/GoBackN已有测试；多消息调度和唯一PSN CP的TC同序约束分开验证。 |
| UE11-p0415-003 | §3.5.21.1，ROD服务列表 | GoBackN与一次有序交付；ACK/READ按请求顺序；NACK含Expected_PSN；新丢失阻止高PSN并从缺口重传。 | 重传轮次/Expected_PSN/阻止新业务已有覆盖；已补异步SES首次ACK按序、旧响应查询重放和回绕测试，READ顺序仍缺。 |
| UE11-p0416-001 | §3.5.21.1，ROD ACK恢复 | ACK同序且回显entropy；按有效累计信息推断非保证响应；保证响应丢失选择查询/原请求/GoBackN。 | 普通查询、保证错误与entropy已有证据；新增ROD首次ACK顺序门限，缓存查询不越过未完成SES，旧ACK仍可重放；READ和RODL另验。 |
| UE11-p0417-001 | §3.5.21.1，READ ACK恢复 | 丢失READ数据重发原请求；ROD允许重复旧PSN触发保证ACK；可选择完整GoBackN。 | 保证错误重复重放部分覆盖；READ重新执行与缓存例外尚缺。 |
| UE11-p0417-002 | §3.5.21.1，重复处理例外 | 查询/原包恢复期间可继续发新PSN；目的端仍须处理乱序到达的重复包。 | chkRxError区分重复与新缺口，RUD/ROD恢复部分覆盖；READ专项仍需补充。 |
| UE11-p0421-001 | §3.5.22.1.1，RODL可选禁重传 | 关闭RODL重传时，单包丢失即fatal并关闭PDC。 | M8缺失；RODL默认需先实现可靠重传，禁重传独立配置和验收。 |
| UE11-p0422-001 | §3.5.22.1.2，RODL关闭 | target发Close Request前完成自己发起的全部事务及Clear；收到Close Command也须完成活动事务再ACK。 | M8缺失，不能复用单向ROD的空闲条件。 |
| UE11-p0422-002 | §3.5.22.1.2，RODL死锁隔离 | 响应与请求使用不同TC；READ/fetch数据放ACK。 | M8缺失；通用双TC网络只提供基础设施，不构成RODL协议实现。 |
| UE11-p0422-003 | §3.5.22.1.2，RODL ACK阈值 | Max_ACK_Data_Size等于Payload MTU；ACK/NACK映射独立TC。 | M8缺失；不得套用scale-out大READ返回请求路径。 |
| UE11-p0423-001 | §3.5.22.1.3，RODL ACK/NACK | 必须支持收发ACK/NACK及READ/fetch/错误有状态响应。 | M8缺失；当前RUD/ROD codec和错误响应不是该模式的证据。 |
| UE11-p0423-002 | §3.5.22.1.3，RODL状态ful响应 | 有状态响应由ACK携带，不能只靠反向CACK捎带。 | M8缺失。 |
| UE11-p0423-003 | §3.5.22.1.3，RODL完整序号 | 双方维护32位PSN和Clear，线上的低位字段只作压缩。 | M8缺失；需结合低位扩展和回绕规则测试。 |
| UE11-p0423-004 | §3.5.22.1.3，RODL空闲状态 | 空闲而Clear/CACK有更新时发送ACK/CP，按ROD合并子集触发。 | M8缺失；RUD/ROD立即Clear只是实现基础。 |
| UE11-p0426-001 | §3.5.24，故障隔离 | 正常事件不改变健康PDC；unexpected事件不能影响其他良性连接。 | 资源压力多peer、错误码/peer绑定和上下文复用已有测试；完整事件矩阵仍需扩展。 |
| UE11-p0427-001 | §3.5.24.2，PDC_ERR计数 | source必须计数，destination建议计数，可用事件位。 | 当前部分generic event_cnt与typed ingress计数，尚无完整按PDC_ERR分类的管理快照；M7仍需补齐。 |

## 第 421～440 个候选

错误总则要服从unknown type、无效网络头、trimmed CP等明确静默丢弃例外。
NSCC是必选；RCCC/TFC是可选算法，但本路线图仍计划在M5实现。CSIG-Reflect的
必选范围是CSIG-capable FEP，当前不能因只实现普通NSCC就公布CSIG能力。

| 候选 ID | 章节与分类 | 拆分后的义务及适用条件 | 当前证据与后续处理 |
|---|---|---|---|
| UE11-p0427-002 | §3.5.24.2，拒绝交付诊断 | 适用的请求/CP交付失败返回说明原因的PDS NACK，遵守具体禁回包例外。 | 未知DPDCID、资源准入及模式/SYN错误部分覆盖；完整表3-68事件生成仍缺。 |
| UE11-p0427-003 | §3.5.24.3，不可恢复事件 | fatal关闭、释放资源、向SES报告失败并丢弃关联包。 | 重试耗尽、连接复用及目标失败完成已有测试；所有fatal生成与关闭CP的矩阵仍需补齐。 |
| UE11-p0427-004 | §3.5.24.3，fatal计数 | source必须计数、destination建议计数。 | 当前generic event_cnt与失败事件不构成完整fatal管理计数接口；M7缺口。 |
| UE11-p0435-001 | §3.5.26，TSS/CRC互斥 | UET_DATA_PROTECT=TSS时不再使用CRC，由ICV保护。 | M6缺失；当前crc开关不是完整DATA_PROTECT协商或配置类型。 |
| UE11-p0435-002 | §3.5.26，发送CRC | CRC模式下所有包包括CP按规定覆盖范围计算并附尾。 | 独立reference CRC、golden、IPv4/IPv6/native/UDP与控制包回归已有覆盖；未实现封装另验。 |
| UE11-p0436-001 | §3.5.26，接收CRC | CRC模式验证所有正常包；trimmed例外按缺失CRC处理。 | CRC破坏、保留位与unknown type完整性优先，以及trim路径已有测试。 |
| UE11-p0437-001 | §3.5.26.1，UFH_16 CRC | UFH_16必须有CRC，其中携带PSN状态并按专门覆盖范围计算。 | M8缺失，不能复用普通CRC尾部而忽略PSN位。 |
| UE11-p0440-001 | §3.6.2，算法支持范围 | NSCC必选；RCCC/TFC可选且可按允许组合运行。 | NSCC已接入真实发送准入；RCCC/TFC按路线图M5待做，各自不得被能力发现提前公布。 |
| UE11-p0441-001 | §3.6.4，网络遥测范围 | 网络必选ECN；端点支持trim，交换机trim可选。 | Fabric的瞬时出队ECN、主机trim接收/NACK和可选出口trimming已有测试。 |
| UE11-p0441-002 | §3.6.4.1，ECN基础 | 端点与交换机必须支持ECN。 | ECT到CE、CE回显与CRC/IPv4 checksum保留已有测试；非IP UFH路径另验。 |
| UE11-p0441-003 | §3.6.4.1，瞬时队列 | 交换机必须支持用瞬时队列深度决定ECN，可选择确定性/概率策略。 | 当前选出队确定性阈值，含在服务帧字节；Fabric解析测试和实验已有证据。 |
| UE11-p0441-004 | §3.6.4.1，ECT条件 | NSCC或依赖ECN的路径算法启用时，所有UET数据设置ECT。 | NSCC的可靠/UUD数据已标ECT；其他尚未启用路径算法未来需独立验证。 |
| UE11-p0441-005 | §3.6.4.2，service time跨页 | 目标测量接收到ACK发送的延迟，反馈后源端从RTT扣除；高优先返回为建议且需服从ROD CP同序。 | MAC首字节通知、ACK发送时stamp及Karn已有回归；无MAC通知适配器明确采用提交边界近似。 |
| UE11-p0443-001 | §3.6.4.4，trim端点 | 按DSCP接收trimmed数据并产生NACK；交换机生成可不开启。 | 主机和可选交换机路径均已实现，首次SYN被trim不分配上下文。 |
| UE11-p0444-001 | §3.6.4.4，MIN_TRIM_SIZE | 大小必须覆盖PDS request、可选CC_State与所有外层封装。 | 当前24字节IP payload覆盖已实现头；TSS/CC_Request/其他tunnel启用前必须重算并校验。 |
| UE11-p0449-001 | §3.6.4.7.3，大READ接收 | lossless下返回方向大READ PDS Request必须可无条件从网络接受以防死锁。 | M5/M7缺失；不能把普通前向SES消息信用拒绝机制直接套到返回READ。 |
| UE11-p0450-001 | §3.6.4.8，CSIG反射条件 | sender CC/路径选择使用CSIG时开启Reflect，回ACK_CCX/NACK_CCX携带至多128位状态。 | CSIG及扩展ACK格式未实现；普通ACK_CC不能替代该能力。 |
| UE11-p0450-002 | §3.6.4.8，CSIG-capable端点 | 支持CSIG的FEP必须实现Reflect，并在NSCC启用时开启。 | 当前不公布CSIG；M5需能力协商、启用条件和反射联合验收。 |
| UE11-p0450-003 | §3.6.4.8，正反射跨页 | Reflect已开且收到CSIG tag，正响应使用ACK_CCX。 | M5缺失，不能静默丢掉tag再发普通ACK。 |
| UE11-p0451-001 | §3.6.4.8，扩展反馈字段 | 负响应用NACK_CCX；按NSCC_CSIG/RCCC_CSIG填算法字段并附64位Reflection Header。 | M5缺失；需独立线格式、源算法解释和错误/保留type测试。 |

## 第 441～460 个候选

CCC的共享键不仅有目的端，还包括流量类组与算法语义。当前模型只启用一种数据TC
组和NSCC，不能将其内部连接键称为已实现线上RCCC CCC_ID。信用是发送前的严格
准入条件，不可由发送后计数或超时重传代替。

| 候选 ID | 章节与分类 | 拆分后的义务及适用条件 | 当前证据与后续处理 |
|---|---|---|---|
| UE11-p0456-001 | §3.6.6，TC组隔离 | 同源同目的但不同TC映射的PDC组必须独立CCC。 | 当前只有一个数据TC组；多组配置/键隔离未实现，不能复用单组共享CCC证据。 |
| UE11-p0458-001 | §3.6.8.1.1，CCC生命周期 | 首个PDC创建时分配CCC，最后PDC销毁后可保留NSCC缓存；RCCC/TFC另有关闭规则。 | 已接入发起PDC分配与目标SYN身份建立时的显式CCC绑定；控制建连、PDC容量拒绝、失败SYN、共享/隔离及释放见nscc_lifecycle_test。独立CCC容量、完整TC/保留池和RCCC/TFC规则仍缺。 |
| UE11-p0459-001 | §3.6.8.1.1，CCC状态约束 | IDLE/ACTIVE/READY/PENDING随发送准入和业务改变；仅IDLE或全部关联PDC失败后可移除。 | 当前窗口/在途/连接关闭路径部分表达这些事实，尚无完整显式状态及所有转换测试。 |
| UE11-p0463-001 | §3.6.9.2.3，可选OOO计数 | 选择计算时支持16位每PDC乱序计数，含最大活动PSN范围。 | 未选择实际OOO计数，不能把placeholder当真实计数；未来早期丢失检测另验。 |
| UE11-p0463-002 | §3.6.9.2.3，无OOO计数 | 未计算时必须发FFFF表示无效。 | 默认congestion_ack及NSCC反馈采用FFFF，反馈测试已有覆盖。 |
| UE11-p0463-003 | §3.6.9.2.4，service_time=0 | 零表示无效，应忽略。 | NSCC将零转换为零扣除量，不作为有效额外延迟；编码/RTT与stamp回归覆盖。 |
| UE11-p0464-001 | §3.6.9.3.1，信用准入 | RCCC/TFC信用耗尽停止发送，不能超分配或记到负数。 | M5缺失；当前NSCC允许的有符号inflight残差不是信用计数实现。 |
| UE11-p0470-001 | §3.6.10.6，丢失记账 | RTO/推断丢失时从原包状态计算名义大小。 | 缓存congestion_nominal_bytes、trim不按短包长度扣费、迟到ACK取消未发送retry debit已有回归。 |
| UE11-p0479-001 | §3.6.13.1，重传RTT歧义 | 已重传但ACK未回显RETX时，不得更新RTT；推荐逐包发送时间。 | MAC时间、宽attempt与Karn检查已有回归；可选其他算法仍未实现。 |
| UE11-p0479-002 | §3.6.13.2，接收窗口惩罚 | 反馈Rcv_Cwnd_Pend必须0～127并按算法影响源窗口。 | 7位线字段/NSCC计算已有；可配置目标处理速率及动态惩罚产生器仍不完整。 |
| UE11-p0490-001 | §3.6.13.10，CSIG maxDelay条件 | 选用时每包插入maxDelay，缺失计数/阈值后永久fallback RTT，管理可响应。 | CSIG未启用；M5需独立状态机、阈值与缺失/恢复测试，不能将RTT模式当fallback实现。 |
| UE11-p0492-001 | §3.6.14.1，线上CCC ID | RCCC/TFC使用RUD_CC_REQ/ROD_CC_REQ，携带ccc_id/credit_target。 | M5缺失；当前标准codec明确拒绝这些已定义格式。 |
| UE11-p0493-001 | §3.6.14.1，信用CCC共享 | RUD建议共享，ROD不得共享；同目的端CCC_ID唯一，跨目的可复用。 | 当前NSCC共享/独立键部分对应，但未实现RCCC/TFC分配器与wire ID。 |
| UE11-p0493-002 | §3.6.14.1，目标查找 | SYN按源地址/CCC_ID查找目标的source与destination CCC；非SYN使用已绑定PDC。 | M5缺失；普通PDC lookup不构成信用CCC lookup。 |
| UE11-p0493-003 | §3.6.14.1，CCC ID作用域 | 同目的不同实例不得重用CCC_ID，可跨另一PDC的前/返回方向共享。 | M5缺失；需双向关联和TC组隔离联合验证。 |
| UE11-p0493-004 | §3.6.14.1，关闭组隔离 | 旧CCC全部PDC正在关闭时，新PDC必须分配新CCC，避免无信用死锁。 | M5缺失；NSCC无信用模式的普通复用不能证明该条件。 |
| UE11-p0494-001 | §3.6.14.1，Credit Request选择 | 无信用且未请求过时建议发请求，但必须使用先前已存在的PDC。 | M5缺失；须避免借尚未建成的新PDC发送信用查询。 |
| UE11-p0494-002 | §3.6.14.1，RCCC关闭 | 最后一个PDC关闭时必须关闭其RCCC CCC。 | M5缺失；不能沿用NSCC允许保留拥塞缓存的策略。 |
| UE11-p0505-001 | §3.6.15，TFC准入 | 无信用不得发送数据包。 | M5缺失；需要等待/唤醒、重传和不同目的信用隔离。 |
| UE11-p0505-002 | §3.6.15，TFC反馈 | Credit CP或CC_CREDIT携带24位信用；OOO必须FFFF且接收忽略。 | M5缺失；共享字段格式不意味着可套用NSCC received-byte计数。 |

## 第 461～480 个候选

TFC的正信用残量可以允许一整个MTU包，目的端必须为此预留空间；不能只比较
`credit >= packet_bytes`就称为实现了规范算法。PCM是路线图明确安排在M8后的独立
增强，以下义务仅在启用PCM时适用。表3-110的逐行候选不是完整表格的替代物。

| 候选 ID | 章节与分类 | 拆分后的义务及适用条件 | 当前证据与后续处理 |
|---|---|---|---|
| UE11-p0505-003 | §3.6.15，TFC正残量 | credit>0即可发送；目的端必须可接收MTU-sized包，与当前包长无关。 | M5缺失，未来信用准入/缓冲预留必须联合验证，不能直接套用NSCC字节窗口比较。 |
| UE11-p0506-001 | §3.6.15，cell计费 | 支持256字节～9KB范围、256字节倍数的cell；默认256，按cell计算credit_used。 | M5缺失；需边界、舍入及跨cell payload测试。 |
| UE11-p0506-002 | §3.6.15，overhead容量 | 计入包头/元数据等目标开销，已分配信用必须保证所有合法包可存储。 | M5/M7缺失；Fabric网络缓冲与目标TFC缓冲不是同一资源。 |
| UE11-p0507-001 | §3.6.15，配置冻结 | 活动PDC不能改变cell size/overhead；非默认值须发送前带外配置。 | M5缺失；管理配置应在建连前验证并绑定到上下文。 |
| UE11-p0507-002 | §3.6.15.2，初始信用 | 初始credit至少overhead；SES NO_OP可带目标信用启动PDC，Credit Request CP不能启动。 | M5缺失；需零overhead配置、NO_OP启动及首次信用丢失恢复测试。 |
| UE11-p0508-001 | §3.6.15.2，TFC共享 | 同CCC_ID关联同CCC，不同ID关联独立CCC。 | M5缺失，不能把普通目标地址相同等同于显式CCC_ID相同。 |
| UE11-p0508-002 | §3.6.15.3，TFC关闭竞态 | 最后PDC进入QUIESCE后，不得给新PDC复用该CCC。 | M5缺失；需要目标释放buffer与源新建同时发生的确定性事件测试。 |
| UE11-p0513-001 | §3.6.16.6.1，多端口条件 | GetSendParams的可用端口列表至少含一个空闲端口。 | 当前单IPacketPort主机模型，不宣称多端口CCC调度；扩展时须验证无空闲情况不会错误调用。 |
| UE11-p0513-002 | §3.6.16.6.2，共享IP多端口条件 | 选择的entropy必须稳定映射到同一出端口，保证反馈路径无歧义。 | 当前entropy控制ECMP路径但没有多NIC端口抽象；后续独立能力，不套用单端口证据。 |
| UE11-p0519-001 | §3.6.18.1，PCM类型条件 | 必须支持整数；浮点可选，未支持时使用浮点的程序必须编译失败。 | M8后PCM增强未实现；未来编译器/验证器拒绝机制不可用运行时静默转换代替。 |
| UE11-p0522-001 | §3.6.18.4，PCM默认信号 | PCM必须支持默认/必选信号集，可扩展optional/vendor信号。 | PCM未启用；事件Trace不是标准PCM信号接口。 |
| UE11-p0522-002 | §3.6.18.4.1，PCM累积器 | 支持表3-106全部运算，并结合表3-110的信号必选组合。 | PCM未启用；未来逐运算类型/溢出/初始化验收。 |
| UE11-p0523-001 | §3.6.18.4.2，PCM读取 | uet_signal_get必选，set/update可选。 | PCM未启用；不能把内部统计访问器当作标准函数。 |
| UE11-p0524-001 | §3.6.18.4.3，PCM必选信号 | 表3-109的tx/rx/time触发与req/ack/ctl分类均须支持。 | PCM未启用；完整表3-109另需拆分和字段位宽证据。 |
| UE11-p0527-001 | 表3-110，PCM条件项 | uet_rx_ack支持sum；last可选，其余N/A。 | PCM未启用；按整表支持矩阵验收。 |
| UE11-p0527-002 | 表3-110，PCM条件项 | uet_rx_ack_bytes支持sum和last。 | PCM未启用。 |
| UE11-p0527-003 | 表3-110，PCM条件项 | uet_rx_ack_count支持sum；last可选。 | PCM未启用。 |
| UE11-p0527-004 | 表3-110，PCM条件项 | uet_rx_ack_ecn支持last；sum可选。 | PCM未启用。 |
| UE11-p0527-005 | 表3-110，PCM条件项 | uet_rx_ack_rtt支持sum/max/min/last。 | PCM未启用；NSCC RTT状态不是该可编程接口的证据。 |
| UE11-p0527-006 | 表3-110，PCM条件项 | uet_rx_ack_svc支持sum/last；max/min可选。 | PCM未启用。 |

## 第 481～520 个候选

以下是表3-110的CC信号及表3-111的LB信号累积矩阵，均以启用PCM为条件。
CC与LB对同名信号的必选运算不同；不能复用一个“所有信号支持sum”的简化接口。
LB的ET表示Event Table模型，PP表示Per-Packet模型，应按所选模型实现对应状态。
本轮M0只分类这些义务；PCM仍是M8后的未启用增强，表中任何行都没有被标记为实现通过。

| 候选 ID | 章节与分类 | 拆分后的义务及适用条件 | 当前证据与后续处理 |
|---|---|---|---|
| UE11-p0527-007 | 表3-110，PCM/CC | rx_cookie：last必选。 | PCM未启用。 |
| UE11-p0527-008 | 表3-110，PCM/CC | rx_credit：sum必选，last可选。 | PCM未启用。 |
| UE11-p0527-009 | 表3-110，PCM/CC | rx_credit_req_value：last必选，其余三种可选。 | PCM未启用。 |
| UE11-p0528-001 | 表3-110，PCM/CC | rx_nack：sum必选，last可选。 | PCM未启用。 |
| UE11-p0528-002 | 表3-110，PCM/CC | rx_nack_ecn：last必选，sum可选。 | PCM未启用。 |
| UE11-p0528-003 | 表3-110，PCM/CC | rx_nack_last_hop_trim：last必选，sum可选。 | PCM未启用。 |
| UE11-p0528-004 | 表3-110，PCM/CC | rx_nack_rtt：sum/max/min/last全部必选。 | PCM未启用。 |
| UE11-p0528-005 | 表3-110，PCM/CC | rx_nack_trim：sum必选，last可选。 | PCM未启用。 |
| UE11-p0528-006 | 表3-110，PCM/CC | rx_probe_id：last必选。 | PCM未启用。 |
| UE11-p0528-007 | 表3-110，PCM/CC | rx_req：sum必选，last可选。 | PCM未启用。 |
| UE11-p0528-008 | 表3-110，PCM/CC | rx_req_bytes：sum/last必选。 | PCM未启用。 |
| UE11-p0528-009 | 表3-110，PCM/CC | rx_telegram_local：last必选。 | PCM未启用；Telegram线编码另有待解决差异。 |
| UE11-p0528-010 | 表3-110，PCM/CC | rx_telegram_type：last必选。 | PCM未启用。 |
| UE11-p0528-011 | 表3-110，PCM/CC | time_current：last必选。 | PCM未启用；未来使用注入时钟。 |
| UE11-p0528-012 | 表3-110，PCM/CC | time_last_update：last必选。 | PCM未启用。 |
| UE11-p0528-013 | 表3-110，PCM/CC | tx_backlog_bytes：last必选。 | PCM未启用。 |
| UE11-p0528-014 | 表3-110，PCM/CC | tx_cookie：last必选。 | PCM未启用。 |
| UE11-p0528-015 | 表3-110，PCM/CC | tx_cwnd：last必选。 | PCM未启用；现有NSCC窗口不等于PCM可编程信号接口。 |
| UE11-p0528-016 | 表3-110，PCM/CC | tx_inflight_bytes：last必选。 | PCM未启用。 |
| UE11-p0528-017 | 表3-110，PCM/CC | tx_req_bytes：sum/last必选。 | PCM未启用。 |
| UE11-p0528-018 | 表3-110，PCM/CC | tx_rto：last必选，sum可选。 | PCM未启用。 |
| UE11-p0529-001 | 表3-111，PCM/LB | rx_ack：ET/PP均last必选、sum可选。 | PCM未启用。 |
| UE11-p0529-002 | 表3-111，PCM/LB | rx_ack_ecn：ET/PP均last必选、sum可选。 | PCM未启用。 |
| UE11-p0529-003 | 表3-111，PCM/LB | rx_ack_rtt：ET/PP均支持全部四种累积。 | PCM未启用。 |
| UE11-p0529-004 | 表3-111，PCM/LB | rx_cookie：PP的last必选。 | PCM未启用。 |
| UE11-p0529-005 | 表3-111，PCM/LB | rx_ev：ET/PP的last必选。 | PCM未启用；现有entropy反馈仅为协议基础。 |
| UE11-p0529-006 | 表3-111，PCM/LB | rx_nack_ecn：ET/PP的last必选、sum可选。 | PCM未启用。 |
| UE11-p0529-007 | 表3-111，PCM/LB | rx_nack_last_hop_trim：ET/PP的last必选、sum可选。 | PCM未启用。 |
| UE11-p0529-008 | 表3-111，PCM/LB | rx_nack_rtt：ET/PP均支持全部四种累积。 | PCM未启用。 |
| UE11-p0529-009 | 表3-111，PCM/LB | rx_nack_trim：ET/PP的last必选、sum可选。 | PCM未启用。 |
| UE11-p0529-010 | 表3-111，PCM/LB | tx_probe_id：ET/PP的last必选。 | PCM未启用；与CC表的rx_probe_id分别映射。 |
| UE11-p0529-011 | 表3-111，PCM/LB | rx_telegram_local：ET/PP的last必选。 | PCM未启用。 |
| UE11-p0529-012 | 表3-111，PCM/LB | rx_telegram_type：ET/PP的last必选。 | PCM未启用。 |
| UE11-p0529-013 | 表3-111，PCM/LB | time_current：ET/PP的last必选。 | PCM未启用。 |
| UE11-p0529-014 | 表3-111，PCM/LB | time_last_update：ET/PP的last必选。 | PCM未启用。 |
| UE11-p0529-015 | 表3-111，PCM/LB | tx_cookie：PP的last必选。 | PCM未启用。 |
| UE11-p0529-016 | 表3-111，PCM/LB | tx_ev：PP的last必选。 | PCM未启用。 |
| UE11-p0529-017 | 表3-111，PCM/LB | tx_ev_tbl_depth：ET的last必选。 | PCM未启用。 |
| UE11-p0530-001 | 表3-111，PCM/LB | tx_ev_tbl_idx：ET的last必选。 | PCM未启用。 |
| UE11-p0530-002 | 表3-111，PCM/LB | tx_rto：ET/PP的last必选、sum可选。 | PCM未启用。 |

## 第 521～540 个候选

这批继续归入M8后PCM增强，均尚未启用。同时读取了候选提取未完整包含的
表3-117、fatal条件列表及ERROR数据路径列表。YAML编译失败、回调内原子状态切换
和无副作用终止是独立义务，不能只靠一个运行时error flag通过整节。

| 候选 ID | 章节与分类 | 拆分后的义务及适用条件 | 当前证据与后续处理 |
|---|---|---|---|
| UE11-p0530-003 | §3.6.18.4.5，optional信号 | YAML引用未支持的optional信号时编译必须失败。 | PCM未启用；未来编译期能力校验。 |
| UE11-p0531-001 | §3.6.18.4.5.1，CSIG量化 | 暴露opaque bucket s及t/m/d；YAML提供去量化参数，建议提供csig_dequantize。 | PCM/CSIG未启用；不能直接把量化索引当原始延迟。 |
| UE11-p0531-002 | §3.6.18.4.6，vendor信号 | 若提供，信号名必须含指定vendor别名前缀。 | PCM未启用，未选择vendor信号。 |
| UE11-p0532-001 | §3.6.18.5.1，trigger语义 | count/time四组合、DISARMED/ONCE/CONTINUOUS、INVOKE/RECORD及deadline；ONCE需显式重arm。 | PCM未启用；未来事件驱动测试应覆盖同时触发与计数/时间清零。 |
| UE11-p0533-001 | §3.6.18.5.3，触发批处理 | 一次调用交付所有非deferred fired triggers，禁止拆成多次回调。 | PCM未启用；未来以单次bitmask交付并验证exactly-once。 |
| UE11-p0533-002 | §3.6.18.5.4，更新语义 | 成功更新后重置全部working state，立即按新配置可评估/触发，reference fidelity一致。 | PCM未启用；不得继承旧计数或旧deadline。 |
| UE11-p0535-001 | §3.6.18.5.7，per-EV作用域 | scope=EV，uniform绑定CCC EV表全部槽位，不可单独选索引。 | PCM未启用；多EV独立状态与uniform配置需区分。 |
| UE11-p0535-002 | §3.6.18.5.7.2，PP触发 | 支持表3-117每包EVENT-COUNT/1、INVOKE、enable等组合；该模式不支持runtime修改。 | PCM未启用；表内旧字段名与前节formal arm/action schema需交叉复核，不能自行默默改线/配置语义。 |
| UE11-p0538-001 | §3.6.18.6.3，telegram接收 | 每次回调一个telegram，提供type/context/字段API，交给算法的字段为native endian。 | PCM未启用；与发送端big endian区分。 |
| UE11-p0539-001 | §3.6.18.6.3，telegram发送 | local发送必选，remote/collector可选；按type和字段API构造。 | PCM未启用；不把未选择remote Telegram作为M8退出条件。 |
| UE11-p0539-002 | §3.6.18.6.3，结构寿命 | 回调结束后结构失效，下次须重新构造。 | PCM未启用；需代次/句柄失效验证。 |
| UE11-p0539-003 | §3.6.18.6.3.1，telegram头 | 8位type_id按YAML赋值；8位reserved发送零、接收忽略。 | PCM未启用；详细字段是8+8，不直接把summary“2B type_id”当16位。 |
| UE11-p0540-001 | §3.6.18.6.3.1，telegram填充 | 不足30字节payload剩余发送零、接收忽略。 | PCM未启用。 |
| UE11-p0540-002 | §3.6.18.6.3.1，telegram编码 | local/remote均big endian且按YAML紧凑排列。 | PCM未启用；回调侧需单独转换为native endian。 |
| UE11-p0541-001 | §3.6.18.7，PCM故障总则 | 破坏正确性/安全性/确定性的条件立即永久禁用CCC并进入ERROR。 | PCM未启用；只有外部reset/reinit才允许恢复。 |
| UE11-p0541-002 | §3.6.18.7.1，fatal触发 | 内部信号/trigger/API故障、非法API/越界、算法显式fatal均原子ACTIVE→ERROR。 | PCM未启用；三类触发分别验收。 |
| UE11-p0541-003 | §3.6.18.7.1，原子可见性 | fatal状态变化对所有CCC/PDC观察者原子可见。 | PCM未启用；软件模型应在同一事件边界提交。 |
| UE11-p0541-004 | §3.6.18.7.1，关联PDC失败 | 所有关联PDC同时ERROR，PCM内部不能退出ERROR。 | PCM未启用；应验证多个PDC的统一失败及资源隔离。 |
| UE11-p0542-001 | §3.6.18.7.2.1，ERROR数据路径 | 禁用CCC、不准入新包、逻辑丢弃关联在途/ACKed/排队包、停止事件和telegram、禁止算法API生效。 | PCM未启用；五项独立义务不能以普通队列清空替代。 |
| UE11-p0542-002 | §3.6.18.7.2.2，ERROR回调 | 在途调用无可见副作用、不再变更状态；API返回-ENOTRECOVERABLE；不再调用算法。 | PCM未启用；完成/中止两种选择均须满足无副作用。 |

## 第 541～560 个候选

PCM剩余要求继续作为M8后条件项；TSS由路线图M6明确选择，当前整体未实现。
可信FEP、安全存储、SDME授权、报文认证和nonce不复用是不同边界。软件行为模型可以
验证状态隔离和协议结果，不能以普通进程内对象冒充经过证明的硬件信任根。

| 候选 ID | 章节与分类 | 拆分后的义务及适用条件 | 当前证据与后续处理 |
|---|---|---|---|
| UE11-p0542-003 | §3.6.18.7.3，PCM错误记录 | 每CCC只记录一个fatal indication，含规定字段。 | PCM未启用。 |
| UE11-p0542-004 | §3.6.18.7.3，PCM错误来源 | source区分IMPLEMENTATION/PCM_ALGORITHM；算法来源value等于uet_ccc_fatal参数。 | PCM未启用。 |
| UE11-p0542-005 | §3.6.18.7.3，PCM首错保留 | 后续原因不得覆盖/追加/累计；保留到CCC reset/reinit。 | PCM未启用；须区别事件计数与first-fatal记录。 |
| UE11-p0543-001 | §3.6.18.7.3，PCM管理访问 | 软件可查询每CCC的ACTIVE/ERROR与fatal信息，并满足后续时序/非破坏要求。 | PCM未启用；完整接口及并发事件边界另验。 |
| UE11-p0543-002 | §3.6.18.7.3，PCM可见性 | ERROR对软件可见不晚于内部原子转换；查询不清除记录。 | PCM未启用。 |
| UE11-p0543-003 | §3.6.18.7.4，PCM重置条件 | 若提供外部reset，恢复实例不得保留任何旧PCM状态。 | PCM未启用；reset为可选平台行为，选用后完整清理。 |
| UE11-p0544-001 | §3.6.18.8.4，PCM实例绑定 | 一个PCM-managed UET instance的全部流量由恰好一个CC及一个LB算法实例控制。 | PCM未启用；不能与旁路native算法同时修改同一CCC。 |
| UE11-p0545-001 | §3.6.18.8.5，PCM YAML模式 | ev-table需要hw_algo/hw_config；per-packet禁止这些字段。 | PCM未启用；编译器schema按operation model验证。 |
| UE11-p0546-001 | §3.6.18.9，PCM运行时跨页 | 每CCC最多一个活跃调用；事件批次只含一种触发上下文；TX/RX各自有序但可跳过，TIME可靠可迟到，EV请求可靠有序，telegram各来源有序，控制按发出顺序执行。 | PCM未启用；已读取跨页列表，未来需分别测试跳过、延迟、重入和不同事件类型无全序假设。 |
| UE11-p0547-001 | §3.6.18.10，可选eBPF | 选择合规时仅有界循环、无递归、可验证指针、栈≤512B、调用深度≤8、tail call≤32。 | PCM/eBPF未启用；真实eBPF验证器集成不属于M8退出门槛。 |
| UE11-p0548-001 | §3.7.2.1，TSS信任模型 | 负责安全处理的可信FEP部分形成信任根，不信任交换网络。 | M6缺失；软件仅建模此边界，硬件信任验证另属系统集成。 |
| UE11-p0550-001 | §3.7.2.2.1，TSS安全义务 | 认证所使用的AAD/密文、加密全部payload、隔离域/客户端、安全保存密钥和参数；不把ECN/trim视为可信认证数据。 | M6缺失；需分别验证权限、字段保护范围与不泄露协议秘密，不能只调用AES-GCM通过整段。 |
| UE11-p0552-001 | §3.7.2.4.2，未认证提示影响范围 | 被篡改密文/头最多影响拥塞或重放状态，不得影响数据放置或完整性/认证决定。 | M6缺失；需认证失败与trim/congestion组合负向测试。 |
| UE11-p0553-001 | §3.7.2.5，TSS初始化门限 | 发送到TSS前配置SDKDB、全局参数如Rekey_Mask及密码底层。 | M6缺失；未来禁止未初始化发送，不能惰性填默认密钥。 |
| UE11-p0556-001 | §3.7.3，服务混合 | 同时支持TSS/非TSS服务；其他非UE流量旁路给上层。 | M6缺失；需按服务安全配置分流而非每端口单一加密开关。 |
| UE11-p0559-001 | §3.7.4，域标识唯一 | 域内SSI或IP唯一；可达网络中SDI唯一。 | M6/M7缺失；JobID与SDI不可互相代替，需管理冲突检查。 |
| UE11-p0560-001 | §3.7.4，epoch与重入 | TSC不能保存时SDME协调epoch或key变化；同关联epoch单调，新key安装重置epoch。 | M6缺失；需断电/重入与key rotation联合测试。 |
| UE11-p0560-002 | §3.7.4.1，加入域 | SDME分配SSI和参数，确保所有FEP参数当前后才允许发送。 | M6缺失；可调度SDME模型需有参数安装/ready门限。 |
| UE11-p0560-003 | §3.7.4.3，nonce不复用 | reboot后保存nonce状态，或重新经SDME更新epoch。 | M6缺失；禁止重新使用旧seed/计数器冒充安全恢复。 |
| UE11-p0561-001 | §3.7.5，所有KDF轮换 | 所有KDF模式支持显式key rotation；cluster还可用隐式counter重key。 | M6缺失；不能只实现单一KDF或把rekey等同于rotation。 |

## 第 561～580 个候选

本批属于M6已选TSS范围，当前均缺实现。发送调用次数上限、接收伪造尝试上限、
AN双key过渡和epoch/TSC不复用需要分别计数。重传同一PDS PSN也必须取得新的安全计数器；
不能直接重发缓存的TSS密文来绕过发送状态。密码运算选OpenSSL EVP，生命周期仍由协议实现。

| 候选 ID | 章节与分类 | 拆分后的义务及适用条件 | 当前证据与后续处理 |
|---|---|---|---|
| UE11-p0561-002 | §3.7.5，发送调用上限 | 发送端跟踪key invocation，不超上限；rotation开始时重置计数。 | M6缺失；需上限前/等于/超过与在途包测试。 |
| UE11-p0561-003 | §3.7.5，接收调用上限 | counter≥invokeFatalThreshold时丢弃，并向SDME报告该SDI超限。 | M6缺失；须与后文发送counter溢出规则分别实现。 |
| UE11-p0561-004 | §3.7.5.1，rotation参数 | 更新SDK，可更新IVMask；direct模式必须更新IVMask。 | M6缺失。 |
| UE11-p0561-005 | §3.7.5.1，AN key槽 | 接收端每SD保存多个AN key；切换关联时counter/epoch归零。 | M6缺失；新key关联允许归零但旧关联不能重用nonce。 |
| UE11-p0562-001 | §3.7.5.1，rotation步骤总则 | SDME可任意时刻发起，按后续规定步骤执行。 | M6缺失；warn阈值是可选触发，流程本身必选。 |
| UE11-p0562-002 | §3.7.5.1，rotation五阶段 | 通知新AN/epoch0；所有SDKDB安装并更新TxAN/Rx双AN；新发改用新AN且首包counter0；寿命内停止接收旧AN并静默丢弃计数，清auth-fail计数；完成收敛。 | M6缺失；需不同FEP安装延迟、过渡期丢失/重复与旧AN迟到测试。 |
| UE11-p0563-001 | §3.7.5.3，默认KDF | 必须支持counter-mode AES-CMAC-256 PRF；其他算法可扩展。 | M6缺失；不能用HMAC或HKDF替代必选默认构造。 |
| UE11-p0563-002 | §3.7.5.4，AEAD | 使用AEAD，AAD认证不加密、payload加密并携带ICV。 | M6缺失；字段覆盖按正式封装，不按C++结构体内存布局。 |
| UE11-p0564-001 | §3.7.5.4，默认cipher | AES-GCM-256、16字节ICV，算法由SDKDB选择。 | M6缺失；官方/独立向量及负向tag验证需分别提供。 |
| UE11-p0564-002 | §3.7.5.4，认证失败门限 | authFail计数超过阈值后整个域丢弃所有包，并向SDME发事件。 | M6缺失；不是只丢弃本次坏包或单个PDC。 |
| UE11-p0564-003 | §3.7.5.4，cipher key来源 | 输入满足NIST SP800-108的cryptographic key要求。 | M6缺失；需区分确定性测试向量与运行key生成/配置。 |
| UE11-p0564-004 | §3.7.5.5，nonce唯一 | 同SDK不得重用IV，由epoch/counter构造保证。 | M6缺失；域、SSI、AN及发送重传都需纳入作用域。 |
| UE11-p0564-005 | §3.7.5.5，IV隐藏 | 送入cipher前，packet IV必须与IVMask XOR。 | M6缺失；需独立字节向量检查。 |
| UE11-p0564-006 | §3.7.5.5，重启恢复 | AES-GCM采用deterministic IV；reboot/reinit后经SDME更新epoch，或保存完整状态并证明无复用。 | M6缺失；随机重置PSN不是此项证据。 |
| UE11-p0564-007 | §3.7.5.5，direct IVMask | SDME在rotation时配置，必须为密码学随机值并符合所述随机源要求。 | M6缺失；软件模型须明确随机源/可重放测试注入，不冒充TRNG硬件认证。 |
| UE11-p0564-008 | §3.7.5.6，TSC单调 | 每个发送包TSC严格增加，不发送重复TSC。 | M6缺失；PDS同PSN重传依然算新的安全发送。 |
| UE11-p0564-009 | §3.7.5.6，TSC布局 | 64位=16位epoch拼48位counter，每包递增；epoch启动/变化时counter初始化0。 | M6缺失；需独立端序、最大值与首包向量。 |
| UE11-p0565-001 | §3.7.5.6，发送溢出 | counter回绕或超过fatal阈值时域内发送丢弃，每次增加OutInvokeFail。 | M6缺失；不得回绕后继续加密。 |
| UE11-p0565-002 | §3.7.6，SDKDB范围 | SDME配置连续SDI范围与base/max；base可置于规定24位范围；lookup失败丢弃计数；SDI0不可分配。 | M6/M7缺失；须验证范围端点、容量协商及失败统计。 |
| UE11-p0566-001 | §3.7.6，域封装一致 | 一个安全域按SDKDB encap-type使用统一packet encapsulation。 | M6缺失；native/UDP/UFH不能在同域默默混用。 |

## 第 581～600 个候选

M6按路线图覆盖direct、cluster和client-server三个模式；规范本身把direct列MUST、
其余列SHOULD，不能混淆规范最低要求与本项目选择。KDF采用352位派生结果，包含
96位IVMask和256位SDK，不是通用HKDF的替代命名。server IPv6 context的简写未列
cluster格式的前导32位零，与“继承cluster构造”和块对齐文字需用正式向量交叉核对。

| 候选 ID | 章节与分类 | 拆分后的义务及适用条件 | 当前证据与后续处理 |
|---|---|---|---|
| UE11-p0566-002 | §3.7.7，模式/SSI | direct+IPv6必须显式SSI；其他模式可在满足唯一性时使用SSI/IP。 | M6缺失；不能直接截断IPv6源地址构造IV。 |
| UE11-p0566-003 | §3.7.7，模式能力与错误 | direct必选，cluster/client-server建议；kdfModes如实公布；packet带SSI而配置不用时丢弃计数。 | M6缺失；模式能力、发送配置和接收拒绝均须独立验收。 |
| UE11-p0567-001 | §3.7.8，KDF输入块 | IPv4/显式SSI使用单块，无SSI的IPv6使用双块；client-server涉及两类KDF。 | M6缺失；不可只验证单块CMAC。 |
| UE11-p0567-002 | §3.7.8，默认构造 | 每域选择kdf-algo；默认按SP800-108及表3-134实现AES-CMAC-256。 | M6缺失；其他构造为实现特有扩展。 |
| UE11-p0567-003 | §3.7.8，跨页PRF | SP800-108 §4.1 counter mode，以CMAC为PRF，后页指定AES-256。 | M6缺失。 |
| UE11-p0568-001 | §3.7.8，CMAC底层 | CMAC按SP800-38B使用AES-256，并支持表3-134输入参数。 | M6缺失；调用库底层仍需自行构造标准输入。 |
| UE11-p0568-002 | 表3-134，KDF参数 | L=352/16位，i=8位/BE且放fixed data前，label16位，context80/208位，3次PRF，Ki/SDK256位、IVMask96位。 | M6缺失；表中IVMask128指最后PRF块，仅取96有效位，不能把全部128输出当mask。 |
| UE11-p0568-003 | §3.7.8，fixed data | label/0x00/context/BE长度352，label/context按mode/SSI构造。 | M6缺失；需完整字节输入向量而非只比最终roundtrip。 |
| UE11-p0568-004 | §3.7.8，三次迭代 | i从1逐次增加；第三次仅取12字节作为IVMask。 | M6缺失；输出分配顺序结合正式示例验证。 |
| UE11-p0569-001 | §3.7.8，label/对齐 | CMAC AES-256，输入为块大小对齐，16位label是按模式的ASCII文字。 | M6缺失；U1/U2及padding不得按主机端序拼装。 |
| UE11-p0569-002 | §3.7.8，自动rekey条件 | 仅cluster可从TSC按mask/逻辑右移抽0～32位，零抽取初始化0；所有域成员mask/shift一致。 | M6缺失；rekey与AN轮换独立。 |
| UE11-p0569-003 | §3.7.8.1，cluster单块 | label U1(5531)，context80位=epoch/Rekey/SSI或IPv4源地址。 | M6缺失；字段均独立golden验证。 |
| UE11-p0570-001 | §3.7.8.2，cluster双块 | 无SSI的IPv6 context208位=32位零/epoch/Rekey/IPv6源地址。 | M6缺失；必须保留前导零及完整128位地址。 |
| UE11-p0571-001 | §3.7.8.3，server构造 | 继承cluster结构，label U2(5532)、使用目的SSI/IP，Rekey位置为零。 | M6缺失；IPv6简写padding与正式向量交叉核对后再实现。 |
| UE11-p0573-001 | §3.7.10，可选epoch拒绝 | 若启用，按wrapSubtract及rxMaxEpochLifetime丢弃过旧epoch并计InLatePkts。 | M6缺失；读取了跨页窗口说明，不能用普通有符号比较处理16位回绕。 |
| UE11-p0574-001 | §3.7.11，Unified Local TSS | Unified Local支持TSS时必须支持UFH_32普通TSS模式。 | M6/M8缺失；IP-only AES-GCM路径不构成通过。 |
| UE11-p0579-001 | 表3-135，TSS头 | type=UET_TSS，SP/AN与24位SDI、可选32位SSI、64位TSC按正式字段编码。 | M6缺失；保留位发送/接收规则另依通用要求。 |
| UE11-p0579-002 | §3.7.11，单包约束 | entropy/TSS/PDS/SES/payload/ICV全部在一个transport Payload MTU内。 | M6缺失；分片器必须扣除安全开销，不能先按明文MTU切片后越界。 |
| UE11-p0580-001 | §3.7.11.1.1，AAD/Coff | AAD含所有安全相关字段，如用于KDF的源IP；建议Coff仅暴露TSS头。 | M6缺失；可变IP字段与PDS可变提示需按规定屏蔽/覆盖。 |
| UE11-p0580-002 | 表3-136，IV错误矩阵 | SSI-mode/SP及IP类型组合不合法时丢弃并计InInvalid；合法IV按模式XOR mask。 | M6缺失；已读取8组IPv4/IPv6组合，direct IPv6无SSI禁止，其他组合需独立向量。 |

## 第 601～620 个候选

TSS正常认证失败与截短包的处理不同：后者按§3.7.11.3明确不增加auth-fail计数。
TSS计数器初始化为零、按位宽回绕，并向SDME提供64位值；不能沿用其他层选择的
计数器溢出策略。第4章switch trimming与FEP受限接收也分别验收。

| 候选 ID | 章节与分类 | 拆分后的义务及适用条件 | 当前证据与后续处理 |
|---|---|---|---|
| UE11-p0581-001 | §3.7.11.1.3，ICV | 对AAD/密文计算16字节GCM ICV并附尾；正常认证失败丢弃计数，trim提示按受限规则。 | M6缺失；回包/内存交付不得发生在认证成功前。 |
| UE11-p0581-002 | §3.7.11.2，TSS发送列表 | 非TSS旁路原样并计数；SDKDB缺失丢弃；按三模式派生key，设置type/SDI/AN/SSI/SP与epoch/counter；溢出/fatal丢弃计数。 | M6缺失；长段拆分为配置、构造、计数和失败门限多项，不能以加密roundtrip通过。 |
| UE11-p0582-001 | §3.7.11.2，发送失败保护 | warn建议通知；按Aoff/Coff加密并计OutAuthPkts；任何不能安全发送的条件均丢弃计OutErrored，禁止明文泄出。 | M6缺失；需错误key/offset/SDI和发送队列失败负向测试。 |
| UE11-p0582-002 | §3.7.11.3，接收分流/AN | 非TSS原样给PDS且rx_auth=false并计旁路；按AN/SDI查SDKDB，缺失丢弃；RxActiveAN=00全拒、01拒AN0、10拒AN1、11双接收。 | M6缺失；位序严格按原文及SDKDB定义交叉验证，不自行假定bit0等于AN0。 |
| UE11-p0582-003 | §3.7.11.3，无效关联 | AN被拒绝时计InInvalidSa，并向PDS发lastAN错误指示。 | M6缺失；指示与网络响应不是同一动作。 |
| UE11-p0582-004 | §3.7.11.3，SDKDB校验 | encap、Aoff/Coff、key或SSI/SP不匹配均丢弃并计InInvalid。 | M6缺失；不能在错误参数下尝试普通明文解析。 |
| UE11-p0583-001 | §3.7.11.3，认证交付 | 按模式及packet epoch派生；检查可选epoch窗口；构造IV/AAD并认证；成功rx_auth=true计数，失败计数/域阈值通知；rotation后重置auth-fail；trim可受限解密或丢弃且不计auth-fail；旁路rx_auth=false。 | M6缺失；普通auth-fail、trim、bypass和成功四条路径分别验收，计数不重复。 |
| UE11-p0584-001 | §3.7.12，TSS统计 | 表3-137必选计数器从0开始按位宽wrap，提供管理访问，给SDME统一64位。 | M6/M7缺失；需回绕与域/端口作用域测试。 |
| UE11-p0584-002 | 表3-137，统计全集 | InAuth/AuthFail/Invalid/InvalidSa、可选InLate、OutInvokeFail/OutAuth、端口In/OutErrored与加密旁路、SES binding failure分别计数。 | M6/M7缺失；已读取全表，optional epoch功能一旦启用其计数也必选。 |
| UE11-p0591-001 | §4.1，switch trim准入 | 只对合法IP且buffer admission失败的包执行trim，先完成适用L2/L3/egress校验。 | Fabric/codec已验证IP格式与出口准入；真实FCS尚未建模，M7另验。 |
| UE11-p0591-002 | §4.1，DSCP类别 | 仅TRIMMABLE可截短，两类至少各有码点，数值由operator选。 | 当前可配置单trimmable/trimmed及可选last-hop，错误码点拒绝与非trimmable不截短已有回归。 |
| UE11-p0591-003 | §4.1，DSCP映射 | 每个支持trim的switch为每个所选trimmable配置对应trimmed，可多对一。 | 当前选择一组映射，所有相关FEP/出口共享；多trimmable集合尚未启用。 |
| UE11-p0591-004 | §4.1，MIN_TRIM_SIZE | 网络共同配置；正常截短保留量≥下界，并能识别协议/tunnel/PDS序号标识。 | 当前24字节覆盖已实现明文格式；TSS/CC扩展/tunnel启用前需按完整头链重算。 |
| UE11-p0591-005 | §4.1，截短与小包 | 可截短且准入失败时执行trim，结果不增长；原IP payload小于下界时可仅换DSCP或丢弃。 | 当前选择小包只改DSCP，长度/内存分配/重准入已有测试。 |
| UE11-p0592-001 | §4.1，改DSCP | 截短后标为对应TRIMMED码点，使端点/下游识别。 | 普通/last-hop两种输出及链路PCAP已有覆盖。 |
| UE11-p0592-002 | §4.1，合法IP/FCS | 更新IP长度/IPv4 checksum，并保持合法Ethernet FCS。 | IP部分已测试；IPacketPort帧当前省略FCS，M7链路完整性模型仍需补齐。 |
| UE11-p0592-003 | §4.1，重新准入 | 截短结果按新DSCP当新包准入对应队列，失败执行正常overflow处理。 | Fabric重分类、独立队列容量及通知队列也可丢失已有回归/实验。 |
| UE11-p0595-001 | §4.1.3，外部trim表示 | 交给FEP或switch时必须保留TRIMMED DSCP，IPv4 checksum有效。 | 多hop捕获、codec边界和checksum已有测试；其他封装未实现。 |
| UE11-p0595-002 | §4.1.3，transport识别 | 启用trim时上层能由保留头识别原包，MIN_TRIM_SIZE覆盖必要信息。 | RUD/ROD依peer/PDC/PSN生成NACK且不交付残留SES；RUDI/RODL/TSS仍缺。 |
| UE11-p0595-003 | §4.1.3，UET头链保留 | 保留entropy、所选tunnel头及完整PDS req/response，含PSN/PDCID。 | 当前明文IP路径部分完成；未启用头型必须在能力打开前补保留长度与恢复验证。 |

## 第 621～640 个候选

本批从trim配置进入CSIG。CSIG的base profile是该子协议的能力集合，不能仅凭名称
将其等同于AI Base。M5计划实现CSIG及反射；wide tag是单独的可选能力，当前未选择。
量化和局部信号计算都使用整数，必须在加入tag编码前明确precision与饱和边界。

| 候选 ID | 章节与分类 | 拆分后的义务及适用条件 | 当前证据与后续处理 |
|---|---|---|---|
| UE11-p0595-004 | §4.1.3，多封装trim | MIN_TRIM_SIZE取所有同时启用封装所需头长度最大值，可按包动态确定。 | 当前统一24字节覆盖已选明文格式；TSS/tunnel启用时需管理侧重算最大值。 |
| UE11-p0596-001 | §4.1.4.1，TC映射 | TRIMMABLE映射TC_low，CONTROL映射TC_high。 | 当前0/1独立队列、DSCP重分类、ACK隔离与ROD非trim同TC控制已有回归。 |
| UE11-p0596-002 | §4.1.4.1，trim优先级 | trimmed与未截短数据必须不同TC；建议trim/control再分开TC_med/high。 | 当前使用两个TC的允许策略，trim/control共享高TC；三TC完整配置未启用。 |
| UE11-p0596-003 | §4.1.4.1，DSCP分离 | TRIMMED与TRIMMABLE不同。 | TrimmingOptions验证与codec负向测试已有覆盖。 |
| UE11-p0596-004 | §4.1.4.1，控制DSCP分离 | TRIMMED与CONTROL不同，即使二者共享TC也保留码点区别。 | 当前独立DSCP校验与endpoint识别已有覆盖。 |
| UE11-p0598-001 | §4.1.6，加密trim限制跨页 | 未认证trim不能改变超出ECN/drop影响的连接状态，不能交付残余数据或导致后续合法数据被拒。 | M6缺失；现有明文trim的受限tuple/NACK路径提供部分基础，不能代替密文认证边界。 |
| UE11-p0605-001 | §4.2.4，CSIG基础格式 | CSIG-capable主机/交换机必须支持compact tag。 | M5缺失；不公布CSIG能力。 |
| UE11-p0606-001 | §4.2.4.1.1，CSIG EtherType | 永久分配前支持可配置compact/wide EtherType，两者不同且不冲突。 | M5缺失；不得硬编码一个实验码点并称为正式分配值。 |
| UE11-p0607-001 | §4.2.4.1.2，CSIG base信号 | 支持CSIG时实现§4.2.7.1的base信号集合。 | M5缺失；后续需按具体signal/type表逐项拆分。 |
| UE11-p0608-001 | §4.2.4.1.3，整数信号 | 本地原始值和量化值都是整数，按type指定聚合函数比较更新。 | M5缺失；不能用浮点舍入掩盖桶边界。 |
| UE11-p0609-001 | §4.2.4.1.5，compact桶 | inclusive区间连续且不重叠。 | M5缺失；未来配置校验须覆盖空隙、重叠与端点相邻。 |
| UE11-p0609-002 | §4.2.4.1.5，compact量化 | 5位共32桶；原始precision高于桶precision时先右移差值位，再作区间映射。 | M5缺失；不得直接按原值索引或引入浮点近似。 |
| UE11-p0609-003 | §4.2.4.1.5，compact饱和 | 低于最低值归桶0，高于最高值归桶31；建议记录越界事件。 | M5缺失；未来零/最大整数及两端越界测试。 |
| UE11-p0609-004 | §4.2.4.1.6，wide条件项 | 20位桶，e≥1，base为0或2的幂，每桶2^e连续值。 | 未选择可选wide tag；启用后需精确整数量化及参数上界。 |
| UE11-p0610-001 | §4.2.4.1.6，wide饱和 | v<b归桶0，超出b+2^(e+20)−1归最大桶；建议计越界。 | wide未启用；未来计算须避免移位/加法溢出。 |
| UE11-p0610-002 | §4.2.4.1.7，locator | compact6位/wide15位，signal更新时必须同时更新locator。 | M5缺失；不能只更新数值而保留上一个bottleneck的位置。 |
| UE11-p0611-001 | §4.2.4.1.8，D位 | 初始D=0；D=0按type比较更新；D=1禁止修改signal。 | M5缺失；需多hop聚合及冻结位置测试。 |
| UE11-p0611-002 | §4.2.4.1.8，trim冻结 | CSIG+trim网络的基础行为是在trim处置D=1，建议不再改其他tag字段。 | M5缺失；不能在下游继续覆盖已冻结的信号。 |
| UE11-p0611-003 | §4.2.4.1.8，基础冻结能力 | 即使提供其他可选策略，CSIG-capable交换机也必须支持trim时置D的基础行为。 | M5缺失；可选扩展不能取代该能力。 |
| UE11-p0612-001 | §4.2.4.1.9，CSIG保留位 | 发起FEP设置r=0，接收忽略。 | M5缺失；保留字段测试将与type/precision有效字段分开。 |

## 第 641～660 个候选

CSIG基础信号的完整列表是ABW、ABW/C、Delay；extended里的nQD/Experimental可选择
空集。LLDP的tag格式能力与每个signal的支持能力分别管理。链路层LLR开始出现，
其确认/重传和byte-spacing属于M7链路状态机，不能套用PDS的PSN/RTO定时器。

| 候选 ID | 章节与分类 | 拆分后的义务及适用条件 | 当前证据与后续处理 |
|---|---|---|---|
| UE11-p0612-002 | §4.2.5.1，CSIG基础能力 | compact/base必选，wide/extended可选；switch可跨端口携带tag、egress更新，并可strip支持的格式。 | M5/M7缺失；parse、forward、update、strip分别验收。 |
| UE11-p0612-003 | §4.2.5.1.1，peer不支持 | 对不支持相应格式的peer，发送前strip compact/wide，不受D位影响。 | M5/M7缺失；D只冻结signal更新，不阻止格式移除。 |
| UE11-p0613-001 | §4.2.5.1.1，LLDP通告 | 支持TLV对象时按本地能力/启用状态公布NO/COMPACT/COMPACT-WIDE。 | M7缺失；物理支持但本地禁用时不可继续通告已开启。 |
| UE11-p0613-002 | 表4-7，LLDP配置状态 | 选用LLDP配置时执行完整状态表；可有管理override，但通告必须一致。 | M7缺失；状态表额外转换仍需结构化映射。 |
| UE11-p0613-003 | §4.2.5.1.2，链路能力协调 | 链路启用LLDP时双方协调能力并按例示状态转换。 | M7缺失；需能力不一致、更新丢失/重复和link reset测试。 |
| UE11-p0614-001 | §4.2.5.2，tag初始化 | FEP插tag同时按表4-8初始化type/signal，D/R置零。 | M5缺失；min/max类初始值不能一律设零。 |
| UE11-p0615-001 | §4.2.5.4，Strip-and-Forward | LLDP获知下一跳不支持CSIG，先strip再forward，即使D=1。 | M5/M7缺失；需混合支持拓扑和MTU变化验证。 |
| UE11-p0616-001 | §4.2.5.5.1，transport反射 | Term将tag交给transport；sender-based CC/路径算法使用时开启Reflect并随ACK/NACK回送Reflection Header。 | M5缺失；普通NSCC ACK_CC不能替代ACK_CCX/NACK_CCX反射格式。 |
| UE11-p0616-002 | §4.2.5.5.1，FEP反射能力 | CSIG-capable FEP必须实现Reflect。 | M5缺失；未来能力发现与实际路径共同验收。 |
| UE11-p0619-001 | §4.2.7，CSIG子Profile | base所有信号必选；extended可任意子集含空集。 | M5缺失；子Profile不等于AI Base/HPC等端到端Profile。 |
| UE11-p0619-002 | §4.2.7.1，base信号全集 | ABW、ABW/C、Delay全部支持。 | M5缺失；已读取候选未包含的完整列表，三者需独立解析值验算。 |
| UE11-p0620-001 | §4.2.7.2，extended发现 | 若提供额外信号，必须能查询具体支持集合。 | 未选择extended；将来开启nQD/vendor等时补发现接口。 |
| UE11-p0620-002 | §4.2.7.2，重复说明 | informative段重复CSIG支持base的要求，不新增独立能力。 | 义务并入前述base集合，保留候选ID便于追溯。 |
| UE11-p0620-003 | §4.2.8，测量周期 | fabric所有switch周期必须一致；建议默认102.4µs及128ns～1024ms范围的可选精度。 | M5/M7缺失；周期/量化与RTT反馈不能混作同一个参数。 |
| UE11-p0620-004 | §4.2.8，周期近似 | 若近似周期，其误差不得超过量化允许精度损失。 | M5缺失；采用整数事件周期可直接避免额外近似。 |
| UE11-p0622-001 | §4.2.9.1.2，负载口径 | 支持排除MAC生成帧的端口负载模式，建议不计PAUSE/LLR/CBFC/PFC。 | M5/M7缺失；普通Fabric总字节统计不是CSIG数据负载统计。 |
| UE11-p0625-001 | §4.2.9.3.3，Delay测量 | ingress SOP至egress SOP之差，可减固定空载delay；不混入与包长成比例的额外延迟。 | Fabric已有逐hop首字节时间基础，CSIG信号产生/聚合仍缺。 |
| UE11-p0633-001 | §5.1.1，UE链路前导 | 所有UE链路帧使用规定8字节preamble。 | M7缺失；当前Ethernet帧抽象省略preamble，需链路表示与串行化记账。 |
| UE11-p0637-001 | §5.1.3.1.1，LLR CtlOS间距 | ACK/NACK速率在400～17296字节之间；不插入首256字节；同帧两CtlOS至少隔2KB，NACK_SENT按特例。 | M7缺失；须按字节流位置而非固定墙钟sleep建模。 |
| UE11-p0646-001 | §5.1.9.1.1，LLR INIT | INIT周期重发含tx_seq，间隔至少4倍target spacing；receiver必须回显init_data。 | M7缺失；需独立LLR初始序号、丢失重试及回显验证。 |

## 第 661～680 个候选

CBFC采用每端口/每VC的独立循环计数器，不与TFC接收信用或NSCC窗口混用。
LLR重放不再次消费CBFC信用，discard window对CC_Update、CF_Update及PFC有不同处理。
LLDP协商中wanted、enabled和operational也必须分开，不能将单端开关直接当链路已就绪。

| 候选 ID | 章节与分类 | 拆分后的义务及适用条件 | 当前证据与后续处理 |
|---|---|---|---|
| UE11-p0655-001 | §5.2.5.2，VC映射 | 双方按同一规则从PCP/DEI、DSCP及其任意子集映射VC。 | M7缺失；现有8个Fabric TC不等于CBFC VC。 |
| UE11-p0656-001 | 表5-18，计数初始化 | Port/VC credit limit、used、consumed为20位，freed为15位；port limit初始TotalCredits，其余按表初始化；启用CBFC至少一个lossless VC。 | M7缺失；初始化值与counter wrap须逐项测试。 |
| UE11-p0657-001 | §5.2.5.3，内部位宽 | S_P_CL/CU、S_VC_CL/CU支持20位CC范围，内部字段也不能截短。 | M7缺失。 |
| UE11-p0659-001 | §5.2.5.6.4，CC周期 | 周期发CC_Update覆盖所有lossless VC，0～15/16～31分两种消息，恢复丢包泄漏信用。 | M7缺失；与LLR丢弃/重放组合验收。 |
| UE11-p0660-001 | §5.2.5.6.4，CC线性化 | 64B帧至多16个VC计数，含此前发送包的全部消耗，不含此后包。 | M7缺失；生成时与真正发送时必须有明确序列边界。 |
| UE11-p0660-002 | §5.2.5.6.4，CC timer | 提供可配置CC_msg_timer。 | M7缺失；使用注入事件时钟，不在协议中sleep。 |
| UE11-p0661-001 | §5.2.5.7.3，CF timer选择 | 至少实现全局或per-VC CF_max_timer之一，以恢复丢失的freed更新。 | M7缺失；可选择全局策略但必须覆盖全部VC。 |
| UE11-p0663-001 | 表5-22，CC_Update编码 | DA按组播/对端地址；8808/FFFE、CID FA-7A-CB、type01/02，16×20位计数和FCS；未用或BE VC填0。 | M7缺失；不能以JSON通知代替要求检查的64B控制帧字段。 |
| UE11-p0667-001 | §5.2.8.3，初始化自举 | lossless VC初始化使用的LLDP不能使用正在初始化的lossless VC。 | M7缺失；需控制通道无信用也能推进。 |
| UE11-p0668-001 | §5.2.8.4，CBFC启动门限 | 双方初始化完成且RTS/RTR就绪后才能按CBFC信用发包。 | M7缺失；禁止只收到一边参数就放行。 |
| UE11-p0677-001 | §5.2.9，LLR/CBFC/PFC组合 | LLR replay不重扣信用；discard不计被丢弃LLR数据；CC_Update参与LLR并在discard丢弃；CF_Update仍处理；PFC不参与LLR、走BE且仍生效，只限制后续首次发送；CC_Update走BE不花信用。 | M7缺失；八组独立规则须做组合故障测试。 |
| UE11-p0679-001 | 表5-27，CBFC能力范围 | 至少2VC，最多32，lossless数可配；CreditSize支持32～2048列举值，TotalCredits1～2^19−1，perVC limit可配，PktOvhd−16～12；CF格式/min≥800B/max16KB～1MB及CC格式。 | M7缺失；完整表格参数/颗粒度与负值overhead解析需专项验收。 |
| UE11-p0680-001 | 表5-27续，范围与映射 | CC timer1µs～250ms；20/15位各counter范围；PCP/DEI/DSCP灵活映射；CF max全局或perVC至少其一。 | M7缺失；不以现有unsigned统一配置解析替代带符号/位宽校验。 |
| UE11-p0687-001 | §5.3.1，LLDP目的地址 | UE组织TLV使用表5-32 nearest-bridge组地址。 | M7缺失；需完整TLV/目的MAC编解码。 |
| UE11-p0688-001 | §5.3.2.1，W/E握手 | 双W为真才设置本地E；见远端E后才operational，双方E必须都真。 | M7缺失；management状态与数据路径准入分别验证。 |
| UE11-p0689-001 | §5.3.2.1.5，版本兼容 | v1支持新选项；遇v0时只用v0功能，禁止启用额外能力。 | M7缺失；v0/v1混合链路必测。 |
| UE11-p0689-002 | §5.3.2.1.5，未来兼容 | 未来版本兼容0/1；旧端忽略扩展长度、未知码点/保留字段。 | M7缺失；长度边界与未知字段不能引入越界访问。 |
| UE11-p0689-003 | §5.3.2.1.6，选项启用 | E表明正在运行；wanted端仅在peer也wanted后置E并启用。 | M7缺失；本地capable不等于协商enabled。 |
| UE11-p0689-004 | §5.3.2.1.6.1，LLR W/E码点 | W仅0或3；收1/2禁用；v0 E为1位，v1为2位值3，混合版本按规定解释。 | M7缺失；保留码点与位序转换需独立测试。 |
| UE11-p0690-001 | §5.3.2.1.6.1，LLR双方就绪 | 本地已置E也须等待peer E，双端启用才开始LLR。 | M7缺失；防止未协商的重放序号被对端当普通帧。 |

## 第 681～700 个候选

本批读取跨页的CSIG compact-only条件及UFH参数匹配要求。可选IPGR/wide格式
未选用时应如实通告不可用；M7/M8的协商模型仍需处理对端通告、缺失TLV和版本回退。
CBFC每个方向独立握手，不能用一个全链路ready布尔值替代32个VC的状态。

| 候选 ID | 章节与分类 | 拆分后的义务及适用条件 | 当前证据与后续处理 |
|---|---|---|---|
| UE11-p0690-002 | §5.3.2.1.6.2，IPGR条件 | 支持时仅在peer C=1后减少发送idle；能力双方满足时启用；缺TLV/v0按false。 | 未选择可选idle reduction，M7仍需正确通告/解析不可用状态。 |
| UE11-p0690-003 | §5.3.2.1.6.3，CSIG无能力 | 一端C=0则不得发送带CSIG tag；缺TLV/v0按C=0。 | M5/M7缺失；应结合strip-forward而非直接向不支持端发tag。 |
| UE11-p0691-001 | §5.3.2.1.6.3，compact-only跨页 | 任一端仅compact时双方不发wide，收到wide记录错误。 | M7缺失；已读取前页条件，不能把禁止wide套到双方都wide-capable的情况。 |
| UE11-p0691-002 | §5.3.2.1.6.4，UFH启动 | 收齐双方Options/参数前丢弃出链路UFH；仅启用共同格式、相同位数/版本，没交集置S=0。 | M7/M8缺失；原文表号引用另需按UFH字段定义核对。 |
| UE11-p0691-003 | §5.3.2.1.6.4，UFH相同能力跨页 | 同能力仍需匹配格式版本与地址位数，后续页细化条件。 | M7/M8缺失；共同能力只是必要条件。 |
| UE11-p0692-001 | §5.3.2.1.6.4，UFH匹配集 | 32/16分别比较V32/位长及V16/位长；只有匹配的格式可用。 | M7/M8缺失；一套不匹配时保留另一套允许的交集。 |
| UE11-p0692-002 | §5.3.2.1.6.4，UFH不同能力 | 只发两端共同支持的编码，无共同编码时禁止UFH。 | M7/M8缺失；不能以较大格式自动包裹较小格式。 |
| UE11-p0692-003 | §5.3.2.1.6.4，RR字段 | RR32/RR16发送零、接收忽略。 | M7缺失。 |
| UE11-p0692-004 | §5.3.2.1.6.5，RESV1 | 1位保留字段发送零、接收忽略。 | M7缺失。 |
| UE11-p0692-005 | §5.3.2.1.6.6，RESV2 | 4位保留字段发送零、接收忽略。 | M7缺失。 |
| UE11-p0692-006 | §5.3.2.1.6.7，RESV3 | 1位保留字段发送零、接收忽略。 | M7缺失；保留字段可忽略不等于忽略明确无效的长度。 |
| UE11-p0693-001 | §5.3.2.2，CBFC三方位序 | 每方向receiver WANT→sender RTS→receiver RTR；不得提前置RTS/RTR或使用信用。 | M7缺失；每VC独立配置及重新初始化测试。 |
| UE11-p0695-001 | §5.3.2.2.5，CBFC TLV版本 | 初始v0，未来向后兼容；旧端跳过新增保留字段/码点/扩展长度。 | M7缺失；解析必须按长度安全跳过。 |
| UE11-p0695-002 | §5.3.2.2.7，S_CreditSize冻结 | 等peer R_CellSize后选择；任何VC RTS=true时值有效且不可改变；0表示未设。 | M7缺失；配置更新需先解除受影响握手。 |
| UE11-p0695-003 | §5.3.2.2.8，overhead冻结 | 任一VC RTS=true时S_PacketOverhead有效且不可变化。 | M7缺失；有符号语义与8位线编码需分别测试。 |
| UE11-p0696-001 | §5.3.2.2.9，RTS等待 | 32位每VC标志，bit0为VC0；RTS=true仍等receiver RTR。 | M7缺失。 |
| UE11-p0696-002 | §5.3.2.2.10，R_VCnLength | v0元素长6B，future可增，v0读完6B后跳过扩展。 | M7缺失；未知尾部不可误当下一VC。 |
| UE11-p0696-003 | §5.3.2.2.15.1，WANT撤销 | WANT变false后sender停止信用准入、清RTS、回BE。 | M7缺失；不把撤销当保持旧信用无限有效。 |
| UE11-p0696-004 | §5.3.2.2.15.2，RTR撤销 | peer RTS之前不得置RTR；RTR变false后sender停止按CBFC信用发送。 | M7缺失；停用/重启与在途帧处理需明确。 |
| UE11-p0698-001 | §5.3.2.2.15.10，可选opaque匹配 | R_PktID_Sel=3时12位handle列表须由管理双方预配一致；不要求某种特定复杂匹配法。 | 未选择该可选匹配方式；M7可先实现必选PCP/DEI/DSCP映射。 |

## 第 701～729 个候选

最后一批区分UFH/链路行为模型与真实PHY电气/PCS实现。路线图排除了电气及RTL逐周期
仿真，因此硬件PHY类型合规不作声明；LLR/CBFC控制表示、误码/FEC结果与时延/容量
行为仍属于M7。IPGR与MTBPE估计均是未选择的可选增强。

| 候选 ID | 章节与分类 | 拆分后的义务及适用条件 | 当前证据与后续处理 |
|---|---|---|---|
| UE11-p0698-002 | §5.3.2.2.15.11，信用分配模式 | R_VC_CreditLimit与R_TotalCredits不得同时非零，选择其一。 | M7缺失；配置/LLDP接收均需拒绝冲突。 |
| UE11-p0716-001 | §5.4.1，UFH共存 | UFH与普通Ethernet同链路共存，不要求修改MAC以下物理实现。 | M8缺失；已实现IP帧只是共存的一半。 |
| UE11-p0717-001 | §5.4.1，UFH设计要求 | tag stacking、兼容LLR/CBFC但不依赖、地址至少256K endpoints；地址族不固定，建议无状态转ETH/IP。 | M8缺失；64节点仿真规模不降低地址字段可表达范围，gateway翻译为可选。 |
| UE11-p0718-001 | §5.4.2，UFH适用范围 | 需要不支持的fragment/tunnel等特性时继续用Ethernet/IP。 | M8缺失；能力选择需在发包前确定。 |
| UE11-p0719-001 | §5.4.3，UFH V/W | 发送V=0，接收验证V/W后选择格式；V=1保留未来。 | M8缺失；位码校验与协商结果共同验收。 |
| UE11-p0720-001 | §5.4.4，opaque字段 | UFH_32的8位、UFH_16的44位opaque由端到端覆盖，switch转发忽略。 | M8缺失；不把transport状态错误作为交换机路由字段。 |
| UE11-p0722-001 | §5.4.5，tag顺序 | 遵循Ethernet tag stack规则，VLAN在offset12首先出现。 | M8缺失；将与CSIG/TSS位置和MTU预算一起验证。 |
| UE11-p0723-001 | §5.4.6，地址有效位 | 地址LSB对齐，端点/交换机按配置忽略容器未使用高位。 | M8缺失；不能因高保留位变化误选目的端。 |
| UE11-p0724-001 | §5.4.8，UFH trimming | 若选择对UFH trim，按§4.1更新UFH DSCP。 | M8缺失；RODL仍按其独立禁NSCC/trim约束选择路径，不把可选UFH trimming强加给RODL。 |
| UE11-p0725-001 | §5.4.10，UDP/IPv4校验 | 特定UDP/IPv4映射可发送checksum0，receiver忽略。 | M8缺失；当前普通IP/UDP规则不能直接证明UFH映射路径。 |
| UE11-p0725-002 | §5.4.11，UFH显式启用 | 域内通过适用管理方式显式开启UFH，假定全部路径支持。 | M7/M8缺失；不得仅由单个发送者header设置自动启用整网。 |
| UE11-p0728-001 | §5.5.1，IPGR条件 | 选用时保留terminate block并按8字节对齐，减少idle而非删除合法帧边界。 | 未选择可选IPGR数据路径；协商能力需如实保持false。 |
| UE11-p0729-001 | §5.5.4，IPGR接收能力 | 通告支持即须能接收reduced idle，无论发送侧是否enabled；建议向管理报告能力。 | IPGR未选择；未来不得将disabled与incapable混淆。 |
| UE11-p0730-001 | §6.1，真实PHY条件 | 声明UE PHY硬件合规的设备须符合列出的某种PHY类型。 | 电气/真实PHY合规不在当前软件模型声明范围，M7仅验证配置速率/FEC/误码行为。 |
| UE11-p0732-001 | §6.2，可选CtlOS PHY | PHY选择该可选能力后遵守全节要求。 | M7需要控制ordered-set的行为表示；实际MII/PCS实现不在本轮RTL范围。 |
| UE11-p0733-001 | 表6-3，CtlOS表示 | CtlOS的MII D4低半字节为6，其余字节按表。 | M7控制表示/编解码仍缺；不声明物理lane接口已经实现。 |
| UE11-p0734-001 | §6.2.3.1，特定PHY decoder | 指定200G/400G/800G/1.6T PHY采用所引用stateless 64B/66B decoder及RS要求。 | 真实PCS电气/RTL不在本轮范围；相关错误结果可映射到M7行为模型。 |
| UE11-p0735-001 | §6.2.3.1，100G overwrite条件 | 若作FEC error overwrite，用指定stateless decoder并按未纠正codeword设置前四EBLOCK_R。 | 未选择真实PCS实现；不能把简单BER计数当该decoder符合性证据。 |
| UE11-p0735-002 | §6.2.3.1，100G非overwrite条件 | 不作overwrite时用表6-5而非旧state-diagram decoder。 | 真实PCS不在本轮范围。 |
| UE11-p0735-003 | §6.2.3.2，PCS encoder | 所支持线速率采用指定stateless encoder。 | 真实PCS不在本轮范围；行为串行化不冒充encoder实现。 |
| UE11-p0736-001 | §6.2.4.1，CtlOS与数据隔离 | 任意合法插入位置不破坏802.3 packet transfer。 | M7缺失；模型需保证控制符号插入/提取后交付字节不变。 |
| UE11-p0736-002 | §6.2.4.1，DIC隔离 | CtlOS不改变发送RS的Deficit Idle Count。 | 实际RS不在本轮范围；M7的idle/控制记账须保持独立。 |
| UE11-p0736-003 | §6.2.4.2，接收CtlOS | lane0合法CtlOS编码需被RS接受。 | M7可验证控制表示合法性；不声明真实MII接口。 |
| UE11-p0736-004 | §6.2.4.2，DATA_VALID隔离 | 合法CtlOS不改变RS DATA_VALID_STATUS。 | M7缺失；控制事件与数据有效/损坏事件分开。 |
| UE11-p0736-005 | §6.2.4.2，Start前CtlOS | 判断lane0 Start的数据有效性时跳过紧前CtlOS，用其之前RXC/RXD。 | 真实RS逻辑不在本轮范围；控制提取行为需保留前序数据状态。 |
| UE11-p0736-006 | §6.2.4.2，CtlOS错误窗口 | 单次CtlOS不使数据无效；过密多次按允许策略处理，窗口由表6-6定义。 | M7缺失；可选择规定的忽略策略但须验证合法数据不受影响。 |
| UE11-p0736-007 | §6.3，可选PHY预测 | 选择FEC link-quality prediction后遵守该节要求。 | 未选择硬件预测能力；M7基本FEC纠正/失败统计另行实现。 |
| UE11-p0742-001 | §6.3.2，可选MTBPE | 若支持MTBPE估计，则全部规定counter可由软件访问。 | 未选择该可选估计器，不把普通包丢失率计数当MTBPE。 |
| UE11-p0762-001 | §8.1.1，能力与验收声明 | 明确公布支持功能/相关Profile，执行对应checklist；旧例名依§3.3四Profile及实际适用功能解释。 | 当前capabilities/validator/inventory四Profile均false；M8完成后再按完整义务和证据开放。 |

729个自动提取候选已逐条分类并拆分上述义务。该数字不是MUST总数，也不代表729项
功能已实现或验收。M0仍需补充候选未覆盖的表格字段、状态图、算法步骤和条件集合，
并把每个最终义务映射到实现、Profile适用性、正反边界测试及证据。
`requirements.json`的53个开发任务保持独立粒度，`inventory_complete`继续为false。
