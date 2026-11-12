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
| UE11-p0088-002 | §2.2.2.1，跨 Profile 条件项 | AI Full/HPC 互通时：限制在 AI Full 操作集；HPC 把 deferrable send 当 SEND；把 deferrable tagged send 当 tagged SEND。 | 必须拆成三项。已有未标记 SEND 的接收兼容回归 `send_header_data_test`；tagged 与跨 Profile 协商未实现，不能据此通过整段。 |
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
| UE11-p0104-001 | 表 2-13，多个 key 字段约束 | IDEMPOTENT_SAFE=0 禁止幂等传输；保留位为零；用户 key 的 vendor 位为零；optimized key 的中间保留位为零且使用 12 位 index。 | `memory_key_test` 验证格式与 namespace；RUDI 尚未实现，所以幂等传输的使用约束不能通过。optimized 头也未实现。 |
| UE11-p0104-002 | §2.2.5.3.4.1，key API 格式 | 用户和 provider key 都使用标准 64 位格式；API 传递完整 64 位；RKEY 范围由 mr_key_size 决定。 | native 用户 key 与 provider 生成 key 有部分覆盖，公开 provider 仅 FI_MR_PROV_KEY；mr_key_size 约束由下一段续完。 |
| UE11-p0105-001 | §2.2.5.3.4.1，前段续文 | mr_key_size<6 时，把未使用的高位 RKEY 位清零。 | 与 p0104-002 合并追踪位宽义务；当前 provider 固定 6，尚无可选小位宽路径的边界验收。 |

## 第 41～60 个候选

这批复核了表 2-14～2-16 的选择前提、表 2-20 的 Profile 条件及跨页的发送 API 表。
仅支持一个函数入口不表示它的所有必选 flag 或所有 Profile 映射已经实现。

| 候选 ID | 章节与分类 | 拆分后的义务及适用条件 | 当前证据与后续处理 |
|---|---|---|---|
| UE11-p0105-002 | §2.2.5.3.4.1，本地 key 解释 | provider 选择 RKEY 到 MR 的本地映射方法；不要求复制特定 vendor 的 key 编码。 | native registry 已按 key/地址 namespace 查找，并保留注册 identity；`memory_key_test` 有覆盖。 |
| UE11-p0105-003 | §2.2.5.3.4.1，optimized 条件项 | 采用 optimized RMA 头时，把 RKEY/index 放入 ses.resource_index。 | optimized 头未实现；不能把标准头中的 48 位 key 映射算作本项。 |
| UE11-p0105-004 | §2.2.5.3.4.1，small RMA 条件项 | 只有满足表 2-15 的单 MTU 操作、无 remote CQ data 等前提才使用 small RMA 头；优先使用属于 SHOULD。 | small RMA 头未实现。后续必须把“允许使用的条件”和“建议选择”分开。 |
| UE11-p0105-005 | §2.2.5.3.4.1，标准头回退 | 不满足 optimized 与 small RMA 前提时，RMA 使用标准 SES 头。 | 当前 RMA 一律使用标准头，覆盖回退分支；不据此通过所有头格式选择要求。 |
| UE11-p0105-006 | §2.2.5.3.4.1，RUDI 条件项 | RUDI 需要表 2-16 中无 R/W 消息顺序、IDEMPOTENT_SAFE、目标支持等前提；选择使用属于条件性 SHOULD。 | RUDI 未实现；保留 safe key 元数据不等于可直接启用 RUDI。 |
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
| UE11-p0112-004 | 表 2-22，fi_sendv 与跨页映射 | fi_sendv 必选，iovec 上限由 vendor 声明；AI Full/HPC 的大消息 opcode 选择在下一页展开。 | 单 iovec 路径存在；deferrable/rendezvous 的源端大小选择仍未实现。 |
| UE11-p0113-001 | 表 2-22，多个 send/inject 义务 | fi_sendmsg 支持 CQ data、completion、inject、三种完成级别及 fence；fi_inject 成功不生成 CQ，可靠端点交付失败必须生成错误 CQ。 | CQ data/部分完成语义及 FI_FENCE 已实现；inject API/flag 已有所有权、CQ 与重试回归；三个可靠完成等级采用更强 GO 完成点，标准地址/授权仍不全。需拆成功抑制、错误报告和每个 flag，不能用 sendmsg 基础通过代替。 |

## 第 61～80 个候选

本批复核 §2.2.5.4 的 API 表格及跨页续文。表中的 “all profiles” 使用本章
libfabric 映射范围，不能据此把 Unified Local 强制映射到 libfabric。

| 候选 ID | 章节与分类 | 拆分后的义务及适用条件 | 当前证据与后续处理 |
|---|---|---|---|
| UE11-p0114-001 | 表 2-22，两种携带 CQ data 的 API | fi_senddata 与 fi_injectdata 都必选，远端 CQ data 放在 ses.header_data；inject 继承成功不生成 CQ、可靠交付失败生成错误 CQ 的规则。 | senddata 有公开进程与 header_data 回归；injectdata 已通过公开 API 到原生对端的复制、目标 CQ data、成功 CQ 抑制和错误完成测试。 |
| UE11-p0114-002 | §2.2.5.4.1.1，接收策略与发送兼容 | 目标至少选一种规范 unexpected-message 策略；发起端正确响应所有目标行为。 | 已有 ROD 暂存、RUD 丢弃/查询及晚到 receive 场景；全部目标行为及 deferral/rendezvous 的组合仍未覆盖。 |
| UE11-p0114-003 | §2.2.5.4.1.2，Profile 条件项 | AI Full 支持 deferrable send；HPC 支持 rendezvous。 | 实际 defer/RTR/后续数据与 rendezvous 未实现。已有把收到的 DS 当 SEND 处理的兼容分支不能代替源端与目标完整协议。 |
| UE11-p0114-004 | §2.2.5.4.1.2，rendezvous 条件项 | RENDEZVOUS_SEND 的 eager 数据不超过配置上限。 | M5 未实现；需要零、恰好上限及超限测试。触发使用 rendezvous 的大小选择另列 SHOULD。 |
| UE11-p0115-001 | §2.2.5.4.2，Profile 条件项 | AI Full/HPC 支持 tagged API；DGRAM 不支持。 | 当前没有 tagged 能力和 API，均待 M5。 |
| UE11-p0115-002 | 表 2-23，接收 API 与匹配 | 支持 trecv/trecvv/trecvmsg，按 posted 顺序搜索；AI Full 至少 exact match，不支持 wildcard 时拒绝非零 ignore；HPC 支持 wildcard。 | 需拆分三个 API、FIFO、exact、ignore 拒绝及 wildcard，当前均缺失。 |
| UE11-p0115-003 | 表 2-24，发送 API 与 opcode | tsend/tsendv 及跨页 tsendmsg/tinject/tsenddata 必选；AI Full/HPC 分别按大小选择 tagged、deferrable tagged 或 rendezvous tagged。 | 尚无 tagged/注入协议；须按每个 API、完成与大小边界分别验收。 |
| UE11-p0116-001 | §2.2.5.4.2.1，两个匹配分支 | 指定 src_addr 时同时匹配 tag 与地址中的 Initiator ID；UNSPEC 时不得用 initiator 过滤。 | M5 缺失；其他地址字段参与 directed receive 属于可选，不能混入基础强制匹配。 |
| UE11-p0116-002 | §2.2.5.4.2.1，Profile/能力条件项 | AI Full/HPC 支持 UNSPEC；HPC 支持指定源地址。 | 未实现；FI_EXACT_DIRECTED_RECV 例外声明及与前句的关系需在选用该能力时单独复核，当前不宣称该能力。 |
| UE11-p0116-003 | §2.2.5.4.2.2，tagged rendezvous 条件项 | RENDEZVOUS_TSEND 的 eager 数据不超过配置上限。 | 与未标记 rendezvous 分开验收；两者当前均缺失。 |
| UE11-p0117-001 | 表 2-25，RMA API 与 flags | AI Full/HPC 支持 read/readv/readmsg；AI Base/Full/HPC 支持 write/writev/writemsg/inject_write/writedata；分别支持表列 flags 与 vendor iovec 上限。 | WRITE/WRITE IMM、单 iovec、CQ data 和部分完成等级已有覆盖；READ 仍缺失；三个完成等级采用 GO 点，inject 已覆盖复制/CQ/边界，FI_FENCE 已覆盖混合模式/重试。不能用 WRITE 成功证明整张表通过。 |
| UE11-p0118-001 | §2.2.5.4.4，原子数量约束 | 非取回原子支持 bulk；取回原子限制为所选类型的一个单位。 | 非取回 bulk 已在 native/provider 实现并测试，公开 valid/query 返回类型相关数量；fetching 未实现，未来必须拒绝多单位。 |
| UE11-p0118-002 | 表 2-26，非取回 API 与 flags | atomic/atomicv/atomicmsg 必选；支持 COMPLETION、INJECT、FENCE，以及下一页续列的 TAGGED。 | bulk 整数操作已有覆盖；FI_FENCE 与 FI_INJECT 已有公开 API 回归；TAGGED 尚缺。“all profiles” 按本章范围解释。 |
| UE11-p0119-001 | 表 2-26，inject 与 fetching | inject_atomic 为基础要求；AI Full/HPC 支持 fetch_atomic/v/msg，flags 继承 atomicmsg。 | inject_atomic 已有公开 API 所有权、字节上限和成功 CQ 抑制回归；fetching 未实现，单单位约束仍待验收。 |
| UE11-p0119-002 | 表 2-26，CAS 与能力查询 | AI Full/HPC 支持 compare_atomic/v/msg；所有本章 Profile 支持 atomicvalid/fetch_atomicvalid/compare_atomicvalid/query_atomic，返回实际支持类型和操作。 | 非取回查询已有实现；fetch/CAS 当前明确不支持。需逐一复核查询 API 对不支持组合的返回值，不能把拒绝取回操作算作已实现取回。 |
| UE11-p0120-001 | §2.2.5.4.5，选定 INC 后的条件项 | 支持 INC 时公布 FI_COLLECTIVE；不支持时不公布属于 SHOULD。 | INC 留给 M8 后独立增强，当前不公布 FI_COLLECTIVE，不算作已实现 INC。 |
| UE11-p0120-002 | §2.2.5.4.5，选定 INC 后的管理条件项 | 支持 INC 时能与 manager 通信，并解释 PRIMARY/SECONDARY URL 配置。 | 当前未选定 INC；后续增强需正向、fallback 与失效测试。 |
| UE11-p0121-001 | §2.2.5.6，错误 CQ 三项义务 | err 采用相应 libfabric 错误，无对应项时用 FI_EIO；prov_errno 保留 SES 错误码。 | provider 已实现映射、FI_EIO fallback 与 prov_errno；公开错误进程测试仅覆盖部分 SES 错误，完整映射表仍需逐项验证。 |
| UE11-p0121-002 | §2.2.6，DGRAM 模式 | FI_EP_DGRAM 使用 UUD。 | 已有公开 DGRAM 进程与 wire 路径；不能推断为远端可靠交付。 |
| UE11-p0121-003 | §2.2.6，RDM 模式跨页续文 | RDM 使用 RUD/ROD，HPC 可使用 RUDI；AI Base/Full 依操作和排序按表 2-29/30 选择，HPC 按表 2-31。 | provider 现按独立 SEND/R/W 谓词选择 ROD/RUD，公开 API 与实际报文检查四种组合；HPC RUDI/rendezvous 未实现。后续 p0122 候选包含同一义务的细化。 |

## 第 81～100 个候选

本批同时检查表格和跨页上下文。§2.2.10.4 对 small/medium 头的文字与表题
存在不一致，后续编码依据 §3.4 的正式线格式；不能直接复制 API 映射表题作为类型值。

| 候选 ID | 章节与分类 | 拆分后的义务及适用条件 | 当前证据与后续处理 |
|---|---|---|---|
| UE11-p0121-004 | §2.2.6，前段 RDM 选择的细化 | AI Base/Full 只使用 RUD/ROD，按操作和配置的排序选择。 | 与 p0121-003、后续两张表共享实现差距，不重复算已实现功能。 |
| UE11-p0122-001 | 表 2-29，AI Base 四种组合 | SEND 排序只控制 SEND 的 ROD/RUD；R/W 排序只控制 RMA/ATOMIC 的 ROD/RUD，两者独立。 | `libfabric_mode_selection_test` 检查四行中的 SEND、WRITE、ATOMIC 及实际 PDS type，另覆盖 RAS/SAR/SAW/WAS 交叉 flags；完整 Profile 仍有其他缺口。 |
| UE11-p0122-002 | 表 2-30，AI Full 四种组合 | SEND/TAGGED 与 RMA/ATOMIC 分别遵循各自排序；有 SEND 排序的 deferrable tagged 初始/eager 数据用 ROD，后续数据用 RUD。 | 基础模式选择与 M5 延迟恢复均缺失；不能只修改一个 Operation 字段就通过整表。 |
| UE11-p0122-003 | 表 2-31，HPC 组合与策略 | SEND/TAGGED、rendezvous 初始/后续、RMA、ATOMIC 分别选择表列模式；无 R/W 排序的 RMA 可依策略用 RUD 或 RUDI。 | RUDI 为可选分支而非所有 RMA 强制；当前未实现 HPC/rendezvous/RUDI，未作能力声明。 |
| UE11-p0124-001 | §2.2.8.1，排序端点条件项 | 配置消息排序的 endpoint 操作约束到一个发送队列。 | provider 当前串行应用队列符合这一局部分支；多队列及流量类别映射是 SHOULD，PDC 内 packet window 不等于多个应用发送队列。 |
| UE11-p0126-001 | §2.2.9，选定 TSS 后的条件项 | provider 支持表 2-33 的完整安全绑定参数，并由特权地址分配流程取得。 | M6/M7 管理与 TSS 缺失；真实 kernel driver 后续系统集成。 |
| UE11-p0126-002 | 表 2-33，字段与保留位 | 支持 AES-GCM-256、三种模式、AN/automatic rekey 选择、shift/mask、四种封装及 offset/AN/SDI/SSI；rekey 保留位必须为零。 | 需逐字段、范围、组合和无效保留值建项，当前未实现。AES 库调用本身不代替安全绑定。 |
| UE11-p0126-003 | 表 2-34，rekey 条件项 | 支持 AN/SDI/SSI、16 位 epoch、96 位 IVMASK、raw/wrapped key 类型、长度及 key 参数。 | M6 缺失。后页 C 示例把 IVMASK octet 常数写为 96，与表中 96 bit 不一致，需以正式 TSS 结构/算法交叉复核。 |
| UE11-p0127-001 | §2.2.9，三方管理流程 | driver 发请求；特权进程返回参数；driver 接受主动推送及请求响应并编程安全状态。 | 本轮需 M6/M7 行为模型；真实驱动不在 M0–M8 范围。请求/响应权限与主动推送分别验收。 |
| UE11-p0127-002 | 表 2-35，请求字段 | rekey 请求带 AN、31 位 SDI、32 位 SSI。 | 当前缺失；必须校验安全域与源归属，不能仅把任意 key 写入对象。 |
| UE11-p0131-001 | §2.2.10.4，optimized 原子条件项 | 原子操作使用与 RMA 相同的 optimized 头前提；使用该头的建议另列 SHOULD。 | optimized 未实现。该段将 SMALL 表示 optimized non-matching；与后续 small-message 表题须按正式 SES 格式区分。 |
| UE11-p0132-001 | §2.2.10.4，small RMA 原子条件项 | 原子也采用 small RMA 的适用前提。 | small RMA 未实现；与 optimized 条件分开，不把两类紧凑头合并。 |
| UE11-p0132-002 | 表 2-43，small RMA 映射 | hd 必须为零，其余 opcode/dc/rel/index/generation/Job/PID/长度/offset/initiator/key 按各自来源映射。 | 未实现；无 CQ data 是必要前提，不能静默丢弃调用者提供的 CQ data 来选择该头。 |
| UE11-p0132-003 | §2.2.10.4，deferrable token | 两个 restart token 替代 buffer_offset，RTR 携带相同 token；发起 FEP 的活跃 token 唯一。 | M5 缺失；需要跨 endpoint/并发/取消/复用的唯一性与迟到 RTR 回归。 |
| UE11-p0133-001 | 表 2-44，rendezvous 源 MR | 源 buffer 注册 REMOTE_READ；扩展头包含源 PID/index/generation、消息起始 offset、rkey 和受上限约束的 eager 长度。 | M5 缺失；源 MR 撤销、偏移边界及全消息 READ 必须共同验证。 |
| UE11-p0133-002 | §2.2.10.4，原子映射 | libfabric datatype/op 映射至 SES 对应 mnemonic。 | 当前支持的 8 种整数类型、12 种非取回操作已有 native/wire/provider 回归；不据此声明浮点、fetching 或 CAS。 |
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
| UE11-p0189-003 | 表 3-2，wildcard | HPC 需 wildcard tag。 | M5 缺失；不是 AI Base/Full 的通用必选项。 |
| UE11-p0189-004 | 表 3-2，本地直接寻址 | Unified Local 通过 FA/JobID 选择目标内存。 | M8 缺失；禁止把收到的地址直接转换为执行器指针。 |
| UE11-p0189-005 | §3.3.3，四个授权义务 | 所有 Profile 实现 SES 授权、插入 JobID、访问前检查 JobID，每 FEP 至少一个 JobID。 | native Job0/多 Job/exact/any MR 已有测试；特权管理到公开 provider 的链条与 Unified Local 未实现。 |
| UE11-p0189-006 | §3.3.4，表格总要求 | 按表 3-3 各 Profile 支持相应 buffer 行为。 | 这是后续行的总则，不额外记为一个已通过功能。 |
| UE11-p0189-007 | 表 3-3，use-once RMA | HPC 支持 RMA use-once。 | M5 缺失；当前重复消除不是 use-once buffer 生命周期的替代。 |
| UE11-p0189-008 | 表 3-3，full-range key | AI Base/Full/HPC 支持标准头全范围 memory key。 | native 64 位 API/48 位线 RKEY 已有边界回归；provider 用户 key 与完整授权矩阵仍不全。 |
| UE11-p0189-009 | 表 3-3，limited-range key | HPC 支持 optimized 头有限范围 key。 | M5 optimized 编解码/索引授权缺失。 |
| UE11-p0190-001 | 表 3-3 续，本地与 tag | Unified Local 支持本地头直接内存；Full/HPC exact tag，HPC wildcard。 | M5/M8 缺失；MULTI_RECV/Sync Group 行为空，不把本表当作其所有 Profile 强制依据。 |
| UE11-p0190-002 | §3.3.5，字段总要求 | 必选头的所有字段/flags 都要支持，除非表中明确例外。 | 标准头通过单一字段子集不等于整头通过；当前保留 partial，逐 flag/组合仍需补验收。 |
| UE11-p0190-003 | 表 3-4，标准头 | AI Base/Full/HPC 均需 44 字节标准请求头。 | codec 黄金样例/native/参考互通部分覆盖；尚非全部字段组合通过。 |
| UE11-p0190-004 | 表 3-4，多格式矩阵 | Full 需 DS/RTR；前三 Profile 需 DS-as-SEND；HPC 需 optimized non-matching/small 和 rendezvous；Unified Local 需 local 格式；原子扩展四种必选；CAS 扩展 Full/HPC/Local 必选。 | DS-as-SEND、标准原子扩展已有子集测试，其余 M5/M8 缺失；不能把未选择的 DS/RTR 当作 AI Base 源端必选。 |
| UE11-p0191-001 | 表 3-4，标准响应 | AI Base/Full/HPC 支持标准 response。 | 当前 codec 和 SES 响应有回归；表中 16B 与正式 §3.4.3.7 的长度差异已在 BASELINE-AUDIT 记录，按正式字段布局编码。 |
| UE11-p0191-002 | 表 3-4 续，响应/packing/GO | Full/HPC 支持带数据响应；HPC optimized response；Local compact response 和每包最多 16 消息的接收处理；四种均支持 GO delivery complete。 | 带数据/optimized/local/packing 缺失；native 成功在受检目标内存写入后报告，完整 GO、完成等级及本地路径联合证明未完成。 |
| UE11-p0191-003 | §3.3.6，模式总要求 | 各 Profile 支持表 3-5 列出的模式及对应网络行为。 | 不能用一种通用可靠网络后端覆盖所有模式；当前仍由原 PDC 实现 RUD/ROD/UUD。 |
| UE11-p0191-004 | 表 3-5，模式矩阵跨页截断 | AI Base/Full/HPC 都需 RUD/ROD/UUD；HPC 需 RUDI；Unified Local 需 RODL。 | 原图确认本候选文本遗漏表后两行。前两种可靠模式与 UUD 有回归；RUDI/RODL 缺失，独立能力保持 false。 |

## 第 141～160 个候选

本批补完 Profile 模式表的拆行，并复核基础寻址/授权。JobID 授权与 TSS 安全域
授权是两道独立检查；成功定位一个 buffer 不能替代随后检查权限。

| 候选 ID | 章节与分类 | 拆分后的义务及适用条件 | 当前证据与后续处理 |
|---|---|---|---|
| UE11-p0191-005 | 表 3-5，RUDI | HPC 必选幂等操作的 RUDI。 | 与 p0191-004 的原图补行相同义务；尚未实现，不因 provider 可为某次 RMA 选 RUD 就免除 HPC RUDI 能力要求。 |
| UE11-p0191-006 | 表 3-5，UUD | AI Base/Full/HPC 必选 UUD。 | native/provider DGRAM 已有回归；不推断远端收到或可靠交付。 |
| UE11-p0192-001 | 表 3-6/3-7，网络条件 | 最佳努力网络中 AI Base/Full/HPC 必选 NSCC；无损表的 NSCC/RCCC 格为空。 | NSCC 已接入发送准入、反馈及真实 trim；尚未全部规范验收。RCCC 虽非此表通用必选，仍按 roadmap 在 M5 实现。 |
| UE11-p0199-001 | §3.4.2.3，key namespace | 两种 namespace 都遵守 key 格式及绑定；未找到或不允许的 MR 映射返回 RC_BAD_MKEY。 | native exact/any/Job/PID/index 优先与 key 格式已有回归；权限错误与映射错误需按标准区分，不能统一报告成功或任意错误。 |
| UE11-p0200-001 | §3.4.2.3，本地直接内存隔离 | 无 PID/index/key/initiator 的本地事务用 JobID 隔离：单一授权 Job，或 Job 对应地址基址。 | M8 未实现；应使用受检模拟地址空间，管理翻译是软件策略，不能直接解引用远端地址。 |
| UE11-p0201-001 | §3.4.2.3.1，Job provisioning | 同一可达网络内同时运行、不可互通的实体使用不同 JobID；可通信实体可共享；应用可用多个 Job。 | native 能表示多 Job，但网络级特权分配/冲突检测与回收生命周期待 M7；单 registry 的集合不代替全局 provisioning。 |
| UE11-p0201-002 | §3.4.2.3.2，进程隔离 | 各 OS 进程有不同 PIDonFEP；同一 OS 进程可有多个，且与 OS PID/PASID 解耦。 | 当前 native 可配置 PID namespace，尚无特权进程分配模型；固定 PID=1 的 provider 不是完整跨进程隔离证明。 |
| UE11-p0202-001 | §3.4.2.3.2，PID scope | PIDonFEP 范围相对于 Job 或 Fabric Address。 | `ResourceDirectory` 支持相对映射和绝对 PID；provider 标准地址入口仍缺失。 |
| UE11-p0202-002 | §3.4.2.3.3，资源空间/optimized | SEND/tag/RMA index 空间独立；optimized RMA 的 index 精确选择一个 RMA resource。 | native SEND/RMA 空间已分开；tag 与 optimized 单资源关联未实现。标准头允许一个 RMA resource 的情形不能反推所有 index 强制只有一个 MR。 |
| UE11-p0204-001 | §3.4.2.3.5，匹配顺序 | ROD wildcard 在所有匹配的 posted buffers 中按 FIFO 消耗；RUD FIFO 为 SHOULD，网络乱序可导致不同次序。 | tagged 未实现。ROD 普通 receive 的 FIFO 测试不等于 wildcard 匹配验证。 |
| UE11-p0204-002 | §3.4.2.3.5，API key 映射 | 采用 RMA memory key 时把 API key 映射到线头 match_bits，保持相应 namespace。 | native/provider 标准头已有 key 到线格式与目标授权回归；optimized 通过 index 选择的无 key 路径另验。 |
| UE11-p0204-003 | §3.4.2.3.7，唯一 buffer 选择 | 未标记 tuple 唯一选择一个 buffer；匹配 tuple+criteria 也唯一选择 buffer，可采用不同内部数据结构。 | native untagged/RMA 受检选择有覆盖；tag 缺失，不把具体 map 容器误写成标准要求。 |
| UE11-p0205-001 | §3.4.2.3.7，无 key RMA | 未携 key 时 tuple 唯一选择 buffer；三种操作使用独立 index 空间。 | optimized/index-only RMA 与 tag 缺失；标准头 key lookup 不代替无 key 条件项。 |
| UE11-p0206-001 | §3.4.2.4，定位后授权 | buffer 定位后执行 JobID 与适用安全域授权。 | native Job/MR 检查已有负向回归；M6 SDI 检查尚缺。 |
| UE11-p0206-002 | §3.4.2.4.1，源端可信 Job | 由发起节点可信层分配或验证 JobID。 | native 源端检查配置 Job，但任意应用可自行配置的教学 API 不等于特权管理；M7 授权对象/可信边界待实现。 |
| UE11-p0206-003 | §3.4.2.4.1，逐 buffer 授权 | 每次访问确认 Job 可访问该 buffer；至少一个 Job。只确认 Job 属于 FEP 集合不充分。 | exact/any MR 与相对/绝对访问已有回归；provider 固定 Job 和未完成的配置链仍需补全。 |
| UE11-p0207-001 | §3.4.2.4.2，选定 TSS 后的 SDI 授权 | SDI 必须被 endpoint 允许；失败按 TSS 丢弃并报告，不发送 SES response 或 PDS NACK。 | M6 缺失；认证失败不得沿当前普通 semantic error 路径回复。UET_NO_RESPONSE 的提前返回例外不允许最终成功完成。 |
| UE11-p0207-002 | §3.4.2.5，消息大小与分包 | bulk 上限由标准头 32 位长度决定，可分别限制 RMA/send；分包遵循 Payload MTU，紧凑头还有更窄限制。 | streamed WRITE 已验证 UINT32_MAX 和内存有界；其他大消息与紧凑头仍缺失，provider 大小能力不能由 WRITE 单测推广到全部操作。 |
| UE11-p0211-001 | §3.4.2.6.1，use-once 生命周期 | 一条消息独占已匹配 buffer，其他消息不可再用；保留到该消息完成才还给应用。支持 SEND/RECV，支持 tag 时也覆盖 tag。 | native posted receive 绑定 registration identity 并在最终完成前保留，撤销/重复/晚到有回归；tag 与 RMA use-once 仍未实现。 |
| UE11-p0212-001 | §3.4.2.6.3，HPC tag 匹配 | HPC 目标支持 tagged；使用 match_bits 和 initiator，是否硬件加速不影响要求。 | M5 未实现；后续测试同时验证 tag 与 source criteria，不能只比较 tag。 |

## 第 161～180 个候选

本批检查消息顺序、MTU、标准头和 DS 重启规则。协议配置的标准 Payload MTU
与教学测试使用的小片段大小要分开记录，不能把任意小整数称为标准 MTU 配置。

| 候选 ID | 章节与分类 | 拆分后的义务及适用条件 | 当前证据与后续处理 |
|---|---|---|---|
| UE11-p0212-002 | §3.4.2.6.4，目标 memory key | RMA 支持把 match_bits 用作 memory key，并遵循 libfabric 定义的结构。 | native/provider 标准头已有 key 映射及授权回归；不把内部容器选择当作线格式要求。 |
| UE11-p0213-001 | §3.4.2.7.1.1，消息排序条件 | 需要 SEND 顺序时，决定目标 buffer 的初始 SEND/TSEND/rendezvous 请求使用 ROD；DS/rendezvous 后续数据可独立使用 RUD。 | provider 普通 SEND 模式映射已按独立谓词修正并检查实际报文；M5 tagged/rendezvous/DS 初始与后续消息关联尚未实现。 |
| UE11-p0213-002 | §3.4.2.7.1.1，混合顺序 | 混合 RMA/messaging 的顺序可由 ROD 保证；未使用 ROD 时用源端 fence 等待前操作完成。 | provider 已支持 FI_FENCE；公开模式用例同时验证 SENDMSG/WRITEMSG/ATOMICMSG 的 flags，以及 NO_MATCH 重试不被后续 fenced 操作越过。 |
| UE11-p0213-003 | §3.4.2.7.1.2，WAR 条件 | 使用 ROD 实现 WAR 时，保留先前 READ 的结果直到 PDS Clear 表明发起端收到；公布相应大小限制。 | READ/WAR 及结果缓存未实现；不能用按请求顺序发送 READ 请求证明结果生命周期正确。 |
| UE11-p0214-001 | §3.4.2.7.1.3，消息内连续性 | SOM 首 PSN 与 offset0；后包 PSN 连续、offset=(N−1)×Payload MTU；最后包 EOM；同 PDC 两条消息不交错。 | native FIFO producer、PDC PSN 及大消息分片已有回归；M5 多消息/重启格式仍需各自测试。 |
| UE11-p0214-002 | §3.4.2.7.1.3，线端顺序 | ROD 按 PSN 顺序发往线端；RUD 可任意顺序。 | 初始 FIFO、GoBackN 顺序和回绕已测试；不同 NACK 延迟、NIC 背压与重传组合仍须持续覆盖。 |
| UE11-p0215-001 | §3.4.2.7.3，READ 响应顺序 | 同 PDC 上 ROD/RODL 的带数据 READ 响应按请求接收顺序生成。 | M5/M8 缺失；异步 SES 必须显式维护顺序，不能依赖当前同步 WRITE 实现的回调顺序。 |
| UE11-p0216-001 | §3.4.2.11，Payload MTU 能力/默认 | 支持 4096；1024/2048/8192 为 SHOULD；规范默认 4096。 | native 可配置并测试 4096/8192；现有入口默认 1024、研究测试还使用非标准小片段，需明确配置策略及后续 Profile 严格模式。 |
| UE11-p0216-002 | §3.4.2.11，分包/路径限制 | 每个非末包恰好 Payload MTU；包适配全路径 Ethernet MTU；IPv4 DF=1；FEP 不再分片。 | codec DF、原生分片及场景 MTU 校验已有覆盖；动态管理路径变化与所有扩展头的容量校验仍需补全。 |
| UE11-p0217-001 | §3.4.2.14，message ID | READ 请求携 ID；其他单包有字段时可用有效 ID 或0；DGRAM=0；同目标 PDC 的在途消息 ID 唯一。 | native ID lease、迟到/复用与 DGRAM0 已有回归；READ 未实现，紧凑无 ID 格式另验。 |
| UE11-p0218-001 | §3.4.3，保留位总规则 | 保留字段发送为零，接收时忽略。 | 复核发现 SES decoder 原先拒绝多处 reserved 值；新 `ses_reserved_fields_test` 覆盖已实现请求/原子/带数据响应的忽略、规范重编码与 CRC，其他格式仍未实现。 |
| UE11-p0218-002 | §3.4.3.1，标准头/完成数据 | AI Base/Full/HPC 的请求支持标准头；多包和完整 key/match 使用该头；completion data 使用标准或 medium 头。 | 当前标准头和 SEND/WRITE CQ data 有回归；扩展 opcode、medium 头及全部字段尚不全。 |
| UE11-p0219-001 | 表 3-9，首部字段 | opcode 六位，前两位 reserved 为零；有效 opcode 按表 3-23。 | encoder 显式字段编码；新增 reserved 接收测试；opcode 支持集仍为子集。 |
| UE11-p0219-002 | 表 3-9，多字段义务 | DC 等到 GO；IE 阻止该包写入并使消息报错；末包 EOM；Job/PID/index/generation 等按位宽解释。 | native IE/错误完成/权限已有测试，完整 DC/所有响应等级和扩展组合仍待完成；不是一个不可拆分的通过项。 |
| UE11-p0220-001 | 表 3-9 续，地址/DS/长度 | buffer base+offset+消息偏移寻址；初始 DS 的 initiator token 唯一、target 半部0；每包都填 request_length，零长度合法。 | native 受检偏移、零长度和重复长度字段已有测试；DS token 与 FI_MR_VIRT_ADDR 未实现，当前不声明 VIRT_ADDR。 |
| UE11-p0221-001 | 表 3-10，非 SOM payload | 十八位 reserved 为零，十四位 payload_length 正确，其余字段继承标准头。 | 显式 codec 和多包 WRITE 有覆盖；新增 reserved 忽略/重编码测试保留有效 payload_length/offset。 |
| UE11-p0222-001 | 表 3-10 续，长度重复 | 非 SOM 也携带完整 request_length 和消息 offset。 | native 分片和 wire 回归覆盖已有操作；READ/重启消息格式另验。 |
| UE11-p0222-002 | §3.4.3.1，RTR 与重启跨页 | target 不分配 token 时置0，可再次 defer；非零 token 对应重启恰好一次且之后不再 defer；重启 SOM=1，offset 0..2^32−2。 | M5 缺失；已阅读下一页续文，资源耗尽重试不计作 DS deferral。需要区分协议重启和网络重传。 |
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
| UE11-p0233-001 | §3.4.3.6，同步完成类型 | completing SYNC_WRITE 设置 hd；SYNC_ATOMIC 长度至多8、hd=0，只用允许的非取回操作/至多8字节类型，排除 READ/MSWAP/CSWAP。 | M5 缺失；按 opcode、datatype、长度、hd 分别验证，不能直接复用任意普通原子组合。 |
| UE11-p0233-002 | §3.4.3.6，同步 scope/count | 目标按源 IP+sync_group 查状态；完成操作携包括自身的总消息数，非完成 write 为0。 | M5 缺失；正文“所有 sync write 为0”的宽泛用语需与表 3-15 completing 分支一起解释，不能让 completing write 丢失计数。 |
| UE11-p0233-003 | 表 3-15，字段编码续文 | group/count 各16位；非 completing count=0，completing count=整组消息数。 | 已阅读下一页续表；M5 缺失，还需零/最大计数与重复完成消息回归。 |
| UE11-p0235-001 | §3.4.3.7，带数据响应选择 | 请求长度大于 Payload MTU 时使用完整带数据响应；optimized request 不用此完整格式。 | codec 能解析/编码部分格式，但 READ 源/目标和响应关联未实现，不能以 codec round-trip 证明语义功能。 |
| UE11-p0237-001 | §3.4.3.8，packed 非 DEFAULT | 一组请求中任意响应不是 DEFAULT 时，PDS ACK 中每个请求都有对应响应。 | M8 缺失；需整组默认/混合错误/含数据响应的组合测试。 |
| UE11-p0238-001 | 表 3-19，local response | reserved 发送0；mm/opcode/version/code/ehl/payload_length 按本地格式解释。 | M8 缺失；不能由标准 SES reserved 接收测试推广到本地头。 |
| UE11-p0239-001 | 表 3-21，small 合法集跨页 | optimized non-matching 单包，NO_OP payload0，其他允许请求不超过一 Payload MTU。 | M5 格式未实现；需结合下一页完整 opcode 列表与响应头要求。 |
| UE11-p0240-001 | 表 3-21 续，格式/opcode 限制 | 分别校验 small/medium/std/local 的合法 opcode、NO_OP0、单包、offset 和长度约束；local ac0 至多16383、ac1 至多4095且仍受 MTU约束；响应格式与请求匹配。 | 标准头与零长 NO_OP 子集有测试，其余紧凑/packed 与完整响应关联缺失；本候选含多组独立义务，不能整体通过。 |
| UE11-p0241-001 | §3.4.4.1，buffer 集/行为 | relative tuple 和 absolute pair 唯一选择 buffer 集；每个 buffer 可配置 use-once/persistent；direct 按 Job。 | native posted receive 与 persistent MR 部分覆盖；RMA use-once、tagged 与直接本地地址缺失。 |
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
| UE11-p0244-001 | §3.4.4.3，DEFAULT 与保证传递 | DEFAULT 前完成处理；无法用 DEFAULT 表达的结果保证传递，并结合后述首错例外。 | PDS 区分 delivery/semantic/Clear；普通消息已修正重复 gtd，实际 8 包场景检查单一保证归属；容量耗尽的无记录拒绝路径仍待完善。 |
| UE11-p0244-002 | Informative Text | 重复说明每条消息需要响应，无新增独立规范义务。 | 归入解释材料，不重复计作 MUST。 |
| UE11-p0244-003 | §3.4.4.3，多响应 | 后续响应保持首响应 opcode/code 或为错误；首个错误保证传递，后续错误不得保证传递；每包至多一个语义响应。 | `reply_error` 独立选择显式错误和保证属性；RUD/ROD、丢失/重放及遇到顺序有针对性覆盖，容量耗尽 fallback 尚未完成。 |
| UE11-p0245-001 | §3.4.4.3，提前 ACK | 未处理包提前 ACK 使用 NO_RESPONSE；DS 首包必须带实际语义响应。 | native RUD 缺口/DS-as-SEND 有回归；真正 DS/RTR M5 缺失。 |
| UE11-p0245-002 | §3.4.4.3，DC | DC 等到整个消息 GO；“最后收到”不等同于带 EOM 的包。 | provider 各完成等级保守选择 GO，原生乱序缺口有回归；完整操作集尚未完成。 |
| UE11-p0245-003 | §3.4.4.3，响应 ID | 回显 request message ID 或 read_request_message_id；请求无 ID 时响应 ID 为0。 | 标准请求路径回显已有覆盖；READ/紧凑格式缺失。 |
| UE11-p0245-004 | §3.4.4.3，响应 Job | 请求有 Job 时响应回显，某些 PDS 控制查询例外。 | 当前 SES response 构造回显，管理/TSS 扩展仍待验收。 |
| UE11-p0245-005 | §3.4.4.3，数据偏移 | SOM 响应 offset0，其余回显请求 offset。 | 带数据 codec 不能代替 READ/fetch 实际语义路径，M5 缺失。 |
| UE11-p0245-006 | §3.4.4.3，显式响应 | 非 DEFAULT 无数据用 RESPONSE，有数据用 RESPONSE_W_DATA，并遵守保证传递规则及先述重复错误例外。 | 当前无数据显式响应有覆盖；数据响应生命周期与完整保证矩阵未完成。 |
| UE11-p0245-007 | §3.4.4.3，首错优先 | 成功 RC_OK；首错按 SES 实际遇到顺序，非 PSN 顺序。 | native sticky error 与乱序错误测试已有覆盖；保证归属也按实际遇到次序检查，非 SOM 可先持有保证。 |
| UE11-p0246-001 | §3.4.4.3，modified_length | 普通响应为整个接受长度；DS defer 为0，RTR 指定重发量。 | 普通接受/错误长度已实现；完整 DS/RTR 缺失。 |
| UE11-p0246-002 | §3.4.4.3，响应 payload | payload_length 表示本包实际返回字节数。 | READ/fetch 缺失；codec round-trip 不构成完整操作验收。 |
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
| UE11-p0247-004 | §3.4.4.6，DS 初始传输 | OK/length0 后仍发至少一个 EOM 包；OK/full length 发送全部 payload；初始窗口上限为 SHOULD。 | 完整 DS 发起端未实现，目标 DS-as-SEND 子集不能代替。 |
| UE11-p0248-001 | §3.4.4.6，DS header 耗尽 | DS 必须实现 header 耗尽时 backoff/retry，buffered header 为 SHOULD。 | M5 缺失，需与已捕获 header 等待 RTR 的情况区分。 |
| UE11-p0248-002 | §3.4.4.6，restart token | 初始 target token0；非零 target token 保证重启可匹配；defer 后等待 RTR，只重发请求部分；backoff 不产生 RTR。 | M5 缺失；32+32 位 token 生命周期、陈旧/重复 RTR 和再次 defer 均待测。 |
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
| UE11-p0274-001 | §3.4.6.4.2，目标不可恢复错误 | 消息首错传播并保证传递，不影响 PDC；结合重复错误的单一保证规则。 | 普通 tracked message 已修正首错 gtd，后续消息可继续；无记录容量耗尽拒绝路径待完善。 |
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
| UE11-p0303-001 | §3.5.5，参数范围/状态 | 按指定单位及所需范围支持配置，允许更细粒度；表3-36状态也须支持。 | 纳秒RTO/NACK、0～15retry、MPR部分覆盖；表3-35/36需逐字段验收，参考默认值不是完整符合性证据。 |
| UE11-p0305-001 | 表3-35续，MPR/SYN及注释 | MPR0 override 0～127；丢SYN后关闭遵守安全时间；启用加密时设0为SHOULD；native IP协议号可配置。 | MPR override/MAC-time SYN safety已有回归；Syn范围表格与正文位宽有冲突须记录。实验253/254不得当作生产默认分配号，当前研究默认仍为显式符合性缺口。 |

复核进度为上述 280 个候选的分类与义务拆分；其余 449 个候选、表格/算法的额外
义务和每项最终证据仍待完成。此账本与 `requirements.json` 的 51 个开发任务是不同
粒度的记录，两个数量都不能解释为完整 MUST 总数。
