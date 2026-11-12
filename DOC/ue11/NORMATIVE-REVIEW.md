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
| UE11-p0094-002 | §2.2.4.3.3，regattr 零长度授权键 | auth_key_size=0 的 MR 授权 any JobID。 | 发现具体差距：当前 provider `register_memory` 把 MR 注册为固定 JobID=1；native 已有显式 `allow_any_job`，仍须正确接入。 |
| UE11-p0094-003 | §2.2.4.3.3，regattr 三字节授权键 | auth_key_size=3 时，MR 关联 endpoint auth_key 中的 JobID。 | 当前拒绝非零 auth_key_size；需要完成分配/验证及对象关联。 |
| UE11-p0094-004 | §2.2.4.3.3，AV 授权键条件项 | FI_AV_AUTH_KEY 时，attr.auth_key 指向 fi_mr_auth_key，包含 AV 与其中已插入的地址；MR 关联该地址的授权键所代表的 JobID。 | 至少拆成结构解释、AV 归属/有效地址校验和 MR 授权关联三项；均待实现。 |
| UE11-p0094-005 | §2.2.4.3.3，其他注册方法 | 非上述 regattr 特定授权方法的 MR 注册为 any JobID。 | 与 p0094-002 共享当前固定 JobID=1 的差距；不能因当前发送端也固定为 1 而认为已满足。 |
| UE11-p0094-006 | §2.2.4.3.3，特定 JobID 的 MR | MR 一旦关联特定 JobID，只允许相同 SES JobID 访问。 | native exact/any MR 检查有回归；provider 所有注册方法的授权联合矩阵仍缺失。 |
| UE11-p0094-007 | §2.2.4.4，direct 发送方法 | SES JobID 从 endpoint auth_key 获取。 | 未实现；当前固定 1 的实验 provider 不满足该映射。 |
| UE11-p0094-008 | §2.2.4.4，AV 发送方法 | 根据操作 dest_addr 所关联的 AV 授权键选择 SES JobID。 | 未实现。需验证同一 endpoint 向不同 JobID 地址发送及非法/撤销键。 |
| UE11-p0098-001 | 表 2-10，UET 地址字段 | 分别校验 flags、capabilities 的各组保留位；根据有效位解释地址、PID、资源范围等字段。 | FI_ADDR_UET 编解码与能力映射未实现；本段仅为跨页表格片段，完整表 2-10 仍须逐字段复核。 |
| UE11-p0100-001 | 表 2-11，fi_getinfo 条件项 | 非空 node 指向 UET 地址；其 FI_SOURCE 过滤建议另建 SHOULD 项。 | 当前使用 socket 地址/端口的实验入口，不能通过；service 描述在下一页继续。 |
| UE11-p0101-001 | 表 2-11，多个 API 义务 | 配置文件中的同名 service 优先；按指定 service 过滤；支持 FI_SOURCE；非 FI_ADDR_UET 不返回 info；返回规定源地址字段并保留 service 识别；不返回目的地址。 | 至少分为配置优先、过滤、flag、地址格式、源地址字段与目的地址六组，不能整体算一项。上游 libfabric 2.0 与固定参考头缺少 FI_ADDR_UET 定义；需显式兼容方案和独立公开 API 验收。 |
| UE11-p0101-002 | §2.2.5.2.2，端点类型条件项 | scalable endpoint 的每个 RX context 获得独立 resource index；普通 endpoint 获得一个 index。 | 本段跨页；scalable endpoint 未实现。当前 native/provider 的固定目标索引不等于完整服务索引分配。 |
| UE11-p0103-001 | §2.2.5.3.2，基础要求 | provider 支持 EQ，且每个 endpoint 至少支持绑定一个。 | 当前 `fabric_ops.eq_open` 明确为 unsupported；需要 EQ 对象、绑定、生命周期及公开 API 测试。 |
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
| UE11-p0113-001 | 表 2-22，多个 send/inject 义务 | fi_sendmsg 支持 CQ data、completion、inject、三种完成级别及 fence；fi_inject 成功不生成 CQ，可靠端点交付失败必须生成错误 CQ。 | CQ data/部分完成语义已实现；inject、inject-complete、RDM transmit-complete 与 fence 尚缺。需拆成功抑制、错误报告和每个 flag，不能用 sendmsg 基础通过代替。 |

复核进度为上述 60 个候选的分类与义务拆分；其余 669 个候选、表格/算法的额外
义务和每项最终证据仍待完成。此账本与 `requirements.json` 的 51 个开发任务是不同
粒度的记录，两个数量都不能解释为完整 MUST 总数。
