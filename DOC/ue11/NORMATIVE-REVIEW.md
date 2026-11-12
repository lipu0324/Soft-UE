# 规范候选的人工复核记录

这是 M0 的逐段复核账本，不是完整要求清单。自动提取的 729 条记录是含规范关键词的
候选段落；一段可能有多个义务，也可能只定义术语。表格、图和算法还可能包含未被
提取的要求。下列分类没有把未实现的条件项当作已通过，也不增加 Profile 声明。

来源固定为 UE 1.1；PDF SHA-256 见 `requirements.json`。候选文本来自
`build/ue11-normative-candidates.json`，对应提取文本 SHA-256 为
`1ba84e30bffb069df9ad8b98ea28cab1ec2a474acf3358359700824a69467a4f`。
这里只记录义务的转述与覆盖缺口，不复制整段规范。

## 首批 20 个候选

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

复核进度为上述 20 个候选的分类与义务拆分；其余 709 个候选、表格/算法的额外
义务和每项最终证据仍待完成。此账本与 `requirements.json` 的 51 个开发任务是不同
粒度的记录，两个数量都不能解释为完整 MUST 总数。
