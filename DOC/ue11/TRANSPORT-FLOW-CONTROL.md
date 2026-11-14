# TFC 源信用计算与接入边界

`CMS/TfcCredit.hpp`、目的预算、信用线格式和 PDS 发送准入桥已有分范围验证。
`TfcEngine` 已接入真实 PDS 信用反馈、缓冲池、定时器和 CCC 生命周期，并通过
固定源的完整176项整合回归。Host 仍是显式实验配置，限 TC0、共用 Payload MTU；
没有 Endpoint 宣告 TFC/Profile 支持，正式规范歧义与其他配置仍需复核。

## 显式的单位

`TfcSourceCredit` 的余额以字节表示。线端 `pds.credit` 是24位累计计数，最低位代表
256字节；信用计数器与 NSCC 的接收字节计数器分别持有状态，只共用24位序列解码。
重复、重排和回绕按已有的前半序列空间规则处理。半空间及更远的跳变不能仅凭此
字段区分旧值，故不增加信用；后续目的分配/在途限制仍须与这一界限一致。

每个新包的信用消耗由
`ceil((payload_bytes + packet_overhead_bytes) / destination_cell_bytes) * destination_cell_bytes`
计算。这里的 payload 是 UET 数据 payload，不是 NSCC 使用的完整 nominal packet
字节数。单元直接覆盖 §3.6.15.1 的4096+256、512字节 cell →4608字节例子，
以及9216字节单包 cell。8192字节 payload 加256字节 overhead 配8192字节 cell
会占用两个 cell，即16384字节。

只要余额大于0，源就能发送一个 MTU-sized 新包。目的必须预留这种潜在超出余额的
容量。消耗后余额可为负，后续新包暂停；使用有符号数可避免欠额回绕成巨量信用。
原 PDS 确定的重传不要求额外信用、也不再次扣除。不能从一个未认证的远端标志
直接取得这种重传权限。

目的 cell 支持256～9216字节、以256递增；overhead 支持0～256、默认256。
初始信用不得小于 overhead。overhead=0时显式配置初始0是允许值，但不能启动新包；
规范建议使用更大的初始值。配置由构造时固定，不能修改活动 PDC 的 cell/overhead。
标准 Payload MTU 为1024/2048/4096/8192，本仿真也保留更小值用于边界实验。

## 已确认的规范单位矛盾

固定规范 PDF 的实际第505页中，`TFC.OnCreditUpdate` 使用 `>> 8`。
这与以下定义冲突：

- §3.6.10.4 明确传入 Credit 的单位是256字节。
- §3.6.15 同样规定24位 `pds.credit` 的一个单位代表256字节。
- §3.6.14.4 的 `RCCC.OnCreditUpdate` 使用 `<< 8`，余额以字节保存。
- §3.6.15.1 的 `credit_used` 以字节计算并从同一余额扣除。

当前数值模型按明确的字段单位将每个新增 wire unit 解码为256字节。没有逐字采用
会把小额合法授权变成0字节的右移。这是有记录的实现解释，仍保留正式规范复核项。
原页已渲染核对：`/tmp/softue-tfc-spec-page505.png`；规范 PDF SHA256 见固定清单。
同页后续例子有“9126-byte cell”的拼写，配置范围和计算结果均为9216，模型使用9216。

## 接入下一步

需要将新包信用预约/实际发送、未发包取消、免费重传和 NSCC 准入组合，避免 NIC
背压时重复预约或重复扣费。目的分配需保证已授权 MTU/cell 的存储，处理原 PDS
重复和信用返还。信用 CP/ACK 使用24位累计值，TFC 的 `ooo_count=0xffff` 必须
忽略；多 PDC 共享 CCC、最后 PDC QUIESCE 后禁止新绑定，以及关闭时回收预算，
都需要真实 SES/PDS/CMS 场景。信用定时器必须使用注入时钟和当前 RTO。

`tfc_credit_test` 检查规范例子、576种 cell/MTU/overhead 组合、正数准入/负余额、
零成本 NO_OP、免费重传、24位重复/重排/回绕，以及溢出拒绝后的累计计数原子更新。
固定源版本 `64c796abaf156ad1dfbd73cc5b218843eb2bfbe8` 的该项 CTest 已通过：
普通 Debug 构建0.01秒，ASan/UBSan/leak 构建0.03秒。日志为
`/tmp/softue-tfc-credit-{normal,asan}-tests.log`。仅验证数值单元，不扩大为接入证明。

## 信用线格式接入

编解码器新增 RUD_CC_REQ / ROD_CC_REQ 的4字节 `req_cc_state`，其中 CCC_ID 为8位、
累计 credit target 为24位。类型13/14仍保留独立身份；尚未启用 TFC 的 PDS 仍拒绝
这些请求，不会把它们悄悄转换成普通 RUD/ROD。信用控制包已有32位 payload 外壳，
Credit 使用高24位与低8位保留，Credit Request 使用 CCC_ID 与24位 target。

ACK_CC 的 `CC_CREDIT=1` 使用独立 `credit_units` 字段。实际 PDF 第464页图3-129
规定信用位于8字节 CC_STATE 的最前24位，随后24位保留，再跟16位 ooo_count；
它的位置与 NSCC 的 `received_byte_units` 不同。NSCC 的 service_time、窗口罚值
和字节遥测不能被写入或读作信用。NIC 的 service_time stamping 也不改信用 ACK。
`credit_header_test` 使用手写黄金字节验证40个格式/封装组合，并覆盖截断、保留位
和24位范围。固定源版本 `cf4cdacd60c1d08eceae58f553be8087d0047057` 的9项
信用线格式、NSCC、trimming 和 PDS 非法/保留字段回归全部通过：普通构建0.42秒，
ASan/UBSan/leak 构建4.32秒。日志为 `/tmp/softue-tfc-wire-{normal,asan}-tests.log`。
不代表真实信用发送/接收已经启用。

PDS 发送准入桥新增 `can_send_attempt` / `transmitted_attempt`，显式传入本地发送
路径是否拥有已缓存 PSN 的重传。新包和重传在入网络队列时只记账一次；端口
`WouldBlock` 的重试仍使用该队列项，不能再次扣费。旧 NSCC 策略通过默认适配继续
对每次数据发送记账，收到的 wire 标志不会控制本地免费的重传权限。
`credit_admission_test` 是8个原 PDS 事务的隔离验证：RUD/ROD、首包丢失和三次 NIC
背压组合。目的没有 TFC，信用由测试显式注入，以验证桥接边界；它不是信用线端
互通或完整 TFC 实现。固定源版本 `6455adb4388fc9ebb9e152d4fa68f6aa949886f1`
的4项桥接/NSCC/trimming 回归通过：普通构建0.38秒，ASan/UBSan/leak 构建4.29秒。
日志为 `/tmp/softue-tfc-admission-{normal,asan}-tests.log`；均为虚拟时间场景。

## 目的缓冲计算单元

`TfcDestinationCredit` 管理一个 CCC 的独占 transport buffer 预算，尚未接入 PDS。
创建者必须先从主机总池预留这块容量；单元不能凭空承诺其他 CCC 的缓冲。
初始信用之外，始终保留一个最大 packet cell 成本，覆盖正信用允许的 MTU 超出。
例如4096字节 payload、512字节 cell、256字节 overhead 的最大成本为4608字节；
初始256字节时，该 CCC 的最低保留容量为4864字节。

新包取得不可复用的本地 buffer lease，交给下一层后才能释放。累计请求、已授予信用、
正负承诺余额和实际占用分别记账；重排释放和重复释放不会重复返还。目的 eager grant
策略只满足已观察到的累计需求，且不借出仍占用的 storage 或 MTU 保留量。信用以
256字节粒度分配；CCC 总预留低于24位信用计数的半空间。这个上限是当前仿真的
资源策略，不是规范规定的最大配置。调用者仍负责原 PDS 的去重、CCC 身份与生命周期。
`tfc_destination_credit_test` 包含独立数值例子、缓冲占满/延迟释放、target 回绕、
越界不改状态，以及576种 MTU/cell/overhead 几何的双向计数实验。固定源版本 `49cf6545be20f09d3aaecd1d1833ceada072932b`
的源/目的两个数值单元 CTest 通过：普通构建0.08秒，ASan/UBSan/leak 构建0.25秒。
日志为 `/tmp/softue-tfc-destination-{normal,asan}-tests.log`。

## 原 PDS 接入草稿与验证边界

`PdsHost::enable_tfc` 在创建连接前启用；可先启用 NSCC，再将 TFC 与其组合。
配置区分 outgoing（对端目的缓冲几何）和 incoming（本机目的缓冲几何），允许
双向 cell/overhead 不同。Host 当前共用一个 Payload MTU，实验适配器仅支持数据
TC 0，其他 TC 的提交显式拒绝。RUDI/UUD 继续走不受 UET CCC 控制的路径。

原 PDS 队列登记累计需求，原 TX cache 提供可信重传身份，原 receive admission
在 SES 资源预约前检查目的 CCC 预算。成功接受后取得 transport buffer lease；
Host 完成有效 SES upcall 后释放这块 transport buffer。SES 可能保留的 unexpected
消息存储属于另一个资源域。未成功进入 PDS 的 PSN 不消耗新 buffer lease。

源 RUD 可配置共享 CCC，ROD 默认独立；8位 CCC_ID 在一个 peer 的活动源上下文中
唯一。最后成员进入 QUIESCE/关闭流程后，旧 CCC 从新绑定查询中移除，但保留旧成员
的重传与关闭状态。目的按 peer+CCC_ID 共享独占缓冲预算，最后成员 Close 后退回
主机总池；无可用预算时拒绝，不向另一个 CCC 借出已经承诺的空间。

未组合 NSCC 时，ACK_CC/CC_CREDIT 携带累计授权；组合 NSCC 时保留 NSCC ACK，
用 Credit CP 携带 TFC 信用。重复/重排反馈不重复授权。Credit/Credit Request CP
使用原 PDS 已建立的连接发送，PSN、AR、SYN 均为0，不另建 PDC 或数据重传栈。

§3.6.15.4（PDF 第508页）描述“有未发送工作、没有信用”时启动当前 RTO 信用定时器，
随后伪代码却以 `ccc.state != READY` 返回；§3.6.8 将这种受阻状态定义为 ACTIVE。
其注释还要求排除无工作、已有信用、已有数据包 RTO 的情形。当前实验适配器按这些
明确恢复条件执行：有信用受阻的新包、没有未确认数据、且存在仍可用的已建立 PDC
时计时；到期重发累计 target。规范 READY 条件的矛盾仍是正式符合性复核项。

`tfc_context_test` 检查共享/最后 QUIESCE、新 CCC_ID、256 ID 耗尽与恢复、目的共享池
和关闭回收。`tfc_integration_test` 的48个原 SES/PDS 事务覆盖 STD/MEDIUM、RUD/ROD、
NSCC 开关、IPv4 UDP/IPv6 native、首包丢失、只有信用字段丢失而数据已经确认的恢复。
初始接入版本 `d670a2e71f9ff28a52501438c8e13b2ccb91588d` 的两个构建都在编译阶段
发现公共 PDC 读取了发起端专有 close_req，未运行新测试。修正后使用两类 PDC 的
关闭状态查询，并在 QUIESCE/关闭转换时立即通知 CMS。新增原生双 Job 事务，在旧
PDC 仍受65毫秒 SYN 关闭保护时，检查新 RUD PDC 取得不同 CCC_ID。
`03a2b82fcc48e5dba15fa0ea50239bd53046e90d` 已完成两个构建。首次两个普通
CTest 中，context 测试通过，但首个集成事务超时；诊断轨迹显示只有256字节授权、
没有 SES handoff 后的缓冲返还。原因是目标处理 SYN 前的调度查询缓存了旧/未建立的
CCC 身份。现在等待目标 establishContext 后再查询 CCC；失败日志保留于
`/tmp/softue-tfc-runtime-03a-initial-tests.log` 与
`/tmp/softue-tfc-integration-03a-debug-tests.log`。故障夹具也改为在源发出 Credit Request
之前屏蔽所有信用载体，保留普通 PDS/SES 确认，避免另一个 CP 掩盖定时器路径。
`ebff7c802966dd8bb60ec0ff55d4727acea6fb02` 的普通11项范围回归为10通过、
集成夹具1失败：STD 初始场景已越过原停顿，但 MEDIUM 夹具把512字节请求放在
Payload MTU=64 的单包格式上，原生 API 正确返回 Unsupported。独立诊断日志为
`/tmp/softue-tfc-integration-ebf-debug-tests.log`。夹具现改成8个合法64字节 MEDIUM
WRITE（STD 保持一个8分片消息），共48场景、216个源操作，另有双 Job QUIESCE 回归。
固定源版本 `bc9865067941eedd674e8b110f8db842af740237` 的11项范围回归已通过：
普通构建0.78秒，ASan/UBSan/leak 构建7.75秒；日志为
`/tmp/softue-tfc-runtime-medium-{normal,asan}-tests.log`。这是范围证明，不是完整174项回归。

新增 `tfc_bidirectional_test` 的96个场景覆盖 STD/SMALL/MEDIUM、RUD/ROD、NSCC开关、
ACK-data READ 与反向数据 READ、fetch-add/CAS，以及首次结果丢失后修改远端内存。
短 READ 按规范允许重新读取新内容；反向 PDS 数据及原子结果必须保持已缓存内容。
每个操作后排队一个 NO_OP，以验证双向数据与新消息信用共同进展。固定源版本
`444e206a004c745e24ab8f46ae58b570529465e0` 的该项 CTest 通过：普通构建0.17秒、
ASan/UBSan/leak 构建1.94秒；日志为 `/tmp/softue-tfc-bidirectional-{normal,asan}-tests.log`。

`tfc_receive_pressure_test` 新增4个三 Host 场景：RUD/ROD、NSCC开关，目的池只够
一个 CCC；第二个发送方必须收到 NO_CCC 且不改变内存，第一 CCC 完成真实65毫秒
SYN保护的 Close 后，第二发送方通过原 PDS 重试成功，预算始终不超过预留上限。
固定源版本 `0a72faef5bad7bc264043727aed8e92041bf72bf` 的该项 CTest 已通过：
普通构建0.02秒、ASan/UBSan/leak 构建0.12秒；日志为
`/tmp/softue-tfc-pressure-{normal,asan}-tests.log`。随后补上 RUD 独立 CCC 配置回归，
并在 group key 中显式保留 RUD/ROD 模式。新的整合版本尚待范围与全量编译验证。
完整资源拒绝故障组合、
其他 TC 和正式规范歧义复核仍需继续，不能宣告完整 TFC 或 Profile。


## 完整整合回归中的 CQ 夹具问题

固定源 `6f4115d818d65eb75213ba1364df5a359ab76fde` 完成全部176项构建，普通回归
176/176通过（132.50秒）。ASan/UBSan/leak 为175/176通过（716.59秒），失败项为
`libfabric_rendezvous_recovery_processes`。完整现场保留于
`build/libfabric-process-failure-3xvgsu3n`，全量日志为
`/tmp/softue-tfc-full-{normal,asan}-tests.log`。同源单项重跑通过（9.74秒），不能用此
覆盖全量失败。首次 CHECK 退出后产生的清理泄漏报告不应掩盖先发生的 CQ 断言。

夹具把第一个接收 CQ 当作 context11的大消息、第二个当作 context12的小消息。
但 provider 显式报告 `rx_attr.comp_order=FI_ORDER_NONE`；libfabric 2.0 的
`fi_endpoint(3)` 明确区分 `msg_order` 与 `comp_order`。小 eager 消息可先完成，
而早先匹配的 rendezvous READ 仍在进行。修正后以真实 op_context 校验对应长度、
每个 context 恰好一次，并保留两个缓冲的完整字节检查；不再断言未提供的 CQ 顺序。
这只修改公共 API 测试夹具，没有更改 TFC 或 provider 协议逻辑。

修正后固定源 `afaca88f68928f7ec105d9d022fe136c0f043fa9` 的四项进程恢复范围回归
均通过：普通12.36秒、ASan/UBSan/leak 18.44秒。随后停止所有编译/链接，源保持
不变，按普通→Sanitizer、各 `ctest -j1` 顺序完成**完整176/176 + 176/176**：
普通130.02秒，ASan/UBSan/leak 633.60秒。provider 与固定参考对照均启用。
全量日志为 `/tmp/softue-tfc-afaca-full-{normal,asan}-tests.log`，报告为
`/tmp/softue-tfc-afaca-full-report.json`。这次是真正的固定源完整回归，保留了较早6f
版本的175/176失败报告及现场。

此证据包含48个 TFC wire/恢复场景、真实 QUIESCE、96个双向 READ/原子场景和
4个三 Host 目的池拒绝/回收场景，不包含独立分支的多数据 TC 字段和 producer 调度
增量。后者即使13项范围回归通过，也不能合并称为本次178项完整通过。所有四种
Profile 继续保持未完成；TFC 单位与 READY 伪代码歧义、其余 TC/配置验收仍开放。
