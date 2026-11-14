# TFC 源信用计算与接入边界

`CMS/TfcCredit.hpp` 目前只实现 §3.6.15 的源端数值规则，尚未接入 PDS 发送准入、
目的缓冲分配、Credit CP/ACK、信用请求定时器或 CCC 生命周期。没有 Endpoint 宣告
TFC 支持；不能把这个单元当作完整 TFC 或 M5 的验收。

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
和24位范围。此线格式增量尚待编译验证；不代表真实信用发送/接收已经启用。
