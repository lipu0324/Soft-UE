# 明文 PDC 的起始 PSN

PDC（包传递上下文）拥有自己的 PSN（包序号）空间。UE 1.1 §3.5.8.2 要求明文
连接的起点随机或伪随机，并与该本地 PDCID 上次使用的最后 PSN 至少相隔2¹⁶。
记录属于本地 PDCID，不能因为换了对端、Job 或模式而丢弃。

`InitialSequenceAllocator` 使用注入种子的 SplitMix64 生成可重放的伪随机字。
首次分配使用完整32位结果；复用时，从旧末序号向前选择 `[2¹⁶, 2³¹−1]` 的步长。
无符号加减自然处理32位回绕，半序号空间的限制保留明确的串行先后关系。
这项步长范围是模拟器的具体选择，规范要求的最小间隔为2¹⁶。

原 `IPDCProcessManager` 在创建上下文时预留起点，在关闭时保存
`tx_cur_psn−1`：`tx_cur_psn` 表示下一个未分配序号，因此其前一项保守地覆盖已经
分配但可能尚未发出的包。预留后即使建连失败，也不立即复用同一起点。
这份有限记录随 PDC 对象销毁而保留，每个本地 ID 最多一项。

`PdsHost::configure_initial_sequence_seed` 在建连前设置场景种子；主机 ID 派生
独立序列流。场景运行器使用 YAML 已有的 `seed`，不读取墙钟或 `random_device`。
关闭全部连接后允许重新设种子，但继续保留旧末 PSN，因此重设种子不会取消间隔
约束。低层 `I_PDC::initPDC(id, initial_psn)` 仍允许显式起点，用于黄金报文和回绕
单元测试；它不替代管理器的标准分配策略。SUP1/SUE1 保持独立的 legacy 策略。

目标端按 §3.5.8.2 建连步骤3.d.i处理明文起点，不把已退休连接的 PSN 当作新连接的
anti-replay floor。同一源 PDCID 先访问另一个对端再返回时，新起点可能在旧对端
记录的半序号空间之外，仍是合法新连接。活动连接的源FA/SPDCID、SYN起点一致性、
接收窗口和重复包检查继续执行；加密起点验证由后述TSS机制承担。

## 已建立连接的 SYN 范围

同一活动 PDC 的 SYN 包仍需恢复出相同起点，并满足
`PSN − Start_PSN <= MP_RANGE`（§3.5.8.2）。该范围描述初始序号区间，不能用
“距当前 Expected_PSN 不远”代替。超过上界返回 `UET_INVALID_SYN`，不进入 SES；
上界本身合法，ROD 若存在缺口仍按普通有序规则返回 `UET_ROD_OOO`。

`chkRxError` 与 numbered NOOP/Negotiation 的控制处理均先检查此条件，再处理
重复、乱序和普通接收窗口。无符号差值处理32位回绕。`syn_range_test` 用真实
PdsHost/Fabric 报文验证数据/控制、RUD/ROD、相等/超出边界以及回绕，检查错误码
和未交付给 SES。修正前，RUD 超界场景会静默丢包，测试因收不到规定 NACK 失败。

`initial_sequence_test` 检查2万次复用、回绕、间隔、种子重放和非法 ID；实际
PdsHost/Fabric 路径还检查同 ID 跨对端复用、重新设种子、NOOP 建连与 Close。
恢复、控制建连、目标 Close、Probe、迟到包及 SACK 测试从捕获报文取得起点，
不再将固定1000当作标准协议要求。

这是明文起点选择；它不是密码随机数生成器，也没有实现 TSS 的安全起点握手。
加密模式的 RANDOM_1RTT_START、EXPECTED_0RTT_START、SDI anti-replay floor 仍需
在 M6 独立实现和验收。
