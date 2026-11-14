# 同步状态层与接入历史

当前行为与API见 [SYNCHRONIZED-TRANSACTIONS.md](SYNCHRONIZED-TRANSACTIONS.md)。
本页保留从状态层到原生事务的设计修正，便于研究者理解不能由局部测试推出的结论。

## 状态层基础：28d138e

标准扩展头来自a4655a8，整合基线为b76e340。SynchronizationIdPool使用FEP游标，
成功确认后的ID可本地回收；未知结果不重用。SynchronizationGroups以
`{initiator FEP, wire group}` 为key，核对Job，并用本地owner/member序号隔离旧组。
`processed_messages` 包含失败成员；第一completer不可被后来的completer替换。

原型最初错误地把小于admitted count的completer变为Ready；负例
`/tmp/softue-sync-state-tests.log` 揭示该问题，随后加入invalid-count屏障。
已经计数但仍在等待执行的completer若遇MSG_ERROR或PDC失败，也必须能阻止动作，
同时保持processed count不变；这在原生接入时另加回归。

PDS准入增加typed NoSynchronizationState。新建PDC和既有PDC分别按标准发0x1B，
普通消息预算仍发0x1A。固定扩展头必须复制到preadmission元数据中；payload不复制。
脚本SES的恢复测试只证明准入、PSN不前进及恢复后交付一次，不能证明同步内存操作。

冻结28d138e在ASan/UBSan与泄漏检查下通过状态层、同步准入、普通准入、同步线头4/4，
0.90s，日志 `/tmp/softue-sync-state-asan-cmake-tests.log`。

## 最终请求不能借NO_RESPONSE挂起

早期接入原型在delivery-complete atomic的最终请求上返回NO_RESPONSE，随后试图复用
同一句柄补响应。分片回归暴露提前DEFAULT和Incoming退休：
`/tmp/softue-sync-native-tests4.log`、`/tmp/softue-sync-native-tests5.log`。
§3.4.4.3要求最终收到包满足完成语义，§3.5.13又允许NO_RESPONSE被提升为DEFAULT。
当前实现保留真实PDS句柄直至动作；源端通过NOOP建立新映射，并把completing atomic的
首次发送排在其他成员确认之后，避免有限窗口被屏障阻塞。

## 逻辑错误、线消息尾部和Clear是三件事

generation恢复前撤销临时组成员，避免新MID重复计数或第二次绑定completer。
旧Incoming仍需看到EOM。最初扩展检查发生在EOM记录之前，已撤销的旧成员使其EOM
永远不能记录，造成两条旧Incoming不退休；故障回归
`/tmp/softue-sync-native-tests9.log` 后改为先捕获终止元数据，再返回粘滞的首个错误。

未准入的generation错误曾产生目标RMA header-data错误CQ，最终重试又产生成功CQ；
`/tmp/softue-sync-native-tests8.log` 记录该失败。当前恢复前的失败不报告目标CQ。

源收到全部ACK不等于目标已应用Clear。完成组尚未退休时，合法新组曾被误判额外成员；
同一份tests8日志包含丢Clear重用负例。当前等待退休时临时发同步资源NACK，由原PDS
重试；尚未对该区间内非法提前追加完成全部规范验收。

早期关闭fixture的tests12..15误把initiator的Close_cmd当成responder的Close_req来丢弃，
实际走的是正常关闭；旧PDC结束后恢复成功，或在持续disabled时等到总deadline。
当前fixture丢弃真实Close_cmd，检查错误CQ先于组deadline、恰好一次且没有新的重试MID，
以验证generation退避中的活跃逻辑事务被致命关闭停止。Source批量清理期间也暂停
重试调度，防止回调给尚待取消的成员建立新attempt。

## 固定参考实现的边界

5b4e049的uet_get_sync_grp_src_fep维护计数，uet_rx_cq_post完成时删除组，
uet_rx_sync_grp_age清理空闲组。其任意成员错误会污染completing action，区别于1.1
Table3-31 Case1；其延迟atomic只支持64位SUM并保存主机指针。原生实现保留注册身份。

互测首版失败日志 `/tmp/softue-sync-native-reference-tests.log`：参考把最终count填进
排队的非completing WRITE，而Table3-15要求这些WRITE为0。
第二版 `/tmp/softue-sync-native-reference-tests2.log`：参考请求CPU coherent atomic，
目标按§3.4.9.2返回0x0f。互测随后显式核对该预期错误及未修改的目标数据，并将正向
三成员组、反向单成员completing WRITE列为实际共有路径。参考shared library未修改。
