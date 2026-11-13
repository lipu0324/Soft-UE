# 不延期目标的 deferrable SEND 兼容路径

UE 1.1 §3.4.4.6.1 允许未实现延期的目标，将 UET_DEFERRABLE_SEND/0x08 和
UET_DEFERRABLE_TSEND/0x0b 分别作为 SEND/0x05 和 TAGGED_SEND/0x09 接收。
这条兼容路径只能返回 RC_OK/全长，或 RC_NO_MATCH/0；它不能捕获 unexpected
头后承诺日后发送 RTR。

`nondeferring_send_opcode` 统一消息状态预留和接收解释的 opcode，防止预留为
0x0b、匹配后又与0x09比较而误报操作错误。解释只修改本地头副本，原线格式仍用于
PDS 响应与故障恢复。重启 token 占用 buffer_offset 的位，但在这条接收路径中必须
忽略；实际目标地址来自匹配到的本地接收投递，不能把 token 当作偏移或主机地址。

正常匹配仍使用独立 Tagged 资源空间、完整 tag 与 Job 内 rank、共同 FIFO 和精确
注册身份。无接收项时，即使是 ROD 也返回 NO_MATCH/0，不进入普通 ROD 的 unexpected
payload 缓冲。RUD 的 EOM 若先于空洞到达，当前包仍返回普通默认/全长接受语义，
不能把“尚未放完的消息”错误表示成 RC_OK/0 的延期请求；源端仍需完成所有包。

原生能力 `deferrable_send_as_send` 和 `deferrable_tagged_send_as_send` 专指目标
兼容。它们不表示源端已实现停止发送、唯一重启 token、延期消息、RTR 或部分重启。
这些完整事务功能仍需后续实现与验收，Profile 标志保持 false。

`send_header_data_test` 验证未标记 SEND 的兼容行为。`tagged_message_test` 另用独立
线端适配器将正常 tagged 请求改为0x0b、写入全1 token，验证 RUD/ROD、NSCC、
全长接受、NO_MATCH/0、无 unexpected 缓冲、ACK 丢失/重复、EOM先到和 tag 篡改。
适配器不提供匹配、确认或恢复服务，所有状态仍由原 SES/PDS 执行。实际结果以
生成报告为准。

独立源端/RTR 与可选捕获目标现见 [DEFERRABLE-TRANSACTIONS.md](DEFERRABLE-TRANSACTIONS.md)。
本页两个兼容能力位仍只描述默认目标策略，完整源 API 使用单独能力位。
