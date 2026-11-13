# READ：数据随 ACK 返回

UE 1.1 §3.4.5.2、§3.5.12.1、§3.5.16.2、§3.5.17 是此路径的依据。
当前原生接口支持 RUD/ROD、标准请求头、单 Payload MTU 内且不超过
`Max_ACK_Data_Size` 的 READ。默认阈值为 16 B，配置范围为 0～8192 B、
16 B 粒度；配置必须在打开 PDC 和创建 SES Endpoint 前完成，且整个 fabric
使用相同值。超过 ACK 阈值的消息使用 [反向数据通道](RETURN-DATA.md)，其
原生分片与完成条件见 [READ.md](READ.md)。AI Full/HPC 和 Unified Local 的完整验收仍未完成。

## 请求、返回与本地放置

`Operation.read_length` 表示需要读取的字节数；READ 请求本身不携带 payload。
`remote_key`、`remote_offset` 和目标 PID/resource index 由目标端的 ResourceDirectory
与 MemoryRegistry 验证，要求远端区域具有 Read 权限。

`Operation.read_result` 是发起端本地的 `ReadResultBuffer`：包含 key、offset、capacity、
PID 和 resource index。这些信息不传给目标端。提交时保存注册身份，响应到达时
再次检查同一注册及 Write 权限。撤销后用相同 key 注册的另一个缓冲区，不能接收
旧 READ 的迟到结果。

目标端使用 `UET_HDR_RESPONSE_DATA`（20 B 语义头），设置
`read_request_msg_id`、`payload_length`、`modified_length` 和 `message_offset`。
发起端必须收到且验证数据，再进行本地内存放置，才报告一次成功完成。
普通 DEFAULT 或较高 CACK 不能替代 READ 数据。

## READ ACK 丢失后的恢复

READ 结果与 fetching atomic 结果的生命周期不同：

| 状态 | READ 数据 ACK | fetching atomic 数据 ACK |
|---|---|---|
| 保证交付 | 设置 REQ_CLEAR | 设置 REQ_CLEAR |
| 发送后保留结果数据 | 不保留 | 必须保留，后续实现 |
| 目标保留内容 | 需要 Clear 的 PSN 标记与语义消息元数据 | 结果及保证交付状态 |
| ACK Request | NACK `UET_ACK_WITH_DATA` | 重放缓存结果 |
| 原请求重传 | 经 MR 再次读取，允许观察新值 | 不得再次执行非幂等操作 |

`uncached_read_responses_` 保存 PSN，不保存数据。它参与 SACK 和 CACK/Clear
约束，收到 Clear 后释放。重发原 READ 使用同一 PSN。已由 SACK 等确认收到的
READ 仍然重发原请求，不转换成 ACK Request；这一分支也不对 NSCC 再次收费。
目标重新执行读取时，不重复增加同一 PSN 的累计收到字节数。

ROD 的首次 ACK 继续经过现有顺序屏障；旧 PSN 的重读响应可以恢复丢失的 ACK，
不占用第二个顺序位置。状态转换和计算均由注入的整数纳秒时钟驱动。

`read_ack_data_test` 还会注入错误 JobID、原请求 ID、长度、offset 和缺少数据的 DEFAULT，验证它们不能完成 READ；正常的原请求重试仍能继续。

## 待补齐

- optimized 请求/数据响应头、provider `fi_read` 映射。
- fetching atomic/CAS 的结果缓存；不得复用 READ 的重新执行策略。
- READ 与 TSS、RODL 的组合路径及相应 Profile 验收。
