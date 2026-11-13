# 原生 READ 的请求、返回与完成

READ 复用原 SES → PDS → CMS → 网络路径，入口为 `OperationType::Read`。
完整 Profile 验收、optimized headers、provider `fi_read` 和 RODL 仍独立推进。

## 原生接口

`Operation.read_length` 是总长度；`remote_key`、`remote_offset` 和目标 PID/resource
index 选择远端注册区域。`Operation.read_result` 是发起端本地的
`ReadResultBuffer{key, offset, capacity, pid, resource_index}`，不进入线格式。
提交前检查目标缓冲区容量与 Write 权限，随后保留精确的本地注册身份。
每次放置返回数据都重新验证这份注册，撤销或重用同一个 key 不会授权旧结果。

READ 请求没有 payload，也不接受 payload reader 或 immediate data。零长度 READ
允许省略本地结果缓冲区，仍经过远端权限检查并产生一个完成事件。

`Max_ACK_Data_Size` 默认16 B，配置范围0～8192 B、16 B粒度；各 FEP 配置一致。
当前原生能力根据 fabric 与 Payload MTU 公开 `max_read_length`：阈值低于 MTU
时允许32位总长度；阈值达到 MTU 时采用 §3.5.12.1 的单 MTU 配置分支。

## 一个消息、两条返回路径

UE 1.1 §3.4.5.2：每个请求最多索取一 Payload MTU 的数据。标准头中所有分片的
`request_length` 仍是整个消息长度；非 SOM 请求用 `message_offset` 标识位置，
其 `payload_length` 为0。目标按总长度与 offset 推导这一个请求要读取的字节数。

- 整个消息不超过阈值：使用 [数据 ACK](READ-ACK-DATA.md)。ACK 丢失后重发原
  READ 并重新读取；目标发送后保留 PSN 标记，不保留结果快照。
- 整个消息超过阈值：所有片段，包括最后不足阈值的一片，都使用
  [同一 PDC 的反向 PDS Request](RETURN-DATA.md)。两个方向采用相同起点，
  随后独立推进 PSN、窗口及 Clear。

`read_request_msg_id` 关联原操作；目标的 `response_message_id` 则关联反向数据的
语义 ACK。目标自己的另一项原生操作可以拥有同一个数值 ID，处理时必须同时
检查 PDC 方向、对端、连接代次和原始 PSN。

## 有界工作与完成条件

目标端另设全局 READ 包容量，默认8，独立于整消息槽和本地发送窗口。
在 PDS 接收之前预约这个容量；不足时返回 `UET_NO_SES_MSG_AVAIL`，此 PSN
不进入收到位图，也不增加 NSCC 累计收到字节。新 PDC 分配失败会撤回预约。

大 READ 的每个反向数据完成后，目标才产生对应正向 READ 的 DEFAULT。
这是 §3.5.20.2.2 允许的本地策略，使已缓存 payload、响应 token 和未确认请求
受到窗口约束。SES 不再保存一份返回 payload。小 READ 的 PSN 预约保留到 Clear。

发起端只有同时满足以下条件才报告一次成功：

1. EOM 请求已发送。
2. 所有已发送请求都有正向语义结果。
3. 返回数据已完整放置到经过授权的本地注册区域。

`ReadCoverage` 合并相邻区间；顺序大消息保留一个区间，乱序只保留窗口范围内的洞。
重复区间不重复放置，交叠或越界数据不能成为成功完成。正向 DEFAULT 本身不代表
READ 数据已到达，也不能替代实际放置。

## 错误、取消与排空

`cancel_read(operation)` 停止该操作的后续本地放置，产生一次 `Cancelled`，长度为
已放置字节。结果缓冲区撤销产生 `LocalError`；远端授权或边界错误产生对应语义
错误。已经发送的包继续由原 PDS 排空；未发送的尾部通过既有 `MSG_ERROR` 结束。

§3.4.5.2 允许发起端在读取返回数据时始终回复 DEFAULT。因此取消、超时或本地
放置失败后，迟到数据会被丢弃并确认，使目标能释放反向发送记录。取消不撤销
此前已经放置的字节。各片段读取期间，应用并发修改的远端内存可以产生不同时间
的观测值；READ 不提供整个大消息的原子快照。
