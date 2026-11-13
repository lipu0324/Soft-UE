# 原生 READ 的请求、返回与完成

READ 复用原 SES → PDS → CMS → 网络路径，入口为 `OperationType::Read`。
完整 Profile 验收、optimized headers 和 RODL 仍独立推进。provider 的
`fi_read/readv/readmsg` 复用此路径，接口约束见 [provider](PROVIDER.md)。

## 原生接口

`Operation.read_length` 是总长度；`remote_key`、`remote_offset` 和目标 PID/resource
index 选择远端注册区域。`Operation.read_result` 是发起端本地的
`ReadResultBuffer{key, offset, capacity, pid, resource_index}`，不进入线格式。
提交前检查目标缓冲区容量与 Write 权限，随后保留精确的本地注册身份。
每次放置返回数据都重新验证这份注册，撤销或重用同一个 key 不会授权旧结果。

READ 请求没有 payload，也不接受 payload reader 或 immediate data。零长度 READ
允许省略本地结果缓冲区，仍经过远端权限检查并产生一个完成事件。

`Max_ACK_Data_Size` 默认16 B，配置范围0～8192 B、16 B粒度；各 FEP 配置一致。
当前原生能力公开32位 `max_read_length`。两个返回分支都支持多包消息；每一个
请求及其数据响应仍至多一 Payload MTU。SES 构造时配置主机的
`semantic_payload_mtu`，已有连接期间不改变它，PDC 也按代次保存响应策略。

## 一个消息、两条返回路径

UE 1.1 §3.4.5.2：每个请求最多索取一 Payload MTU 的数据。标准头中所有分片的
`request_length` 仍是整个消息长度；非 SOM 请求用 `message_offset` 标识位置，
其 `payload_length` 为0。目标按总长度与 offset 推导这一个请求要读取的字节数。

- 整个消息不超过阈值，或阈值达到 Payload MTU：使用 [数据 ACK](READ-ACK-DATA.md)。ACK 丢失后重发原
  READ 并重新读取；目标发送后保留 PSN 标记，不保留结果快照。
- 阈值低于 Payload MTU 且整个消息超过阈值：所有片段，包括最后不足阈值的一片，都使用
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

发起端另设每个 READ 的结果窗口，默认8个请求，独立于生产队列和 PDS 窗口。
即使对端先确认所有正向请求，等待返回数据的 offset 集合也不超过此窗口；实际
放置后才允许继续索取下一片。未曾索取的 offset 不能被当作有效数据放置。

`ReadCoverage` 合并相邻区间；顺序大消息保留一个区间，乱序状态受到结果窗口与 PDS 范围约束。
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

READ 失败时若还有结果未到达，原消息 ID 保留到所属 PDC 退休。实现会请求优雅
关闭该连接，让既有操作排空、新消息等待替换连接；正向 Clear 不单独释放这类
ID。§3.5.8.3 的 Close 隐式确认全部返回方向，连接退休后，旧帧由新代次的 PDS
校验拒绝。用户的本地错误/取消完成无需等待这个后台退休过程；
`transport_pending(operation)` 可以观察它是否仍在进行。

`read_early_acceptance_test` 采用合法的独立 SES 策略：先返回正向 DEFAULT，再在
200µs 后交付返回数据。它验证1/2/8个源端结果窗口、正向已 Clear 后取消、发包前
取消、PDC 未分配时的资源拒绝，以及迟到旧数据不会写入取消操作的缓冲区。

`read_large_ack_test` 覆盖阈值等于/大于 MTU、总长大于阈值的多包数据 ACK。
它丢失 SOM/EOM 数据 ACK 后更改远端对应片段，验证重发的原 READ 读取新值；
ACK 中的 offset 与本片长度必须匹配原 PSN，不能用整个消息长度代替。

§3.4.5.2 Figure3-32 明确给出大 ACK 阈值下的多包 READ。§3.5.12.1 的“一 MTU”
按单个请求/响应解释，保留整个消息分片的能力；不能把它变成大消息 API 上限。

## 流式边界实验

`streaming_read_test` 使用真实原生 READ 路径、8192 B Payload MTU 和两端稀疏
MR。每次实际放置都逐字节核对三个标记与其余零字节；独立校验器最多保留8个
片段编号，不分配整条消息大小的期望数组。默认 CTest 覆盖两种返回载体、NSCC
开关和1 MiB+3 B消息，另用64 KiB队列验证数据 ACK 尾丢失后的原 READ 重执行。

正式4 GiB−1实验使用1 MiB链路队列，要求没有队列丢失、524288次唯一放置、
4294967295字节全部核对、源端生产队列/结果窗口和目标 READ 包占用均不超过8。
源/目标覆盖各至多一个区间，稀疏 MR 各至多三个页，完成后排空资源和定时器。
这验证32位消息长度边界，执行器耗时与 RSS 不代表目标硬件性能。

先在干净提交重新配置并构建 Release `streaming_read_test`，再运行：

```sh
python3 scripts/test_large_read.py --binary build/release/streaming_read_test \
  --output build/read-boundary
# 另外分别增加 --nscc、--ack-data 及二者组合。
```

可执行文件的 `--build-info` 嵌入配置时的提交和工作树状态；脚本拒绝旧二进制或
脏工作树，保存二进制哈希、命令、逐字节校验计数与资源峰值。NSCC 下的反向
PDS Request 还跨越24位累计收到字节计数器；数据 ACK 不计入这条请求计数。
实际实验结果单独保存在生成的 `report.json`，本节不将测试入口当作通过证据。
四个组合的实际通过记录见 [READ 边界证据](READ-BOUNDARY.md)。
