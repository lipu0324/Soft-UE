# MEDIUM DATAGRAM_SEND 与 UUD 接收准入

表3-21允许 MEDIUM `DATAGRAM_SEND`。原生 `OperationType::DatagramSend` 可选择
`RequestHeaderFormat::Medium`，使用32字节 SES 基础头和原有4字节 UUD 头。
支持单个 Payload MTU、零长度、完整32位 Job rank 和可选 header data，包括值0。
`optimized_medium_datagram_send` 只声明原生能力；公开 provider 仍选择既有 STD 格式。

UUD 的语义不因优化头改变：源完成只表示本地发送接受，不表示目标交付。PDS 不建立
可靠连接、不分配 PSN、没有 ACK、重传或接收消息状态。源本地 submission handle
仍是进程内完成关联，不编码为线端 MID。

PDS 允许 MEDIUM UUD 外壳，并通过已有字段视图投影成 SES 的本地 Standard 字段，
同时保留 `request_wire_format`。SES 先按 UUD 路径处理，不查可靠消息的 Incoming 表。
Job/PID/资源代次、initiator 匹配、posting 注册身份、权限及范围检查仍由原接收路径执行。
SMALL UUD 和数据响应作为 UUD 请求仍被拒绝。

独立原 PDS 探针也发现既有 STD UUD 接收没有检查配置的 Payload MTU：一个65字节
请求会消耗 Payload MTU=64 的目标 posting。接收端现在在选择 posting 前丢弃超长包，
不发送语义错误 ACK，不消耗 posting；后续合法 datagram 仍能使用它。此检查遵循
§3.4.2.11 的配置上限。小 MTU 用于边界回归，正式部署的规定值仍为1024/2048/4096/8192。

轨迹事件 `datagram_drop_mtu` 记录这种本地丢弃，`datagram_delivered` 记录实际放置；
两者均不代表网络上出现可靠完成或错误响应。

回归入口：

- `optimized_datagram_test`：384个原生场景，包含 IPv4/IPv6、native/UDP、CRC、NSCC
  开关、0/1/MTU 长度、header data、链路丢失和未投递接收。直接检查 UUD/MEDIUM
  固定字节、一次本地完成、无反向报文及零 PDC/接收消息状态。
- `unreliable_admission_test`：14个 STD/MEDIUM 原 PDS 请求生产者场景，检查超长、
  错误 opcode、SOM/EOM/长度不一致、Job/代次和非法 SMALL 格式。拒绝后用合法
  STD datagram 验证原 posting 未被消耗。

基线 `5c30b3376768bef76c1175ef1e40e192637ce841` 的两个有效探针分别记录原生
MEDIUM `Unsupported` 与 STD 超长包消耗 posting，日志
`/tmp/softue-medium-datagram-before-tests.log` 和
`/tmp/softue-unreliable-admission-before-tests.log`。
当前新增实现及回归尚待固定版本编译验证，不构成完整 M5/Profile 声明，也不宣告
独立参考支持优化 datagram。
