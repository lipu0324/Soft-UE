# 同一 PDC 上的反向数据通道

UE 1.1 §3.5.12.1、§3.5.20.2.2：大于 `Max_ACK_Data_Size` 的 READ，
其所有数据响应都使用原 PDC 的反向 PDS Request；不能重新选择一个普通发起端
PDC。反向不能承载新的 SEND、WRITE 或 READ。取回原子的结果按 §3.5.17 始终
放在关联的 ACK 中，本接口只开放需要反向数据的 READ。
RODL 的规则另行实现。

## 内核接口

`PdsHost::submit_return_data(original, data)` 使用已接收请求中的本地目标 PDCID、
对端 FEP、模式及 `connection_start_psn`。管理器逐项检查这个仍存活的连接，
再将数据送入原 `T_PDC::tx_req_q`，复用其发送窗口、CMS、RTO、重传和 Clear。
接口拒绝错误/过期代次；它不为失败的返回请求分配另一条连接。

§3.5.8.2 规定两个方向采用相同 Start_PSN，之后分别推进 PSN、ACK 和 Clear。
因此数值相等不表示同一个发送窗口。提前打开连接的 NO_OP 只占用正向 PSN；
它不占用反向数据的 PSN。

返回数据头有两个不同的消息 ID：

- `read_request_msg_id` 关联发起端的原 READ。
- `response_message_id` 是目标端的响应标识；它必须在反向数据的语义 ACK 中被回显。

`default_semantic_response()` 按实际语义头类型选择回显标识。反向数据与普通请求
一样，需要语义结果才能释放发送记录。严格较高 CACK 可推断 DEFAULT；只有相等
的 CACK 或 SACK 仍不能替代缺失的语义结果。

## 返回数据可能先于正向 ACK

网络可以让返回数据先到。发起端据已通过 PDS 身份和窗口校验的返回请求得知
目标 PDCID，从而能寻址反向 ACK；在正向 ACK 真正到达以前，正向 SYN 状态仍保留。
目标端可以等反向数据完成后再产生原 READ 的 DEFAULT，这是一种有界缓存策略，
不是规范要求的固定 ACK 顺序。

## 当前边界

`return_data_transport_test` 通过显式 SES 回调驱动真实 PDS、Fabric 和 MemoryRegistry，
验证反向传输内核契约。原生 Endpoint 已接入多包 READ 的区间放置、目标包容量
预约、响应标识与错误后排空，见 [READ.md](READ.md)。`native_read_test` 验证两端
均使用本实现时的原生操作、故障恢复与缓存约束。`read_early_acceptance_test` 另用合法的提前确认策略，验证源端独立结果窗口和
失败 MID 退休。当前固定版本参考进程互通尚未覆盖 READ。本项不建立任何 Profile 符合性声明。
