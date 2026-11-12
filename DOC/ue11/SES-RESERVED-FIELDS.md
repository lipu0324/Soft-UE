# SES 保留位与完整性校验

UE 1.1 §3.4.3 要求 SES 保留字段发送为零、接收时忽略。接收端应先完成
报文长度和启用的 CRC 校验，再从已验证的报文中提取有效字段。

`UetWireCodec.cpp` 中的 `get_semantic` 对已实现格式采用显式掩码：

| 格式 | 忽略的接收字段 | 保留的有效字段 |
|---|---|---|
| 标准请求 | opcode 前两位、PID/index 前四位 | 六位 opcode、十二位 PID/index |
| 非 SOM 标准请求 | payload_length 上方十八位 | 十四位 payload_length 与完整 message_offset |
| 原子扩展 | 最后一个 reserved octet | opcode、datatype、semantic control |
| 带数据响应 | JobID 前八位、payload_length 前两位 | 二十四位 JobID、十四位 payload_length |

版本字段有实际协议含义。当前只支持版本零，非零版本仍明确拒绝。发送端继续
生成零保留位；接收时不会把原始保留位复制到新的发送报文。受检 MR 的 JobID、
PID、index、权限和边界检查继续使用解析后的有效字段。

`ses_reserved_fields_test` 覆盖 IPv4/IPv6、原生/UDP、CRC 开关的八种组合，分别
注入标准请求、非 SOM、原子扩展和带数据响应的保留位。测试检查有效字段保持
一致、重新编码得到原先的规范字节、未知版本被拒绝，并验证启用 CRC 时不能靠
“忽略保留位”绕过完整性检查。CRC 故障注入修复只更新既有报文的 trailer。

这项覆盖属于已实现 SES 格式的接收行为。完整 Profile 仍依赖其他头格式、字段、
操作、资源授权、PDS 和安全路径的独立验收。
