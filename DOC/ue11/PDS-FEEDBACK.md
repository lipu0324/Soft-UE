# 反馈必须属于触发包

UE 1.1 §3.5.12.2 要求 ACK 使用触发包的熵（EV）；UDP 下对应源端口，原生 UET 下对应熵头。
§3.5.12.7 对 NACK 也有相同要求。CE 与 RETX 同样来自本次触发，而不是最早收到的数据副本。

`RX_pkt_meta` 在接收请求时保存 `wire_entropy`、`congestion_marked`、`retx` 和
`arrival_time_ns`。它与各个请求的处理句柄关联。SES 响应可以交错返回，不能用一个“最后收到
的包”变量为所有响应生成反馈。

当重传数据或 ACK Request 触发保证响应重放时，显式传入这次触发包，覆盖缓存中的旧网络
反馈。语义返回码仍来自保证缓存。例如，原数据带 CE、查询 CP 未带 CE 时，重放结果可以仍是
同一个远端错误，但 M=0，EV 使用查询 CP 的路径，RETX 也反映查询 CP。

`decorateAcknowledgmentNetwork()` 负责 ACK/NACK 的共同规则，覆盖初次响应、查询、重放、
无效 SYN、关闭 CP_ACK 和未知连接 NACK；不以 CMS 开关作为启用条件。

`PdsHost` 使 Frame.entropy 与实际上线的熵一致。未开启 CMS 时，数据与前向控制使用部署的
固定默认熵；返回 ACK/NACK 使用其触发熵，不被本机不同的默认熵覆盖。开启 NSCC 后，
`decorate_control()` 复用 ROD CCC 的固定 EV，RUD 可以另选 EV。控制选路不消耗数据 cwnd，
不增加名义在途字节，也不因此阻塞 ACK/Probe/Clear。

当前 service_time 使用仿真收到首位的时间与 PDS 生成反馈的时间，单位 128 ns。真实 NIC 的
MAC 发送时间、端口背压或本机出口排队引入的额外等待仍需单独建模和校准；不能将这个边界
估计值当作已验证的硬件时间戳。

`pds_feedback_test` 检查两次 SES 响应倒序完成、CE 与 RETX 的相反组合、查询与重传触发重放、
关闭握手、未知连接，以及 RUD/ROD × IPv4/IPv6 × native/UDP × NSCC 开关的实际编码路径。
