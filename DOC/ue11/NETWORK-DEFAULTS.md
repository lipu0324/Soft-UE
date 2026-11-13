# 默认封装与原生 IP 协议号

UE 1.1 表3-35的参考配置选择 UET-over-UDP，目的端口为4793。原生 UET 的
IP 协议号允许配置为0～255，但标准没有给出已分配的默认号；实验用253/254
不能视作生产分配。Soft-UE现在默认发送 UDP/4793。

原生封装必须显式配置。例如实验场景：

```yaml
wire:
  ipv6: false
  udp: false
  crc: true
  native_ip_protocol: 253
```

`WireOptions::native_ip_protocol`采用`std::optional<uint8_t>`。未配置与配置为0
是不同状态，避免把合法范围端点当成哨兵值。codec发送与主机构造时都检查原生
封装是否具有协议号；YAML入口另拒绝布尔值、非整数和越界值。

接收时，主机把配置的封装模式与协议号分别传给codec。这样，即使实验原生协议号
配置为17，仍按4字节entropy头解释，而不会误当成8字节UDP头。诊断调用者省略
模式时优先识别普通UDP；分析协议号17的原生帧需要显式传入`udp_encapsulation=false`。
MAC发送时的ACK_CC service-time更新也沿用相同配置。

默认1024字节WRITE payload的NSCC名义包长变为1132字节：
`40 + 8(UDP) + 12(PDS) + 44(SES) + 1024 + 4(CRC)`。
其中40是规范的统一IP记账开销，IPv4与IPv6使用同一名义值，不能直接使用
Ethernet帧长作为拥塞窗口扣账。显式原生封装比UDP少4字节。

`network_defaults_test`覆盖所有256种协议号、IPv4/IPv6、CRC开关、trim、错误
配置拒绝，以及默认UDP和原生0/17/252/253/254/255下的分片WRITE与NSCC反馈。
场景测试独立读取PCAP协议号与默认UDP端口。原有原生黄金样例和固定参考端点
互通测试显式选择253，避免把实验互通设置扩散为运行时默认值。

这些行为只覆盖封装配置。UFH、TSS、隧道、完整地址族映射和Profile验收仍按需求
清单跟踪。
