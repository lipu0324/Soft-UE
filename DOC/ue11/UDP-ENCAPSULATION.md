# UET-over-UDP 的目的端口

UE 1.1 表3-35定义`UDP_Dest_Port`为可配置的16位值，默认`4793`。
此前codec将`49150`写死在发送、正常接收和trim接收三条路径中；仅比较PDS字段的
roundtrip测试没有发现这个默认值错误。

现在`WireOptions::udp_destination_port`由发送编码、接收验证和NIC service-time
stamp共同使用。接收端按本地配置识别UET-over-UDP，端口不匹配时按无效网络头规则
静默丢弃，记录`malformed_frame`，不会分配PDC或返回NACK。trim路径仍检查目的端口，
同时按规范豁免IP/UDP长度检查。

YAML场景可以设置：

```yaml
wire:
  ipv6: true
  udp: true
  crc: true
  udp_destination_port: 4793
```

范围为0～65535，Python校验器拒绝越界值、布尔值和非整数；C++场景入口再次检查位宽。
自定义配置下，所有模拟FEP使用同一端口。实时`UdpFramePort`以应用socket地址承载
完整Ethernet帧，帧内的UET UDP目的端口由上述参数控制，两个地址层次各自保存。

`udp_encapsulation_test`独立检查默认字段字节`12 b9`，并验证端口0/4793/49150/65535、
IPv4/IPv6、CRC开关、错误端口、trim和ACK_CC stamp。主机测试用背景流量占用返回链路，
确保自定义端口的ACK_CC在实际发送时更新service_time。它使用SES NO_OP产生NSCC数据反馈；
PDS NOOP控制包本身没有收到数据的CMS计数，不能用其基本ACK假定存在ACK_CC状态。

场景回归另从PCAP字节独立读取自定义端口65535，避免编码器与解码器共享同一个错误。
固定版本参考实现的实验默认值是49150；对照程序通过其`uet_udp_port`配置字段显式
选择4793或49150，保留参考解析器原代码，36组样例验证两种UDP配置及原生封装。
默认封装和显式原生协议号见[网络默认值](NETWORK-DEFAULTS.md)。这些检查覆盖
UDP端口配置；完整TSS、UFH及Profile验收仍分别跟踪。
