# 有序控制包如何避免越过数据

UE 1.1 §3.5.16要求，ROD上分配独立PSN的控制包必须使用PDS请求流量类。
这些包与数据共享序号；若NOOP、Negotiation或Close进入更快的ACK队列，
它可能先于较低PSN的数据到达，制造无谓的ROD_OOO和GoBackN。

当前标准主机采用两个流量类，开启和关闭NSCC时映射一致：

| 包 | 流量类 | 未启用trimming的DSCP | 启用trimming的DSCP |
|---|---:|---|---|
| RUD/ROD/UUD数据请求 | 0 | 配置的bulk DSCP，默认0 | TRIMMABLE，默认0 |
| ROD唯一PSN CP：NOOP、Negotiation、Close Command/Request | 0 | 同bulk DSCP | NO_TRIM，默认32 |
| 其他当前CP，包括RUD唯一PSN CP | 1 | CONTROL，默认48 | CONTROL，默认48 |
| ACK/NACK | 1 | CONTROL，默认48 | CONTROL，默认48 |

数值是本模拟器的映射，UE没有指定这些数字。NO_TRIM与TRIMMABLE虽然进入同一
队列，只有后者允许截短，因而同时满足CP的非trimmable规则与ROD的同流量类规则。
`TrimmingOptions::no_trim_dscp`与其他码点必须不同；交换机按该码点重新分类到请求队列。
这也使中间交换机不必依赖主机传来的本地元数据。

PDC在`tagTransmission()`中记录`control_uses_request_traffic_class`。这是不进入线格式的
PDS到网络元数据，与NIC时间通知是否存在无关。不能从Close的wire `pdc_type`推断模式，
因为该字段只对NOOP/Negotiation有效。重传会按当前PDC模式重新设置同一分类。

`pds_traffic_class_test`经公开native操作驱动真实PDS/Fabric，覆盖RUD/ROD、NSCC开关、
trimming开关、NOOP/NO_NEG启动、源端/目标端发起关闭的32种组合。它从捕获的标准帧检查
DSCP/流量类、数据和ACK分离、CP不可截短，并核对目标内存和双方关闭结果。

RODL、Credit类控制、tail-loss专用Probe选择及自定义多流量类策略还没有完整实现。
本次不把ROD修复等同于RODL/所有CMS模式已通过。
