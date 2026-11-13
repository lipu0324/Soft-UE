# 可重放的拥塞与链路实验

场景运行器使用与 native API 相同的 SES/PDS/CMS 内核。YAML 先经严格字段、
类型和边界校验，再交给 C++ 运行器。拓扑支持 2～64 个主机；新增配置没有开启
任何完整 Profile 声明。NO_OP、SEND 和 WRITE 是当前运行器的操作集。

```sh
python3 scripts/run_simulation.py examples/simulation/nscc-incast-trim.yaml \
  --binary build/cmake/softue_sim --output build/experiments/incast-trim
```

另外两个例子是 `nscc-flow-competition.yaml` 和 `nscc-asymmetric-recovery.yaml`，
分别展示公共瓶颈上的多流竞争，以及不对称多路径和中途断链恢复。

## 配置对应哪一层

| YAML 字段 | 含义与单位 |
|---|---|
| `wire.udp`、`wire.udp_destination_port` | 默认使用UDP/4793；目的端口范围0～65535。 |
| `wire.native_ip_protocol` | `wire.udp: false`时必填，范围0～255；没有隐含的实验协议号。详见[默认封装](NETWORK-DEFAULTS.md)。 |
| `pds.rud_mapping`、`pds.rod_mapping` | 分别选择JobID、源/目标PID与RI字段；见[PDC元组](PDC-MAPPING.md)。 |
| `pds.default_mpr` | 初始MPR编码0～255，0按1；参考默认8表示1024 PSN。 |
| `pds.local_packet_capacity` | 本地发送缓存上限，1～32640个包，默认8；独立于线上MPR。 |
| `pds.advertised_mpr`、`pds.mpr_zero_override` | 可选固定接收通告和共同零值解释，见[三个窗口](PDS-WINDOWS.md)。 |
| `payload_mtu` | SES 单包 payload 上限，默认 1024 字节，范围 1～8192；不等于完整链路帧 MTU。 |
| `rto_ns` | 初始重传超时，0～8000000000 ns，默认 1000000；零值表示立即到期。NACK 与 RTO 的退避区别见 [重试计时](RETRY-TIMING.md)。 |
| `max_packet_retries` | 0～14 为共同 NACK/RTO 重试上限，15 为无限，默认5；不计初次发送。 |
| `nack_delays_ns` | 四个 0～8000000000 ns 延迟槽，按正常恢复、资源、SES 处理和预留分组选择；默认 `[0, 2000000, 1000000, 0]`，详见 [NACK 恢复](NACK-RECOVERY.md)。 |
| `nscc.enabled` | 显式开启所有主机的 NSCC；默认 false。 |
| `nscc.base_rtt_ns` | 配置的空载路径 RTT，默认 12000 ns；不是实验测得的平均流延迟。 |
| `nscc.sender_bytes_per_second`、`receiver_bytes_per_second` | 算法初始化使用的速率，单位 byte/s，默认均为 12500000000。链路 `rate_bps` 另用 bit/s。 |
| `nscc.nominal_mtu` | NSCC 的 transport 长度加 40 字节，默认按最大 payload、标准头、封装与 CRC 计算。显式配置不能小于实际最大分片。 |
| `nscc.initial_window_bytes` | 可选的初始最大窗口覆盖；0 表示按 NSCC 配置推导。正值至少容纳一个名义 MTU。 |
| `operations[].delivery_mode` | `rod` 或 `rud`，默认 `rod`。该选项进入原 PDS 状态机。 |
| `trimming` | 所有端点使用共同的默认 DSCP 映射，并默认在所有链路启用截短。单条链路可设置 `trimming: false`。 |
| `links[].ecn_threshold_bytes` | 恰好八个 TC 阈值；null 关闭，0 对每个 ECT 帧标记。检查包含正在服务的字节。 |
| `links[].traffic_class_weights` | 恰好八个正整数 DRR 权重，默认全为 1。 |
| `links[].scheduling_quantum_bytes` | DRR 字节 quantum，默认 256；这是模拟器调度策略。 |
| `link_events` | 有向链路的 `at_ns`、`from`、`to`、`up`。同一时刻/有向边不重复；双向链路的反向边须另设事件。 |

链路 `buffer_bytes` 是**每个 TC** 的独立容量，不是八类合计。所有场景链路 MTU
都必须容纳配置中最大的完整帧；异构 MTU 与按路径准入实验可通过 native API 构建。
当前运行器对所有主机使用同一组 NSCC 初始化参数，尚未提供逐主机的异构配置。
链路事件在同时间的应用提交之前注册；同时事件按输入顺序稳定执行。

## 如何追踪一次丢失

| 输出 | 实际观测边界 |
|---|---|
| `scenario.yaml`、`scenario.config` | 原始配置与经过校验的 v2 内部记录。 |
| `metadata.json` | 源提交、dirty 状态、源码及二进制 SHA-256、规范版本、种子对应的配置 hash 和抓包边界说明。 |
| `packets.pcap` | FEP 提交给端口时的完整报文，在 NIC 排队、链路 ECN/trim 和最终 ACK service stamp 之前。 |
| `link-packets.pcap` | 每条有向链路首字节发出时的实际字节，在该跳 ECN/trim 和一次性 ACK 时间更新之后。丢失在链路上的帧也被记录。 |
| `link-packets.jsonl` | 一对一的 PCAP 记录索引，包含记录序号、时间、出口边、源/目的 FEP、TC 和长度。 |
| `trace.jsonl` | 原 PDS/CMS 的事件及虚拟时间，用于解释准入、NACK、RTO、本地拒发和应用完成。 |
| `result.json` | 应用完成与目标内存校验、链路及 TC 统计、流完成时间、有效吞吐和条件性公平性指标。 |

PCAP 使用 Ethernet 链路类型和纳秒时间戳。两份 PCAP 不能混作同一个观测点：
只检查 `packets.pcap` 无法证明链路上发生了 ECN 或真实截短。
例如默认 IPv4/UDP trim 帧只保留 24 字节 IP payload，共 58 字节；IP 长度和
IPv4 校验和已修复，保留的 entropy/PDS/SES 前缀与原包一致，UDP 长度/checksum
如存在则不修改。接收端继续使用受限 trim 解析器，而不是把通知当完整数据。

链路 `packets`/`bytes` 表示成功排入该链路队列的量，可能包括尚未发送或后来丢弃的帧；
`transmitted_frames` 是首字节实际发出的次数。`drops` 包含本地队列丢弃、随机链路
丢失和断链失效。全局 `source_data_retransmissions` 只在源端第一跳统计带 RETX 的
数据帧，避免把同一个重传在多跳重复计数；控制查询另可从事件轨迹识别。

`flow_completion_ns` 从该操作提交到实际应用完成。`goodput_bps` 仅把成功且内存
校验通过的 payload 计入；失败流为零。总有效吞吐使用首个成功操作的开始至最后
成功完成的时间跨度，不使用运行器墙钟耗时。公平性仅在至少两个非零 payload 流
具有相同大小和开始时间时提供，计算各自完成有效吞吐的 Jain index；它不是持续负载
下的稳态公平性证明。其他情况下 `eligible=false`，`jain_index=null`。

## 当前证据的边界

`simulation_scenarios` 对相同 NSCC incast 重跑后逐字节比较结果、事件和两份 PCAP；
独立 Python 记录解析检查实际 CE、真实 trim 长度/保留字节和逐跳索引。另覆盖
IPv6/UDP 的 trim 恢复、临时无路由、RUD 不等延迟 ECMP 及 64 主机写内存。
这些确定性场景没有穷尽所有控制/故障组合，也不是 AI Base 完整必选项验收。
链路 LLR/PFC/CBFC、TSS 和后续 Profile 继续按 ROADMAP 实施。
