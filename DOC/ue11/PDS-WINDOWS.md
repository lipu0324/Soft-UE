# 三个发送限制各自记录什么

PDS 可以有可发送的包，但仍须等待本地资源、对端序号范围或 CMS 字节窗口。它们不能
用同一个计数器替代。动态 MP_RANGE 的依据是 UE 1.1 §3.5.11.13。

| 状态 | 单位 | 当前代码与职责 |
|---|---|---|
| 本地发送缓存上限 | 包 / 本地序号跨度 | `local_packet_capacity`，默认8，约束本地outstanding和缓存，不是线上MPR。 |
| 初始及对端MP_RANGE | PSN距离 | `PeerSequenceWindow`，创建时按`Default_MPR × 128`初始化，随后以对端最新CACK和通告限制发送。 |
| NSCC cwnd | 名义字节 | `NsccController`，按网络/接收反馈限制在途数据；见[NSCC](NSCC.md)。 |

旧内核把值为8的本地缓存上限同时当成初始接收PSN范围，因而错误拒绝了部分合法
SYN，也没有在首次ACK之前建立规范要求的初始对端窗口。现在标准路径使用
`PsnRangeConfiguration`：`default_mpr`为8位编码，默认8表示1024个PSN；设置为0
按表3-35使用编码1。`local_packet_capacity`是独立的软件资源策略，不能覆盖接收范围。
旧`Default_MPR`宏只保留给显式legacy路径，本地成员已改为描述性名称。

每个PDC保存创建时的配置快照，避免修改主机默认值改变活跃连接。默认接收通告与
初始编码相同；可通过`advertised_mpr`选择另一个固定接收范围。当前不实现运行中
动态调整接收资源的策略。所有ACK_CC（包括Probe ACK）带相同的本地通告。

## 线上MPR如何解码

ACK_CC的八位`mpr`非零时，MP_RANGE = mpr × 128，最大32640。零值由共同配置
`mpr_zero_override`解释：

- override非零时，用该PSN数量作为范围。
- override为零时，收到零编码后不再施加MP_RANGE限制；本地缓存和CMS限制仍生效。
  这不是简单忽略这条通告而保留初始窗口。
- override为零且目标已发送非零MPR后，规范禁止该目标再次发送零。对于这种违规
  输入，源端采用保守策略保留非零限制。

表3-35要求至少支持0～127；软件显式支持到32640，属于该表允许的更大配置范围。
当前有界接收策略若选择零通告，要求共同的非零override，不提供无限接收跟踪策略。
这些参数应在建连前配置：

```yaml
pds:
  default_mpr: 8                 # 初始1024 PSN，不是8个包。
  local_packet_capacity: 8       # 软件发送缓存上限。
  advertised_mpr: 0             # 小窗口实验的接收端通告。
  mpr_zero_override: 4           # 两端共同解释为4 PSN。
```

`PeerSequenceWindow` 分开保存最新 CACK 与上一次 MPR 更新所用的 CACK。普通 ACK
也能前移锚点；只有 CACK 严格晚于上一次 MPR 更新时，新的 MPR 才被采用。旧 ACK
或相同 CACK 的重复 ACK 不能把窗口改回旧值。所有先后比较使用 32 位模算术。

标准线格式先验证 ACK_PSN 是否处于已发送的有效区间、CACK 是否超出已发送范围。
ACK_PSN 超界时整份 ACK 被忽略，不会因为其中有看起来合法的 CACK 就更新 MPR、CMS
或确认状态。测试同时覆盖“未来 ACK_PSN + 合法 CACK”和“旧 ACK_PSN + 更新的 CACK”。

在没有新的 CACK 时，单个包的 selective ACK 可能前移本地 Clear tracker，却不能
前移对端 MP_RANGE 的锚点。比如 CACK=1004、范围=4，允许 PSN 1008；确认了 PSN
1005 但 CACK 仍为 1004 时，不能因此发送 PSN 1009。

## 缩小范围时如何恢复

已经发送的包可能落在新范围之外。检测到它超时后，PDS 保留它的发送记录，但等待
CACK 前移到允许范围后才重传；等待期间不增加重试计数、不重新启动 RTO。数据丢失
在 NSCC 中只记账一次，重传真正准入后才增加新的在途贡献。

待重传列表按相对 Clear 的无符号距离选择，而非按整数自然大小选择，从而在 PSN
回绕时保持恢复顺序。失效的列表记录会被移除。受限的请求不会让 `hasPendingWork()`
持续报告同一虚拟时间上的可运行工作；新的 ACK 或其他协议事件负责唤醒。

已经确认接收的数据若只缺少语义响应，仍通过不分配新 PSN 的 ACK Request 查询缓存，
不把查询当成另一份数据。控制路径的完整联合验收仍在继续。

```sh
ctest --test-dir build/cmake -R 'peer_sequence_window|pds_mpr' --output-on-failure
```

纯状态测试检查零编码、最大范围、严格更新顺序和回绕；原 PDC 内核测试检查缩窗后的
真实发送/重传阻塞、定时器与重试计数、较新 CACK 唤醒、错误未来 CACK 拒绝，以及
本地发送缓存上限不会随对端通告变化。更广泛的网络资源和控制包组合仍不等于已完成
Profile 验收。

## 接收窗口的锚点

接收窗口同样使用CACK而非连续收到的最高PSN。保证语义响应可能阻挡CACK，即使
`rx_cur_psn`已经前进，仍不能接收CACK+MP_RANGE之外的新包。Clear到CACK之间保留
响应重放的例外；小于等于Clear的包不再ACK。数据与编号控制包使用同一检查。

`psn_range_configuration_test`覆盖全部默认编码、0按1处理、缓存独立性、首次ACK前
的发送限制、无数据时伪造ACK拒绝、CACK阻挡、编号控制/Probe通告、创建后的配置
快照、配置拒绝及回绕。`syn_range_test`用显式编码1检查128-PSN边界，并保留
首个ROD缺口优先返回ROD_OOO、初始RUD范围外不建连的规则。它还检查offset=8
这个旧缓存上限附近的合法输入，避免把旧实现错误写回测试预期。

固定接收通告可以比初始Default_MPR更小。首个RUD包在初始建连范围内、但超出
当前接收窗口时，保留已建立的PDC并静默丢弃，随后窗口内的恢复包仍可推进。
该情况不能返回只适用于ROD缺口的ROD_OOO。对应的初始RUD范围外拒绝仍发生在
分配PDC之前，两种原因各有独立测试。
