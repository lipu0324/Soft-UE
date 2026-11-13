# PDS配置表逐字段复核

本表补充729段候选文字之外的表格审阅。依据为UE 1.1表3-35（PDF页303～305）
和表3-36（页305～306）。参考默认值不是所有部署都必须使用的数值；所需范围、
单位、条件项与选择的可选功能必须分别落实。此表不表示M0清单已经完整。

| 字段 | 所需范围/条件 | 当前路径与待完成项 |
|---|---|---|
| `UET_Over_UDP` | Boolean，参考默认1 | `WireOptions::udp`，默认UDP，原生封装显式配置。 |
| `UDP_Dest_Port` | 0～65535，参考4793 | 编码、普通/trim接收、MAC stamp、YAML与独立PCAP测试。 |
| `IP_Proto_Nxt_Hdr` | 0～255，无默认分配号 | optional协议号；原生模式必须配置，含0和17的边界。 |
| `UET_Data_Protect` | 0无保护、1CRC、2TSS；3保留 | 0/1由CRC开关选择；2属于M6，未实现。 |
| `Limit_PSN_Range` | 可选安全功能，Boolean | 尚未实现达到起点+2³¹时的关闭策略，不能以普通32位回绕测试替代。 |
| `Default_MPR` | 编码1～255；0按1处理 | `PsnRangeConfiguration::default_mpr`，与本地包缓存上限分开；每单位128 PSN。 |
| `Max_ACK_Data_Size` | 0～8KiB，16B粒度 | M5 READ/fetch数据响应与分片选择尚未实现。 |
| `Trimmable_ACK_Size` | 0～10KiB，16B粒度；trim ACK可选 | 当前没有READ数据ACK；不把普通请求trim验收作为该项证据。 |
| `ACK_On_ECN` | Boolean | 固定逐包ACK策略会确认每个新请求并反射CE；独立配置入口尚未提供。 |
| `Enb_ACK_Per_Pkt` | coalescing启用时必需 | 当前选择逐包ACK，不启用coalescing。 |
| `ACK_Gen_Trigger` | coalescing条件项，0～32KiB、256B粒度 | 未选择coalescing，未提供该配置。 |
| `ACK_Gen_Min_Pkt_Add` | coalescing条件项，0～2KiB、64B粒度 | 同上。 |
| `RTO_Init_Time` | 0～8s，128ns或更细粒度 | 注入纳秒RTO；范围、零值、NACK/RTO退避区别有回归。 |
| `Max_RTO_Retx_Cnt` | 0～15，15无限 | 共同NACK/RTO预算、宽重试身份和实际发送次数有回归。 |
| `NACK_Retx_Time` | 至少一个0～8s延迟；建议四组 | 已提供四个纳秒延迟槽及按NACK代码分组。 |
| `Max_NACK_Retx_Cnt` | 可选独立阈值0～31，31无限 | 未选择独立阈值，当前使用共同预算。 |
| `New_PDC_Timeout_Thresh` | 0～64K，TSS建连状态 | M6安全建连与DoS事件未实现。 |
| `New_PDC_Time` | 0～100ms、100µs粒度，TSS条件项 | M6未实现。 |
| `PDS_Clear_Time` | 可选0～100ms定时Clear | 已选择无请求待发时立即Clear，未选择延时合并。 |
| `Close_REQ_Time` | 可选0～100ms | 未选择独立请求响应期限。 |
| `Tail_Loss_Time` | 可选0～100ms | 未选择独立尾丢失优化；普通RTO保留。 |
| `Max_Tail_Loss_Retx` | 可选0～15 | 同上，不等于普通重试预算。 |
| `Override_MPR_Zero_Value` | 至少支持0～127 | 当前支持0～32640的显式扩展；0表示收到零编码时不限制MP_RANGE。小窗口接收策略须配置共同非零override。 |
| `Syn_Retx_Safety_Time` | 表列16位µs，正文要求24位µs | 注入纳秒安全等待，按实际丢失SYN的MAC时间计算。位宽不一致已记录；统一管理配置与TSS策略仍待补齐。 |

表3-36中必需的`PDS_TYPE_INVALID`与`PDS_CTL_TYPE_INVALID`已实现为可清除的
16位本地计数器，饱和策略见[PDS非法类型](PDS-INVALID-TYPES.md)。
`NEW_START_PSN_TO_ERR`、`NEW_PDC_TIMEOUT_CNT`属于尚未启用的TSS建连路径。
CC/CCX/NCCX事件、CRC错误、Close错误、REQ错误及窗口外事件等可选计数器尚未
形成完整统一管理接口。结构化trace不能自动替代规定的管理状态。

完整reserved pool要求另一组独立配置。保留PDC/CCC资源池未实现，因此也没有
以复制普通池参数来宣称支持该条件项。四种Profile继续保持未通过状态。
