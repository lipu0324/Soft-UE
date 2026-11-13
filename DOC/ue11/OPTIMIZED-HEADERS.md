# Scale-out优化语义头

本轮先实现线格式，事务能力保持关闭。§3.4.3.2的SMALL/MEDIUM适用于单包消息，
均用14位request_length替代标准头中的MID；数据返回还可以用Table3-18的优化格式，
通过original_request_psn关联原请求。它们不等同于M8的Unified Local压缩头或消息打包。

| 格式 | 线宽 | 主要差异 |
|---|---:|---|
| REQUEST_SMALL，Figure3-15 | 20B | 不携带MID、matching字段及header data；hd位保留 |
| REQUEST_MEDIUM，Figure3-16 | 32B | 不携带MID，保留initiator及match_bits/memory_key；地址与header data共用一个64位槽 |
| RESPONSE_DATA_SMALL，Table3-18 | 12B | 无MID、modified_length、offset；有原请求PSN；有数据时payload_length也表示modified length |

已直接渲染并核对规范PDF第224与226页（index223/225），图为
`/tmp/ue-optimized-small-header.png`、`/tmp/ue-optimized-medium-header.png`。
不能把MEDIUM误写成SMALL加两个独立的64位地址和header-data字段。

旧占位结构把请求长度位置命名为msg_id，并把JobID拼作jod_id。现在按规范字段命名，
用本地字段容器保存值，再由UetWireCodec显式编码；C++结构体尺寸和位域布局不是线ABI。
MEDIUM的union只表达同一个槽的两种名字，不授权任何内存访问。

原有STD以及新SMALL/MEDIUM共用操作扩展编解码。atomic、synchronized group及其组合
仍按各自规范次序紧跟基础头。原有RNDV/同步/RUDI/legacy codec回归核对该整理没有
改变既有报文；不将“能够编码扩展”当作该操作的优化事务能力。

## 安全的接入边界

当前PDS入口在分配PDC、学习对端和调用SES准入之前丢弃这三类未接通的优化格式。
不能把它们的union当作Standard_Header读取：请求没有MID，且字段位置不同。六个
直接PDS回归覆盖RUD/ROD及三种格式，核对没有PDC、SES请求、响应、网络回复或timer变化。
完成真实PSN关联及MR授权后才能删除该围栏，原生能力目前不宣告支持优化事务。

下一步需分别处理：

- 本地应用operation ID、仅用于本地跟踪的MID与线上原请求PSN的不同身份。
- Table2-14规定的优化MR key/index放入ses.resource_index，以及Table2-47的Job/PID作用域。
- SMALL/MEDIUM的单包SOM/EOM、header data共享槽、有效操作与MTU约束。
- DEFAULT、显式错误和优化数据响应的关联、保证交付、反向READ、重试及Clear所有权。
- 原生API、provider格式选择、配置发现及完整Profile矩阵。

Table2-14/15的RMA优化选择条件排除FI_REMOTE_CQ_DATA，而§3.4.3.2正文还讨论带立即数
的用法。共享槽的具体操作约束仍需在事务接入时逐项复核，不能仅凭字段存在而宣告支持。

## 证据与参考限制

`optimized_header_test`有120组独立字节向量：SMALL/MEDIUM的WRITE/READ/atomic/fetch/
同步扩展、MEDIUM SEND以及带数据和无数据优化响应，组合IPv4/IPv6、UDP/native、CRC。
另检查0/8192/14位最大值的字段保存、非法编码、保留位、版本及逐字节截断。14位字段
能保存16383不代表原生接口接受超过8192的Payload MTU；语义准入是另外的工作。

七项普通检查全部通过（1.30s），七项ASan/UBSan/泄漏检查全部通过（2.45s），日志为
`/tmp/softue-optimized-wire-tests2.log` 与 `/tmp/softue-optimized-wire-asan-tests.log`。
检查期间另有完整版本构建，因此这里只作为功能证据，不作性能或实时调度结论。

固定5b4e049的 `util/uet_util.c` 在解析next_hdr时，把REQ_SMALL、REQ_MEDIUM和
RSP_DATA_SMALL直接送到err_exit；未修改它的源码或shared library来扩大对照范围。
现有48项独立parser/CRC比较仍通过，用于保护其他已实现格式。这不构成优化头正向
参考解析或事务互通证据，也不构成任何Profile验收声明。
