# RUDI线格式与事务边界

RUDI是针对幂等操作的可靠无序交付，见§3.5.23。目标允许重复执行同一请求，可靠性
由源端逐包重试提供；适用于RMA WRITE/READ。它不使用PDC和UET拥塞控制，目标不保留
PDS/SES恢复状态，也不产生目标消息完成。READ数据在同方向的RUDI Response中返回。

| 属性 | RUD/ROD | RUDI | UUD |
|---|---|---|---|
| 传输关联 | PDC与PSN | 源本地32位pkt_id | 无可靠交付关联 |
| 目标重复处理 | PDS去重 | 幂等操作可重复执行 | 不保证去重 |
| 响应 | ACK/NACK及语义响应 | 每个请求一个Response；源负责重试 | 无远端确认 |
| Clear | 回收保证响应等状态 | 无目标恢复状态需要Clear | 无Clear |

## 8字节头

已复核规范PDF第343页（index342）的Figure3-74，渲染图为
`/tmp/ue-rudi-header.png`。它的第一行包含prologue16位及reserved16位，第二行才是
pkt_id32位。Table3-48没有单列该reserved word；按表中有效字段相加得到6字节会错位。

| 顺序 | 字段 | 线宽 |
|---|---|---|
| 0 | type5 / next_hdr4 / flags7 | 2字节 |
| 1 | reserved | 2字节，发送为0，接收在完整性检查后忽略 |
| 2 | pkt_id | 4字节，网络字节序 |

type4为Request，type5为Response。flags.retx位表示重传；flags.m只在Response中有意义，
用于回显请求的ECN标记，Request中该位保留。pkt_id是源本地响应关联号，不是PSN，
也不编码PDCID。每个标准请求/响应的SES头紧接在完整8字节PDS头后。

`PDS_RUDI_header` 只保存本地字段。UetWireCodec显式编解码prologue、reserved word和
pkt_id，不序列化C++结构体。原有NACK的nt/pkt_id字段在线格式上另有定义；其运行时
分发及可靠性仍属于事务接入工作。

## 当前证据与剩余工作

`rudi_header_test`有288组独立字节向量，覆盖WRITE/READ Request、语义Response、带数据
Response、IPv4/6、UDP/native、CRC、retx、ECN回显、ID0/0xabcd1234/UINT32_MAX、保留
字段及逐字节截断。Header的独立向量包含reserved word，避免只验证往返编解码。

固定参考5b4e049的parser/CRC与既有格式一起比较48个报文，包括RUDI请求和响应，
使用默认/自定义UDP端口。参考源码及shared library保持不变，测试wrapper额外输出
其解析的pds_rudi_pkt_id。基于009ca6b的工作树改动通过两项普通检查及两项
ASan/UBSan/泄漏检查；日志为 `/tmp/softue-rudi-header-tests.log` 和
`/tmp/softue-rudi-header-asan-tests.log`。运行期间另有完整版本编译，因此只作为
功能证据，elapsed不作为网络性能或基准指标。

这是线格式基础。源端唯一ID与逐包timer、RTO/NACK/trim恢复、无状态受检目标WRITE/READ、
源READ结果注册身份固定、资源界限、丢失/重复与取消关闭、实时互通及公开接口仍需接入。
原生RUDI与Profile能力尚未声明；它不会通过普通RUD连接去模拟这些语义。
