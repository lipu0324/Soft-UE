# 同步操作扩展头

§3.4.3.6 / Figure3-24 定义4字节扩展：先16位 `sync_group`，再16位
`sync_count`，均以网络字节序编码。原图已从规范 PDF page index233 复核。
Table3-23 的 opcode 是 `UET_SYNC_WRITE=0x10`、`UET_SYNC_ATOMIC=0x11`。

| 操作 | 标准头后、payload 前的内容 |
|---|---|
| SYNC_WRITE | 4字节同步扩展 |
| SYNC_ATOMIC | 4字节同步扩展，然后4字节普通原子扩展 |

复合原子扩展的顺序来自 Table3-20；不能把同步扩展当成原子操作码，也不能把它
计入 payload。每个标准分片均按相同规则编解码，SOM/EOM 不改变扩展的存在。
发送时缺少相应扩展类型会失败，接收时长度不足会拒绝。

`synchronized_header_test` 使用独立字节向量 `ab cd 01 23`，以及其后的原子向量
`02 07 00 00`，覆盖64种 WRITE/ATOMIC、SOM/EOM、IPv4/6、UDP/native、CRC组合。
测试另检查 payload 分界、nominal packet size、逐字节截断和错误扩展类型。

线格式之外，[原生同步组](SYNCHRONIZED-TRANSACTIONS.md)已接入组计数、目标通知、
受检整数atomic、原PDS确认/恢复与有界清理。失败成员仍计数，RUD写入不为组内排序而
延迟，header data值0保留。专用 `NO_SES_SYNC_AVAIL` 覆盖新建/已有连接及真实预算恢复。
状态层的早期原型与接入修正见[历史记录](SYNCHRONIZED-IN-PROGRESS.md)。
优化头及完整Profile验收仍开放；各Profile声明保持关闭。
