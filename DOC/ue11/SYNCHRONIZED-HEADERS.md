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

线格式之外，现有[状态层原型](SYNCHRONIZED-IN-PROGRESS.md)验证了本地组计数、
失败成员计数、第一 completing member、过期和有界ID分配。PDS的专用资源NACK
`NO_SES_SYNC_AVAIL` 已覆盖新建/已有连接，但该测试使用脚本SES，尚未执行同步内存操作。
原生同步组尚需接入并验证：

- 目标以 `{initiator FEP, sync_group}` 跟踪状态并核对 Job；每条已处理消息只计数一次，失败也计数。
- RUD 写入不为同组消息排序而延迟；唯一 completing WRITE/ATOMIC 等全部写入完成。
- 源端收到组内所有消息的确认前不得重用 group；资源耗尽、错误和管理清理有界。
- completing WRITE 的 header data、8字节以内非取回原子，以及优化头格式各自验收。

当前没有原生同步组 API 或同步组能力声明；各 Profile 声明保持关闭。
