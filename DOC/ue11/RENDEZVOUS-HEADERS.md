# Rendezvous 扩展头：线格式基础

§3.4.3.4 / Figure3-21 的扩展头紧跟44字节标准请求头，总长24字节。本文描述
编码器基础；原生事务、源 MR、eager/READ 双完成与能力边界见 [RENDEZVOUS.md](RENDEZVOUS.md)。

| 扩展头内字节 | 字段 | 用途 |
|---|---|---|
| 0–3 | `eager_length`，32位 | 本次请求最多推送的 eager 数据长度 |
| 4–7 | `read_ri_generation` / `read_PIDonFEP` / `read_resource_index`，8/12/12位 | 后续 READ 按原值使用的源资源地址 |
| 8–15 | `read_offset`，64位 | 原消息起点在受检源 MR 内的偏移，可用于读取整个消息 |
| 16–23 | `read_mem_key`，64位 | 授权后续 READ 的内存 key |

`UetWireCodec` 显式按网络字节序编解码，不复制 C++ 位域。0x06/0x0a 的每个分片
都携带扩展头，SOM/EOM 不改变它的位置；发送时缺少 rendezvous 类型或误用 atomic
扩展会明确失败。地址与 key 在这里仅是数值，后续必须经过 MR、Job、权限和边界检查。

`rendezvous_header_test` 的24字节黄金向量独立抄自 PDF page index230 的原图，覆盖
SEND/TSEND、SOM/非SOM、IPv4/6、UDP/native IP、CRC 开关的32个组合，以及逐字节
截断和错误扩展类型。旧编码器缺少24字节扩展的失败已保留；修复后此测试与现有
`uet_wire_test` 通过 CMake/CTest，另有独立编译的 ASan/UBSan/leak 检查。
这些是线格式证据，不表示 eager 上限、源 MR 生命周期、READ 数据交付或应用完成已验收。

完整事务还需同时等待 eager 消息完成和 READ 返回数据被确认。尤其 ACK_DATA 的读取
结果允许重读，不能在第一次生成响应时就报告 rendezvous 源端完成；standalone 返回
数据则须等真实反向 PDS 确认。两条路径和两种完成先后顺序都应分别测试。
