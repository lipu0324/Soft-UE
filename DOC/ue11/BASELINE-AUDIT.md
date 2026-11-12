# 基线审计与待完成项

审计基线为 Soft-UE `4a4e6d874909720097b1ae20302a538a97116976`、
uet-ref-prov `5b4e0491329b8e28764bca6847e2f6a0eaa84b9b` 与 UE 1.1。
这是首批实现的代码审计，不是完整 MUST 清单，也不是 Profile 验收报告。
完整条目状态见 [requirements.json](requirements.json)。

## 测试经过的路径

| 测试 | 实际路径及可以证明的内容 | 不能据此推断 |
|---|---|---|
| `packet_codec_test`、交互 UDP 测试 | 旧消息通道编码、重组、UDP 聊天与进程退出 | SES/PDS 可靠性、标准 UET 报文互通 |
| `ses_payload_test` | 原 SES 的拥有型 payload 到 PDS 出站报文 | 远端注册内存实际被修改 |
| `pds_runtime_loopback_test` | 已构造的 PDStoNET 报文经过队列适配器回环 | SES 发起与双方 PDC 完成语义 |
| `pds_process_loopback_test` | 上述回环由原线程进程管理器驱动 | 完整双端点事务 |
| `PDS_fulltest` | 原 PDS/IPDC/TPDC 的同管理器内回环与状态推进 | 标准线格式、严格自动化语义断言 |
| `pds_simulation_test` | 两个独立端点的原 SES/PDS/IPDC/TPDC，在虚拟时间上经过显式 legacy 编码 | UE 1.1 标准 SES 版本、真实 MR 权限 |
| `endpoint_test` | 新原生 SES 入口 → 原 PDS/PDC → 标准编码子集 → 仿真网络 → 原 PDS/PDC → 受检稀疏内存及语义响应 | AI Base 全部操作或完整 Profile |
| `pds_fault_test` | 以上实际协议路径上的 SYN/数据丢失、ACK/语义响应丢失、永久丢失、端口背压与关闭清理 | 所有 NACK、乱序、trimming、重连组合 |
| `simulation_scenarios` | YAML 拒绝、重复运行逐字节比较、PCAP 基本独立解析、IPv6/UDP、64 端点写内存 | 64 端点拥塞合规与硬件性能 |

## 原内核仍然存在的占位逻辑

下列事项必须在宣称对应标准功能前替换，并添加正向、负向和边界验证。
保留旧路径是为了回归；标准原生入口不会把这些占位校验当作 MR 授权。

| 位置 | 当前差距 | 处理门槛 |
|---|---|---|
| `SES/SES.hpp` 的 `validate_job_id`、`validate_rkey`、`validate_header_type`、`validate_data_length`、`validate_pdc_status` | 部分返回固定成功；旧版本校验使用 version 2 | M3 完成原 SES 与受检内存/能力服务的统一；当前 `SES/Endpoint.hpp` 独立校验所支持的子集 |
| `SES/SES.hpp` 的 `validate_msn` | 旧表按 JobID 建索引，不能作为多消息完整上下文 | M3 消息生命周期、并发及分片约束 |
| `PDS_Manager/PDSManager.hpp::checkRxPkt` | 原入口仅检查非空，不是完整的连接元组/头部验证 | M2 补齐管理器及上下文检查；新 wire decoder 的长度、保留位、CRC 检查不能替代它 |
| `PDS_Manager/PDSManager.hpp::checkUnexpectEvent` | 默认示例 NACK 原因，尚无完整错误分类 | M2 将错误原因和恢复行为对应到规范 |
| `PDS_Manager/PDSManager.hpp::rxPkt` | NACK 分发尚不完整 | M2 验证 NACK 的接收、重传及关闭；当前只声明 NACK 编解码 |
| `PDS_Manager/PDSManager.hpp::fwdRsp2PDC` | `nack_payload` 传播仍有 TODO | M2/M3 错误完成必须经过真实错误路径 |
| `PDC/TPDC.cpp` 的关闭/PSN 保存/校验及控制逻辑 | 有 TODO；关闭后的迟到报文、重连代次、序号全路径回绕未完成 | M2 连接生命周期退出条件 |
| `PDC/IPDC.cpp::rxAck` / `rxCtrl` | Close 请求的所有编码及分支未完成（包括旧代码的 `req == 0x10` 比较） | M2 标准控制报文、关闭 ACK 丢失与重用测试 |
| `PDC/PDC.cpp` 的 Credit、部分 Clear/Close 逻辑 | 信用和所有回绕边界未完成 | M2/M5 分别按 PDS/CMS 模式验证 |
| `SES/Endpoint.hpp::incoming_` | 已完成消息记录有上限，尚无完整协议退休/消息 ID 重用机制 | M2/M3；不能把顺利完成少量事务当作长期运行保证 |

本次已修复的原问题包括：两个 PDC ID 空间的数组越界、首个 TPDC 边界、
哈希碰撞导致的上下文混用、重复 ACK 记账、最后一个包的 ACK 清理、
选择性 ACK 丢失、已 ACK 的过期 RTO、语义响应丢失后的缓存重放、
控制包覆盖数据重传槽、窗口背压和仿真时钟下的空转。
这些修复各有回归测试，仍不代表对应整章要求已通过。

## 官方实现的使用边界

- 官方 README 明确 SES 是功能子集。其 `pds` 后端列出 RUD、ROD、RUDI、UUD；
  `sng` 是用于上层开发的 stop-and-go ROD，不能用于替代完整 PDS 验收。
- 官方 README 的 Congestion Control 节声明 NSCC 是基于 v0.6 的部分实现，
  多路径未完整支持。因此 M4 必须按 UE 1.1 重建要求与闭环测试。
- 共同支持的报文应在固定版本下做独立解析/差分及进程互通；目前尚未运行
  官方 provider 进程互通，没有把 codec 自往返测试记为互通通过。
- RODL/Unified Local、UE 1.1 新增路径不因参考实现缺失而从范围中删除。
- §3.3 与第 8 章 Profile 命名差异、表 3-4 与 §3.4.3.7 语义响应长度差异，
  已在 [IMPLEMENTATION.md](IMPLEMENTATION.md) 记录，不能用来宣称完整合规。

## 继续推进顺序

1. 完成 M0 全规范条目人工复核，把 729 个自动抽取候选区分为规范性、条件性、
   可选和资料性文字；提取数量不等于 MUST 数量。
2. 在现有虚拟运行时上完成 M2 的 ROD 生命周期、NACK、RUD、UUD 和官方共同路径互通。
3. 补齐 M3 的寻址、immediate、非取回原子、完成语义及真实 libfabric 2.0 provider。
4. 通过上述门槛后，实施 M4 NSCC 并验收 AI Base，然后依原计划推进 M5–M8。

当前环境没有 CMake、libfabric/libibverbs 开发依赖；包获取遇到代理 HTTP 503。
Make 仿真回归无需这些依赖。CMake/CTest、provider ABI、真实网络互通与硬件适配
仍须单独验证，不能记为已通过。
