# UEC_C / Soft-UE

当前协议核心来自 `https://github.com/lipu0324/Soft-UE`，导入提交为
`e139409838f52bf63ca0aab39998d68698fcb2da`。2026-09-25 导入了 `UET/src`，随后将预编译头与构建产物移出源码目录。

## 当前入口

```bash
make core       # 从源码构建 build/PDS_fulltest，不依赖 libfabric
make test-core  # 运行 PDS 软件测试，日志在 build/PDS_fulltest.log
make message-lib # 构建可链接的 build/libsoftue_message.a
make test-codec  # 编码、分片、错误包的无硬件测试
make test-ses-payload # 验证 SES 拥有的字节进入 PDStoNET 队列
make test-udp    # 两进程 UDP 消息回环
make test-rdma   # 两进程 mlx5_1 RDMA 消息回环
make test-pds-process-loopback # 正式 PDS 线程 TX/RX 内存回环
make test-pds-rdma-queue # PDS 队列桥接的 mlx5_1 RDMA 双进程回环
make check-env  # 检查当前机器的 RDMA 环境
```

新的 `SES::MessageEndpoint → PDS::MessageStream → PacketCodec → RdmaChannel`
已通过两进程、双向二进制消息回环；也可选 `UdpChannel`。
这是可运行的消息子集，尚未把旧 PDS 状态机和旧 libfabric provider 改接到该路径。
新 `PdsPacketCodec` 和 `PdsQueueTransport` 已把 `PDStoNET` 公共队列接到同一个
`PacketChannel` 抽象，支持显式 PDS/SES 头和拥有的 payload 字节。
`PdsQueueTransport::progress()` 提供一个共享超时预算的双向 progress 步进，
可由外部事件循环反复调用；它不创建每连接线程，空闲接收以 `PacketTimeout`
表示，真正的 verbs 或套接字错误继续抛出。
正式 `PDSProcessManager` 循环现在会自动驱动该步进；`setNetworkChannel()` 必须
在 `start()` 前调用。`test-pds-process-loopback` 覆盖线程循环，
`test-pds-rdma-queue` 覆盖真实 `mlx5_1` RC 队列。
旧 `uet_provider` 与新核心的 API 不兼容，不能使用旧的 `.so` 代表新代码的验证结果。
适配设计、验收步骤与实测记录见 [RDMA 适配评估](DOC/RDMA_ADAPTATION_2026-09-25.md)。

两台服务器上手工运行时，先在服务端启动 `build/rdma_message_test --server --port 18515 --device mlx5_1`，
再在客户端启动 `build/rdma_message_test --client --peer <服务端管理网IPv4> --port 18515 --device <本机活动设备>`。
TCP 只用于连接参数交换；消息走 RDMA。两端必须位于可互通的 InfiniBand fabric。

## 目录说明

| 路径 | 用途 / 当前状态 |
| --- | --- |
| `UET/src/` | 导入的协议核心及新增的 SES/PDS 消息子集、两种传输实现与测试 |
| `build/` | 新构建入口产生的二进制与软件测试日志，Git 忽略 |
| `scripts/check_rdma_env.sh` | 可用的环境检查入口 |
| `uet_provider/` | 旧 libfabric / RDMA 集成代码，保留参考，尚未接入新的消息接口 |
| `scripts/smoke_*`、`generate_nccl_regression_gate_report.sh` | 旧集成测试入口，依赖已移除的测试和旧 provider，暂不可作为新核心验收入口 |
| `scripts/env_local_rdma.sh` | 历史环境脚本；本机实际 libfabric 前缀是 `/home/user/opt/libfabric-2.3.1`，需显式指定 `UET_LOCAL_LIBFABRIC_PREFIX` |
| `Readme/` | 原项目介绍与架构图片；功能声明需结合当前评估理解 |
| `DOC/` | 协议资料、历史设计文档与当前适配评估 |
| `logs/` | 历史诊断与本次硬件自环测试日志；Git 忽略 |

根目录的 `README_rdma.md`、`RDMA_HARDWARE_PHASE_PLAN_2026-03-15.md`、
`NEXT_PHASE_PLAN_2026-02-14.md` 记录旧核心的开发过程，不代表新导入核心已具备这些能力。

## 本机恢复位置

- 替换前的完整 `UET/src`：`/home/user/UEC_C_UET_src_backup.ES7BxJ/src`
- 本轮整理移出的缓存、预编译头、旧动态库和根目录日志：`/home/user/UEC_C_cleanup_jselhljf/`
- 整理清单：上述目录的 `manifest.json`，路径相对本仓库。

整理采用移动归档，原文件仍可恢复。协议源码、历史诊断与设计资料保留，构建输出统一从 `build/` 开始管理。
