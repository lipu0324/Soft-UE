# softue libfabric 实验适配器

`softue` 是可被 libfabric 2.0 动态加载的 provider。它把公开 `fi_*` 调用映射到
原生 `SES::Endpoint`，继续经过已有 PDS/IPDC/TPDC 内核。网络实验使用无特权 UDP
帧隧道：外层 UDP 的 payload 是完整 Ethernet/UE 帧，可靠性来自 PDS。
此适配器不声明任何 UE Profile 已通过验收。

## 构建和独立进程验证

```sh
cmake -S . -B build/provider -DSOFTUE_ENABLE_LIBFABRIC=ON \
  -DSOFTUE_PROVIDER_LIBFABRIC_ROOT=/path/to/libfabric-2.0-prefix
cmake --build build/provider --target softue_fabric libfabric_provider_peer libfabric_datagram_peer -j2
ctest --test-dir build/provider -R 'libfabric_.*processes' --output-on-failure
FI_PROVIDER_PATH="$PWD/build/provider" FI_PROVIDER=softue fi_info -p softue
```

安装前缀包含 `include/rdma` 和 `lib/libfabric.so`；也支持使用已经构建的
libfabric 2.0 源码目录（库位于 `src/.libs`）。普通仿真构建不依赖 libfabric。

`libfabric_provider_peer.c` 只包含公开 libfabric 头文件，没有链接原生 SES API。
两进程测试覆盖插件发现、在 endpoint 创建前注册 MR、实际应用缓冲区写入、
多包 WRITE IMM、SEND 往返、512 元素的批量整数 SUM、原子能力查询、远端 CQ data、
非法 key 和仅允许本地写的 MR 拒绝远端写。独立的 DGRAM 应用验证 UUD、1 MTU
边界和本地发送完成；不由发送完成推断远端收到。

## 当前接口边界

| 项目 | 当前行为 |
|---|---|
| Endpoint | `FI_EP_RDM` 或 `FI_EP_DGRAM`；每个 domain 一个 endpoint；域间状态独立 |
| 线程和 progress | `FI_THREAD_DOMAIN`、手动 progress；应用串行调用域内 API；`fi_cq_read/readerr` 推进 socket 和协议定时器 |
| 消息 | `fi_send/recv`、单 iovec 的 `sendv/recvv`、`sendmsg/recvmsg`；接收缓冲区先投递 |
| 长度和缓冲区 | RDM 宣布最大消息为 4 GiB−1；SEND/WRITE 按需读取应用缓冲区，应用须按 libfabric 规则保持其有效且稳定直到完成；原子查询上限单独返回 |
| RMA | `fi_write/writev/writemsg/writedata`；实际注册的 host 缓冲区；地址是 MR 内的零基偏移 |
| 原子 | 非取回 `fi_atomic/atomicv/atomicmsg`；8/16/32/64 位有符号/无符号整数；逐元素原子性和标准能力查询 |
| DGRAM | SEND/RECV 映射到 UUD；最大 1024 字节；仅本地发送完成，无 PDC/确认/重传 |
| 完成 | CONTEXT/MSG/DATA CQ；可靠成功依据整条消息语义完成；WRITE IMM 产生独立远端 CQ data |
| 访问权限 | 仅 `FI_WRITE` 不授予远端写；`FI_REMOTE_WRITE` 才授予相应 MR 权限；撤销使 key 立即失效 |
| 地址和 key | `FI_AV_TABLE`、数值 IPv4 `FI_SOCKADDR_IN`、provider 分配的 64 位 key |
| 资源生命周期 | 父对象仍有子对象、AV/CQ 仍被 endpoint 绑定、endpoint 仍有未完成发送时，关闭返回 `FI_EBUSY` |

外层 socket 的端口号在本适配器内用作该端口存活期间的 FEP 数字 ID，内层地址由
`PdsHost` 生成。这是明确的实验地址映射，不是 UE 地址发现协议。同一实验中的对端
端口号必须唯一；相同 ID 映射到不同 socket 地址会被拒绝。通过 `fi_getname` 获取
实际分配的地址，再加入对端 AV。实验不要求 root 或 raw socket。

READ、取回原子/CAS、浮点原子、tagged、inject、directed receive、
多 iovec、自动 progress、等待对象和选择性完成尚未实现，不会在发现结果中宣称这些
能力。未实现的方法返回明确错误。消息的恢复性 SES 错误重试、接收截断错误的完整
API 映射和更多 operation flags 仍属于 M3；当前测试不代替 libfabric 全套一致性验收。

## 阅读代码的顺序

1. `get_information()` 描述应用可依赖的能力；不要按函数指针是否非空推断支持范围。
2. `register_memory()` 把本地指针封装为受检存储；线上仍只有 key 和偏移。
3. `submit_operation()` 把 SEND/WRITE 转成原生操作，并保留应用 context。
4. `progress()` 驱动同一协议内核，再把原生完成转换为 CQ entry 或 error entry。
5. `close_object()` 检查父子关系并依次关闭 SES、PDS 和端口，取消其定时器。

整数原子操作目前只在 little-endian 主机平台上公布能力；标准线格式中的操作数逐元素
转换为 network byte order，注册缓冲区中的整数保持本机表示。官方参考进程的 SUM
测试独立验证这一边界；普通 SEND/WRITE 数据不进行这种转换。

`Runtime::Trace` 在 provider 中显式关闭，避免长期应用累积实验轨迹。独立仿真仍保留
有上限的结构化 trace；文本协议诊断可通过 `Services::diagnostic_output` 接入流。
