# 从 PDS 发送到 NSCC 反馈

NSCC（Network-Signaled Congestion Control，网络信号拥塞控制）属于 CMS。PDS 决定
一个包应否重传、包的 PSN 和重复消除；CMS 决定当前窗口能否准许它发送。这两类状态
通过 `CMS::ICongestionControl` 连接，继续使用原来的 IPDC/TPDC 内核。

依据：UE 1.1 §3.6.8～3.6.13、§3.6.16，ACK_CC 格式见 §3.5.10.8。
当前这是 M4 的实现增量，尚未完成 M4 或任何 Profile 的验收。

## 两种计数为什么不同

发送端每次实际准入数据包，按以下大小增加 `inflight_bytes`：

```text
nominal_packet_size = transport_packet_size + 40
```

原生 IP 的 transport 长度从 entropy header 到 UET trailer；UDP 封装使用 UDP
length，包括 UDP header。增加的 40 字节是标准规定的名义开销，与实际 Ethernet/IP
头总长不是同一个量。接收端与发送端必须使用一致的计算方式。

接收端只在 PDS 接受新的完整数据包时增加精确的累计字节数。ACK_CC 返回：

```text
received_byte_units = ceil(total_accepted_bytes / 256) mod 2^24
```

不能分别对每个包向上取整再相加。源端对 24 位计数做模比较，忽略旧 ACK 与重复
ACK，再把新增单位乘 256 反馈给共享窗口。取整和反馈乱序可能使 `inflight_bytes`
暂时为负，因此它是有符号整数，不能在零处截断。

ACK_CC 的 32 字节 PDS 头包含基础 ACK、MPR、SACK 和八字节 NSCC state。编码器
逐字段使用网络字节序；NSCC state 包含 service time、接收窗口惩罚/恢复、24 位字节
计数和可选乱序计数。当前乱序估计明确编码 `0xffff`，表示未提供该可选估计。

## 窗口真正限制在哪里

`PDC::hasPendingWork()` 和两个 PDC 角色的发送分支同时检查 PDS 窗口与 CMS 准入。
CMS 阻塞的请求不会让事件循环在同一虚拟时间持续轮询；ACK、NACK、定时事件和关闭
仍可推进。ACK 到达后，CMS 的唤醒只安排后续事件，不递归进入协议内核。

RTO 或推断丢失先移除该发送尝试的在途贡献，再等待 CMS 窗口。等待期间不增加重试
计数，不启动下一次 RTO。重传实际准入后才重新增加在途字节和启动 RTO。PDS 使用
已经缓存的 payload，不重新读取应用缓冲区。一个发送尝试的 NACK/丢失记账只执行一次。

如果收到数据确认但语义响应尚未到达，PDS 保留语义恢复状态，并用 ACK Request
查询接收端缓存。重复发送已经确认的数据会在源端重复增加在途字节，而接收端重复
消除不会再增加累计新字节；因此这条恢复分支必须与真正的数据丢失区分。

## 拥塞上下文与路径

CCC（Congestion Control Context，拥塞控制上下文）保存窗口和 NSCC 算法状态；
每个 PDC 另存自己的接收字节计数历史。当前明确使用数据 TC 0、控制 TC 1：

- 同一目的端的 RUD PDC 共享一个 CCC，并对数据包选择递增的 entropy，实现 oblivious
  spraying，不宣称实现了 path-aware ECN 避让。
- ROD PDC 各自拥有 CCC，数据发送与重传保留同一个 entropy。
- 关闭一个 PDC 会移除它在共享 CCC 中的有符号记账贡献；最后一个使用者退休后释放 CCC。

算法主体包含四种 ECN/延迟响应、基于 RTT 的最大窗口调整、fair/proportional/fast
increase、multiplicative decrease、quick adapt、接收窗口惩罚与恢复。配置时间统一使用
整数纳秒；涉及比例的运算使用 double，窗口赋值向零取整，至少保留一个名义 MTU。
`delay ~= 0` 的本地实现策略是 128 ns 容差。延迟平均值采用最近一个测得 base RTT 内
样本的算术平均。它们是明确的数值/采样策略，不是新增的规范常数。

RTT 样本结合最后发送时间、重传次数、ACK RETX flag 和 service time 判断有效性。
零 service time 被忽略，饱和值不用于精确 RTT 测量；不确定的样本仍处理字节确认。
Fabric 提供目的链路的首字节到达时间，PDS 在生成 ACK 时估计 service time。发送端
时间戳和 ACK 生成时间目前位于 PDS/端口边界；端口排队很长时尚不能保证 MAC 测量
精度目标，实时 socket 也不宣称提供真实 MAC 硬件时间戳。

## 交换机队列与 ECN

每条有向链路有八个独立容量的流量类队列，容量包含正在串行化的帧。默认每类
64 KiB；`LinkConfig::buffer_bytes` 是每类的容量。调度采用可配置权重和 byte quantum
的 deficit round robin，以字节分配服务，避免短控制包与长数据包按包数竞争。

`ecn_threshold_bytes[tc]` 为空表示关闭标记，零表示对每个 ECT 包标记。出队时按该类
当前字节占用检查阈值，只把 ECT(0)/ECT(1) 改成 CE；Not-ECT 保持不变。IPv4 校验和
相应更新，UET CRC 的保护范围不需要因 ECN 变化而重写。接收端在 ACK 的 M flag
反射触发包的 CE。链路掉线会丢弃排队帧，并用链路 generation 防止已中断帧在恢复后
重新出现；这是一项可观察的模拟器故障策略。

## 使用与验证

所有参与同一 NSCC 实验的端点都应在提交操作/建连之前显式配置：

```cpp
auto congestion = UET::CMS::NsccConfig::for_link(
    12000,             // 最长空载路径 RTT，ns
    12500000000ULL,    // 源端 100 Gb/s，单位 byte/s
    12500000000ULL,    // 目的端速率，单位 byte/s
    1128);            // 1024 字节 WRITE payload 的原生/CRC 名义 MTU
host.enable_nscc(congestion);
```

名义 MTU 必须覆盖实验中最大的语义头、扩展头及 payload。UDP、不同 payload MTU 或
原子扩展头需要重新计算，不能直接复制示例数值。NSCC 当前须显式开启，便于
与尚未配置 CMS 的旧测试、实时适配器和参考实现分别进行实验。

```sh
ctest --test-dir build/cmake -R 'nscc|fabric_congestion|uet_wire' --output-on-failure
python3 scripts/test_large_message.py --binary build/release/streaming_payload_test \
  --output build/large-message-nscc --nscc
```

算法测试独立检查四种 ECN/延迟方程、负在途数、24 位计数回绕、RTT 有效性、接收窗口
惩罚与 quick adapt。协议测试检查一个包窗口的真实阻塞、RUD/ROD 数据与语义响应恢复、
共享 CCC 和状态释放。线格式测试用手写黄金字节检查 ACK_CC 八种封装/CRC 组合。
队列测试检查出队标记、Not-ECT、IPv4/IPv6、独立容量、不同包长下的字节公平和断链代次。
流式测试另覆盖 NSCC 下的多 MiB WRITE、真实数据丢失和仅在首次发送前取消的 PDC。
完整 4 GiB−1 NSCC 命令需要跨越一次 24 位接收字节计数回绕；夜间工作流分别保存
NSCC 开启和关闭两种运行的报告。命令和工作流的存在不代替实际运行记录。

仍需完成：合规 trimming、完整 Probe/base RTT 初始化、MPR/SACK 与所有控制路径的
联合验收、控制路径 entropy 完整覆盖、端口/MAC 时间戳细化、incast/竞争流/不对称路径
验收与场景配置输出。RCCC、TFC、CSIG 和其他 Profile 的相关路径在后续阶段实现。
