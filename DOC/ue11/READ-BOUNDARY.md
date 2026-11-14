# 4 GiB−1 原生 READ 的实际边界证据

四个实验均在干净提交 `0be66b0f123827a3fb9550dd9802927c1e5fb998` 的独立 Release
构建运行。该提交包含多包 READ 两种载体与有界结果窗口；之后的 provider 映射
不参与本实验。二进制 SHA256 为
`4d28fe3b75772024fecbb4cd0eb501b17c461cd96ac2eab5b83eedb520cd75b7`。
脚本核对可执行文件嵌入的提交与干净状态，拒绝用当前 HEAD 为旧二进制背书。

| 返回载体 | 拥塞控制 | 结果 | 执行器墙钟秒 | 子进程峰值 RSS KiB |
|---|---|---|---:|---:|
| 同一 PDC 反向 Request | 关闭 | 通过 | 82.847 | 11264 |
| 同一 PDC 反向 Request | NSCC | 通过 | 106.218 | 11264 |
| 数据 ACK，阈值=MTU | 关闭 | 通过 | 61.265 | 11264 |
| 数据 ACK，阈值=MTU | NSCC | 通过 | 94.014 | 11392 |

每个实验都实际读取4294967295字节，产生524288次唯一结果放置。每次放置均逐
字节核对，包括三个稀疏标记、其余零字节，以及应被清除的两个旧缓冲区字节。
这里的片段数来自真实放置回调，不是根据总长推算后当作测量结果。

共同观测结果：源端生产队列峰值8，待结果窗口峰值8，目标 READ 包占用峰值8；
源/目标各一个合并覆盖区间，MR 各最多三个已分配页。1 MiB链路队列没有丢包，
实际远端读取次数等于唯一放置次数。应用只收到一次成功，完成长度正确；两端
消息、READ 包/返回记录和定时器在收尾后排空。NSCC 的反向 Request 数据量超过
24位累计收到字节计数范围；数据 ACK 不属于该请求字节计数。

这是协议正确性、消息长度边界和有界状态证据。表中的时间/RSS来自本次 Linux
执行器，不能解释成硬件吞吐或 FEP 实现的资源需求，也不代表任何 Profile 完成。

## 复现与日志

在干净源码重新配置并构建 `streaming_read_test`，依次执行
`scripts/test_large_read.py --binary build/release/streaming_read_test --output DIR`，
分别使用无附加参数、`--nscc`、`--ack-data`、`--ack-data --nscc`。
完整配置与校验约束见 [READ](READ.md)。

本次报告保存在工作区：

- `build/read-boundary-return/{report.json,streaming.log}`
- `build/read-boundary-return-nscc/{report.json,streaming.log}`
- `build/read-boundary-ack/{report.json,streaming.log}`
- `build/read-boundary-ack-nscc/{report.json,streaming.log}`

报告包含完整命令、规范与二进制哈希、源提交、每项实际计数，以及执行器资源
测量。生成报告不进入版本库。夜间工作流已增加这四个组合，但本文件的通过证据
来自上述实际本地执行，未声称夜间任务已经运行。

开发中出现的小队列失败来自校验器错误地要求按序放置：64 KiB队列尾丢失后，
原 READ 重执行的数据 ACK 可以晚于后续片段。独立校验器改为最多8个片段编号，
并在默认 CTest 中保留64 KiB丢包恢复回归；正式无丢包边界实验显式使用1 MiB队列。
原失败日志保留在 `/tmp/softue-streaming-read-focused-tests.log` 和
`/tmp/softue-streaming-read-focused-tests2.log`。
