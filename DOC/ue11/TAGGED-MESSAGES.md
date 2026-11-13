# Tagged send 的匹配与放置

`OperationType::TaggedSend` 对应标准 opcode0x09。它通过同一个 SES→PDS→CMS→网络
路径传输，复用 RUD/ROD 的分片、去重、响应恢复和 Clear，而不是在应用层另建消息通道。

## 三种身份各自负责什么

- `peer` 选择网络 FEP；`source_pid` 是本地进程标识，不是消息 rank。
- `initiator_id` 是 JobID 内的32位 rank（§3.4.2.3.4）。未提供时取 node ID，是仿真器的默认策略。
- `tag` 是全部64位匹配字段，不与 RMA 的 `remote_key` 混用。线上共用 match_bits 字段，
  由 opcode 决定其含义。

接收方调用 `post_tagged_receive(job,pid,key,offset,capacity,match,context,index)`。
`TaggedReceiveMatch{tag,ignore,initiator}` 中，ignore 为1的位不参与 tag 比较；
未指定 initiator 表示任意源。匹配条件为 `(received_tag ^ posted_tag) & ~ignore == 0`。
指定的 rank 始终在接收投递的 JobID 内解释，即使网络请求使用绝对 PID 寻址，也不能
让另一个 Job 的同号 rank 消耗该投递。

§3.4.2.3.5 要求 ROD 在所有匹配的接收项中选择软件最早投递的一项。因此实现使用
一条按投递顺序扫描的队列，较早的通配项可以先于较新的精确项匹配。RUD 也采用这个
确定性的策略；网络本身仍可能乱序。完成中的 `tag` 返回实际收到的完整值，包括被
ignore 忽略的位，而不是投递模板。

## 接收资源与内存权限

SEND、Tagged、RMA 是三个独立 ResourceSpace（§3.4.2.3.7）。它们可以拥有相同的
PID/index 数值，却有不同的 generation 和启用状态。未匹配的 ROD 消息可以进入有界
unexpected 存储；RUD 返回 NO_MATCH，应用须使用新消息重新提交。普通 SEND 的接收
投递不能恢复耗尽的 Tagged 空间，UUD 也不能消耗 tagged 接收项。

接收投递保存精确的本地注册身份。匹配后按该身份做权限与范围检查，注册撤销及 key
重用不能把消息重新绑定到新区域。截断产生目标错误完成并保持零放置。零字节 tagged
send 消耗一项接收投递，验证地址和权限，但不调用存储写入（§3.4.2.12）。header data
附着到这个接收完成，不生成额外 RMA 完成。

同一消息所有分片必须保留 tag；中途改变 tag 是 OP_VIOLATION。PDS 的重复消除和
保证响应重放确保丢失 ACK 或重复请求不会再次消耗接收项。

## 验证范围

`tagged_message_test` 覆盖精确/通配的共同 FIFO、部分位忽略、0/全1 tag与 rank、
Job 内 rank、三种资源空间和 generation、ROD迟投递、RUD NO_MATCH、零字节、截断、
注册撤销与 key 重用、乱序 SOM、重复请求、丢失响应和分片 tag 篡改，并验证关闭后的
消息记录、ID租约、缓冲和定时器均回收。实际结果以生成的验证报告为准。

固定版本参考实现的独立进程另验证双向 exact tagged send：线上 tag 为完整64位，
目标内存与 FI_CQ_FORMAT_TAGGED 中的 tag/flags/len 均检查。参考 SES/PDS 未修改；
其接收 API 明确拒绝 ignore bits，因此互通证据不包含通配匹配。

本增量是标准头原生 tagged send。公开 libfabric tagged 映射、tagged rendezvous、
优化头、multi-receive、tagged atomics、TSS 与 RODL 仍分别验收，不据此声明完整
AI Full/HPC Profile。
