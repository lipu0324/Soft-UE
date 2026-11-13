# libfabric tagged 消息

RDM 端点提供 `fi_tsend/tsendv/tsendmsg`、`fi_trecv/trecvv/trecvmsg`、
`fi_tsenddata` 与 `fi_tinject/tinjectdata`。查询公布 FI_TAGGED 和全部64位
`mem_tag_format`；DGRAM 端点不公布 tagged 能力。所有操作仍进入原生 SES/PDS。

接收项由 tag、ignore bits 和应用 context 描述。provider 为应用缓冲区创建仅供本地
放置的临时注册，不把地址或这个 key 发送给 peer。SEND 和 Tagged 的接收项分别
消费；精确和通配 tagged 项共同遵守软件投递顺序。公开接口当前接受任意源
FI_ADDR_UNSPEC；原生 API 的 Job 内 rank 匹配不等于已经提供 FI_DIRECTED_RECV。

## 完成队列与内存所有权

FI_CQ_FORMAT_TAGGED 返回 `fi_cq_tagged_entry`，其中 flags 为 FI_TAGGED|FI_RECV
或 FI_TAGGED|FI_SEND。接收完成的 tag 是实际消息的64位值，包含忽略位。
`fi_tsenddata` 的 header data 附在接收完成上，并设置 FI_REMOTE_CQ_DATA；即使
数据值为零，也保留这个标志。错误 CQ 保留 context、buffer、实际 tag 和 data；
截断的 len 为实际放置量，olen 记录未放置的原始长度。

内部保存完整 tagged 项，再根据队列格式分别复制到 CONTEXT、MSG、DATA 或 TAGGED
格式，不能把较大的结构直接写进 DATA 格式的应用数组。普通 SEND/RMA/原子 CQ
仍使用各自 flags。

普通发送的应用缓冲区保持有效直到完成。inject 在返回前复制至多256 B，随后应用
可以修改原缓冲区；其正常成功不产生发送 CQ。接收缓冲区保持有效直到完成，并在
最终完成/错误后撤销临时注册。

## 模式、generation 与恢复

Tagged SEND 使用 §2.2.6/Table2-29 的 SEND ordering 谓词选择 RUD/ROD。provider
的保守 FIFO 等待前一操作真正完成，包含语义重试，保持 FI_FENCE。

peer generation 以 `{peer,ResourceSpace}` 保存，Tagged、SEND 和 RMA 三类分别
恢复，不能共用一个“消息类/内存类”布尔位。BAD_GENERATION 更新对应空间的代次；
NO_MATCH 隐藏中间尝试，使用新 MID 重试，直到成功或达到现有恢复上限。PDS 负责
已执行消息的响应重放，重复报文不能再次消耗接收项。

PEEK/CLAIM/DISCARD、multi-receive、FI_DIRECTED_RECV、tagged atomics、rendezvous
和优化头需要各自的状态机，当前接口明确拒绝尚未实现的调用，不据此声明 Profile
完成。

`libfabric_tagged_test` 经公开 fi_* 与原生对端检查三种调用、0/MTU边界/多包消息、
实际 wire mode、完整 tag 与 CQ data、通配 FIFO、SEND隔离、inject所有权、分空间
代次、丢失响应、迟投递、截断以及已知 key 不能直接写入私有 tagged 接收注册。
实际通过结果记录于该提交的验证报告。
