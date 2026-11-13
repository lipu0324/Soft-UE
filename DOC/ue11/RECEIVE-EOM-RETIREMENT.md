# 乱序消息必须等真正的 EOM 被 Clear

RUD 允许不同 PSN 的分片乱序交付给 SES。`received == total` 表示全部字节已经放置，
却不意味着当前回调处理的分片就是消息末包。例如三包 WRITE 的线上 PSN 为
`N,N+1,N+2`，EOM 在 N+2；若 SOM/N 最后到达，它是最后一次放置，但不是 EOM。

原实现在完成放置时把 `completion_psn` 改成当前包 N。现在该字段明确命名为
`end_of_message_psn`。随后对端合法地只 Clear 到
N，SES 就把完整消息记录回收，尽管 EOM/N+2 尚未被 Clear。这会过早丢失错误、
匹配和消息身份状态，破坏后续重复/响应恢复的生命周期。

修正沿用收到 EOM 时保存的 PSN，完成放置不再覆盖它。应用完成、字节覆盖与协议
状态退休是不同条件：前两者完成后仍要等真正的 EOM 被 Clear，或等对应 PDC 关闭。
参照 §3.4.2.14 与 §3.5.11.4.3。

`receive_eom_retirement_test` 经真实 SES/PDS/Fabric 延迟 SOM，让 EOM 先到达，捕获
真实生成的 Clear CP，再分别注入只到 SOM 和到 EOM 的 Clear。WRITE、SEND 和
Tagged SEND 都必须在第一步保留消息记录、第二步释放。基线的 WRITE 在第一步
实际失败；修正后的三条路径通过。该回归专门验证接收状态退休，不把关闭时取消的
源操作计作成功完成。
