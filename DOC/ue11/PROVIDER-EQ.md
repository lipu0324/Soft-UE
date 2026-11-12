# EQ 控制事件队列

UE 1.1 §2.2.5.3.2 要求 provider 提供 EQ，并允许每个 endpoint 至少绑定一个。
EQ（event queue）承载控制事件；数据传输完成仍使用 CQ。两者有独立对象、操作表
和生命周期。

当前实现提供 `FI_WAIT_NONE` 下的非阻塞 EQ：

| 操作 | 行为 |
|---|---|
| `fi_eq_open` | 默认 256 条，配置至多 4096 条；EQ 是 fabric 的直接子对象 |
| `fi_eq_write` | 以 FI_WRITE 打开时支持；每条事件复制自己的 payload，至多 4096 字节；满队列返回 FI_EAGAIN |
| `fi_eq_read` | 每次读取队首一条；空队列返回 FI_EAGAIN；短缓冲区返回 FI_ETOOSMALL 并保留事件 |
| `FI_PEEK` | 读取队首而不消费；后续正常读取仍得到同一条 |
| endpoint 绑定 | 同 fabric，enable 之前绑定一个 EQ；多个 endpoint 可共享 |
| 关闭 | 仍有绑定时 EQ 返回 FI_EBUSY；仍有 EQ/域时 fabric 返回 FI_EBUSY |

FI_WAIT_UNSPEC 意味着调用者可能使用阻塞 sread。当前明确拒绝该请求，避免把它
静默变成不支持阻塞的 WAIT_NONE。等待对象、信号亲和性和异步管理控制生产者仍未
提供。MR/AV 当前同步执行，RDM 也没有连接管理操作，因此 EQ 没有启用异步错误
生产者，`fi_eq_readerr` 返回 FI_EAGAIN；未来管理/TSS 接入需要单独补齐错误队列。
普通访问失败继续按其操作语义进入 CQ，不被改写成 EQ 成功事件。

`libfabric_event_queue_test` 只包含公开 libfabric 头，验证加载后的实际 EQ API。
覆盖事件副本/FIFO、扩展 payload、PEEK、短读、容量背压、非法参数、同 EQ 绑定多个
endpoint、跨 fabric 拒绝、重复绑定、父子对象关闭顺序及明确拒绝阻塞请求。

这项支持补齐 EQ 的基础队列和绑定路径，不表示异步控制或完整管理层已经完成。
