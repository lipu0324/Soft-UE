# PDC 与拥塞上下文的生命周期

PDC（Packet Delivery Context）负责可靠交付，CCC（Congestion Control Context）
负责拥塞准入和窗口。两者的生命周期相关，但不能把“已经创建连接”与“已经发送
数据”混为一谈。UE 1.1 §3.6.8.1.1要求首个PDC创建时分配CCC；最后一个PDC销毁后
可以释放，也可以保留NSCC拥塞状态缓存。

此前Soft-UE的NSCC在`can_send`或首次控制发送时才惰性建立CCC。现在PDS通过
`ICongestionControl::opened`显式绑定：

1. 发起端分配PDC后，已知peer、本地PDCID、起始PSN与delivery mode，立即绑定CCC。
   此时尚未运行事件循环，也可能还没有发出SYN。
2. 目标端从验证过的SYN确定对端身份、起点与模式后绑定，包括NOOP/Negotiation
   创建的控制连接。无效或trimmed SYN不会建立CCC。
3. 数据准入和发送继续通过同一CCC；控制流量只选路径，不扣数据窗口。
4. 正常Close、重试耗尽、应用关闭和对象析构都经过同一释放入口。最后一个使用者
   离开时释放CCC；本实现当前不保留空闲CCC缓存。

绑定键包含peer、本地PDCID、起始PSN和可靠交付模式，避免复用ID继承旧代次状态。
RUD在同一目的端共享窗口，ROD每个PDC独立；不能因初始PDC默认模式是ROD而把
尚未发送的RUD连接错误绑定到独立窗口。模式在分配时从原始请求传入。
目前主机配置只提供一个请求TC组；完整DSCP/TC映射与reserved pool另行跟踪。

目标端绑定CCC并不表示收到数据。RUD可能为SACK/MPR发送ACK_CC，但控制包本身
不会增加NSCC累计收到字节数，也不会产生数据采样记录。测试检查此计数约束，
不假定控制建连只能使用基本ACK。

`nscc_lifecycle_test`验证事件推进前的源端绑定、控制建连、RUD共享、ROD隔离、
跨目的端隔离、逐个释放使用者、PDC容量拒绝、永久SYN丢失后的释放、失败后重新
分配及第一次progress之前的应用关闭。独立CCC容量限制、RCCC/TFC关闭规则、
完整TC组和保留资源管理继续按M5/M7验收。
