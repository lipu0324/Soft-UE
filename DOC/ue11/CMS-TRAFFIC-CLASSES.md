# CMS 的数据流量类身份

§3.6.6 要求不同数据 TC 使用不同 CCC：一个 TC 的拥塞或信用不足不能阻止另一个
TC 的合法发送。源 RUD 的共享查询因此至少需要 peer+outgoing data TC；ROD 仍按
各自 PDC 实例独立分配。ACK/control 使用的反向流量类不作为该源数据 CCC 的 TC。

`CMS::Connection::traffic_class` 是本地源数据 TC，默认0，加入连接身份以及 NSCC/TFC
的源上下文 group key。TFC 的8位 CCC_ID 仍在一个 peer 的所有活动源 CCC 中唯一，
不会为不同 TC 各自复用相同标识符；目的继续按 source peer+CCC_ID 关联共享预算。

`cms_traffic_class_test` 直接在 CMS 接口上验证：

- 同 TC 的两个 RUD PDC 共享窗口/信用，不同 TC 独立。
- TC 0 用满 NSCC 窗口后，TC 1 仍能发送。
- TC 1 的累计 TFC 授权不能补充 TC 0；同 TC 另一成员收到的授权可共同使用。
- 关闭一个成员不会清除仍活动的其他 TC 或共享成员状态。

这份增量尚待固定版本编译验证。它只处理 CMS 分组身份，**尚未**把 Native Operation、
PDC 创建、NIC 排队和 DSCP/TC 配置贯穿连接。`PdsHost::enable_tfc` 仍显式限制 TC 0，
原有 Host 构造的 Connection 也默认 TC 0。因此不能凭这个单元宣布多 TC 端到端支持，
也不能把 CMS 直接调用测试称作网络隔离回归；后续还需统一配置与原 PDS/NIC 场景。

完整176项整合验证在另一份固定源 `6f4115d818d65eb75213ba1364df5a359ab76fde`
上进行，位于 `/workspace/Soft-UE-tfc-runtime`。该版本没有本文件所述 TC 字段增量；
即使176项通过，也不能作为这里新增第177项或多 TC 功能的证据。
