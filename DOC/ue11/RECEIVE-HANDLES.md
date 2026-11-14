# 一次 SES 执行与一个线上 PSN 是不同的身份

READ 可以在丢失 data ACK 后以相同 PSN 再执行一次（§3.5.17）。它仍属于同一个消息、
同一个 PDC 和连接代次，但两个本地执行不能共用回调句柄。否则第一次执行的迟到
SES 响应就可能消费第二次执行的 RX 状态。

| 身份 | 拥有者与用途 |
|---|---|
| application operation ID | Endpoint 的应用 CQ 和取消操作 |
| 线上 MID | STD 消息；SMALL/MEDIUM 没有这个字段 |
| PSN | PDC 连接中的一个线上包；重传与 READ 重执行可以重复它 |
| `ReceivePacketHandle` | 本地一次已接受的 SES 执行；不编码到 UE 报文 |
| 目标 READ response token | 反向返回包的本地提交与确认关联；是另一个命名空间 |

## 复现的别名问题

原 `PDC::setRXhandle` 返回16位值，实际只留下 PSN 的低16位；拼接的 PDC 高位被返回
类型截掉。即使没有序号回绕，同一个 READ PSN 的合法重执行也立即重复句柄。
`/tmp/softue-receive-handle-before2-tests.log` 记录：先完成一次 READ，重执行该 PSN，
再交付旧 SES 响应，新的 RX handle 被消费。该 probe 使用原 T_PDC 的 READ replay、
响应与缓存路径，不通过应用层伪造传输完成。

另一个独立 PDS 消费者故意保留已接受的上行请求，令旧连接真实重试耗尽、关闭，再
在只有1个 target PDC 槽时复用编号。旧请求仍在公共 PDS-to-SES 队列中；原 pop 接口
把它交付给新的消费者，见 `/tmp/softue-stale-semantic-queue-before3-tests.log`。
测试保留默认 plaintext SYN 安全等待，没有把超时或 Close 前沿直接改成完成。

## 实现与边界

`Services::receive_handle_allocator` 在每个存续 Host 内为一次执行分配新的64位本地
标识，跨 PDC 实例、连接代次和 PSN 回绕保留历史。`rx_pkt_map`、SES/PDS 请求与响应
及关闭去重集合都使用命名类型 `ReceivePacketHandle`。已经完成或退休的旧句柄不会
重新绑定新执行；删除不用的旧 PSN 拼接 helper，避免后续代码误用。

0保留，全1值表示无有效句柄。分配空间耗尽时，PDS 在申请 SES 消息资源、接受 PSN
和接收记账前返回 `UET_NO_PKT_BUFFER`；直接绕过准入的本地低层调用明确抛出耗尽，
不回绕。这个64位分配与耗尽策略是仿真器的本地策略，不是新增的线上字段或安全密钥。

`PDSProcessManager::popSESRequest` 在注入运行时中重新核对 PDC、peer、mode、连接
代次、真实 RX handle 与原 PSN。原 PDC 已关闭或执行已退休的排队上行请求被丢弃，
不会进入新 SES，也不会选择其 MR。无状态 RUDI/UUD 使用各自既有路径。

没有注入 Services 的 legacy 适配器使用 PDC 对象本地的分配器；本轮 Host 跨实例保证
针对注入运行时，包含仿真与 PdsHost 实时适配。完整 legacy 硬件生命周期不据此声明。
这是本地 C++ 接口类型变更，自定义 SES/PDS 适配器需要重新编译，并以命名类型或
`auto` 保存句柄，避免缩窄成16位；标准 UE 线格式保持原样。

## 验证范围

初始三项普通 CTest 通过（0.07s），日志
`/tmp/softue-receive-handles-queue-normal-tests3.log`：

- `receive_handle_lifetime_test`：4个 RUD/ROD、PSN0/MAX 的同 PSN READ 重执行。
- `receive_handle_boundary_test`：6个宽于32位的句柄、PDC 复用、错误 peer/代次/PSN、
  最后有效句柄和准入前耗尽场景。
- `stale_semantic_queue_test`：2个实际报文、重试耗尽和同编号 PDC 复用场景；独立
  消费者只负责网络适配与延后读取 SES 队列，全部恢复与关闭仍由原 PDS 执行。

更广的生命周期与线格式用例通过 `softue_lifetime_regressions` 构建目标和 CTest 的
`ses_lifetime` 标签选择；普通与 sanitizer 的最终结果另行记录。上述定向结果不等于
完整 M1、管理重启代次或任何 Profile 完成。

已有 Clear/reexecuted-READ 竞态用例也改用命名句柄类型，注入大于32位的执行标识，
确认有效 Clear 在第二次执行期间仍会等待真实响应并正常回收。

固定、干净的 `8f4bccb156c1c124f5885aadc95c8db36c36c52b` 已完成29/29普通
（83.15s）和29/29 ASan/UBSan/泄漏（420.22s），报告
`/tmp/softue-receive-handles-lifetime-report.json`。先完成两套构建及宽 Clear 重建，
停止编译，再顺序执行两套 CTest。集合还覆盖66000次实际原子操作、消息号回绕、
完整原生 READ 故障矩阵和独立黄金报文；仍不替代整个本地完整套件。
