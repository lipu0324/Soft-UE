# Clear与尚未返回的SES响应

§3.5.11.4.3定义CLEAR_PSN=X为源已经收到X及以前所有包的PDS ACK。
接收端的 `rx_pkt_map` 保留尚未向PDS提供任何SES响应的真实请求句柄。
收到字节、提供SACK信息、返回SES响应及完成整个应用消息，是不同的状态。

此前Clear只检查是否越过已连续收到的PSN；即使某个请求仍在等待SES，也会推进
`rx_clear_psn` 并发出ReceiveCleared事件。这个事件可令异步SES提前退休Incoming。
`clear_processing_safety_test` 的旧版本负例已复现该推进，日志为
`/tmp/softue-clear-processing-before-tests.log`。

当前对这种源尚不可能拥有相应ACK的Clear采用防御策略：如果拟推进区间内仍有真实
RX句柄，则忽略整次非法推进，保留响应、窗口和SES所有权。有效的较短prefix仍可清理；
SES实际返回后，重发Clear正常退休响应cache。该检查在发ReceiveCleared事件之前进行，
对显式Clear和请求中的piggyback Clear使用相同入口。

`NO_RESPONSE` 已经是一个返回给PDS的响应，原逻辑会消费其RX句柄；它仍可被Clear，
也仍可按§3.5.13提升为DEFAULT。这不保证整个应用消息完成。同步atomic要等待组屏障的
最终请求保留真实句柄，不使用NO_RESPONSE。缓存完操作数时也不设置Incoming.completed；
该标志在真实动作完成并准备返回结果后才置位。

新增回归直接调用原I_PDC/T_PDC的接收控制、SES响应和Clear处理方法，覆盖RUD/ROD、
两种序号回绕边界、DEFAULT/NO_RESPONSE、合法prefix、保证响应cache退休及重复Clear，
共16个场景。它是内核状态测试；同步事务及两进程回归另外验证集成路径。

基于caa46fa的工作树改动通过同步及相关PDS的12/12普通针对性回归（0.65s）和12/12
ASan/UBSan/泄漏检查（8.09s）。日志分别为
`/tmp/softue-clear-processing-after-tests.log`、
`/tmp/softue-clear-processing-asan-tests.log`。完整版本回归另行记录；该修正不构成
Profile验收声明。

009ca6b的完整CI run43516970768中，普通作业有101/102通过，旧rud_window_test在Clear
断言处失败。该fixture手动调用响应计数辅助函数，却保留RX句柄。修正后通过真实txRsp
发送响应并核对句柄消费，保留所有窗口、保证响应和回绕断言。窗口/新Clear两项普通及
消毒器回归另行通过；原失败保留在
`/tmp/softue-clear-processing-ci-off-failure.log`。
