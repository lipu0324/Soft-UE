# Clear与尚未返回的SES响应

§3.5.11.4.3定义CLEAR_PSN=X为源已经收到X及以前所有包的PDS ACK。
接收端的 `rx_pkt_map` 保留尚未向PDS提供任何SES响应的真实请求句柄。
收到字节、提供SACK信息、返回SES响应及完成整个应用消息，是不同的状态。

此前Clear只检查是否越过已连续收到的PSN；即使某个请求仍在等待SES，也会推进
`rx_clear_psn` 并发出ReceiveCleared事件。这个事件可令异步SES提前退休Incoming。
`clear_processing_safety_test` 的旧版本负例已复现该推进，日志为
`/tmp/softue-clear-processing-before-tests.log`。

当前对这种源尚不可能拥有相应ACK的Clear采用防御策略：如果拟推进区间内仍有尚未产生首次响应的真实
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

## READ重执行期间的合法Clear

§3.5.17允许不缓存READ数据ACK，只保留其PSN。丢包恢复再次交给SES执行READ时，
会产生一个新的RX句柄；但源可能已经收到早先的ACK。因此，不能把所有活动句柄都当成
“尚未产生首次响应”。直接忽略这次合法Clear会丢失清理事实；直接应用则可能先退休
仍在执行READ的SES所有者。

PDC现在用 `uncached_read_responses_` 区分这两种情况。首次响应尚未产生的Clear仍被
拒绝；已产生过READ数据ACK、但正在重执行的区间，把最新合法前沿保存在
`deferred_read_clear_`。当前句柄被真实 `txRsp` 消费后，重新经过同一Clear入口应用；
如果区间还有READ重执行，就继续等待。这个可选32位前沿归属于单个PDC，关闭时清空，
不增加目标数据缓存，也不要求源重复发送已经成立的事实。

新增4个RUD/ROD与32位序号边界场景，真实执行首次READ响应、重复请求、控制Clear和
第二次响应。负例 `/tmp/softue-read-clear-race-before-tests.log` 在旧守卫上失败；
修复后的Clear与RUD窗口两项普通回归2/2通过（0.01s），ASan/UBSan/泄漏检查2/2通过
（0.08s），日志分别为 `/tmp/softue-read-clear-race-after-tests.log` 与
`/tmp/softue-read-clear-race-asan-tests.log`。该内核测试现共20个场景，完整版本回归另行记录。

## 冻结版本完整回归

009ca6b的干净工作树完成全部构建后，普通完整回归120/121通过（114.64s），唯一失败是
上述旧窗口fixture；ASan/UBSan/泄漏检查119/121通过（740.70s），另有rendezvous事务
矩阵触发180秒CTest超时。日志分别为 `/tmp/softue-sync-clean-normal-tests.log` 与
`/tmp/softue-sync-clean-asan-tests.log`，不能记为完整通过。

同一冻结ASan二进制在无其他编译/CPU实验时单独完成448个rendezvous场景，87.53s、
exit0，无消毒器报告，记录在 `/tmp/softue-sync-rendezvous-budget-probe.json` 和同名log。
这证明该独立执行可以结束；完整回归超时的根因尚未证实，180秒预算保持不变。

修正窗口fixture的0c7be0e在GitHub run43519905515（workflow160）中，普通、消毒器及
独立参考作业全部成功。后续READ重执行修复9f01c57及RUDI线格式626248a的完整验收另记，
不把旧版本的二进制结果当作后续提交的证据。

后续946e0ec的完整干净回归126/126普通和126/126消毒器均通过，含9f01c57的合法READ
Clear暂存修复及新RUDI事务；详见 [RUDI完整回归](RUDI.md)。009ca6b的两项原失败和独立
测量仍保留，未把它们覆盖为通过。
