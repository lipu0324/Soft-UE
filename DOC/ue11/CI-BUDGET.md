# CI 编译与测试预算

任务 `simulation` 的预算由15分钟调整为30分钟。它包含完整编译、测试、需求清单
验证和证据上传；这个执行器墙钟预算不影响协议的注入时间、RTO 或测试通过条件。

已保留的运行 [43460972612](https://github.com/lipu0324/Soft-UE/actions/runs/43460972612)
对应 `b900e71`：普通任务及 reference-wire 成功，ASan任务为 **cancelled**。其日志
显示16:16:10开始编译、16:27:08开始测试、16:31:14报告81/81通过（244.79秒），
紧接着 operation canceled；任务预算为15分钟，随后清单检查被跳过。不能把“测试
输出通过”写成整个工作流成功，也不能通过删测、并行实时用例或放宽断言解决预算不足。

同提交在干净本地工作树、停止所有编译器后，provider/reference启用的95项普通测试
全部通过（97.18秒），ASan/UBSan/leak全量95项通过（419.33秒）。不同执行器的耗时
分别记录，不作为硬件吞吐或协议延迟指标。新的30分钟工作流结果须单独确认。

## Rendezvous 矩阵的单项时间预算

冻结提交 `2c57040a63a63f5830ae5f2047a9c36e9cd5980f` 的完整普通回归105/105通过，
耗时115.19s；完整ASan/UBSan/leak回归104/105通过，耗时523.70s。唯一未通过项是
`rendezvous_transaction_test` 达到原60s的CTest限制，原日志保留于
`/tmp/softue-rendezvous-clean-asan-tests.log`，不能记为整套全绿。

随后在没有其他编译器/CPU实验时，直接运行同一个干净提交的消毒器二进制，完整
448个场景与全部断言通过：墙钟107.7876s、用户CPU103.7443s、系统CPU3.8582s、
峰值RSS494432KiB。二进制SHA256为
`6425cf31dc67dc139ad205c96aea5e366745e822a6674b70d9512f64177c9dbb`，记录为
`/tmp/softue-rendezvous-transaction-asan-budget-probe2.{log,json}`。

因此仅将此矩阵的CTest预算设为180s，保留原消息长度、MTU、组合与断言。
这解决执行预算，不替代后续提交的完整回归，也不将原超时改写为成功。
