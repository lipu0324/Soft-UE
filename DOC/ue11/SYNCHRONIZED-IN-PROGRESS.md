# 同步事务接入笔记（未实现，不是能力声明）

基于 b76e340；标准头扩展 a4655a8 已整合。下一步仍属于 M5。
下面是规范检查和待实现接口，不可写成已通过的行为。

## 已复核的依据

- §3.4.2.5.5、§3.4.2.7.4、§3.4.3.6、§3.4.4.8、§3.4.9.6及Table3-31。
- 目标 key 为 {initiator FEP, sync_group16}；SHOULD核对最初Job。
- 组最多65534条非completing WRITE，加唯一completing WRITE(hd1)/ATOMIC(hd0)。
- completing sync_count为全部消息数，非completing必须0。不能误抄正文的含混一句为全部WRITE都0。
- 同步WRITE的payload在RUD下不能为了组内排序而延迟；完成通知/原子动作才是屏障。
- Table3-31 Case1：失败消息仍计数，不能让它取消或污染其他消息；变量应叫processed_messages，而不是successful_messages。
- Case2：目标必须age out缺失消息的组；已收到的completer不得完成或执行。
- Case3：completer的count小于当前已计数，报OP_VIOLATION。
- Case4：未等规定完成就追加的Y条WRITE必须OP_VIOLATION，不影响原X条。
- Case5：第二个completer失败，不能让它的失败计数提前触发第一个completer。

## 源接口方向

begin_synchronized_group(peer,job,total_messages)返回本地可信handle。handle含非零64位token、
Endpoint authority weak identity及16位wire group，wire0合法。Operation增加optional group。
SYNC_WRITE通过immediate_data决定是否completing；SYNC_ATOMIC天然completing。普通op拒绝group字段。
源在本地检查peer/job、成员数、唯一completer和datatype/rights/bounds，再走原submit_message。
每条操作保留自己的用户ID/CQ，组不额外制造CQ。

FEP Services保存32位next_synchronization_group_id cursor，防止16位wrap和Endpoint替换重置。
正常完成组可在Endpoint中回收wire ID；必须等全部成员真正确认。错误CQ可早于尾部/Clear，
所以需使用transport_pending检查，不能仅用用户CQ数释放group。未知失败/本地取消/超时保守隔离ID。
源组总deadline使用注入EventLoop；源组及成员表有明确资源上限，源handle跨Endpoint不可用。

## 目标方向

独立target group root保存peer/group/job、本地不可重用owner serial、processed_messages、唯一
completer身份/总数、计时器和关联PDC epoch。Incoming固定本地owner，不能只用wire group
查当前root，否则旧报文会混入重用后的组。

同步WRITE复用受检RMA放置、覆盖/SOM/EOM及first-error；每个已处理消息仅计数一次，
失败也计数。非completing可以正常ACK；completer的payload同样立即放置，header data通知
等组计数满足。SYNC_ATOMIC只缓存一个<=8字节整数非取回操作及精确授权MR，在屏障后
重新检查原注册再执行一次；不能按旧key绑定新MR。READ/CAS/masked swap、hd1原子非法。

completer先于其余成员且恰好是PDC首个SOM/EOM时，需及时返回NO_RESPONSE让PDS握手/进度
继续；最终结果复用同一真实handle，不能提前DEFAULT导致源成功。RUD不应阻塞后来的WRITE。

资源满必须是UET_NO_SES_SYNC_AVAIL(0x1B)，不能复用NO_SES_MSG_AVAIL(0x1A)。当前
SemanticAdmission只有Rejected，需扩展typed rejection并覆盖PDSManager及PDC两个准入入口。
组老化必须释放tracking预算，未执行completer不能迟到执行；其Incoming/PDS状态单独排空。
完成/已满组的早期追加、重用与跨PDC Clear可见性需独立审查和故障测试，不能把本地CQ
误当成对端已清理的事实。源先等Clear的保守策略不足以证明目标接受所有合法外部重用。

## 验收方向

真实PDS：WRITE/ATOMIC completer先/后到、RUD/ROD、NSCC、多peer同group数字、Job隔离；
失败成员仍计数/其他成员继续，count不足老化、不足/过量count、重复completer、非法字段、
MR权限/撤销复用、数据/ACK/控制丢失重复乱序、NO_SYNC资源恢复、group0/65535/耗尽及
Endpoint替换、正常/错误Close和源取消超时。验证一次动作/CQ、组与Incoming/MID/定时器释放。
固定参考实现也有同步组实现，可用于核对共有的线格式和行为，但不能替代1.1规范。
固定版本 uet_api.c 的 uet_get_sync_grp_src_fep 维护组计数，uet_rx_cq_post 在
完成时立即删除组，uet_rx_sync_grp_age 清理空闲组。其错误路径会把任何成员的错误
传播给 completing action；这与1.1 Table3-31 Case1的独立错误语义有差异。
其延迟原子只支持64位SUM并保存主机指针；本项目必须保留注册身份并重新授权，不能照搬。

## 当前原型（未接入 Endpoint）

新增 SynchronizationState.hpp：SynchronizationIdPool 使用FEP cursor与确认后的本地回收；
SynchronizationGroups用本地owner/member序号区分旧组、处理计数与唯一completer，支持
rollback、Clear、完成前的年龄回收，成员记录上限独立于组数。SynchronizationStateTest
覆盖65535计数边界、失败成员、错误count、重复completer、两种完成先后、Job/FEP隔离、
过期旧owner与相同wire ID新owner、撤销准入、source ID0/65535/耗尽/pool替换。
pool替换测试共享FEP cursor；原生Endpoint替换尚未接入验证。
首轮错误count测试暴露原型错误：小于admitted的count会在第一个成员完成时提前Ready；
现已阻断，原失败 /tmp/softue-sync-state-tests.log，后续普通测试通过。

PDS支持typed NoSynchronizationState，两个准入入口分别发0x1B；普通Rejected仍0x1A。
semantic_admission_request现在拷贝固定extension元数据，仍不拷贝payload，否则SES不能
在接受PSN前看到sync_group/count。SynchronizationAdmissionTest有I/T直测与真实PDS的
新建/已建立、RUD/ROD、NSCC、两种sync扩展恢复。CMake三项普通通过0.12s，日志
/tmp/softue-sync-state-cmake-tests2.log。消毒器状态层检查单独进行；未声明原生同步功能。

## 接入前需保持的区别

§3.4.2.7.4说sender完成处理不改变：completing WRITE自己的payload可完成/ACK，目标
header-data通知等组；completing ATOMIC必须等实际执行再成功ACK。Atomic为PDC首包时
需要NO_RESPONSE先打开后续消息进度，不可提前成功。

TransmitCleared是本地已收到交付/语义响应后推进clear_psn的事实，发生在Clear Command
发送之前；它不是对端已应用Clear的证明。ReceiveCleared才是对端本地事实。Completed组
保留到Clear的策略会影响合法跨PDC重用，必须进一步处理，不得宣称只等transport_pending
就解决目标兼容性。Table3-31 Case4早期额外成员与合法重用需要独立协议证据。

恢复性BadGeneration/Disabled错误与组计数的关系也需核对：源必须按规范重发，不能让
同一逻辑成员的新MID重复计数；尤其不能把恢复性错误的completer绑成不可替换的第一个
completer。候选方案为资源地址验证前的provisional reservation rollback，以及原生源每个
逻辑成员维护新MID重试/总deadline。未验证前不要将它当成已实现规则。
