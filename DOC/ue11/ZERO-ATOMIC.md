# 零字节 atomic put/get

UE 1.1 §3.4.2.12 将零字节 atomic put/get 定义为真实协议操作：使用普通请求头，
长度为零，经过通常的地址、权限、对齐和边界检查，并遵守 delivery complete。
GET 必须在指定偏移触发一次零长度内存读取；PUT 不写入任何字节。

## 应用接口与线格式

原生 `OperationType::Atomic` 的空 WRITE 是非取回 PUT。取回 PUT/GET 使用
`OperationType::FetchingAtomic`、`atomic_operation=Write/Read` 和
`zero_length_atomic=true`。这个显式标志是本地 API 策略，不增加线格式字段：
普通原子 READ 的输入操作数可以省略，但它仍需返回一个完整 datatype 元素。
二者不能仅凭空的输入向量区分。

零字节操作仍选择有效的 datatype；偏移按该类型宽度对齐。区域末端偏移合法，
超过区域末端则返回通常的地址错误。零字节 GET/取回 PUT 可以省略本地结果描述符；
如果提供描述符，提交和完成仍校验那个精确的注册身份及零长度范围。旧注册注销后，
重用相同 key 不能授权旧操作，即使本次没有字节要写。

公开 libfabric 接口将 `count=0` 的 FI_ATOMIC_WRITE 和 FI_ATOMIC_READ 映射到这些
路径。输入和结果指针可以为空；v/msg 的显式结果项及远端项使用 count=0。查询的
最大元素数仍为1。零元素 SUM、CAS 等操作不在此例外之内。

## 完成与恢复

目标经过 MR 的 Read、Write、Atomic 权限检查后，GET 调用存储的
`read(offset,nullptr,0)`；PUT 不调用存储写入。取回路径产生 payload 长度为零的
数据 ACK，仍设置保证交付标记，缓存到 PDS 收到 Clear 为止。丢失结果后重放同一个
空数据 ACK，不再次执行内存读取。普通 DEFAULT 或 CACK 不能冒充这个结果。

CQ 的 len 为0；取回 flags 为 FI_ATOMIC|FI_READ，非取回 PUT 为 FI_ATOMIC|FI_WRITE。
不能因为长度为零而提前生成应用成功完成，或绕开远端错误。

`zero_atomic_test` 在 RUD/ROD、启用/关闭 NSCC 的组合中观察实际存储调用，覆盖
区域末端、权限和越界、空结果丢失、结果注册撤销与 key 重用，并检查正常单元素
READ 仍返回数据。`libfabric_atomic_return_test` 另从公开标量/v/msg 接口验证 CQ、
零元素拒绝和远端错误。实际通过情况以该提交生成的验证报告为准；这些测试不构成
完整 Profile 验收。
