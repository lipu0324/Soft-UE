# SES 接口与状态转换的源码位置

`UET/src/SES/Endpoint.hpp` 保留原生 API、事务状态类型和所有权字段；
`UET/src/SES/Endpoint.cpp` 实现对应的118个成员函数。后者由现有 `softue_protocol`
库编译，原生测试、实时适配和 provider 继续链接同一个内核。

拆分前每个使用 Endpoint 的测试翻译单元都要重复编译约3600行头文件中的事务实现。
现在接口头约580行，状态转换集中在实现文件；后续修改一次事务处理，只需重编译
实现及重新链接消费者。解析器仅用于本次机械迁移，已提交的 C++ 文件直接通过
CMake 构建，运行时和 CI 不需要 Python 解析器。

本次保持 API 参数默认值、成员布局、构造初始化顺序和函数体中的协议表达式。
实现定义去掉重复的参数默认值，并去除原类作用域的一层缩进。仍按原路径处理
SES → PDS → CMS/TSS → 网络；MR、完成语义、恢复与定时器策略均由原代码实现。
现有完整 CTest 是本次源码组织变更的验证依据，结果另行记录。

阅读时可先从接口头中的 `Operation`、`Completion` 和 Endpoint API 开始，再按问题
查实现中的 `submit`、`feed_submissions`、`receive`、`respond`、`context_event` 和 `close`。
消息/执行身份的区别见[接收句柄](RECEIVE-HANDLES.md)，跨对象所有权见
[Endpoint 生命周期](ENDPOINT-LIFETIME.md)。这次源码整理不增加 Profile 能力声明。
