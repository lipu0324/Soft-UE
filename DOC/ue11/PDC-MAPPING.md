# 可配置的PDC选择元组

UE 1.1 §3.5.8.1规定PDC选择必须包含源FA、目的FA、TC与delivery mode，并支持把
JobID、源PIDonFEP、目标PIDonFEP、Resource Index的任意组合加入元组。RUD与ROD
各有独立默认策略。当前默认保留JobID，使同一Job的请求共享相应连接；关闭这个
字段即可使用基础FA/TC/mode元组。

`PdcMappingConfiguration`保存两种模式的字段选择。完整key使用明确命名的字段；
未选择的字段规范化为零，策略在活跃连接存在时不可修改。PDCID的哈希仅选择一个
候选起点，完整key比较和空闲ID探测处理碰撞，保持全FEP上的ID唯一性。
哈希和分配顺序是模拟器策略，不属于标准报文格式。

```cpp
UET::PDS::PdcMappingConfiguration mapping;
mapping.rud.include_job_id = false;       // 使用基础元组。
mapping.rod.include_target_pid = true;    // 在默认JobID之外加入目标进程。
mapping.rod.include_resource_index = true;
host.configure_pdc_mapping(mapping);      // 在建连或提交操作前配置。
```

原生`Operation::source_pid`是本地进程身份，经SES→PDS接口的本地元数据传递。
`ses.initiator`则是Job中的匹配rank（§3.4.2.3.4），两者单独命名和保存。
源/目标PID与资源索引均为12位值。预建控制连接可通过`PdcMappingIdentity`选择
相同身份，使NOOP/Negotiation建立的连接与后续数据选择一致。

元组决定哪些消息共享PDC。每个消息的所有分片继续使用同一PDC；同一PDC上不同
消息的原始发送不会交错；恢复重传按相应模式处理。任意字段子集都保持相同Job/源PID/目标PID/RI/TC的ROD消息
使用相同连接这一要求。MR访问仍逐次核对JobID、PID、key、权限和边界。

YAML可分别选择两种模式的四个布尔字段：

```yaml
pds:
  rud_mapping:
    include_job_id: false
    include_source_pid: false
    include_target_pid: false
    include_resource_index: false
  rod_mapping:
    include_job_id: true
    include_target_pid: true
```

省略字段使用默认值；非布尔值和未知字段均被拒绝。场景入口目前使用默认PID与
资源索引1，因此YAML多Job示例展示JobID开关的共享差异；所有PID/RI组合通过原生
接口测试。主机当前仍使用请求TC0与应答TC1。完整TC组、保留池及TSS的SDI元组
分别在M7、保留资源与M6继续实现。

`pdc_mapping_test`在RUD和ROD上检查四个可选字段的全部16种组合，并从真实报文
观察连接选择、分片和消息顺序；每个WRITE都验证对应Job/PID/RI注册内存中的结果。
它也检查独立的模式策略、必需FA/TC字段、无效本地身份及活跃连接期间禁止改配置。
场景回归从独立PCAP字节检查开启/关闭JobID字段实际产生的连接数量。
