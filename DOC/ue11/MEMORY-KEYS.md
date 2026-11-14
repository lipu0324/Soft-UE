# MR key、命名空间与撤销

MR（Memory Region，注册内存区域）是 SES 访问本地存储的授权记录。远端提交的 key 和
偏移只用于查找与校验；它们不会被解释成进程指针。本实现的依据是 UE 1.1
§2.2.5.3.4.1、Table 2-13、Table 2-17 和 §3.4.4.2。

## 64 位 key 包含什么

| 位 | 标准字段 | 当前实现 |
|---|---|---|
| 63 | IDEMPOTENT_SAFE | 可设置；表示区域允许幂等传输使用，不表示非幂等原子操作可以重复执行 |
| 62 | OPTIMIZED | 原生接受应用显式 optimized key，低12位为索引；provider 请求该标志时仍回退到非 optimized key |
| 56～61 | Reserved | 注册时校验为零 |
| 48～55 | Vendor-specific | provider 分配的 key 可使用；应用分配的 key 必须为零 |
| 0～47 | RKEY | 非 optimized key 的 48 位远端内存 key；零值也合法 |

RKEY 的范围与整体 key 的大小不同。provider 的 `mr_key_size=6` 描述 RKEY 的六字节
范围；`fi_mr_key()` 和线上标准头仍携带完整 64 位，包括高位元数据。provider 在
`FI_MR_PROV_KEY` 模式下分配 RKEY，保留请求中的 IDEMPOTENT_SAFE 标志；OPTIMIZED
在 provider 路径暂不启用。原生 RUDI WRITE/READ 要求区域实际具有幂等权限，见 [RUDI](RUDI.md)；
幂等标志不改变普通 ROD/RUD 的去重规则。

`MemoryKeyFormat` 只判断格式是否合法。一个格式正确的 key 仍须在目标注册表中存在，
并通过 JobID、PID、Resource Index、权限和边界检查。

## 相同数值不一定是同一个区域

非 optimized key 的命名空间包含 Job/PID/Resource Index。原生注册接口因此允许同一
应用 key 在不同作用域中指向不同存储：

```cpp
endpoint.memory().add_job(1);
endpoint.memory().add_job(2);
RegionOptions registration_options;
registration_options.requested_key = 0x0000ffffffffffffULL;
registration_options.resource_index = 17;
auto job_one_region = endpoint.memory().register_region(
    1, 7, 4096, Access::Read | Access::Write, registration_options);
auto job_two_region = endpoint.memory().register_region(
    2, 7, 4096, Access::Read | Access::Write, registration_options);
```

两次注册的数值 key 相等，但 JobID 分别为 1 和 2。相对寻址时，请求头中的 JobID、PID
和资源索引共同选择对应区域。绝对寻址时，JobID 只参与授权，不用于区分同 key 区域；
如果在该绝对 PID/索引下存在多个同 RKEY 绑定，访问会因歧义被拒绝。改变幂等元数据
也不会扩展这个命名空间。`memory_key_test` 还通过真实 SES/PDS/fabric 验证资源索引 17
和 18 下的同 key 写入不会互相污染。

应用分配 key 使用指定的具体 PID，包括合法的 PID 0；省略资源索引时，原生接口绑定默认 RMA 资源索引 1。
显式索引 0 是真实索引，与“未指定”不同。相同作用域内重复注册同一 RKEY 会被拒绝；
改变 IDEMPOTENT_SAFE 标志不会额外增加一个 RKEY 命名空间。

`pid_scope` 明确区分具体 PID 0 与本地 domain scope。旧的自动 key 注册接口保留
`pid=0` 表示 domain scope 的行为；需要把自动 key 限定到真实 PID 0 时，设置
`RegionOptions::bind_zero_pid=true`。应用分配 key 总是绑定指定 PID。

注册表先按完整 key 查找候选，再按作用域选择。精确的 Job/PID/索引绑定优先于明确
配置的通配绑定；选中区域权限不足时，不会回退到权限更宽的区域。原生本地读取若
无法在多个同 key 作用域中唯一选择，也会返回错误，调用者须提供资源索引。

SEND 的 posting 已经选定接收缓冲区，因此保存具体注册身份，而非仅保存数值 key。
随后每个片段都对同一有效注册进行授权：不能用来包的 JobID 重新选择其他区域，也
不能在原注册撤销后跟随同 key 的新注册。UUD 的接收路径遵守相同绑定规则。

## 为什么撤销句柄不同于线上 key

每次注册另有一个本地 `registration_id`，并关联所属注册表的 authority。这些值从不
编码进报文。它们解决的是本地对象生命周期问题：

- 同 key 的多个作用域需要分别撤销。
- 原区域撤销后，应用可再次注册同一数值 key；旧注册句柄不能撤销新区域。
- 一个注册表的句柄不能误撤销另一个注册表里数值 key 和计数器恰好相同的区域。

```cpp
endpoint.memory().deregister(job_one_region);
// job_two_region 仍有效；重复使用 job_one_region 撤销会返回 false。
```

仍保留 `deregister(key)` 作为数值 key 唯一时的便捷接口；存在多个作用域时，它会拒绝
歧义。撤销后，后续远端访问会重新检查注册表。应用在复用线上 key 前仍须协调旧操作
的退休；本地注册身份不在线上传输，不能替代远端 key 的生命周期管理。

## 当前边界与验证

原生接口已支持应用分配的普通与 OPTIMIZED key。OPTIMIZED 的位12～47必须为零，
资源索引由低12位导出；若显式提供不同 RI，注册失败。SMALL 省略 key，接收端按
Job/PID/index 解析实际 key，再执行完整 MR 授权。绝对寻址的等索引歧义仍拒绝；
见 [优化头](OPTIMIZED-HEADERS.md)。自动分配优化索引尚未实现。实验 libfabric provider 仍明确要求
`FI_MR_PROV_KEY`，不会把原生能力当作已实现的 libfabric 用户 key 模式。优化头、
provider optimized-key 绑定及更多 MR/API 模式在后续阶段实现，各 Profile 的符合性声明保持关闭。

```sh
ctest --test-dir build/cmake -R 'memory_key_test|memory_registry_test|addressing_test' --output-on-failure
```

测试覆盖完整 48 位边界、零 key/索引、元数据格式、作用域隔离、重复注册、旧句柄与跨
注册表撤销、Job 删除后的隔离，以及经过协议的实际内存效果。provider 进程测试另验证
六字节 RKEY 声明、完整高位元数据传递和 OPTIMIZED 回退。

## 本地放置专用注册

接收posting及返回结果的内部注册，使用 `local_placement_only` 区分本地放置与
远端RMA授权；不新增线格式key位。精确注册撤销检查仍适用，见
[本地放置权限](LOCAL-PLACEMENT.md)。
