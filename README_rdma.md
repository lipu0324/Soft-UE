# README_RDMA

本文件用于记录 UET 中与 RDMA 内存语义相关的实现更新（READ/WRITE、DMA 模拟、payload 句柄化等），包含修改思路、主体流程与使用方式，后续相关更新也集中追加在此。

## 修改思路

- 将 payload 从“值语义 vector”升级为“引用语义 handle/descriptor”，减少跨层拷贝，接口形态更接近硬件 SGE/DMA。
- 将 DMA 行为抽象为“语义层 memcpy”，把 on-wire payload 的处理点放在 SES，便于以后替换成真实 DMA/硬件。
- READ/WRITE 都以“分片 + message_offset + total_len”的方式处理，保证与 UE Spec 的数据面语义一致。
- 生命周期由 Pool 统一管理，避免悬挂指针/重复释放；保持 HLS 友好的 descriptor 形态。

## 已实现功能概览

1) Payload 句柄/池
- `PayloadDesc/Handle/Pool`：固定大小 buffer pool + 句柄引用计数。
- 句柄只拷贝描述符，不拷贝数据；`data()`/`size()` 提供指针 + 长度。
- 默认 pool 参数通过宏控制：`UET_PAYLOAD_POOL_SLOTS`、`UET_PAYLOAD_POOL_BYTES`。

2) MR 注册与查表
- SES 内部 MR registry：`register_mr()`/`unregister_mr()`。
- READ/WRITE 按 rkey 查询 MR，计算落地地址。

3) WRITE（方案 B）
- 目标端收到 WRITE 分片后直接 `memcpy` 到 `MR.base + buffer_offset + message_offset`。
- 使用 `WriteTrackKey` + bitmap 跟踪分片覆盖，全部覆盖后回 `RC_OK`（key 包含 src_fep，避免多连接冲突）。

4) READ response‑with‑data
- 目标端 READ：从 MR 读取并按 MTU 分片回响应包。
- 发起端 READ：按 `message_offset/payload_length/modified_length` 重组，写回本地缓冲区。
- 使用 `ReadTrackKey` + bitmap 追踪分片完成。

5) 响应管道对齐
- PDC 发送 response-with-data 使用 `UET_HDR_RESPONSE_DATA`。
- response 路径沿现有 SES→PDS→PDC→NET 流转。

6) 端到端测试
- 新增 `READTest`：本地回环验证 READ 分片/重组。
- 新增 `WRITETest`：单包 + 分片 WRITE 验证。

## 主体修改流程（已完成）

1) 定义描述符与池接口  
在 `UET/src/PayloadHandle.hpp` 定义 `PayloadDesc`、`PayloadHandle`、`PayloadPool`。

2) 改 packet 结构体的 payload 字段  
将 `SEStoPDS_pkt::payload` 从 `std::vector<uint8_t>` 改为 `PayloadHandle`，跨层结构体同步替换。

3) 改发送路径（写入 pool，再引用发送）  
发送时从 pool 分配 buffer，`memcpy` 载荷，再通过 handle 传递。

4) 改接收路径（先落地，再传递 handle）  
UDP 收包后把 payload 拷贝进 pool buffer（保留一次 copy），向上层只传 handle。

5) 改序列化/反序列化接口  
发包用 `payload.data()/size()`；解包时分配 handle 并填充。

6) WRITE 语义与 tracking  
目标端分片直写 + bitmap 完成判定。

7) READ response-with-data 分片/重组  
目标端分片回包；发起端重组回写本地缓冲区。

8) 回归测试  
单包与分片 READ 测试通过。

## 如何使用

## 环境准备（Ubuntu 24.04 + CUDA 13.1 + libfabric 2.3.1 + aws-ofi-nccl + nccl-tests）

本节给出当前仓库已验证可用的一套环境安装流程，目标统一到：
- CUDA Toolkit 13.1（`nvcc`）
- NCCL（`+cuda13.1` 分支）
- libfabric 2.3.1（源码安装到 `/opt/libfabric`）
- aws-ofi-nccl（安装到 `/opt/aws-ofi-nccl`）
- nccl-tests（用于后续链路验证）

### 1) 基础依赖
```bash
sudo apt update
sudo apt install -y \
  build-essential cmake git wget curl ca-certificates gnupg \
  autoconf automake libtool pkg-config rdma-core libibverbs-dev libhwloc-dev ripgrep
```

### 2) 安装并切换到 CUDA 13.1
```bash
sudo apt install -y cuda-toolkit-13-1
export PATH=/usr/local/cuda-13.1/bin:$PATH
export LD_LIBRARY_PATH=/usr/local/cuda-13.1/lib64:$LD_LIBRARY_PATH
hash -r
nvcc --version
```

### 3) 安装/确认 NCCL（与 CUDA 13.1 对齐）
优先检查已有 NCCL：
```bash
ldconfig -p | rg -i 'libnccl.so'
strings /lib/x86_64-linux-gnu/libnccl.so.2 | rg -m1 'NCCL version'
```
若未安装，从 CUDA apt 源安装：
```bash
sudo apt update
CUDA_TAG='cuda13.1'
NCCL_VER=$(apt-cache madison libnccl2 | awk -v t="$CUDA_TAG" '$3 ~ t {print $3; exit}')
sudo apt install -y "libnccl2=${NCCL_VER}" "libnccl-dev=${NCCL_VER}"
sudo apt-mark hold libnccl2 libnccl-dev
```

### 4) 安装 libfabric 2.3.1（绑定 CUDA 13.1）
说明：Ubuntu 24.04 默认 apt 版通常是 1.17，不满足本仓库 provider 当前目标 API。
```bash
cd ~
git clone https://github.com/ofiwg/libfabric.git
cd libfabric
git checkout v2.3.1
make distclean || true
./autogen.sh
./configure --prefix=/opt/libfabric \
  --with-cuda=/usr/local/cuda-13.1 \
  --enable-cuda-dlopen \
  --enable-debug
make -j"$(nproc)"
sudo make install
```
验证：
```bash
fi_info --version
pkg-config --modversion libfabric
readelf -d /opt/libfabric/lib/libfabric.so.1 | rg -i 'NEEDED.*cudart'
```
说明：使用 `--enable-cuda-dlopen` 时，上述 `readelf` 可能无 `cudart` 依赖输出，属于正常现象。

### 5) 安装 aws-ofi-nccl（绑定 libfabric）
```bash
OFI_NCCL_VER='v1.17.2'
cd /tmp
curl -L -o aws-ofi-nccl.tar.gz "https://github.com/aws/aws-ofi-nccl/archive/refs/tags/${OFI_NCCL_VER}.tar.gz"
tar xf aws-ofi-nccl.tar.gz
cd "aws-ofi-nccl-${OFI_NCCL_VER#v}"
make distclean || true
./autogen.sh
export CUDA_HOME=/usr/local/cuda-13.1
export LIBRARY_PATH=$CUDA_HOME/targets/x86_64-linux/lib:$LIBRARY_PATH
export CPATH=$CUDA_HOME/targets/x86_64-linux/include:$CPATH
./configure --prefix=/opt/aws-ofi-nccl \
  --with-libfabric=/opt/libfabric \
  --with-cuda=$CUDA_HOME
make -j"$(nproc)"
sudo make install
```
验证：
```bash
find /opt/aws-ofi-nccl -type f -name 'libnccl-net-ofi.so*'
ldd /opt/aws-ofi-nccl/lib/libnccl-net-ofi.so | rg -i 'fabric|nccl|hwloc|not found'
readelf -d /opt/aws-ofi-nccl/lib/libnccl-net-ofi.so | rg -i 'NEEDED.*cudart'
```

### 6) 安装 nccl-tests（仅环境准备，不强制立即跑）
```bash
cd ~
git clone --depth 1 https://github.com/NVIDIA/nccl-tests.git
[ -f ~/nccl-tests/Makefile ] && cd ~/nccl-tests || cd ~/nccl-tests/nccl-tests
make -j"$(nproc)" CUDA_HOME=/usr/local/cuda-13.1 NCCL_HOME=/usr MPI=0
ls -l build/all_reduce_perf build/all_gather_perf build/broadcast_perf
```

### 7) 固化环境变量（推荐单一来源）
建议把所有变量写进 `~/.uet_ofi_env.sh`，并让 `~/.bashrc` 只保留一条 `source`。
```bash
cat > ~/.uet_ofi_env.sh <<'EOF'
export CUDA_HOME=/usr/local/cuda-13.1
export PATH=$CUDA_HOME/bin:/opt/libfabric/bin:$PATH
export LD_LIBRARY_PATH=$CUDA_HOME/lib64:$CUDA_HOME/targets/x86_64-linux/lib:/opt/libfabric/lib:/opt/aws-ofi-nccl/lib:$LD_LIBRARY_PATH
export PKG_CONFIG_PATH=/opt/libfabric/lib/pkgconfig:$PKG_CONFIG_PATH
export LIBRARY_PATH=$CUDA_HOME/targets/x86_64-linux/lib:$LIBRARY_PATH
export CPATH=$CUDA_HOME/targets/x86_64-linux/include:$CPATH

# 按本地仓库实际路径调整
export FI_PROVIDER_PATH=$HOME/UEC_C-1/uet_provider
export FI_PROVIDER=uet
export NCCL_NET_PLUGIN=ofi
export OFI_NCCL_PROTOCOL=SENDRECV
export NCCL_DEBUG=INFO
export NCCL_DEBUG_SUBSYS=INIT,NET
EOF

grep -q "source ~/.uet_ofi_env.sh" ~/.bashrc || echo "source ~/.uet_ofi_env.sh" >> ~/.bashrc
source ~/.bashrc
```

### 8) 最小检查命令（仅检查环境，不跑业务测试）
```bash
which nvcc
nvcc --version
which fi_info
fi_info --version
[ -x ~/nccl-tests/build/all_reduce_perf ] && ls -l ~/nccl-tests/build/all_reduce_perf || ls -l ~/nccl-tests/nccl-tests/build/all_reduce_perf
FI_PROVIDER_PATH=$HOME/UEC_C-1/uet_provider FI_PROVIDER=uet fi_info -t FI_EP_DGRAM -c FI_MSG
```

### 9) 常见问题
- `fi_getinfo: -61 (No data available)`：
  - 常见原因是变量写成了 `PROVIDER_PATH`。正确变量是 `FI_PROVIDER_PATH`。
- `aws-ofi-nccl` 编译时报 `stdlib.h: No such file or directory`：
  - 不要使用 `--with-hwloc=/usr`，该参数可能引入 `-isystem /usr/include` 导致头文件搜索异常。
- `configure: NCCL OFI Plugin requires either CUDA or Neuron runtime.`：
  - 需设置 `--with-cuda=/usr/local/cuda-13.1`，并确保 `LIBRARY_PATH/CPATH` 指向 CUDA 13.1 的 `targets/x86_64-linux`。
- `fi_info` 报 `libcudart.so.12 not found`：
  - 通常是旧版构建残留；按本节步骤重编 `libfabric` 与 `aws-ofi-nccl` 即可。
- `fi_info -p uet` 在 debug 版 libfabric 可能触发 provider layering 断言：
  - 优先使用 `FI_PROVIDER=uet fi_info ...` 做能力检查。
- 为什么建议 `FI_PROVIDER='uet;ofi_rxd'` 而不是仅 `uet`：
  - `uet` 原生能力是 `FI_EP_DGRAM`；aws-ofi-nccl（`SENDRECV`）筛选时需要 `RDM/TAGGED` 语义。
  - `ofi_rxd` 会在 `dgram` 之上提供 `RDM` 语义，因此 `uet;ofi_rxd` 才能稳定被 NCCL/OFI 选中。
  - 仅设 `FI_PROVIDER=uet` 时，常见结果是回退到 `tcp` provider（日志里会出现 `Selected provider is tcp`）。
- `nccl-tests` 报 `No makefile found`：
  - 先 `cd` 到包含 `Makefile` 的目录（常见是 `~/nccl-tests`，也可能是 `~/nccl-tests/nccl-tests`）。
- 在 WSL 上 `all_reduce_perf` 一开始就 `Segmentation fault` 或 `util.cu:555 OS call failed`：
  - 常见原因是 `libcuda.so` 冲突（WSL 映射库 vs Linux 驱动包）。
  - 先确认：`ldconfig -p | rg -i 'libcuda.so'` 只指向 `/usr/lib/wsl/lib/libcuda.so.1`。
  - 若有 `/lib/x86_64-linux-gnu/libcuda.so.*`（例如 `libnvidia-compute-*`），卸载冲突包后在 Windows 执行 `wsl --shutdown` 再重试。
- 使用 `set -e` 时直接“退出终端”：
  - `rg/grep` 在“未匹配”时会返回非 0，触发 `set -e` 退出。
  - 对检查命令建议追加 `|| true`。
- NCCL 日志里出现 `NET/OFI Selected provider is tcp`：
  - 说明 OFI 插件已加载，但当前未选中 `uet` provider。
  - 先视为 smoke test 通过；若目标是强制走 `uet`，需要继续补齐 provider 能力匹配。

### 10) NCCL/OFI smoke test（推荐）
先跑 CUDA/NCCL 基线（不带 OFI 变量）：
```bash
[ -f ~/nccl-tests/Makefile ] && cd ~/nccl-tests || cd ~/nccl-tests/nccl-tests
env -u NCCL_NET_PLUGIN -u OFI_NCCL_PROTOCOL -u FI_PROVIDER -u FI_PROVIDER_PATH \
  ./build/all_reduce_perf -b 8 -e 64K -f 2 -g 1 -n 1
```
再跑 OFI 插件路径（带环境变量）：
```bash
[ -f ~/nccl-tests/Makefile ] && cd ~/nccl-tests || cd ~/nccl-tests/nccl-tests
./build/all_reduce_perf -b 8 -e 64K -f 2 -g 1 -n 1
```
预期关键日志：
- `Successfully loaded external network plugin ...libnccl-net.so`
- `NET/OFI Initializing aws-ofi-nccl`

### 11) 单卡稳定性回归（阶段 2）
当前为单 GPU 环境，建议用下面三组测试做稳定性回归：
```bash
[ -f ~/nccl-tests/Makefile ] && cd ~/nccl-tests || cd ~/nccl-tests/nccl-tests
mkdir -p logs/phase1_singlegpu_2026-02-14

# baseline（不带 OFI 约束）
env -u NCCL_NET_PLUGIN -u OFI_NCCL_PROTOCOL -u FI_PROVIDER -u FI_PROVIDER_PATH \
  NCCL_DEBUG=INFO NCCL_DEBUG_SUBSYS=INIT,NET \
  ./build/all_reduce_perf -b 8 -e 8M -f 2 -g 1 -n 50 \
  2>&1 | tee logs/phase1_singlegpu_2026-02-14/baseline_g1_8M.log

# OFI short（固定 uet;ofi_rxd）
NCCL_DEBUG=INFO NCCL_DEBUG_SUBSYS=INIT,NET \
  ./build/all_reduce_perf -b 8 -e 8M -f 2 -g 1 -n 50 \
  2>&1 | tee logs/phase1_singlegpu_2026-02-14/ofi_uet_rxd_g1_8M.log

# OFI long（固定 uet;ofi_rxd）
NCCL_DEBUG=INFO NCCL_DEBUG_SUBSYS=INIT,NET \
  ./build/all_reduce_perf -b 8 -e 64M -f 2 -g 1 -n 200 \
  2>&1 | tee logs/phase1_singlegpu_2026-02-14/ofi_uet_rxd_g1_64M_long.log
```
可直接使用一键脚本（仓库内）：
```bash
./scripts/smoke_nccl_ofi_single_gpu.sh 2026-02-14
```

门禁策略（功能优先，当前默认）：
- 必须命中：
  - `Collective test concluded: all_reduce_perf`
  - `Out of bounds values : 0 OK`
  - 无 `Segmentation fault|core dumped|Test CUDA failure`
- OFI 场景（short/long）额外必须命中：
  - `Selected provider is uet;ofi_rxd`
  - `Successfully loaded external network plugin`
- 当前阶段允许的 WSL 告警：
  - `NCCL WARN NET/OFI pciPath: Could not find real path ...`
  - `NCCL WARN NET/OFI Error opening file: /sys/devices/virtual/dmi/id/product_name`

回归报告产物（脚本自动生成）：
- 主报告：`~/nccl-tests[/nccl-tests]/logs/phase1_singlegpu_<tag>/regression_gate_<tag>.md`
- 仓库镜像：`logs/regression_gate_<tag>.md`
- 字段：`provider_hit`、`collective_done`、`oob_ok`、`crash_free`、`allowed_warn_only`

详细规范见：
- `DOC/single_gpu_regression_gate.md`

### 12) NIC 元数据补齐方案（uet_provider）
目的：减少 aws-ofi-nccl 的默认回退日志（`No NIC info for dev 0`），提升拓扑可观测性。

实现步骤：
1. 在 `uet_provider/uet_provider.cpp` 的 `uet_getinfo()` 内补齐 `fi_info->nic`。
2. 为 `nic->device_attr / bus_attr / link_attr` 分配并填充最小可用字段。
3. 补齐 `nic->fid` 元数据与控制面能力，避免 provider 叠加路径在 `fi_dupinfo()` 触发异常：
   - `nic->fid.fclass = FI_CLASS_NIC`
   - `nic->fid.ops` 提供 `close/control(FI_DUP)` 最小实现
4. 把链路速度与设备名做成可配置：
   - `UET_NIC_NAME`（默认 `uet0`）
   - `UET_LINK_SPEED_GBPS`（默认 `100`）
   - `UET_BUS_TYPE`（默认 `pci`）
   - `UET_PCI_BDF`（默认 `0000:00:00.0`）
5. 若元数据填充失败，保留功能路径（继续运行），并打印 debug 日志。

字段映射表（当前实现）：

| libfabric 字段 | 来源/策略 | 默认值 |
|---|---|---|
| `info->nic->fid.fclass` | provider 固定 | `FI_CLASS_NIC` |
| `info->nic->fid.ops` | provider 最小 ops（`close` + `FI_DUP`） | `uet_nic_fid_ops` |
| `info->nic->device_attr->name` | 环境变量 `UET_NIC_NAME` | `uet0` |
| `info->nic->device_attr->driver` | provider 固定字符串 | `uet-provider` |
| `info->nic->device_attr->device_id` | provider 固定字符串 | `virtual-uet` |
| `info->nic->device_attr->vendor_id` | provider 固定字符串 | `uet` |
| `info->nic->link_attr->address` | `uet_pick_default_ipv4()` 选本机 IPv4 | `127.0.0.1`（fallback） |
| `info->nic->link_attr->mtu` | provider 常量 | `4096` |
| `info->nic->link_attr->speed` | 环境变量 `UET_LINK_SPEED_GBPS` 转 bps | `100 Gbps` |
| `info->nic->link_attr->state` | provider 固定 | `FI_LINK_UP` |
| `info->nic->link_attr->network_type` | provider 固定 | `ethernet` |
| `info->nic->bus_attr->bus_type` | 环境变量 `UET_BUS_TYPE` | `FI_BUS_PCI` |
| `info->nic->bus_attr->attr.pci` | 环境变量 `UET_PCI_BDF` 解析 | `0000:00:00.0` |

验证命令：
```bash
FI_PROVIDER_PATH=$HOME/UEC_C-1/uet_provider FI_PROVIDER=uet fi_info -v | rg -n "prov_name|nic|device_attr|link_attr|speed|address"
FI_PROVIDER_PATH=$HOME/UEC_C-1/uet_provider FI_PROVIDER='uet;ofi_rxd' fi_info -v | rg -n "prov_name|nic|device_attr|link_attr|speed|address"
```
说明：
- 若 `uet` 已有 NIC 元数据但 `uet;ofi_rxd` 仍显示 `nic: (nil)`，通常是 provider 叠加路径未透传，不等于 `uet` 填充失败。

### 13) NIC 元数据链路解释（`uet -> ofi_rxd -> aws-ofi-nccl`）
这条链路里，三层职责不同：
1. `uet`（core provider）：提供底层 `dgram/FI_MSG`，并在 `uet_getinfo()` 里产出原始 `fi_info` 与 `info->nic`。
2. `ofi_rxd`（util provider）：叠在 `dgram` 之上，向上提供 `RDM` 语义，形成 `uet;ofi_rxd` 视图。
3. `aws-ofi-nccl`（NCCL 网络插件）：调用 `fi_getinfo` 选 provider，并读取最终 `fi_info->nic` 做 NIC 属性判定。

数据流（按调用顺序）：
1. `aws-ofi-nccl` 发起 `fi_getinfo`（通常是 `RDM` 诉求）。
2. `ofi_rxd` 匹配并调用底层 `uet` 的 `getinfo`。
3. `uet` 返回 `fi_info`（可包含 `info->nic`）。
4. `ofi_rxd` 复制/包装为 `uet;ofi_rxd` 的 `fi_info`。
5. `aws-ofi-nccl` 读取最终 `fi_info->nic`。
6. 若为空，会打印 `No NIC info for dev 0` 并回退到默认 NIC 属性（通常不阻断功能）。

最常见的元数据丢失点：
1. `uet` 未填 `info->nic`。
2. `uet` 填了 `nic`，但 `nic->fid` 控制面不完整（尤其 `FI_DUP` 路径），导致上层复制时丢失。
3. `ofi_rxd` 叠加路径未透传底层 `nic`。
4. provider 实际未选中 `uet;ofi_rxd`（例如回退到 `tcp`）。

判定原则（当前项目）：
1. 功能正确性优先看 NCCL 日志：`Selected provider is uet;ofi_rxd` + `Collective test concluded`。
2. `No NIC info for dev 0` 出现时，先视为“属性回退告警”，不是“功能失败”。
3. `fi_info -v | rg nic...` 可作为辅助观察，不作为唯一成功/失败判据。

### 14) 控制面最小升级清单（P0）与测试用例表
目标：在不改整体架构前提下，补齐控制面最小能力（协议显式化、会话隔离、查找收紧），并保持单卡 NCCL/OFI 回归稳定。

本轮改动范围：
1. `uet_provider/uet_provider.cpp`
2. `UET/src/Test/MRDescTest.cpp`
3. `UET/src/Test/MRDescWriteLibfabricTest.cpp`
4. `UET/src/Test/MRDescReadLibfabricTest.cpp`

控制面协议（新格式，旧裸 `MRDesc` 不兼容）：
1. 统一控制头 `uet_ctrl_hdr`：
   - `magic/version/msg_type/hdr_len/total_len/session_id/job_id/resource_index`
2. 消息类型：
   - `HELLO(1)`、`MRDESC(2)`、`ACK(3)`、`ERR(4)`、`DONE(5, 测试扩展)`
3. `MRDesc` 缓存 key 收紧：
   - `peer + session_id + job_id + pid_on_fep + resource_index + rkey`

P0 实现要点：
1. provider 仅在 `msg_type=MRDESC` 时解析并缓存 `MRDesc`。
2. provider 在收到 `HELLO/MRDESC/ACK/ERR` 时更新 `peer_session_by_fiaddr`。
3. `fi_write/fi_read` 前置检查 `session`；未建立返回 `-FI_EINVAL` 并记录 `session not established`。
4. `MRDesc` 查询结果区分：
   - `mrdesc not found`
   - `key mismatch`（同 peer/session/rkey 多命中）

测试用例表（P0）：

| 用例 | 目的 | 通过标准 |
|---|---|---|
| `TC-CP-001` 控制头解析 | 校验 `HELLO/MRDESC/ACK/ERR` 解析路径 | 合法消息可解析；非法头拒绝并记录 `ctrl_parse_err` |
| `TC-CP-002` 会话建立 | 校验 `peer_session_by_fiaddr` 建立 | `HELLO` 后可执行 RMA；未握手时报 `session not established` |
| `TC-CP-003` 严格查找 | 校验 `MRDesc` 查找收紧 | 查询命中唯一条目；冲突时报 `key mismatch` |
| `TC-CP-004` `MRDescTest` | 控制面最小闭环 | server 输出 `MRDesc sent, ack=OK` |
| `TC-CP-005` `MRDescWriteLibfabricTest` | 控制面 + `fi_write` | server/client 均输出 `PASS` |
| `TC-CP-006` `MRDescReadLibfabricTest` | 控制面 + `fi_read` | server/client 均输出 `PASS` |
| `TC-CP-007` NCCL smoke | 回归不退化 | `Selected provider is uet;ofi_rxd` + `Collective test concluded` + 无崩溃 |

执行与验收命令（2026-02-15）：
```bash
# 构建
make -C uet_provider -j"$(nproc)"
make -C UET/src/Test MRDescTest MRDescWriteLibfabricTest MRDescReadLibfabricTest MRRegLibfabricTest

# 控制面+RMA
FI_PROVIDER_PATH=$PWD/uet_provider ./UET/src/Test/MRDescTest --mode server --local-ip 10.26.65.22 --peer-ip 10.26.65.23 --local-port 4000 --peer-port 4001
FI_PROVIDER_PATH=$PWD/uet_provider ./UET/src/Test/MRDescTest --mode client --local-ip 10.26.65.23 --peer-ip 10.26.65.22 --local-port 4001 --peer-port 4000
FI_PROVIDER_PATH=$PWD/uet_provider ./UET/src/Test/MRDescWriteLibfabricTest --mode server --local-ip 10.26.65.22 --peer-ip 10.26.65.23 --local-port 4000 --peer-port 4001 --clients 1
FI_PROVIDER_PATH=$PWD/uet_provider ./UET/src/Test/MRDescWriteLibfabricTest --mode client --local-ip 10.26.65.23 --peer-ip 10.26.65.22 --local-port 4001 --peer-port 4000 --client-id 0 --clients 1
FI_PROVIDER_PATH=$PWD/uet_provider ./UET/src/Test/MRDescReadLibfabricTest --mode server --local-ip 10.26.65.22 --peer-ip 10.26.65.23 --local-port 4000 --peer-port 4001 --clients 1
FI_PROVIDER_PATH=$PWD/uet_provider ./UET/src/Test/MRDescReadLibfabricTest --mode client --local-ip 10.26.65.23 --peer-ip 10.26.65.22 --local-port 4001 --peer-port 4000 --client-id 0 --clients 1

# NCCL 回归
./scripts/smoke_nccl_ofi_single_gpu.sh 2026-02-14-nic
```

当前推荐入口（2026-03-16）：
```bash
# 一键构建 + 控制面 smoke + 日志收集
./scripts/smoke_control_plane_libfabric.sh 2026-03-16

# 检查当前机器是否具备真实 RDMA 联调条件
./scripts/check_rdma_env.sh
```

说明：
1. `MRDescTest` 默认 `timeout_ms` 已提高到 `15000`，降低手工双进程启动导致的误报超时。
2. `UET/src/Test/Makefile` 现已默认支持 `/opt/libfabric/include` 与 `/opt/libfabric/lib`，无需再手工拼接 `CXXFLAGS/LIBRARY_PATH`。
3. 脚本会固定注入 `FI_PROVIDER_PATH/FI_PROVIDER/LD_LIBRARY_PATH/UET_PROVIDER_DEBUG`，并把新日志收集到 `logs/control_plane_smoke_<tag>/`。
4. 当前阶段旧的 1 月、2 月日志只保留为历史基线；当前控制面阶段证据以脚本新生成日志为准。
5. `UET_BACKEND=rdma` 现在会优先尝试初始化真实 verbs runtime；若当前机器看不到 RNIC，`fi_mr_reg` 会显式返回不可用，不再假装进入硬件数据面。

说明：
1. 本轮采用“新格式唯一生效”，旧控制消息格式预期失败。
2. 当前单机单卡环境仅验证功能正确性/稳定性，不给出多机拓扑性能结论。

P0 执行结果（2026-02-15）：
1. 控制面测试通过（server/client 均 0 退出）：
   - `MRDescTest`：server 输出 `MRDesc sent, ack=OK`；client 输出 `MRDesc received ...`
   - `MRDescWriteLibfabricTest`：server/client 均输出 `PASS`
   - `MRDescReadLibfabricTest`：server/client 均输出 `PASS`
   - 运行日志：`/tmp/uet_p0_logs/*.log`
2. NCCL 单卡回归通过：
   - `./scripts/smoke_nccl_ofi_single_gpu.sh 2026-02-14-nic` 返回 `[PASS]`
   - `ofi_uet_rxd_g1_8M.log` 与 `ofi_uet_rxd_g1_64M_long.log` 均命中：
     - `Selected provider is uet;ofi_rxd`
     - `Out of bounds values : 0 OK`
     - `Collective test concluded`
   - 未出现 `Segmentation fault` 与 `util.cu:555`
3. 对照组说明：
   - baseline（不固定 `FI_PROVIDER`）仍会回退到 `tcp`，且可见 `No NIC info for dev 0`；
   - 固定 `FI_PROVIDER='uet;ofi_rxd'` 后，本轮日志未出现 `No NIC info for dev 0`。

### 15) NIC 元数据深挖结论（2026-02-16）
目标：把 `uet -> ofi_rxd -> aws-ofi-nccl` 链路做成可复现、可归因、可回归。

诊断产物目录：
- `logs/diag_nic_2026-02-16/versions.txt`
- `logs/diag_nic_2026-02-16/fi_info_uet_verbose.txt`
- `logs/diag_nic_2026-02-16/fi_info_uet_rxd_verbose.txt`
- `logs/diag_nic_2026-02-16/fi_info_tcp_verbose.txt`
- `logs/diag_nic_2026-02-16/nccl_keylines_2026-02-16-nicdiag.txt`
- `logs/diag_nic_2026-02-16/nccl_keylines_2026-02-16-nicdiag-busfix.txt`
- `logs/diag_nic_2026-02-16/nccl_keylines_2026-02-16-nicdiag-busfix-bdf.txt`
- `logs/diag_nic_2026-02-16/nic_matrix_2026-02-16.md`
- `logs/diag_nic_2026-02-16/regression_summary.txt`
- `logs/diag_nic_2026-02-16/regression_summary_postfix.txt`

固定诊断命令（本轮执行）：
```bash
# 1) 版本快照
fi_info --version
pkg-config --modversion libfabric
strings /lib/x86_64-linux-gnu/libnccl.so.2 | rg -m1 'NCCL version'
ldd /opt/aws-ofi-nccl/lib/libnccl-net-ofi.so | rg -i 'fabric|nccl|hwloc|cuda|not found'

# 2) fi_info 全量采集
FI_PROVIDER_PATH=$PWD/uet_provider FI_PROVIDER=uet fi_info -v > logs/diag_nic_2026-02-16/fi_info_uet_verbose.txt 2>&1
FI_PROVIDER_PATH=$PWD/uet_provider FI_PROVIDER='uet;ofi_rxd' fi_info -v > logs/diag_nic_2026-02-16/fi_info_uet_rxd_verbose.txt 2>&1
FI_PROVIDER=tcp fi_info -v > logs/diag_nic_2026-02-16/fi_info_tcp_verbose.txt 2>&1

# 3) NCCL 对照采集
./scripts/smoke_nccl_ofi_single_gpu.sh 2026-02-16-nicdiag

# 4) 条件化修复后复测
./scripts/smoke_nccl_ofi_single_gpu.sh 2026-02-16-nicdiag-busfix
UET_PCI_BDF=0000:01:00.0 ./scripts/smoke_nccl_ofi_single_gpu.sh 2026-02-16-nicdiag-busfix-bdf
```

关键观测（矩阵摘要）：
- `uet`：
  - `fi_info -v` 可见 `prov_name: uet`、`protocol: FI_PROTO_UDP`；
  - `fi_info` 文本未直接展开 `nic:` block；
  - provider 代码中已填 `nic/device_attr/link_attr/bus_attr`（见 `uet_fill_nic_metadata`）。
- `uet;ofi_rxd`：
  - 可稳定选中：`Selected provider is uet;ofi_rxd`；
  - 未出现 `No NIC info for dev 0`；
  - 初始诊断出现 `Invalid type of PCI bus returned 0`；
  - 接入 `UET_BUS_TYPE/UET_PCI_BDF` 后，`Invalid type...` 消失，转为 `pciPath: Could not find real path ...`（WSL sysfs 路径不可解析）；
  - HCA 名字可见：`NET/Libfabric ... HCA 0 'uet0'`。
- `tcp` baseline：
  - `fi_info -v` 明确显示 `nic: (nil)`；
  - NCCL 出现 `No NIC info for dev 0`。

根因分类（本轮结论）：
- 归类为 **C 类**：字段不是“完全缺失”，而是 **bus 元数据可用性/可解析性问题**。
- C1（已修）：`bus_type` 从无效值导致的 `Invalid type of PCI bus returned 0`。
- C2（未完）：在 WSL 下 `pciPath` 真实路径解析失败（`Could not find real path`），属于环境路径可见性限制。
- 非 A 类：`uet` 侧并非完全未填 NIC 元数据。
- 非纯 B 类：`uet;ofi_rxd` 并未表现为完全 `nic=nil` 丢失。

条件化最小修复（本轮已实施）：
1. `uet_provider` 已新增并接入：
   - `UET_BUS_TYPE`（覆盖 `bus_attr.bus_type`，默认 `pci`）
   - `UET_PCI_BDF`（BDF 解析，默认 `0000:00:00.0`）
2. 继续使用：
   - `UET_NIC_NAME`
   - `UET_LINK_SPEED_GBPS`
3. 验收结果：
   - `uet;ofi_rxd` 仍被稳定选中；
   - `Invalid type of PCI bus returned 0` 已消失；
   - 新告警为 `pciPath: Could not find real path ...`（WSL 环境可预期）；
   - `MRDescTest` / `MRDescWriteLibfabricTest` / `MRDescReadLibfabricTest` 与 NCCL smoke 全部 PASS。

回归门禁结果（2026-02-16）：
- `MRDescTest`：PASS（`MRDesc sent, ack=OK` / `MRDesc received`）
- `MRDescWriteLibfabricTest`：server/client PASS
- `MRDescReadLibfabricTest`：server/client PASS
- NCCL smoke：PASS（`Collective test concluded`，无 `Segmentation fault`、无 `util.cu:555`）
- 额外说明：在 WSL 下仍可能出现 `pciPath` 解析告警，不影响当前功能闭环。

#### WSL 已知限制与 Bare-metal 复验标准
1) WSL 已知限制（判定规则）：
- 在 WSL 环境若出现 `NET/OFI pciPath: Could not find real path ...`，归类为 sysfs/PCI 路径可见性限制。
- 当以下条件同时满足时，判定为 `PASS with known limitation`：
  - `Selected provider is uet;ofi_rxd`
  - `Collective test concluded`
  - 无 `Segmentation fault`
  - 无 `util.cu:555`
- 区分规则：
  - `Invalid type of PCI bus returned 0`：provider 元数据值问题（本仓库已修）。
  - `pciPath: Could not find real path ...`：运行环境路径解析问题（WSL 限制）。

2) Bare-metal 复验前置条件：
- Linux 物理机（非 WSL）。
- 与当前环境一致的 `libfabric/NCCL/aws-ofi-nccl` 主版本。
- 使用同一仓库 provider（包含 `UET_BUS_TYPE`、`UET_PCI_BDF` 支持）。
- 目标 NIC 的 PCI 设备在 `/sys/bus/pci/devices/` 下可见。

3) Bare-metal 复验命令：
```bash
# fi_info 采集
FI_PROVIDER_PATH=$PWD/uet_provider FI_PROVIDER=uet fi_info -v > logs/diag_nic_<date>-baremetal/fi_info_uet_verbose.txt 2>&1
FI_PROVIDER_PATH=$PWD/uet_provider FI_PROVIDER='uet;ofi_rxd' fi_info -v > logs/diag_nic_<date>-baremetal/fi_info_uet_rxd_verbose.txt 2>&1
FI_PROVIDER=tcp fi_info -v > logs/diag_nic_<date>-baremetal/fi_info_tcp_verbose.txt 2>&1

# NCCL 回归（baseline + ofi short + ofi long）
./scripts/smoke_nccl_ofi_single_gpu.sh <tag>

# 关键字提取
rg -n "Selected provider is|No NIC info for dev 0|Invalid type of PCI bus returned 0|pciPath: Could not find real path|Collective test concluded" <logfile>
```

4) Bare-metal 强通过标准（最终关闭条件）：
- OFI 路径必须命中：`Selected provider is uet;ofi_rxd`。
- 在 `uet;ofi_rxd` 路径必须同时无以下告警：
  - `Invalid type of PCI bus returned 0`
  - `pciPath: Could not find real path`
  - `No NIC info for dev 0`
- 功能必须通过：
  - `Collective test concluded`
  - 无 `Segmentation fault`
  - 无 `util.cu:555`

5) 结果记录模板：
- 日志目录建议：`logs/diag_nic_<date>-baremetal/`
- 最少文件集合：
  - `versions.txt`
  - `fi_info_uet_verbose.txt`
  - `fi_info_uet_rxd_verbose.txt`
  - `fi_info_tcp_verbose.txt`
  - `nccl_keylines_<tag>.txt`
  - `nic_matrix_<date>.md`
- 在 README 更新记录中追加：`Bare-metal 复验是否通过 + 三类告警是否清零 + 最终结论`。

## 问题定位记录（2026-02-14）

现象 1：
- `all_reduce_perf` 在 `# Using devices` 后崩溃，或报 `util.cu:555 OS call failed`。

定位：
- WSL 内 `libcuda.so` 解析发生冲突（`/usr/lib/wsl/lib/libcuda.so.1` 与 Linux 驱动包提供的 `libcuda.so.*` 混用）。

处理：
- 卸载冲突的 Linux 侧包（如 `libnvidia-compute-*`），保留 WSL 映射的 `libcuda.so.1`。
- 在 Windows 侧执行 `wsl --shutdown` 后重开终端。

现象 2：
- NCCL OFI 日志出现 `No eligible providers were found`，随后 `Selected provider is tcp`。

定位：
- provider 选择条件未满足，或环境变量未固定 `FI_PROVIDER`，导致回退到 `tcp`。
- `uet` 仅 dgram 语义，NCCL/OFI `SENDRECV` 推荐使用 `uet;ofi_rxd`。

处理：
- 固化环境变量：`FI_PROVIDER='uet;ofi_rxd'`。
- 复测时确认日志包含：`Selected provider is uet;ofi_rxd`。

结果：
- `all_reduce_perf` 正常结束，`Out of bounds values : 0 OK`。
- NCCL/OFI 插件链路可稳定加载并运行在 `uet;ofi_rxd` 上。

现象 3：
- 日志持续出现 `No NIC info for dev 0. Supplying default values for NIC properties.`。

定位：
- `uet_provider` 已在 `uet_getinfo()` 中补齐 NIC 元数据映射（含 `fid.ops` 的 `FI_DUP` 路径）。
- 但在 `uet;ofi_rxd` 叠加路径中，`nic` 仍可能不透传，aws-ofi-nccl 继续打印默认 NIC 回退日志。

影响：
- 功能与稳定性不受阻（当前单卡回归均 PASS），但拓扑/链路属性会使用默认值，后续多机性能归因精度受限。

后续计划：
- 继续核对 `uet -> ofi_rxd -> aws-ofi-nccl` 链路上的 NIC 透传行为，定位是 util-provider 透传限制还是字段仍缺失。
- 同步增强 provider 选择与过滤路径日志，提升可观测性。

现象 4（阶段二收口，2026-02-14）：
- 执行了单卡 OFI short/long 回归，并对关键日志做 grep 校验。

执行命令与结果：
```bash
rg -n "Selected provider is|Out of bounds values|Collective test concluded|Segmentation fault|No NIC info for dev 0" \
logs/phase1_singlegpu_2026-02-14/ofi_uet_rxd_g1_8M.log \
logs/phase1_singlegpu_2026-02-14/ofi_uet_rxd_g1_64M_long.log

FI_PROVIDER_PATH=$HOME/UEC_C-1/uet_provider FI_PROVIDER='uet' fi_info -v | rg -n "nic|device_attr|link_attr|bus_attr|speed|address"
FI_PROVIDER_PATH=$HOME/UEC_C-1/uet_provider FI_PROVIDER='uet;ofi_rxd' fi_info -v | rg -n "nic|device_attr|link_attr|bus_attr|speed|address"
```

关键结果：
- `Selected provider is uet;ofi_rxd`：short/long 均命中。
- `Out of bounds values : 0 OK`：short/long 均命中。
- `Collective test concluded: all_reduce_perf`：short/long 均命中。
- 未出现 `Segmentation fault`。
- 未出现 `No NIC info for dev 0`（本轮日志中未观测到）。
- `fi_info -v | rg ...` 为空（说明当前 verbose 输出不直接暴露这些关键词，不能单独作为失败判据）。

阶段结论：
- 本轮阶段二单卡链路验证通过，`NCCL + aws-ofi-nccl + uet;ofi_rxd` 可稳定运行。
- 当前可将 `FI_PROVIDER='uet;ofi_rxd'` 作为稳定回归路径。
- NIC 信息可见性仍以 NCCL 运行日志为主，不以 `fi_info -v | rg nic...` 单条命令作为唯一判定。

后续动作：
- 后续在多机或 util-provider 深入阶段，继续核对 `uet -> ofi_rxd -> aws-ofi-nccl` 的 NIC 元数据透传。
- 保留现有 `scripts/smoke_nccl_ofi_single_gpu.sh` 作为回归入口，后续所有改动先跑 short/long 再合并文档结论。

### MR 注册
- 目标端在 SES 注册 MR：
  - `register_mr(rkey, start_addr, length)`

### 发起 READ
在发起端构造 `OperationMetadata`：
- `op_type = READ`
- `job_id, messages_id, s_pid_on_fep, t_pid_on_fep`
- `memory.rkey = rkey`
- `payload.start_addr = remote_base`
- `payload.local_addr = local_dst`
- `payload.length = read_len`
- 将 metadata 推入 SES 队列执行

### WRITE（分片直写）
- WRITE 请求携带 payload 句柄与 `buffer_offset/message_offset/request_length`。
- 发送侧：`payload.start_addr` 作为远端目标地址，`payload.local_addr` 作为本地源数据指针。
- 目标端自动写入 MR 并在完整覆盖后回 `RC_OK`。

## 测试方法

### 编译
```
make -C UET/src/Test
```

### 运行 READ 端到端测试
```
./UET/src/Test/READTest
```
期望输出：`READ test PASS`

### 运行 WRITE 端到端测试
```
./UET/src/Test/WRITETest
```
期望输出：`WRITE test PASS`

### 运行多进程并发 WRITE 测试（单机）
服务端（监听端口 2990，2 个客户端，各写 1KB 分段）：
```
./UET/src/Test/WRITE_MultiProc --mode server --port 2990 --clients 2 --segment-len 1024
```
客户端（分别启动 2 个进程，复用同一 msg_id，靠 src_fep 隔离）：
```
./UET/src/Test/WRITE_MultiProc --mode client --server-port 2990 --client-id 0 --clients 2 --segment-len 1024
./UET/src/Test/WRITE_MultiProc --mode client --server-port 2990 --client-id 1 --clients 2 --segment-len 1024
```
服务端期望输出：`WRITE multiproc server PASS`
日志输出文件：
- `WRITE_MultiProc_server.log`
- `WRITE_MultiProc_client.log`

### 运行 MRDesc 交换测试（FI_MSG 控制面）
先编译 provider 与测试程序：
```
make -C uet_provider
make -C UET/src/Test MRDescTest
```
服务端：
```
FI_PROVIDER_PATH=$PWD/uet_provider ./UET/src/Test/MRDescTest --mode server --local-port 4000 --peer-port 4001
```
客户端：
```
FI_PROVIDER_PATH=$PWD/uet_provider ./UET/src/Test/MRDescTest --mode client --local-port 4001 --peer-port 4000
```
期望输出：client 打印 MRDesc 字段，server 打印 `MRDesc sent, ack=OK`。

说明（RDMA 语义对齐）：
- RMA API 仍要求应用提供 `remote_addr/offset + rkey`，这些来自控制面交换的 MRDesc。
- provider 可缓存 MRDesc 以减少重复维护，但无法完全隐藏 `remote_addr/rkey`（除非做非标准 API）。

### 运行 MRDesc + WRITE 闭环测试（控制面 + 数据面）
先编译：
```
make -C uet_provider
make -C UET/src/Test MRDescWriteTest
```
服务端（控制面端口 4000/4001，数据面端口 2990/2991）：
```
FI_PROVIDER_PATH=$PWD/uet_provider ./UET/src/Test/MRDescWriteTest --mode server \
  --ctrl-local-port 4000 --ctrl-peer-port 4001 \
  --data-server-port 2990 --data-client-port 2991
```
客户端：
```
FI_PROVIDER_PATH=$PWD/uet_provider ./UET/src/Test/MRDescWriteTest --mode client \
  --ctrl-local-port 4001 --ctrl-peer-port 4000 \
  --data-server-port 2990 --data-client-port 2991
```
期望输出：双方分别打印 `MRDescWrite server PASS` / `MRDescWrite client PASS`。
说明：
- 支持分片写入（`segment-len` > MTU 时由 SES 分片发送）
- 写入后校验 `offset/len` 与目标 MR 是否匹配

### 运行 MRDesc + fi_write 闭环测试（libfabric RMA WRITE）
说明：该测试使用 libfabric 的 `fi_write()`，走 provider 内 MRDesc registry，再由 SES/PDS/UDP 完成数据面写入。

先编译：
```
make -C uet_provider
make -C UET/src/Test MRDescWriteLibfabricTest
```
服务端：
```
UET_PROVIDER_DEBUG=1 FI_PROVIDER_PATH=$PWD/uet_provider ./UET/src/Test/MRDescWriteLibfabricTest \
  --mode server --local-ip 10.26.65.22 --peer-ip 10.26.65.23 --local-port 4000 --peer-port 4001 --len 4096 --offset 0
```
客户端：
```
UET_PROVIDER_DEBUG=1 FI_PROVIDER_PATH=$PWD/uet_provider ./UET/src/Test/MRDescWriteLibfabricTest \
  --mode client --local-ip 10.26.65.23 --peer-ip 10.26.65.22 --local-port 4001 --peer-port 4000 --len 4096 --offset 0
```
期望输出：`MRDescWriteLibfabric server PASS` / `MRDescWriteLibfabric client PASS`。

调试日志开关：
- `UET_PROVIDER_DEBUG=1`：关键日志
- `UET_PROVIDER_DEBUG=1 UET_PROVIDER_DEBUG_VERBOSE=1`：详细日志（RX/TX/close/fi_send 等）
- verbose 默认关闭，仅在排查问题时开启。

### 运行 MRDesc + fi_read 闭环测试（libfabric RMA READ）
说明：该测试使用 libfabric 的 `fi_read()`，服务端回传 response‑with‑data，客户端分片重组并完成 CQ。

先编译：
```
make -C uet_provider
make -C UET/src/Test MRDescReadLibfabricTest
```
建议并发启动（单终端一条命令）：
```
UET_PROVIDER_DEBUG=1 FI_PROVIDER_PATH=$PWD/uet_provider ./UET/src/Test/MRDescReadLibfabricTest \
  --mode server --local-ip 10.26.65.22 --peer-ip 10.26.65.23 --local-port 4000 --peer-port 4001 --len 4096 --offset 0 --timeout-ms 60000 \
  > MRDescRead_server.run.log 2>&1 & \
sleep 1; \
UET_PROVIDER_DEBUG=1 FI_PROVIDER_PATH=$PWD/uet_provider ./UET/src/Test/MRDescReadLibfabricTest \
  --mode client --local-ip 10.26.65.23 --peer-ip 10.26.65.22 --local-port 4001 --peer-port 4000 --len 4096 --offset 0 --timeout-ms 60000 \
  > MRDescRead_client.run.log 2>&1; \
wait
```
期望输出：`MRDescReadLibfabric server PASS` / `MRDescReadLibfabric client PASS`。
日志文件：
- `MRDescRead_server.log`
- `MRDescRead_client.log`

### READ 多分片压力测试（len > MTU）
目的：验证 response‑with‑data 多分片回传 + 客户端重组稳定性。

建议并发启动（单终端一条命令）：
```
UET_PROVIDER_DEBUG=1 FI_PROVIDER_PATH=$PWD/uet_provider ./UET/src/Test/MRDescReadLibfabricTest \
  --mode server --local-ip 10.26.65.22 --peer-ip 10.26.65.23 --local-port 4000 --peer-port 4001 --len 65536 --offset 0 --timeout-ms 60000 \
  > MRDescRead_stress_server.run.log 2>&1 & \
sleep 1; \
UET_PROVIDER_DEBUG=1 FI_PROVIDER_PATH=$PWD/uet_provider ./UET/src/Test/MRDescReadLibfabricTest \
  --mode client --local-ip 10.26.65.23 --peer-ip 10.26.65.22 --local-port 4001 --peer-port 4000 --len 65536 --offset 0 --timeout-ms 60000 \
  > MRDescRead_stress_client.run.log 2>&1; \
wait
```
期望输出：`MRDescReadLibfabric server PASS` / `MRDescReadLibfabric client PASS`。
如需更大规模，可把 `len` 提到 `262144/1048576`，同时适当增大 `timeout-ms`。
已验证：`len=65536` 分片压力测试 PASS（server/client 均通过）。

## 定位记录：WRITE 多客户端压力

现象（最近一次并发压力）：server 对 `client_id=1` 超时，`wait_range_ok timeout/fail`；诊断显示该区间**尾部少量字节仍为 0**（头部全为 `0x5a`），说明**并非完全未写入，而是尾包/尾部片未落地**。

已增加的诊断：
- 失败时打印 `range diag`（mismatch 数 + 首个不匹配位置）。
- 同时输出 head/tail sample 便于确认“尾部缺失”。

进一步定位（provider 侧分片日志）：
- `WRITE tx` 与 `WRITE rx` 日志显示 **尾包（44 bytes）已发送并在 server 侧收到并 memcpy**。
- 仍出现校验失败，说明“尾部缺失”**不是分片丢失**。
- server 日志显示在校验过程中发生 **PDC 被监控线程回收**（`Unhealthy process detected` → PDC destructor），与校验失败时间窗口重合。

结论：
- 当前问题更可能是 **PDC 过早回收** 导致写入/校验过程被打断或状态不一致，而非数据分片缺失。

下一步定位方向（计划）：
- 增加 per‑fragment 发送/接收日志（offset/len/som/eom），确认尾包是否到达 SES。
- DONE/ACK 的时序门槛：要求“收到 EOM/最后分片后再触发校验”，避免 DONE 早于落地。
- 让 PDC 监控具备“in‑flight/active”判断：写校验/响应未完成时不允许回收。

## 后续 DMA 方案计划（更贴近真实 RDMA）

- **异步 DMA 队列**：把 `memcpy` 从 SES 直接执行改为 “DMA descriptor → worker/线程/队列 → completion”，模拟 NIC DMA pipeline。
- **Posted buffer / SGE 形态**：接收面提供 `ptr + len + lkey`（或 handle）而非 `vector`，减少内部拷贝并靠 pool 管理生命周期。
- **Completion 语义**：按“消息完整覆盖 + DMA 完成”投递 CQ/ACK（类似 RDMA 远端完成）。
- **流控与可综合结构**：固定大小 descriptor、free list、refcount，避免动态分配，便于 HLS/硬件化。
- **可选零拷贝**：在 UDP 层尝试 `recvmsg` + iovec 直接落入 buffer pool（视实现成本决定）。

## 关键改动文件索引

- `UET/src/PayloadHandle.hpp`：payload 句柄/池实现
- `UET/src/Transport_Layer.hpp`：payload 字段类型替换
- `UET/src/Network_Layer/UDP_Network_Layer.cpp`：序列化/反序列化适配
- `UET/src/SES/SES.hpp`：READ/WRITE 语义、tracking、DMA 模拟
- `UET/src/PDS/PDC/PDC.cpp` / `PDC.hpp`：response‑with‑data 发送与源端标识
- `UET/src/PDS/PDS_Manager/PDSManager.hpp`：response 消息 ID 选择
- `UET/src/Test/READTest.cpp`：READ 端到端测试
- `uet_provider/uet_provider.cpp`：MRDesc registry + fi_write/fi_read 最小支持
- `UET/src/Test/MRDescWriteLibfabricTest.cpp`：libfabric fi_write 闭环测试
- `UET/src/Test/MRDescReadLibfabricTest.cpp`：libfabric fi_read 闭环测试

## 注意事项

- payload handle 只能在 handle 生命周期内使用，避免缓存裸指针跨线程/跨队列使用。
- pool 大小有限，超出会返回空 handle；发送路径需处理分配失败。
- 当前网络层仍有一次拷贝（UDP 收包落地到 pool），属于“语义阶段可接受”的实现。

## READ/WRITE 实现细节（当前版本）

### WRITE（fi_write）
- **发送端**：`fi_write()` → provider 查 MRDesc registry（rkey/remote_base/len）→ 计算 `buffer_offset` → 组装 WRITE 请求。
- **分片**：payload 超过 MTU 时按 `som/eom + message_offset` 分片发送。
- **接收端**：SES 解析 header，查 MR，按片执行 `memcpy(MR.base + buffer_offset + message_offset, payload)`。
- **完成**：分片齐全后回 Semantic_Response；client 收到响应后 CQ completion。

### READ（fi_read）
- **发送端**：`fi_read()` → provider 查 MRDesc registry → 发送 READ 请求（无 payload）。
- **接收端**：从 MR 读取数据，按 MTU 分片构造 response‑with‑data 回传。
- **重组**：client 按 `message_offset/payload_length/modified_length` 重组写回本地 buffer。
- **完成**：全部分片到齐后 CQ completion。

## 更新记录

- 2026-01-21：完成 payload 句柄化、WRITE 直写 + tracking、READ response‑with‑data 分片/重组、READTest 通过。后续相关变更请继续追加在此。
- 2026-01-21：新增 WRITETest（单包 + 分片），WRITE 发送端支持 `payload.local_addr` 作为源数据指针。
- 2026-01-21：新增 `WRITE_MultiProc` 多进程并发测试（同机多客户端）。
- 2026-01-27：provider 内 MRDesc registry + fi_write 最小闭环（MRDescWriteLibfabricTest），日志新增 `UET_PROVIDER_DEBUG_VERBOSE`。
- 2026-01-23：修复 `process_send_packet()` 发送逻辑（payload_len>0 也能进入分片/单包发送），多进程 WRITE 可稳定 PASS；补充收发日志（TX bytes / RX payload_len），失败时记录 errno/strerror。
- 2026-01-23：收敛临时调试日志（移除 `SES - message check`/enqueue/enter op），客户端按“实际发包”判定 PASS/FAIL。
- 2026-01-26：多进程 WRITE 的 PASS 条件改为“数据正确 + 响应队列清空”，客户端按收到 `Semantic_Response` 判定完成；将多连接定位日志降为 DEBUG（RX pkt / TX rsp）。
- 2026-01-28：WRITE 多客户端压力定位新增 `range diag`（mismatch/首个坏字节/头尾样本）；发现尾部片缺失迹象，规划 per‑fragment 发送/接收日志与“EOM 后再校验”策略。
- 2026-02-14：完成 NCCL + aws-ofi-nccl + uet provider 联调；修复 WSL `libcuda.so` 冲突导致的 `util.cu:555`；明确 `FI_PROVIDER='uet;ofi_rxd'` 作为稳定配置，并验证日志出现 `Selected provider is uet;ofi_rxd`。
- 2026-02-15：完成控制面最小升级（P0）落地：provider 切到显式 `CtrlHdr`（`HELLO/MRDESC/ACK/ERR`）+ session 记录 + RMA 前 session 检查 + MRDesc 严格查找；测试程序同步为新格式（不兼容旧裸 `MRDesc`）。
- 2026-02-15：执行验收通过：`MRDescTest`、`MRDescWriteLibfabricTest`、`MRDescReadLibfabricTest` 均 PASS；`./scripts/smoke_nccl_ofi_single_gpu.sh 2026-02-14-nic` 通过，OFI short/long 均命中 `Selected provider is uet;ofi_rxd` 且无 `Segmentation fault`/`util.cu:555`。
- 2026-02-16：完成 NIC 元数据链路深挖（`uet -> ofi_rxd -> aws-ofi-nccl`），沉淀诊断产物 `logs/diag_nic_2026-02-16/*` 与字段矩阵；将根因归类为 C 类（bus 元数据可解析性问题）。
- 2026-02-16：完成条件化最小修复：`uet_provider` 新增 `UET_BUS_TYPE` / `UET_PCI_BDF`，消除 `Invalid type of PCI bus returned 0`；在 WSL 下仍有 `pciPath` 真实路径解析告警（已记录为环境限制）。
- 2026-03-03：新增单卡回归门禁与日志汇总能力：`scripts/generate_nccl_regression_gate_report.sh` 可生成 `regression_gate_<tag>.md`（含 `provider_hit/collective_done/oob_ok/crash_free/allowed_warn_only`），并接入 `scripts/smoke_nccl_ofi_single_gpu.sh` 自动产出报告；新增规范文档 `DOC/single_gpu_regression_gate.md`。
- 2026-03-03：补充 README 单卡回归门禁标准（功能优先 + 允许 WSL 已知告警）与报告产物路径说明。
- 2026-03-03：在当前机器尝试执行 `./scripts/smoke_nccl_ofi_single_gpu.sh 2026-03-03`，因环境缺少 `~/nccl-tests`、`all_reduce_perf`、`nvcc` 未能完成实跑，未生成 `logs/regression_gate_2026-03-03.md`。
