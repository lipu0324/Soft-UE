// Minimal libfabric provider for UET (FI_MSG over UET-over-UDP prototype).
// Phase 1 goal: run fi_pingpong with -p uet -e dgram (send/recv + cq + av).
//
// Design notes (learning-oriented):
// - We expose the existing UET prototype as a libfabric provider named "uet".
// - Scope is intentionally minimal: FI_MSG (send/recv) + CQ + AV over FI_EP_DGRAM.
// - We reuse the current UET implementation as an "engine":
//     * SESManager generates PDStoNET_pkt packets for outgoing SEND (with slicing).
//     * UDPNetworkLayer serializes PDStoNET_pkt to bytes and sends/receives via UDP sockets.
// - Provider responsibilities:
//     * map libfabric objects (fabric/domain/ep/av/cq) to internal UET engine objects
//     * run a progress loop (threads) to move packets between SES/PDS queues and UDP
//     * implement a simple FI_RECV completion path by reassembling payload bytes from
//       SES standard header fields (som/eom/message_offset/request_length).
//
// Limitations (phase 1):
// - No RMA/read/write, tagged, atomics, MR semantics; these are intentionally rejected in getinfo().
// - No connection management: DGRAM "name exchange" uses fi_getname/fi_setname + AV.
// - recv matching is minimal: FIFO posted-recvs; if no recv is posted yet we stash as "unexpected".

// =========================
// 中文导读（建议从这里开始）
// =========================
// 目标：把你们现有 UET 原型（SES/PDS/UDP 垫片）以 libfabric provider 的形式暴露出去（provider 名 "uet"），
// 先跑通 fi_pingpong/自测程序的 FI_MSG（send/recv）基本闭环。
//
// 第一期开荒只实现：
//   - FI_MSG: fi_send / fi_recv（消息收发）
//   - FI_CQ: 完成队列（send/recv completion）
//   - FI_AV: 地址簿（sockaddr_in -> fi_addr_t）
//   - Endpoint: FI_EP_DGRAM（connection-less）
//
// 复用思路（对应“方案 A：provider 直接驱动 队列 + UDP shim”）：
//   - 发送：fi_send -> 构造 OperationMetadata(SEND) -> ses.lfbric_ses_q.push -> ses.mainChk()
//          SES 会生成 PDStoNET_pkt(带 SES 标准头 + payload 分片) -> 进入 pds_process_manager 的 network queue
//          tx_thread 从 queue pop 出来 -> udp_tx.sendPacket() 发到对端
//   - 接收：rx_thread udp_rx.receivePDStoNETPacket() 收到 PDStoNET_pkt -> pushNetworkPacket() 喂给 PDS/SES
//          同时：对 RUOD_req + Standard_Header 的 packet，基于 som/eom/message_offset/request_length 重组 payload，
//          找到一个 posted recv buffer，把数据 memcpy 进去，向 rx_cq 投递 FI_RECV completion
//
// 重要取舍：
//   - recv 完成事件由 RX 线程直接产生（不依赖 SES 的 rsp/ack 语义），最快把 FI_MSG 跑通
//   - send 完成：在 tx_thread 实际发出该消息最后一个分片后投递 FI_SEND completion（仍不等待对端确认）

#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cctype>
#include <cstddef>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <inttypes.h>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <random>
#include <deque>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

// Reuse existing UET prototype implementation.
// Note: include UET headers before libfabric headers to avoid FI_* macro collisions.
// 中文说明：
// - libfabric 头文件里会定义大量 FI_* 宏（例如 FI_DELIVERY_COMPLETE）
// - 你们 UET 头文件/函数形参里也有同名标识符时，会被宏替换导致编译报错
// - 解决方式之一：先 include UET 再 include libfabric（或者对冲突宏进行 #undef）
#include "../UET/src/Network_Layer/UDP_Network_Layer.hpp"
#include "../UET/src/SES/SES.hpp"
#include "../UET/src/logger/Logger.hpp"

#include <rdma/providers/fi_prov.h>

#include <rdma/fabric.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_eq.h>
#include <rdma/fi_errno.h>
#include <rdma/fi_rma.h>

#if __has_include(<infiniband/verbs.h>)
#include <infiniband/verbs.h>
#define UET_HAVE_IBVERBS 1
#else
#define UET_HAVE_IBVERBS 0
#endif

#if __has_include(<rdma/rdma_cma.h>)
#include <rdma/rdma_cma.h>
#define UET_HAVE_RDMACM 1
#else
#define UET_HAVE_RDMACM 0
#endif

namespace {

// =========================
// Debug logging (opt-in)
// =========================
// Enable by exporting: UET_PROVIDER_DEBUG=1
static bool uet_debug_enabled()
{
    static int cached = -1;
    if (cached != -1) return cached == 1;
    const char* v = std::getenv("UET_PROVIDER_DEBUG");
    cached = (v && *v && std::string(v) != "0") ? 1 : 0;
    return cached == 1;
}

static bool uet_debug_verbose()
{
    static int cached = -1;
    if (cached != -1) return cached == 1;
    const char* v = std::getenv("UET_PROVIDER_DEBUG_VERBOSE");
    cached = (v && *v && std::string(v) != "0") ? 1 : 0;
    return cached == 1;
}

static bool uet_env_truthy(const char* name, bool default_value = false)
{
    const char* v = std::getenv(name);
    if (!v || v[0] == '\0') {
        return default_value;
    }
    std::string value(v);
    for (char& ch : value) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    return !(value == "0" || value == "false" || value == "off" || value == "no");
}

static uint64_t uet_now_ns()
{
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count());
}

static void uet_dbg(const char* tag, const char* fmt, ...)
{
    if (!uet_debug_enabled()) return;
    std::fprintf(stderr, "[uet][pid=%d][%s] ", static_cast<int>(::getpid()), tag);
    va_list ap;
    va_start(ap, fmt);
    std::vfprintf(stderr, fmt, ap);
    va_end(ap);
    std::fprintf(stderr, "\n");
    std::fflush(stderr);
}

static void uet_dbg_v(const char* tag, const char* fmt, ...)
{
    if (!uet_debug_enabled() || !uet_debug_verbose()) return;
    std::fprintf(stderr, "[uet][pid=%d][%s] ", static_cast<int>(::getpid()), tag);
    va_list ap;
    va_start(ap, fmt);
    std::vfprintf(stderr, fmt, ap);
    va_end(ap);
    std::fprintf(stderr, "\n");
    std::fflush(stderr);
}

// =========================
// Provider 基本信息（对外可见）
// =========================
constexpr const char* kProviderName = "uet";
// provider interface version：libfabric 用于 provider 插件入口 (FI_EXT_INI) 的 ABI/结构体版本
constexpr uint32_t kProviderInterfaceVersion = FI_VERSION(1, 0);
// provider 对外宣告的 libfabric API 版本（注意：调用方可能传更低版本，见 uet_getinfo）
constexpr uint32_t kProviderApiVersion = FI_VERSION(2, 3); // matches "libfabric api: 2.3"

// CQ 默认容量（fi_cq_open 时如果没指定 size）
constexpr size_t kDefaultCqSize = 1024;

// 与你们 UET 原型保持一致的“单包大小”假设（用于分片/重组）
constexpr size_t kUetMaxMtu = 4096;
constexpr size_t kUetMaxPayloadPerPacket = kUetMaxMtu - sizeof(SES_Standard_Header);
// 向 libfabric 宣告的“最大消息大小”（fi_pingpong 会按它生成测试 size）
constexpr size_t kUetAdvertisedMaxMsgSize = 1024 * 1024; // keep fi_pingpong default sizes working
constexpr uint64_t kUetDefaultLinkSpeedGbps = 100;       // metadata only

// =========================
// container_of：从 fid_* 反查 provider 的 C++ 对象
// =========================
template <typename T>
static inline T* container_of(void* ptr, size_t offset)
{
    return reinterpret_cast<T*>(reinterpret_cast<char*>(ptr) - offset);
}

template <typename T, typename M>
static inline T* container_of(M* member_ptr, M T::*member)
{
    const auto offset = reinterpret_cast<size_t>(&(reinterpret_cast<T*>(0)->*member));
    return reinterpret_cast<T*>(reinterpret_cast<char*>(member_ptr) - offset);
}

static inline bool sockaddr_in_equal(const sockaddr_in& a, const sockaddr_in& b)
{
    return a.sin_family == b.sin_family && a.sin_port == b.sin_port && a.sin_addr.s_addr == b.sin_addr.s_addr;
}

static inline std::string sockaddr_in_to_ip_string(const sockaddr_in& addr)
{
    char buf[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &addr.sin_addr, buf, sizeof(buf));
    return std::string(buf);
}

// 选择一个“可对外公布”的本机 IPv4 地址（优先非 loopback）。
// 用途：fi_pingpong 会交换 fi_getname() 的 sockaddr，如果返回 0.0.0.0，对端无法用它回包。
static bool uet_pick_default_ipv4(in_addr& out)
{
    ifaddrs* ifaddr = nullptr;
    if (getifaddrs(&ifaddr) != 0) return false;

    // Prefer a non-loopback IPv4 address.
    for (auto* ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        if (ifa->ifa_addr->sa_family != AF_INET) continue;
        const auto* sa = reinterpret_cast<const sockaddr_in*>(ifa->ifa_addr);
        const uint32_t ip = sa->sin_addr.s_addr;
        if (ip == htonl(INADDR_LOOPBACK) || ip == htonl(INADDR_ANY)) continue;
        out = sa->sin_addr;
        freeifaddrs(ifaddr);
        return true;
    }

    // Fallback to loopback if nothing else is available.
    for (auto* ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;
        if (ifa->ifa_addr->sa_family != AF_INET) continue;
        const auto* sa = reinterpret_cast<const sockaddr_in*>(ifa->ifa_addr);
        out = sa->sin_addr;
        freeifaddrs(ifaddr);
        return true;
    }

    freeifaddrs(ifaddr);
    return false;
}

static uint64_t uet_get_link_speed_bps()
{
    const char* v = std::getenv("UET_LINK_SPEED_GBPS");
    if (!v || !*v) {
        return kUetDefaultLinkSpeedGbps * 1000ULL * 1000ULL * 1000ULL;
    }

    errno = 0;
    char* end = nullptr;
    unsigned long long gbps = std::strtoull(v, &end, 10);
    if (errno != 0 || end == v || gbps == 0) {
        uet_dbg("nic", "invalid UET_LINK_SPEED_GBPS=%s, fallback to %" PRIu64 " Gbps", v,
                static_cast<uint64_t>(kUetDefaultLinkSpeedGbps));
        gbps = kUetDefaultLinkSpeedGbps;
    }
    return static_cast<uint64_t>(gbps) * 1000ULL * 1000ULL * 1000ULL;
}

static std::string uet_to_lower(std::string s)
{
    for (char& c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return s;
}

static fi_bus_type uet_get_bus_type()
{
    const char* v = std::getenv("UET_BUS_TYPE");
    if (!v || !*v) {
        // Default to PCI so aws-ofi-nccl can treat this as a NIC with bus metadata.
        return FI_BUS_PCI;
    }

    const std::string s = uet_to_lower(std::string(v));
    if (s == "pci" || s == "fi_bus_pci" || s == "2") {
        return FI_BUS_PCI;
    }
    if (s == "unknown" || s == "unspec" || s == "fi_bus_unknown" || s == "fi_bus_unspec" || s == "0") {
        return FI_BUS_UNKNOWN;
    }

    uet_dbg("nic", "invalid UET_BUS_TYPE=%s, fallback to pci", v);
    return FI_BUS_PCI;
}

static bool uet_parse_pci_bdf(const char* bdf, fi_pci_attr& out)
{
    if (!bdf || !*bdf) return false;

    unsigned int domain = 0;
    unsigned int bus = 0;
    unsigned int device = 0;
    unsigned int function = 0;
    if (std::sscanf(bdf, "%x:%x:%x.%x", &domain, &bus, &device, &function) != 4) {
        return false;
    }

    if (domain > 0xffffU || bus > 0xffU || device > 0xffU || function > 0xffU) {
        return false;
    }

    out.domain_id = static_cast<uint16_t>(domain);
    out.bus_id = static_cast<uint8_t>(bus);
    out.device_id = static_cast<uint8_t>(device);
    out.function_id = static_cast<uint8_t>(function);
    return true;
}

static fi_pci_attr uet_get_pci_attr()
{
    fi_pci_attr pci{};
    const char* v = std::getenv("UET_PCI_BDF");
    if (!v || !*v) {
        // Default stays synthetic but parseable.
        pci.domain_id = 0;
        pci.bus_id = 0;
        pci.device_id = 0;
        pci.function_id = 0;
        return pci;
    }

    if (!uet_parse_pci_bdf(v, pci)) {
        uet_dbg("nic", "invalid UET_PCI_BDF=%s, fallback to 0000:00:00.0", v);
        pci = fi_pci_attr{};
    }
    return pci;
}

static int uet_nic_close(struct fid* fid);
static int uet_nic_control(struct fid* fid, int command, void* arg);
static int uet_nic_tostr(const struct fid*, char*, size_t);

static fi_ops uet_nic_fid_ops = {
    .size = sizeof(fi_ops),
    .close = uet_nic_close,
    .bind = nullptr,
    .control = uet_nic_control,
    .ops_open = nullptr,
    .tostr = uet_nic_tostr,
    .ops_set = nullptr,
};

static void uet_free_nic(fid_nic* nic)
{
    if (!nic) return;

    if (nic->device_attr) {
        free(nic->device_attr->name);
        free(nic->device_attr->device_id);
        free(nic->device_attr->device_version);
        free(nic->device_attr->vendor_id);
        free(nic->device_attr->driver);
        free(nic->device_attr->firmware);
        free(nic->device_attr);
    }

    if (nic->bus_attr) {
        free(nic->bus_attr);
    }

    if (nic->link_attr) {
        free(nic->link_attr->address);
        free(nic->link_attr->network_type);
        free(nic->link_attr);
    }

    free(nic);
}

static int uet_nic_close(struct fid* fid)
{
    if (!fid || fid->fclass != FI_CLASS_NIC) return -FI_EINVAL;
    uet_free_nic(reinterpret_cast<fid_nic*>(fid));
    return 0;
}

static char* uet_dup_str(const char* src)
{
    return src ? ::strdup(src) : nullptr;
}

static fid_nic* uet_dup_nic(const fid_nic* src)
{
    auto* dup = static_cast<fid_nic*>(std::calloc(1, sizeof(fid_nic)));
    if (!dup) return nullptr;

    dup->fid.fclass = FI_CLASS_NIC;
    dup->fid.ops = &uet_nic_fid_ops;

    if (!src) return dup;

    if (src->device_attr) {
        dup->device_attr = static_cast<fi_device_attr*>(std::calloc(1, sizeof(*dup->device_attr)));
        if (!dup->device_attr) goto fail;

        dup->device_attr->name = uet_dup_str(src->device_attr->name);
        dup->device_attr->device_id = uet_dup_str(src->device_attr->device_id);
        dup->device_attr->device_version = uet_dup_str(src->device_attr->device_version);
        dup->device_attr->vendor_id = uet_dup_str(src->device_attr->vendor_id);
        dup->device_attr->driver = uet_dup_str(src->device_attr->driver);
        dup->device_attr->firmware = uet_dup_str(src->device_attr->firmware);
    }

    if (src->bus_attr) {
        dup->bus_attr = static_cast<fi_bus_attr*>(std::calloc(1, sizeof(*dup->bus_attr)));
        if (!dup->bus_attr) goto fail;
        *dup->bus_attr = *src->bus_attr;
    }

    if (src->link_attr) {
        dup->link_attr = static_cast<fi_link_attr*>(std::calloc(1, sizeof(*dup->link_attr)));
        if (!dup->link_attr) goto fail;

        dup->link_attr->address = uet_dup_str(src->link_attr->address);
        dup->link_attr->network_type = uet_dup_str(src->link_attr->network_type);
        dup->link_attr->mtu = src->link_attr->mtu;
        dup->link_attr->speed = src->link_attr->speed;
        dup->link_attr->state = src->link_attr->state;
    }

    if (src->prov_attr) {
        dup->prov_attr = src->prov_attr;
    }

    if ((dup->device_attr &&
         ((!dup->device_attr->name && src->device_attr->name) ||
          (!dup->device_attr->device_id && src->device_attr->device_id) ||
          (!dup->device_attr->device_version && src->device_attr->device_version) ||
          (!dup->device_attr->vendor_id && src->device_attr->vendor_id) ||
          (!dup->device_attr->driver && src->device_attr->driver) ||
          (!dup->device_attr->firmware && src->device_attr->firmware))) ||
        (dup->link_attr &&
         ((!dup->link_attr->address && src->link_attr->address) ||
          (!dup->link_attr->network_type && src->link_attr->network_type)))) {
        goto fail;
    }

    return dup;

fail:
    uet_free_nic(dup);
    return nullptr;
}

static int uet_nic_control(struct fid* fid, int command, void* arg)
{
    if (!fid || fid->fclass != FI_CLASS_NIC) return -FI_EINVAL;

    if (command == FI_DUP) {
        if (!arg) return -FI_EINVAL;
        auto** out = reinterpret_cast<fid_nic**>(arg);
        auto* dup = uet_dup_nic(reinterpret_cast<fid_nic*>(fid));
        if (!dup) return -FI_ENOMEM;
        *out = dup;
        return 0;
    }

    return -FI_ENOSYS;
}

static int uet_nic_tostr(const struct fid*, char*, size_t)
{
    return -FI_ENOSYS;
}

static int uet_fill_nic_metadata(fi_info* info)
{
    if (!info) return -FI_EINVAL;

    auto* nic = uet_dup_nic(nullptr);
    if (!nic) return -FI_ENOMEM;
    auto* dev = nic->device_attr = static_cast<fi_device_attr*>(std::calloc(1, sizeof(fi_device_attr)));
    auto* bus = nic->bus_attr = static_cast<fi_bus_attr*>(std::calloc(1, sizeof(fi_bus_attr)));
    auto* link = nic->link_attr = static_cast<fi_link_attr*>(std::calloc(1, sizeof(fi_link_attr)));
    if (!dev || !bus || !link) {
        uet_free_nic(nic);
        return -FI_ENOMEM;
    }

    const char* nic_name_env = std::getenv("UET_NIC_NAME");
    const char* nic_name = (nic_name_env && *nic_name_env) ? nic_name_env : "uet0";
    dev->name = ::strdup(nic_name);
    dev->driver = ::strdup("uet-provider");
    dev->firmware = ::strdup("n/a");
    dev->vendor_id = ::strdup("uet");
    dev->device_id = ::strdup("virtual-uet");
    dev->device_version = ::strdup("1");

    bus->bus_type = uet_get_bus_type();
    if (bus->bus_type == FI_BUS_PCI) {
        bus->attr.pci = uet_get_pci_attr();
    }

    in_addr ip{};
    if (uet_pick_default_ipv4(ip)) {
        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_addr = ip;
        link->address = ::strdup(sockaddr_in_to_ip_string(sa).c_str());
    } else {
        link->address = ::strdup("127.0.0.1");
    }
    link->mtu = kUetMaxMtu;
    link->speed = uet_get_link_speed_bps();
    link->state = FI_LINK_UP;
    link->network_type = ::strdup("ethernet");

    if (!dev->name || !dev->driver || !dev->firmware || !dev->vendor_id || !dev->device_id ||
        !dev->device_version || !link->address || !link->network_type) {
        uet_free_nic(nic);
        return -FI_ENOMEM;
    }

    info->nic = nic;
    return 0;
}

struct uet_cq_entry
{
    // Enough fields to populate FI_CQ_FORMAT_MSG and FI_CQ_FORMAT_CONTEXT.
    // 中文说明：
    // - fi_cq_read 的输出有多种格式（FI_CQ_FORMAT_CONTEXT / MSG / DATA / TAGGED）
    // - 第一期开荒只支持 CONTEXT 和 MSG，因此 CQ entry 只需要 context/flags/len/src_addr
    void* op_context = nullptr;
    uint64_t flags = 0;
    size_t len = 0;
    fi_addr_t src_addr = FI_ADDR_UNSPEC;
};

struct uet_cq
{
    // 完成队列（CQ）实现方式：一个线程安全队列 + 条件变量
    // - TX completion：fi_send 立即 cq_push(FI_SEND)
    // - RX completion：rx_thread 重组完成后 cq_push(FI_RECV)
    fid_cq cq{};
    fi_ops cq_fid_ops{};
    fi_ops_cq cq_ops{};

    fi_cq_attr attr{};

    std::mutex mu;
    std::condition_variable cv;
    std::queue<uet_cq_entry> entries;
    bool closed = false;
};

struct uet_eq
{
    // 事件队列（EQ）这里做最小 stub：fi_eq_open 可以成功，但 read/sread 都返回 -FI_EAGAIN
    // （fi_pingpong 的 DGRAM 模式通常不强依赖 EQ）
    fid_eq eq{};
    fi_ops eq_fid_ops{};
    fi_ops_eq eq_ops{};

    std::mutex mu;
    std::condition_variable cv;
    bool closed = false;
};

struct uet_av_entry
{
    // 地址簿元素：我们只实现 IPv4 sockaddr_in
    sockaddr_in addr{};
};

struct uet_av
{
    // 地址簿（AV）：把 sockaddr 插入并返回 fi_addr_t（我们用 vector index 作为 fi_addr_t）
    fid_av av{};
    fi_ops av_fid_ops{};
    fi_ops_av av_ops{};

    std::mutex mu;
    std::vector<uet_av_entry> entries;
};

struct uet_fabric;
struct uet_domain;
struct uet_ep;
struct uet_mr;
struct uet_rnic_device;
enum class uet_rdma_connect_mode : uint8_t;

static int uet_fid_close(struct fid* fid);
static int uet_fid_bind(struct fid* fid, struct fid* bfid, uint64_t flags);
static int uet_fid_control(struct fid* fid, int command, void* arg);
static int uet_fid_ops_open(struct fid*, const char*, uint64_t, void**, void*);
static int uet_fid_tostr(const struct fid*, char*, size_t);
static int uet_fid_ops_set(struct fid*, const char*, uint64_t, void*, void*);
static bool uet_handle_internal_ctrl_msg(uet_ep* uep, const std::vector<uint8_t>& msg, fi_addr_t src_addr);
static uet_rdma_connect_mode uet_rdma_select_connect_mode(uet_ep* uep);
static void uet_rdma_fail_conn(uet_ep* uep, int err, const std::string& reason);

enum class uet_backend_kind : uint8_t
{
    soft = 1,
    rdma = 2,
};

enum class uet_rdma_connect_mode : uint8_t
{
    auto_select = 0,
    manual_rc = 1,
    iwarp_cm = 2,
};

enum class uet_write_completion_mode : uint8_t
{
    remote_ack = 0,
    local_cq = 1,
};

enum class uet_mem_type : uint8_t
{
    host = 1,
};

static const char* uet_backend_name(uet_backend_kind backend)
{
    switch (backend) {
        case uet_backend_kind::soft:
            return "soft";
        case uet_backend_kind::rdma:
            return "rdma";
        default:
            return "unknown";
    }
}

static const char* uet_rdma_connect_mode_name(uet_rdma_connect_mode mode)
{
    switch (mode) {
        case uet_rdma_connect_mode::auto_select:
            return "auto";
        case uet_rdma_connect_mode::manual_rc:
            return "manual_rc";
        case uet_rdma_connect_mode::iwarp_cm:
            return "iwarp_cm";
        default:
            return "unknown";
    }
}

static const char* uet_write_completion_mode_name(uet_write_completion_mode mode)
{
    switch (mode) {
        case uet_write_completion_mode::remote_ack:
            return "remote_ack";
        case uet_write_completion_mode::local_cq:
            return "local_cq";
        default:
            return "unknown";
    }
}

static uet_backend_kind uet_parse_backend()
{
    const char* env = std::getenv("UET_BACKEND");
    if (!env || env[0] == '\0') {
        return uet_backend_kind::soft;
    }

    std::string value(env);
    for (char& ch : value) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }

    if (value == "rdma") {
        return uet_backend_kind::rdma;
    }
    if (value == "soft") {
        return uet_backend_kind::soft;
    }

    uet_dbg("backend", "invalid UET_BACKEND='%s', fallback to soft", env);
    return uet_backend_kind::soft;
}

static uet_rdma_connect_mode uet_parse_rdma_connect_mode()
{
    const char* env = std::getenv("UET_RDMA_CONNECT_MODE");
    if (!env || env[0] == '\0') {
        return uet_rdma_connect_mode::auto_select;
    }

    std::string value(env);
    for (char& ch : value) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }

    if (value == "auto") {
        return uet_rdma_connect_mode::auto_select;
    }
    if (value == "manual_rc") {
        return uet_rdma_connect_mode::manual_rc;
    }
    if (value == "iwarp_cm") {
        return uet_rdma_connect_mode::iwarp_cm;
    }

    uet_dbg("rdma", "invalid UET_RDMA_CONNECT_MODE='%s', fallback to auto", env);
    return uet_rdma_connect_mode::auto_select;
}

static uet_write_completion_mode uet_parse_write_completion_mode()
{
    const char* env = std::getenv("UET_WRITE_COMPLETION_MODE");
    if (!env || env[0] == '\0') {
        return uet_write_completion_mode::remote_ack;
    }

    std::string value(env);
    for (char& ch : value) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }

    if (value == "remote_ack" || value == "ack") {
        return uet_write_completion_mode::remote_ack;
    }
    if (value == "local_cq" || value == "local") {
        return uet_write_completion_mode::local_cq;
    }

    uet_dbg("rdma", "invalid UET_WRITE_COMPLETION_MODE='%s', fallback to remote_ack", env);
    return uet_write_completion_mode::remote_ack;
}

struct uet_fabric
{
    // libfabric 对象层级：fabric -> domain -> endpoint
    fid_fabric fabric{};
    fi_ops fabric_fid_ops{};
    fi_ops_fabric fabric_ops{};
};

struct uet_domain
{
    // domain 负责创建/打开 CQ、AV、EP 等资源
    fid_domain domain{};
    fi_ops domain_fid_ops{};
    fi_ops_domain domain_ops{};
    fi_ops_mr mr_ops{};
    uet_backend_kind backend = uet_backend_kind::soft;
    bool rdma_requested = false;
    bool rdma_runtime_ready = false;
    std::string rdma_unavailable_reason;
    std::mutex mr_registry_mu;
    std::unordered_map<uint32_t, uet_mr*> local_mr_by_rkey;
    std::unordered_map<uintptr_t, uet_mr*> local_mr_by_base;
    std::atomic<uint64_t> next_reg_epoch{1};
    std::atomic<uint32_t> next_soft_rkey{0x10000u};
    uet_rnic_device* rdma_device = nullptr;
};

struct uet_posted_recv
{
    // Posted recv entry: the user buffer to fill + a context pointer that we return in the CQ entry.
    // 中文说明：
    // - FI_MSG 的 recv 模式是“先 post buffer（fi_recv），后由 provider 异步完成”
    // - provider 必须自己维护 posted recv 队列/匹配逻辑
    void* buf = nullptr;
    size_t len = 0;
    void* context = nullptr;
    fi_addr_t src_filter = FI_ADDR_UNSPEC;
};

struct uet_pending_send
{
    // Pending FI_SEND request queued by fi_send() and executed by ses_thread.
    // 中文说明：
    // - FI_MSG 的语义要求：在 FI_SEND completion 产生之后，上层才可以安全复用/释放用户 send buffer。
    // - 因此我们不能在 fi_send() 里“立刻完成”后再异步去从用户 buffer 读取数据；
    //   必须先让 SES 把 payload copy 进自己的 packet buffer（std::vector<uint8_t>），
    //   再投递 FI_SEND completion。
    OperationMetadata md{};
    void* context = nullptr;
    size_t len = 0;
    bool track_completion = true;
    std::shared_ptr<std::vector<uint8_t>> owned_buffer;
};

struct uet_unexpected_msg
{
    std::vector<uint8_t> data;
    fi_addr_t src_addr = FI_ADDR_UNSPEC;
};

struct uet_reassembly_key
{
    uint32_t src_fep = 0;
    uint16_t msg_id = 0;

    bool operator==(const uet_reassembly_key& other) const
    {
        return src_fep == other.src_fep && msg_id == other.msg_id;
    }
};

struct uet_reassembly_key_hash
{
    size_t operator()(const uet_reassembly_key& key) const noexcept
    {
        return (static_cast<size_t>(key.src_fep) << 16) ^ static_cast<size_t>(key.msg_id);
    }
};

struct uet_reassembly_state
{
    // Tracks a multi-packet FI_MSG receive assembled from SES "Standard_Header" fragments.
    // chunk_size must match the sender's max payload per packet:
    //   MAX_MTU - sizeof(SES_Standard_Header)
    // 中文说明：
    // - 你们 SES 分片使用 Standard_Header：
    //     som/eom 表示首/尾分片
    //     message_offset 表示 payload 在整条消息里的偏移
    //     request_length 表示整条消息总长度
    // - provider 收到分片后按 offset memcpy 到 buffer，直到所有分片到齐并看到 eom 才算完成
    uint32_t total_len = 0;
    size_t chunk_size = 0;
    std::vector<uint8_t> buffer;
    std::vector<uint8_t> chunk_received;
    size_t chunks_done = 0;
    bool saw_eom = false;
    fi_addr_t src_addr = FI_ADDR_UNSPEC;
};

struct uet_rnic_device
{
#if UET_HAVE_IBVERBS
    ibv_context* device_ctx = nullptr;
    ibv_pd* pd = nullptr;
    bool ctx_owned = false;
    ibv_transport_type transport_type = IBV_TRANSPORT_UNKNOWN;
    ibv_device_attr device_attr{};
    ibv_port_attr port_attr{};
    union ibv_gid gid{};
#else
    void* device_ctx = nullptr;
    void* pd = nullptr;
#endif
    bool available = false;
    uint8_t port_num = 0;
    bool gid_valid = false;
    std::string device_name;
};

struct uet_mr
{
    fid_mr mr{};
    fi_ops fid_ops{};
    void* addr = nullptr;
    size_t len = 0;
    uint64_t access = 0;
    uint32_t lkey = 0;
    uint32_t rkey = 0;
    uint64_t reg_epoch = 0;
    uet_mem_type mem_type = uet_mem_type::host;
    uet_backend_kind backend = uet_backend_kind::soft;
#if UET_HAVE_IBVERBS
    ibv_mr* hw_mr_handle = nullptr;
#else
    void* hw_mr_handle = nullptr;
#endif
    uet_domain* domain = nullptr;
};

constexpr uint32_t kUetMrdescMagic = 0x4d524443; // "MRDC"
constexpr uint16_t kUetMrdescVersion = 2;
constexpr uint32_t kUetCtrlMagic = 0x55435452; // "UCTR"
constexpr uint16_t kUetCtrlVersion = 1;

enum uet_ctrl_msg_type : uint16_t
{
    UET_CTRL_HELLO = 1,
    UET_CTRL_MRDESC = 2,
    UET_CTRL_ACK = 3,
    UET_CTRL_ERR = 4,
    UET_CTRL_WRITE_NOTIFY = 9,
    UET_CTRL_WRITE_ACK = 10,
    UET_CTRL_RDMA_CONN_REQ = 11,
    UET_CTRL_RDMA_CONN_RESP = 12,
};

struct __attribute__((packed)) uet_rdma_conn_msg
{
    uint32_t qp_num = 0;
    uint32_t psn = 0;
    uint16_t lid = 0;
    uint8_t port_num = 0;
    uint8_t gid_valid = 0;
    uint8_t gid[16]{};
};

struct __attribute__((packed)) uet_write_notify_msg
{
    uint64_t wr_id = 0;
    uint32_t status = 0;
    uint32_t reserved = 0;
};

struct __attribute__((packed)) uet_ctrl_hdr
{
    uint32_t magic = 0;
    uint16_t version = 0;
    uint16_t msg_type = 0;
    uint16_t hdr_len = 0;
    uint16_t reserved0 = 0;
    uint32_t total_len = 0;
    uint64_t session_id = 0;
    uint32_t job_id = 0;
    uint32_t resource_index = 0;
    uint32_t reserved1 = 0;
};

struct uet_ctrl_view
{
    uet_ctrl_hdr hdr{};
    const uint8_t* payload = nullptr;
    size_t payload_len = 0;
};

struct uet_mrdesc
{
    uint32_t magic = 0;
    uint16_t version = 0;
    uint16_t flags = 0;
    uint32_t job_id = 0;
    uint32_t pid_on_fep = 0;
    uint32_t resource_index = 0;
    uint32_t rkey = 0;
    uint64_t remote_addr = 0;
    uint64_t len = 0;
    uint32_t access = 0;
    uint32_t ri_generation = 0;
    uint64_t reg_epoch = 0;
    uint32_t mem_type = static_cast<uint32_t>(uet_mem_type::host);
    uint32_t backend_kind = static_cast<uint32_t>(uet_backend_kind::soft);
};

struct uet_mrdesc_key
{
    fi_addr_t peer = FI_ADDR_UNSPEC;
    uint64_t session_id = 0;
    uint32_t job_id = 0;
    uint32_t pid_on_fep = 0;
    uint32_t resource_index = 0;
    uint32_t rkey = 0;
    uint64_t reg_epoch = 0;

    bool operator==(const uet_mrdesc_key& other) const
    {
        return peer == other.peer
            && session_id == other.session_id
            && job_id == other.job_id
            && pid_on_fep == other.pid_on_fep
            && resource_index == other.resource_index
            && rkey == other.rkey
            && reg_epoch == other.reg_epoch;
    }
};

struct uet_mrdesc_key_hash
{
    size_t operator()(const uet_mrdesc_key& key) const noexcept
    {
        size_t h = static_cast<size_t>(key.peer);
        h ^= (static_cast<size_t>(key.session_id) << 1) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= (static_cast<size_t>(key.job_id) << 1) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= (static_cast<size_t>(key.pid_on_fep) << 1) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= (static_cast<size_t>(key.resource_index) << 1) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= (static_cast<size_t>(key.rkey) << 1) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= (static_cast<size_t>(key.reg_epoch) << 1) + 0x9e3779b9 + (h << 6) + (h >> 2);
        return h;
    }
};

struct uet_soft_state
{
    SESManager ses{};

    std::unique_ptr<UET::NetworkLayer::UDPNetworkLayer> udp_rx;
    std::unique_ptr<UET::NetworkLayer::UDPNetworkLayer> udp_tx;

    std::atomic<bool> enabled{false};
    std::atomic<bool> stop{false};
    std::thread rx_thread;
    std::thread tx_thread;
    std::thread ses_thread;

    std::mutex peer_mu;
    std::unordered_map<uint32_t, sockaddr_in> peer_by_fep;
    std::unordered_map<uint32_t, fi_addr_t> fiaddr_by_fep;
    std::unordered_map<fi_addr_t, uint64_t> peer_session_by_fiaddr;
    std::unordered_map<fi_addr_t, uint64_t> peer_mrdesc_session_by_fiaddr;

    std::mutex recv_mu;
    std::deque<uet_posted_recv> posted_recvs;
    std::deque<uet_unexpected_msg> unexpected_msgs;

    std::mutex reas_mu;
    std::unordered_map<uet_reassembly_key, uet_reassembly_state, uet_reassembly_key_hash> reassembly;

    std::mutex mrdesc_mu;
    std::unordered_map<uet_mrdesc_key, uet_mrdesc, uet_mrdesc_key_hash> mrdesc_registry;

    std::mutex op_mu;
    std::condition_variable op_cv;
    std::queue<uet_pending_send> op_q;

    struct uet_tx_completion {
        void* context = nullptr;
        size_t len = 0;
        uint64_t flags = 0;
    };
    std::mutex txc_mu;
    std::unordered_map<uint16_t, uet_tx_completion> pending_tx_completions;

    struct uet_read_state {
        void* buf = nullptr;
        size_t len = 0;
        uint32_t total_len = 0;
        uint32_t chunk_size = 0;
        std::vector<uint8_t> chunk_received;
        size_t chunks_done = 0;
        void* context = nullptr;
    };
    std::mutex read_mu;
    std::unordered_map<uint16_t, uet_read_state> pending_reads;
};

struct uet_rdma_state
{
    uet_rnic_device* device = nullptr;
    uet_rdma_connect_mode requested_mode = uet_rdma_connect_mode::auto_select;
    uet_rdma_connect_mode connect_mode = uet_rdma_connect_mode::manual_rc;
    uet_write_completion_mode write_completion_mode = uet_write_completion_mode::remote_ack;
    bool write_stats_enabled = false;
#if UET_HAVE_IBVERBS
    ibv_cq* data_cq = nullptr;
    ibv_qp* data_qp = nullptr;
#else
    void* data_cq = nullptr;
    void* data_qp = nullptr;
#endif
    struct peer_conn {
        fi_addr_t peer = FI_ADDR_UNSPEC;
        uint64_t peer_session = 0;
        bool request_sent = false;
        bool ready = false;
        bool failed = false;
        int last_error_code = 0;
        std::string last_error_reason;
        bool qp_rtr = false;
        bool qp_rts = false;
        uet_rdma_conn_msg local{};
        uet_rdma_conn_msg remote{};
    };
#if UET_HAVE_RDMACM
    struct cm_state {
        rdma_event_channel* event_channel = nullptr;
        rdma_cm_id* listener_id = nullptr;
        rdma_cm_id* active_id = nullptr;
        rdma_cm_id* passive_id = nullptr;
        rdma_cm_id* data_id = nullptr;
        uint8_t established_initiator_depth = 0;
        uint8_t established_responder_resources = 0;
        bool listener_ready = false;
        bool request_sent = false;
        bool ready = false;
        bool failed = false;
        int last_error_code = 0;
        std::string last_error_reason;
        std::thread event_thread;
    };
#else
    struct cm_state {
        void* event_channel = nullptr;
        void* listener_id = nullptr;
        void* active_id = nullptr;
        void* passive_id = nullptr;
        void* data_id = nullptr;
        uint8_t established_initiator_depth = 0;
        uint8_t established_responder_resources = 0;
        bool listener_ready = false;
        bool request_sent = false;
        bool ready = false;
        bool failed = false;
        int last_error_code = 0;
        std::string last_error_reason;
        std::thread event_thread;
    };
#endif
    enum class op_kind : uint8_t {
        read = 1,
        write = 2,
    };
    struct pending_op {
        op_kind kind = op_kind::read;
        void* context = nullptr;
        size_t len = 0;
        fi_addr_t peer = FI_ADDR_UNSPEC;
        uint64_t submit_ns = 0;
        uint64_t local_cqe_ns = 0;
        bool local_cqe_seen = false;
    };
    struct write_stats {
        uint64_t posted = 0;
        uint64_t local_cqe = 0;
        uint64_t remote_ack = 0;
        uint64_t submit_to_local_ns = 0;
        uint64_t local_to_ack_ns = 0;
        uint64_t submit_to_ack_ns = 0;
    };
    std::mutex mu;
    std::condition_variable cv;
    peer_conn conn{};
    cm_state cm{};
    std::unordered_map<uint64_t, pending_op> pending_ops;
    write_stats stats{};
    std::vector<uint8_t> control_recv_buffer;
    std::atomic<uint64_t> next_wr_id{1};
    std::atomic<bool> enabled{false};
    std::atomic<bool> stop{false};
    std::thread cq_progress_thread;
};

#if UET_HAVE_IBVERBS
struct uet_rdma_qp_snapshot
{
    bool valid = false;
    ibv_qp_state qp_state = IBV_QPS_RESET;
    int qp_access_flags = 0;
    ibv_mtu path_mtu = IBV_MTU_256;
    uint32_t dest_qp_num = 0;
    uint8_t max_rd_atomic = 0;
    uint8_t max_dest_rd_atomic = 0;
};
#endif

struct uet_ep
{
    // endpoint：承载真正的“网络 + 进度 + 完成”逻辑
    // - 内部复用 SESManager 生成/消费 PDStoNET_pkt
    // - 内部持有 UDPNetworkLayer 收发
    // - 提供 fi_send/fi_recv 并向 CQ 投递完成
    fid_ep ep{};
    fi_ops ep_fid_ops{};
    fi_ops_ep ep_ops{};
    fi_ops_cm ep_cm_ops{};
    fi_ops_msg ep_msg_ops{};
    fi_ops_rma ep_rma_ops{};

    uet_domain* domain = nullptr;

    uet_av* bound_av = nullptr;
    uet_cq* bound_tx_cq = nullptr;
    uet_cq* bound_rx_cq = nullptr;

    // local name
    sockaddr_in local_addr{};
    bool local_addr_set = false;

    uint32_t job_id = 1;
    std::atomic<uint32_t> msg_seq{1};
    uint64_t local_session_id = 0;
    uet_backend_kind backend = uet_backend_kind::soft;
    uet_soft_state soft{};
    uet_rdma_state rdma{};
};

static void uet_rdma_log_write_stats(uet_ep* uep)
{
    if (!uep || !uep->rdma.write_stats_enabled) {
        return;
    }

    uet_rdma_state::write_stats stats{};
    uet_write_completion_mode mode = uet_write_completion_mode::remote_ack;
    {
        std::lock_guard<std::mutex> lock(uep->rdma.mu);
        stats = uep->rdma.stats;
        mode = uep->rdma.write_completion_mode;
    }

    if (stats.posted == 0) {
        return;
    }

    const uint64_t avg_submit_to_local_ns =
        (stats.local_cqe == 0) ? 0 : (stats.submit_to_local_ns / stats.local_cqe);
    const uint64_t avg_local_to_ack_ns =
        (stats.remote_ack == 0) ? 0 : (stats.local_to_ack_ns / stats.remote_ack);
    const uint64_t avg_submit_to_ack_ns =
        (stats.remote_ack == 0) ? 0 : (stats.submit_to_ack_ns / stats.remote_ack);

    std::fprintf(stderr,
                 "[uet][pid=%d][tp] write_stats mode=%s posted=%" PRIu64
                 " local_cqe=%" PRIu64 " remote_ack=%" PRIu64
                 " total_submit_to_local_ns=%" PRIu64
                 " total_local_to_ack_ns=%" PRIu64
                 " total_submit_to_ack_ns=%" PRIu64
                 " avg_submit_to_local_ns=%" PRIu64
                 " avg_local_to_ack_ns=%" PRIu64
                 " avg_submit_to_ack_ns=%" PRIu64 "\n",
                 static_cast<int>(::getpid()),
                 uet_write_completion_mode_name(mode),
                 stats.posted,
                 stats.local_cqe,
                 stats.remote_ack,
                 stats.submit_to_local_ns,
                 stats.local_to_ack_ns,
                 stats.submit_to_ack_ns,
                 avg_submit_to_local_ns,
                 avg_local_to_ack_ns,
                 avg_submit_to_ack_ns);
}

static std::optional<sockaddr_in> uet_av_resolve(uet_av* av, fi_addr_t addr);

#include "uet_provider_internal_helpers.hpp"

#if UET_HAVE_IBVERBS
static uint32_t uet_rdma_random_psn()
{
    static std::atomic<uint32_t> fallback{0x123456u};
    uint32_t v = static_cast<uint32_t>(std::chrono::steady_clock::now().time_since_epoch().count());
    v ^= static_cast<uint32_t>(::getpid() << 8);
    try {
        std::random_device rd;
        v ^= rd();
    } catch (...) {
        v ^= fallback.fetch_add(0x10101u, std::memory_order_relaxed);
    }
    v &= 0x00ffffffu;
    return v == 0 ? 1 : v;
}

static std::string uet_rdma_conn_to_string(const uet_rdma_conn_msg& msg)
{
    char gid_buf[sizeof(msg.gid) * 2 + 1]{};
    for (size_t i = 0; i < sizeof(msg.gid); ++i) {
        std::snprintf(gid_buf + (i * 2), 3, "%02x", msg.gid[i]);
    }
    char buf[512]{};
    std::snprintf(buf, sizeof(buf),
                  "qp_num=%u psn=%u lid=%u port=%u gid_valid=%u gid=%s",
                  static_cast<unsigned>(msg.qp_num),
                  static_cast<unsigned>(msg.psn),
                  static_cast<unsigned>(msg.lid),
                  static_cast<unsigned>(msg.port_num),
                  static_cast<unsigned>(msg.gid_valid),
                  gid_buf);
    return std::string(buf);
}

static const char* uet_ibv_qp_state_name(ibv_qp_state state)
{
    switch (state) {
        case IBV_QPS_RESET: return "RESET";
        case IBV_QPS_INIT: return "INIT";
        case IBV_QPS_RTR: return "RTR";
        case IBV_QPS_RTS: return "RTS";
        case IBV_QPS_SQD: return "SQD";
        case IBV_QPS_SQE: return "SQE";
        case IBV_QPS_ERR: return "ERR";
        default: return "UNKNOWN";
    }
}

static const char* uet_ibv_mtu_name(ibv_mtu mtu)
{
    switch (mtu) {
        case IBV_MTU_256: return "256";
        case IBV_MTU_512: return "512";
        case IBV_MTU_1024: return "1024";
        case IBV_MTU_2048: return "2048";
        case IBV_MTU_4096: return "4096";
        default: return "?";
    }
}

static int uet_rdma_query_qp_snapshot(uet_ep* uep, uet_rdma_qp_snapshot& out)
{
    if (!uep || !uep->rdma.data_qp) return -FI_EINVAL;
    ibv_qp_attr attr{};
    ibv_qp_init_attr init_attr{};
    const int mask = IBV_QP_STATE | IBV_QP_ACCESS_FLAGS | IBV_QP_PATH_MTU |
                     IBV_QP_DEST_QPN | IBV_QP_MAX_QP_RD_ATOMIC |
                     IBV_QP_MAX_DEST_RD_ATOMIC;
    if (ibv_query_qp(uep->rdma.data_qp, &attr, mask, &init_attr) != 0) {
        return -FI_EIO;
    }
    out.valid = true;
    out.qp_state = attr.qp_state;
    out.qp_access_flags = attr.qp_access_flags;
    out.path_mtu = attr.path_mtu;
    out.dest_qp_num = attr.dest_qp_num;
    out.max_rd_atomic = attr.max_rd_atomic;
    out.max_dest_rd_atomic = attr.max_dest_rd_atomic;
    return 0;
}

static void uet_rdma_log_qp_snapshot(uet_ep* uep, const char* where)
{
    if (!uep || !uep->rdma.data_qp) return;
    uet_rdma_qp_snapshot snap{};
    if (uet_rdma_query_qp_snapshot(uep, snap) != 0) {
        uet_dbg("rdma", "QP snapshot failed: where=%s peer=%" PRIu64 " session=0x%" PRIx64 " errno=%d (%s)",
                where ? where : "-",
                static_cast<uint64_t>(uep->rdma.conn.peer),
                static_cast<uint64_t>(uep->rdma.conn.peer_session),
                errno,
                std::strerror(errno));
        return;
    }
    uet_dbg("rdma",
            "QP snapshot: where=%s peer=%" PRIu64 " session=0x%" PRIx64 " state=%s access=0x%x mtu=%s dest_qpn=%u max_rd_atomic=%u max_dest_rd_atomic=%u",
            where ? where : "-",
            static_cast<uint64_t>(uep->rdma.conn.peer),
            static_cast<uint64_t>(uep->rdma.conn.peer_session),
            uet_ibv_qp_state_name(snap.qp_state),
            static_cast<unsigned>(snap.qp_access_flags),
            uet_ibv_mtu_name(snap.path_mtu),
            static_cast<unsigned>(snap.dest_qp_num),
            static_cast<unsigned>(snap.max_rd_atomic),
            static_cast<unsigned>(snap.max_dest_rd_atomic));
}

#if UET_HAVE_RDMACM
static void uet_rdma_fill_cm_conn_param(uet_ep* uep, rdma_conn_param& param, const char* where)
{
    std::memset(&param, 0, sizeof(param));
    const uint8_t initiator_depth =
        (uep && uep->rdma.device && uep->rdma.device->device_attr.max_qp_init_rd_atom > 0) ? 1 : 0;
    const uint8_t responder_resources =
        (uep && uep->rdma.device && uep->rdma.device->device_attr.max_qp_rd_atom > 0) ? 1 : 0;
    param.initiator_depth = initiator_depth;
    param.responder_resources = responder_resources;
    param.retry_count = 7;
    param.rnr_retry_count = 7;
    uet_dbg("cm",
            "CM conn_param: where=%s init_depth=%u responder_resources=%u dev_max_init_rd_atom=%u dev_max_rd_atom=%u",
            where ? where : "-",
            static_cast<unsigned>(param.initiator_depth),
            static_cast<unsigned>(param.responder_resources),
            uep && uep->rdma.device ? static_cast<unsigned>(uep->rdma.device->device_attr.max_qp_init_rd_atom) : 0U,
            uep && uep->rdma.device ? static_cast<unsigned>(uep->rdma.device->device_attr.max_qp_rd_atom) : 0U);
}
#endif

static int uet_rdma_validate_read_ready(uet_ep* uep, fi_addr_t peer, uint64_t peer_session)
{
    if (!uep || !uep->rdma.data_qp) return -FI_EINVAL;
    uet_rdma_qp_snapshot snap{};
    if (uet_rdma_query_qp_snapshot(uep, snap) != 0) {
        uet_dbg("rdma", "READ readiness query failed: peer=%" PRIu64 " session=0x%" PRIx64,
                static_cast<uint64_t>(peer),
                static_cast<uint64_t>(peer_session));
        return -FI_EIO;
    }
    uet_dbg("rdma",
            "READ readiness: peer=%" PRIu64 " session=0x%" PRIx64 " state=%s access=0x%x max_rd_atomic=%u max_dest_rd_atomic=%u",
            static_cast<uint64_t>(peer),
            static_cast<uint64_t>(peer_session),
            uet_ibv_qp_state_name(snap.qp_state),
            static_cast<unsigned>(snap.qp_access_flags),
            static_cast<unsigned>(snap.max_rd_atomic),
            static_cast<unsigned>(snap.max_dest_rd_atomic));
    if (snap.qp_state != IBV_QPS_RTS) {
        return -FI_EIO;
    }
    if (snap.max_rd_atomic == 0) {
        uint8_t cm_init_depth = 0;
        uint8_t cm_resp_res = 0;
        {
            std::lock_guard<std::mutex> lock(uep->rdma.mu);
            cm_init_depth = uep->rdma.cm.established_initiator_depth;
            cm_resp_res = uep->rdma.cm.established_responder_resources;
        }
        if (uep->rdma.connect_mode == uet_rdma_connect_mode::iwarp_cm && cm_init_depth > 0) {
            uet_dbg("rdma",
                    "READ readiness fallback: peer=%" PRIu64 " session=0x%" PRIx64 " qp.max_rd_atomic=0 but cm.init_depth=%u cm.responder_resources=%u",
                    static_cast<uint64_t>(peer),
                    static_cast<uint64_t>(peer_session),
                    static_cast<unsigned>(cm_init_depth),
                    static_cast<unsigned>(cm_resp_res));
            return 0;
        }
        return -FI_EOPNOTSUPP;
    }
    return 0;
}

static const char* uet_ibv_transport_name(ibv_transport_type transport)
{
    switch (transport) {
    case IBV_TRANSPORT_IB:
        return "IB";
    case IBV_TRANSPORT_IWARP:
        return "iWARP";
    case IBV_TRANSPORT_USNIC:
        return "usNIC";
    case IBV_TRANSPORT_USNIC_UDP:
        return "usNIC_UDP";
    case IBV_TRANSPORT_UNSPECIFIED:
        return "UNSPECIFIED";
    case IBV_TRANSPORT_UNKNOWN:
    default:
        return "UNKNOWN";
    }
}

static uet_rdma_connect_mode uet_rdma_select_connect_mode(uet_ep* uep)
{
    if (!uep || !uep->rdma.device) {
        return uet_rdma_connect_mode::manual_rc;
    }
    if (uep->rdma.requested_mode != uet_rdma_connect_mode::auto_select) {
        return uep->rdma.requested_mode;
    }
#if !UET_HAVE_RDMACM
    return uet_rdma_connect_mode::manual_rc;
#else
    if (uep->rdma.device->transport_type == IBV_TRANSPORT_IWARP) {
        return uet_rdma_connect_mode::iwarp_cm;
    }
    return uet_rdma_connect_mode::manual_rc;
#endif
}

static std::string uet_sockaddr_in_to_string(const sockaddr_in& addr)
{
    char ip[INET_ADDRSTRLEN] = {0};
    if (!inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip))) {
        std::snprintf(ip, sizeof(ip), "0.0.0.0");
    }
    char buf[128]{};
    std::snprintf(buf, sizeof(buf), "%s:%u", ip, static_cast<unsigned>(ntohs(addr.sin_port)));
    return std::string(buf);
}

static sockaddr_in uet_rdma_cm_addr_from_endpoint(const sockaddr_in& in)
{
    sockaddr_in out = in;
    if (out.sin_family == 0) {
        out.sin_family = AF_INET;
    }
    if (out.sin_addr.s_addr == htonl(INADDR_ANY) || out.sin_addr.s_addr == htonl(INADDR_LOOPBACK)) {
        in_addr ip{};
        if (uet_pick_default_ipv4(ip)) {
            out.sin_addr = ip;
        }
    }
    return out;
}

static void uet_rdma_reset_conn_locked(uet_rdma_state::peer_conn& conn, fi_addr_t peer, uint64_t peer_session)
{
    conn.peer = peer;
    conn.peer_session = peer_session;
    conn.request_sent = false;
    conn.ready = false;
    conn.failed = false;
    conn.last_error_code = 0;
    conn.last_error_reason.clear();
    conn.qp_rtr = false;
    conn.qp_rts = false;
    std::memset(&conn.remote, 0, sizeof(conn.remote));
}

static void uet_rdma_reset_cm_locked(uet_rdma_state::cm_state& cm)
{
    cm.established_initiator_depth = 0;
    cm.established_responder_resources = 0;
    cm.request_sent = false;
    cm.ready = false;
    cm.failed = false;
    cm.last_error_code = 0;
    cm.last_error_reason.clear();
}

static void uet_rdma_fail_conn(uet_ep* uep, int err, const std::string& reason)
{
    if (!uep) return;
    {
        std::lock_guard<std::mutex> lock(uep->rdma.mu);
        uep->rdma.conn.failed = true;
        uep->rdma.conn.ready = false;
        uep->rdma.conn.last_error_code = err;
        uep->rdma.conn.last_error_reason = reason;
        uep->rdma.cm.failed = true;
        uep->rdma.cm.ready = false;
        uep->rdma.cm.last_error_code = err;
        uep->rdma.cm.last_error_reason = reason;
    }
    uet_dbg("rdma", "conn fail: peer=%" PRIu64 " session=0x%" PRIx64 " err=%d reason=%s",
            static_cast<uint64_t>(uep->rdma.conn.peer),
            static_cast<uint64_t>(uep->rdma.conn.peer_session),
            err,
            reason.c_str());
    uep->rdma.cv.notify_all();
}

static int uet_rdma_build_local_conn(uet_ep* uep, uet_rdma_conn_msg& out)
{
    if (!uep || !uep->rdma.device || !uep->rdma.data_qp) return -FI_EINVAL;
    out.qp_num = uep->rdma.data_qp->qp_num;
    if (uep->rdma.conn.local.psn == 0) {
        uep->rdma.conn.local.psn = uet_rdma_random_psn();
    }
    out.psn = uep->rdma.conn.local.psn;
    out.lid = uep->rdma.device->port_attr.lid;
    out.port_num = uep->rdma.device->port_num;
    out.gid_valid = uep->rdma.device->gid_valid ? 1 : 0;
    if (out.gid_valid) {
        std::memcpy(out.gid, &uep->rdma.device->gid, sizeof(out.gid));
    } else {
        std::memset(out.gid, 0, sizeof(out.gid));
    }
    return 0;
}

static int uet_rdma_qp_to_init(uet_ep* uep)
{
    if (!uep || !uep->rdma.data_qp || !uep->rdma.device) return -FI_EINVAL;
    ibv_qp_attr attr{};
    attr.qp_state = IBV_QPS_INIT;
    attr.pkey_index = 0;
    attr.port_num = uep->rdma.device->port_num;
    attr.qp_access_flags = IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;
    const int mask = IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS;
    if (ibv_modify_qp(uep->rdma.data_qp, &attr, mask) != 0) {
        return -FI_EIO;
    }
    return 0;
}

static int uet_rdma_qp_to_rtr(uet_ep* uep)
{
    if (!uep || !uep->rdma.data_qp || !uep->rdma.device) return -FI_EINVAL;
    auto& conn = uep->rdma.conn;
    uet_dbg("rdma", "QP RTR start: peer=%" PRIu64 " session=0x%" PRIx64 " local={%s} remote={%s}",
            static_cast<uint64_t>(conn.peer),
            static_cast<uint64_t>(conn.peer_session),
            uet_rdma_conn_to_string(conn.local).c_str(),
            uet_rdma_conn_to_string(conn.remote).c_str());
    ibv_qp_attr attr{};
    attr.qp_state = IBV_QPS_RTR;
    attr.path_mtu = IBV_MTU_1024;
    attr.dest_qp_num = conn.remote.qp_num;
    attr.rq_psn = conn.remote.psn;
    attr.max_dest_rd_atomic = 1;
    attr.min_rnr_timer = 12;
    attr.ah_attr.is_global = conn.remote.gid_valid ? 1 : 0;
    attr.ah_attr.dlid = conn.remote.lid;
    attr.ah_attr.sl = 0;
    attr.ah_attr.src_path_bits = 0;
    attr.ah_attr.port_num = uep->rdma.device->port_num;
    if (conn.remote.gid_valid) {
        std::memcpy(&attr.ah_attr.grh.dgid, conn.remote.gid, sizeof(conn.remote.gid));
        attr.ah_attr.grh.sgid_index = 0;
        attr.ah_attr.grh.hop_limit = 1;
    }
    const int mask = IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN |
                     IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER;
    if (ibv_modify_qp(uep->rdma.data_qp, &attr, mask) != 0) {
        uet_dbg("rdma", "QP RTR failed: peer=%" PRIu64 " session=0x%" PRIx64 " errno=%d (%s)",
                static_cast<uint64_t>(conn.peer),
                static_cast<uint64_t>(conn.peer_session),
                errno,
                std::strerror(errno));
        return -FI_EIO;
    }
    conn.qp_rtr = true;
    uet_dbg("rdma", "QP RTR ok: peer=%" PRIu64 " session=0x%" PRIx64,
            static_cast<uint64_t>(conn.peer),
            static_cast<uint64_t>(conn.peer_session));
    return 0;
}

static int uet_rdma_qp_to_rts(uet_ep* uep)
{
    if (!uep || !uep->rdma.data_qp) return -FI_EINVAL;
    if (!uep->rdma.device) return -FI_EINVAL;
    uet_dbg("rdma", "QP RTS start: peer=%" PRIu64 " session=0x%" PRIx64 " transport=%s local_psn=%u",
            static_cast<uint64_t>(uep->rdma.conn.peer),
            static_cast<uint64_t>(uep->rdma.conn.peer_session),
            uet_ibv_transport_name(uep->rdma.device->transport_type),
            static_cast<unsigned>(uep->rdma.conn.local.psn));
    ibv_qp_attr attr{};
    attr.qp_state = IBV_QPS_RTS;
    attr.timeout = 14;
    attr.retry_cnt = 7;
    attr.rnr_retry = 7;
    attr.sq_psn = uep->rdma.conn.local.psn;
    attr.max_rd_atomic = 1;
    int mask = IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
               IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC;
    if (ibv_modify_qp(uep->rdma.data_qp, &attr, mask) != 0) {
        const int first_errno = errno;
        uet_dbg("rdma", "QP RTS failed: peer=%" PRIu64 " session=0x%" PRIx64 " errno=%d (%s)",
                static_cast<uint64_t>(uep->rdma.conn.peer),
                static_cast<uint64_t>(uep->rdma.conn.peer_session),
                first_errno,
                std::strerror(first_errno));
        if (uep->rdma.device->transport_type == IBV_TRANSPORT_IWARP) {
            std::memset(&attr, 0, sizeof(attr));
            attr.qp_state = IBV_QPS_RTS;
            attr.sq_psn = uep->rdma.conn.local.psn;
            attr.max_rd_atomic = 1;
            mask = IBV_QP_STATE | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC;
            uet_dbg("rdma", "QP RTS retry (iWARP minimal attrs): peer=%" PRIu64 " session=0x%" PRIx64,
                    static_cast<uint64_t>(uep->rdma.conn.peer),
                    static_cast<uint64_t>(uep->rdma.conn.peer_session));
            if (ibv_modify_qp(uep->rdma.data_qp, &attr, mask) == 0) {
                uep->rdma.conn.qp_rts = true;
                uet_dbg("rdma", "QP RTS ok (iWARP fallback): peer=%" PRIu64 " session=0x%" PRIx64,
                        static_cast<uint64_t>(uep->rdma.conn.peer),
                        static_cast<uint64_t>(uep->rdma.conn.peer_session));
                return 0;
            }
            uet_dbg("rdma", "QP RTS retry failed (iWARP): peer=%" PRIu64 " session=0x%" PRIx64 " errno=%d (%s)",
                    static_cast<uint64_t>(uep->rdma.conn.peer),
                    static_cast<uint64_t>(uep->rdma.conn.peer_session),
                    errno,
                    std::strerror(errno));
        }
        return -FI_EIO;
    }
    uep->rdma.conn.qp_rts = true;
    uet_dbg("rdma", "QP RTS ok: peer=%" PRIu64 " session=0x%" PRIx64,
            static_cast<uint64_t>(uep->rdma.conn.peer),
            static_cast<uint64_t>(uep->rdma.conn.peer_session));
    return 0;
}

static int uet_rdma_ensure_data_cq(uet_ep* uep)
{
    if (!uep || !uep->domain || !uep->domain->rdma_device) return -FI_EINVAL;
    if (uep->rdma.data_cq) return 0;
    uep->rdma.data_cq = ibv_create_cq(uep->domain->rdma_device->device_ctx, 256, nullptr, nullptr, 0);
    if (!uep->rdma.data_cq) {
        uep->domain->rdma_unavailable_reason = std::string("ibv_create_cq failed: ") + std::strerror(errno);
        return -FI_EIO;
    }
    return 0;
}

static int uet_rdma_adopt_cm_verbs(uet_ep* uep, ibv_context* verbs)
{
    if (!uep || !uep->domain || !uep->domain->rdma_device || !verbs) return -FI_EINVAL;
    auto* device = uep->domain->rdma_device;
    if (device->device_ctx == verbs && device->pd) {
        return 0;
    }
    if (device->pd) {
        ibv_dealloc_pd(device->pd);
        device->pd = nullptr;
    }
    if (device->device_ctx && device->ctx_owned) {
        ibv_close_device(device->device_ctx);
    }
    device->device_ctx = verbs;
    device->ctx_owned = false;
    device->pd = ibv_alloc_pd(verbs);
    if (!device->pd) {
        return -FI_EIO;
    }
    uep->rdma.device = device;
    uet_dbg("cm", "CM adopt verbs context: ctx=%p dev=%s",
            static_cast<void*>(verbs),
            device->device_name.c_str());
    return 0;
}

static int uet_rdma_prepare_manual_qp(uet_ep* uep)
{
    if (!uep || !uep->domain || !uep->domain->rdma_device) return -FI_EINVAL;
    const int cq_rc = uet_rdma_ensure_data_cq(uep);
    if (cq_rc != 0) return cq_rc;
    if (uep->rdma.data_qp) return 0;

    ibv_qp_init_attr qp_attr{};
    qp_attr.send_cq = uep->rdma.data_cq;
    qp_attr.recv_cq = uep->rdma.data_cq;
    qp_attr.qp_type = IBV_QPT_RC;
    qp_attr.cap.max_send_wr = 256;
    qp_attr.cap.max_recv_wr = 1;
    qp_attr.cap.max_send_sge = 1;
    qp_attr.cap.max_recv_sge = 1;
    uep->rdma.data_qp = ibv_create_qp(uep->domain->rdma_device->pd, &qp_attr);
    if (!uep->rdma.data_qp) {
        uep->domain->rdma_unavailable_reason = std::string("ibv_create_qp failed: ") + std::strerror(errno);
        return -FI_EIO;
    }
    if (uet_rdma_qp_to_init(uep) != 0) {
        uep->domain->rdma_unavailable_reason = "ibv_modify_qp INIT failed";
        return -FI_EIO;
    }
    if (uet_rdma_build_local_conn(uep, uep->rdma.conn.local) != 0) {
        uep->domain->rdma_unavailable_reason = "failed to build local QP connection info";
        return -FI_EIO;
    }
    return 0;
}

#if UET_HAVE_RDMACM
static const char* uet_rdma_cm_event_name(rdma_cm_event_type event)
{
    switch (event) {
        case RDMA_CM_EVENT_ADDR_RESOLVED: return "ADDR_RESOLVED";
        case RDMA_CM_EVENT_ADDR_ERROR: return "ADDR_ERROR";
        case RDMA_CM_EVENT_ROUTE_RESOLVED: return "ROUTE_RESOLVED";
        case RDMA_CM_EVENT_ROUTE_ERROR: return "ROUTE_ERROR";
        case RDMA_CM_EVENT_CONNECT_REQUEST: return "CONNECT_REQUEST";
        case RDMA_CM_EVENT_CONNECT_RESPONSE: return "CONNECT_RESPONSE";
        case RDMA_CM_EVENT_CONNECT_ERROR: return "CONNECT_ERROR";
        case RDMA_CM_EVENT_UNREACHABLE: return "UNREACHABLE";
        case RDMA_CM_EVENT_REJECTED: return "REJECTED";
        case RDMA_CM_EVENT_ESTABLISHED: return "ESTABLISHED";
        case RDMA_CM_EVENT_DISCONNECTED: return "DISCONNECTED";
        case RDMA_CM_EVENT_DEVICE_REMOVAL: return "DEVICE_REMOVAL";
        case RDMA_CM_EVENT_TIMEWAIT_EXIT: return "TIMEWAIT_EXIT";
        default: return "OTHER";
    }
}

static int uet_rdma_cm_build_qp(uet_ep* uep, rdma_cm_id* id)
{
    if (!uep || !id) return -FI_EINVAL;
    const int cq_rc = uet_rdma_ensure_data_cq(uep);
    if (cq_rc != 0) return cq_rc;
    if (!id->qp) {
        ibv_qp_init_attr qp_attr{};
        qp_attr.send_cq = uep->rdma.data_cq;
        qp_attr.recv_cq = uep->rdma.data_cq;
        qp_attr.qp_type = IBV_QPT_RC;
        qp_attr.cap.max_send_wr = 256;
        qp_attr.cap.max_recv_wr = 1;
        qp_attr.cap.max_send_sge = 1;
        qp_attr.cap.max_recv_sge = 1;
        if (rdma_create_qp(id, uep->domain->rdma_device->pd, &qp_attr) != 0) {
            uet_dbg("cm", "CM create_qp failed: errno=%d (%s)", errno, std::strerror(errno));
            return -FI_EIO;
        }
    }
    uep->rdma.data_qp = id->qp;
    uet_dbg("cm", "CM build_qp: skip manual qp_to_init for CM-managed QP");
    if (uet_rdma_build_local_conn(uep, uep->rdma.conn.local) != 0) {
        return -FI_EIO;
    }
    uet_rdma_log_qp_snapshot(uep, "cm_build_qp");
    {
        std::lock_guard<std::mutex> lock(uep->rdma.mu);
        uep->rdma.cm.data_id = id;
    }
    return 0;
}

static void uet_rdma_cm_mark_ready(uet_ep* uep, rdma_cm_id* id, const char* where)
{
    if (!uep) return;
    {
        std::lock_guard<std::mutex> lock(uep->rdma.mu);
        uep->rdma.cm.ready = true;
        uep->rdma.cm.failed = false;
        uep->rdma.cm.last_error_code = 0;
        uep->rdma.cm.last_error_reason.clear();
        uep->rdma.cm.request_sent = true;
        if (id) {
            uep->rdma.cm.data_id = id;
            if (id->qp) {
                uep->rdma.data_qp = id->qp;
            }
        }
        uep->rdma.conn.ready = true;
        uep->rdma.conn.failed = false;
        uep->rdma.conn.last_error_code = 0;
        uep->rdma.conn.last_error_reason.clear();
    }
    uet_dbg("cm", "CM established: where=%s peer=%" PRIu64 " session=0x%" PRIx64,
            where ? where : "-",
            static_cast<uint64_t>(uep->rdma.conn.peer),
            static_cast<uint64_t>(uep->rdma.conn.peer_session));
    uet_rdma_log_qp_snapshot(uep, "cm_established");
    uep->rdma.cv.notify_all();
}

static void uet_rdma_cm_fail(uet_ep* uep, int err, const std::string& reason)
{
    if (!uep) return;
    {
        std::lock_guard<std::mutex> lock(uep->rdma.mu);
        uep->rdma.cm.failed = true;
        uep->rdma.cm.ready = false;
        uep->rdma.cm.last_error_code = err;
        uep->rdma.cm.last_error_reason = reason;
    }
    uet_dbg("cm", "CM fail: err=%d reason=%s", err, reason.c_str());
    uet_rdma_fail_conn(uep, err, reason);
}

static void uet_rdma_cm_handle_event(uet_ep* uep, rdma_cm_event* event)
{
    if (!uep || !event) return;
    uet_dbg("cm", "CM event: %s status=%d id=%p", uet_rdma_cm_event_name(event->event), event->status, static_cast<void*>(event->id));
    switch (event->event) {
        case RDMA_CM_EVENT_ADDR_RESOLVED:
            if (rdma_resolve_route(event->id, 2000) != 0) {
                uet_rdma_cm_fail(uep, -FI_EIO, "CM resolve route failed");
            } else {
                uet_dbg("cm", "CM resolve route start");
            }
            break;
        case RDMA_CM_EVENT_ROUTE_RESOLVED: {
            if (const int rc = uet_rdma_cm_build_qp(uep, event->id); rc != 0) {
                uet_rdma_cm_fail(uep, rc, "CM build QP failed");
                break;
            }
            rdma_conn_param param{};
            uet_rdma_fill_cm_conn_param(uep, param, "active_connect");
            if (rdma_connect(event->id, &param) != 0) {
                uet_rdma_cm_fail(uep, -FI_EIO, "CM connect failed");
                break;
            }
            uet_dbg("cm", "CM connect start");
            break;
        }
        case RDMA_CM_EVENT_CONNECT_REQUEST: {
            if (const int rc = uet_rdma_cm_build_qp(uep, event->id); rc != 0) {
                rdma_reject(event->id, nullptr, 0);
                uet_rdma_cm_fail(uep, rc, "CM passive build QP failed");
                break;
            }
            {
                std::lock_guard<std::mutex> lock(uep->rdma.mu);
                uep->rdma.cm.passive_id = event->id;
                uep->rdma.cm.data_id = event->id;
            }
            rdma_conn_param param{};
            uet_dbg("cm", "CM connect request params: responder_resources=%u initiator_depth=%u flow_control=%u retry=%u rnr_retry=%u",
                    static_cast<unsigned>(event->param.conn.responder_resources),
                    static_cast<unsigned>(event->param.conn.initiator_depth),
                    static_cast<unsigned>(event->param.conn.flow_control),
                    static_cast<unsigned>(event->param.conn.retry_count),
                    static_cast<unsigned>(event->param.conn.rnr_retry_count));
            uet_rdma_fill_cm_conn_param(uep, param, "passive_accept");
            if (rdma_accept(event->id, &param) != 0) {
                uet_rdma_cm_fail(uep, -FI_EIO, "CM accept failed");
                break;
            }
            uet_dbg("cm", "CM accept start");
            break;
        }
        case RDMA_CM_EVENT_ESTABLISHED:
            uet_dbg("cm", "CM established params: responder_resources=%u initiator_depth=%u flow_control=%u retry=%u rnr_retry=%u",
                    static_cast<unsigned>(event->param.conn.responder_resources),
                    static_cast<unsigned>(event->param.conn.initiator_depth),
                    static_cast<unsigned>(event->param.conn.flow_control),
                    static_cast<unsigned>(event->param.conn.retry_count),
                    static_cast<unsigned>(event->param.conn.rnr_retry_count));
            {
                std::lock_guard<std::mutex> lock(uep->rdma.mu);
                uep->rdma.cm.established_initiator_depth = event->param.conn.initiator_depth;
                uep->rdma.cm.established_responder_resources = event->param.conn.responder_resources;
            }
            uet_rdma_cm_mark_ready(uep, event->id, "cm_event");
            break;
        case RDMA_CM_EVENT_ADDR_ERROR:
        case RDMA_CM_EVENT_ROUTE_ERROR:
        case RDMA_CM_EVENT_CONNECT_ERROR:
        case RDMA_CM_EVENT_UNREACHABLE:
        case RDMA_CM_EVENT_REJECTED:
        case RDMA_CM_EVENT_DEVICE_REMOVAL:
            uet_rdma_cm_fail(uep, -FI_EIO,
                             std::string("CM event failed: ") + uet_rdma_cm_event_name(event->event));
            break;
        case RDMA_CM_EVENT_DISCONNECTED:
            uet_rdma_cm_fail(uep, -FI_EIO, "CM disconnected");
            break;
        default:
            break;
    }
}

static void uet_rdma_cm_event_loop(uet_ep* uep)
{
    while (uep && !uep->rdma.stop.load()) {
        rdma_cm_event* event = nullptr;
        if (rdma_get_cm_event(uep->rdma.cm.event_channel, &event) != 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                continue;
            }
            if (!uep->rdma.stop.load()) {
                uet_rdma_cm_fail(uep, -FI_EIO, std::string("CM poll failed: ") + std::strerror(errno));
            }
            break;
        }
        uet_rdma_cm_handle_event(uep, event);
        rdma_ack_cm_event(event);
    }
}

static int uet_rdma_cm_start_listener(uet_ep* uep)
{
    if (!uep) return -FI_EINVAL;
    if (uep->rdma.cm.listener_ready) return 0;
    if (!uep->local_addr_set) return -FI_EINVAL;

    if (!uep->rdma.cm.event_channel) {
        uep->rdma.cm.event_channel = rdma_create_event_channel();
        if (!uep->rdma.cm.event_channel) {
            return -FI_EIO;
        }
        const int flags = fcntl(uep->rdma.cm.event_channel->fd, F_GETFL, 0);
        if (flags >= 0) {
            (void)fcntl(uep->rdma.cm.event_channel->fd, F_SETFL, flags | O_NONBLOCK);
        }
    }
    if (!uep->rdma.cm.listener_id) {
        if (rdma_create_id(uep->rdma.cm.event_channel, &uep->rdma.cm.listener_id, uep, RDMA_PS_TCP) != 0) {
            return -FI_EIO;
        }
        sockaddr_in listen_addr = uet_rdma_cm_addr_from_endpoint(uep->local_addr);
        if (rdma_bind_addr(uep->rdma.cm.listener_id, reinterpret_cast<sockaddr*>(&listen_addr)) != 0) {
            return -FI_EIO;
        }
        if (rdma_listen(uep->rdma.cm.listener_id, 4) != 0) {
            return -FI_EIO;
        }
        if (uep->rdma.cm.listener_id->verbs) {
            const int adopt_rc = uet_rdma_adopt_cm_verbs(uep, uep->rdma.cm.listener_id->verbs);
            if (adopt_rc != 0) {
                return adopt_rc;
            }
        }
        uet_dbg("cm", "CM listen start: ctrl_addr=%s cm_addr=%s",
                uet_sockaddr_in_to_string(uep->local_addr).c_str(),
                uet_sockaddr_in_to_string(listen_addr).c_str());
    }
    uep->rdma.cm.listener_ready = true;
    if (!uep->rdma.cm.event_thread.joinable()) {
        uep->rdma.cm.event_thread = std::thread([uep]() { uet_rdma_cm_event_loop(uep); });
    }
    return 0;
}
#endif

static int uet_rdma_mark_connected(uet_ep* uep, fi_addr_t peer, uint64_t peer_session, const uet_rdma_conn_msg& remote)
{
    if (!uep) return -FI_EINVAL;
    {
        std::lock_guard<std::mutex> lock(uep->rdma.mu);
        if (uep->rdma.conn.peer != FI_ADDR_UNSPEC && uep->rdma.conn.peer != peer) {
            return -FI_EBUSY;
        }
        uep->rdma.conn.peer = peer;
        uep->rdma.conn.peer_session = peer_session;
        uep->rdma.conn.remote = remote;
        uet_dbg("rdma", "conn msg accepted: peer=%" PRIu64 " session=0x%" PRIx64 " remote={%s}",
                static_cast<uint64_t>(peer),
                static_cast<uint64_t>(peer_session),
                uet_rdma_conn_to_string(remote).c_str());
    }

    if (!uep->rdma.conn.qp_rtr && uet_rdma_qp_to_rtr(uep) != 0) {
        return -FI_EIO;
    }
    if (!uep->rdma.conn.qp_rts && uet_rdma_qp_to_rts(uep) != 0) {
        return -FI_EIO;
    }

    {
        std::lock_guard<std::mutex> lock(uep->rdma.mu);
        uep->rdma.conn.ready = true;
        uep->rdma.conn.failed = false;
        uep->rdma.conn.last_error_code = 0;
        uep->rdma.conn.last_error_reason.clear();
    }
    uet_dbg("rdma", "conn ready: peer=%" PRIu64 " session=0x%" PRIx64,
            static_cast<uint64_t>(peer),
            static_cast<uint64_t>(peer_session));
    uep->rdma.cv.notify_all();
    return 0;
}
#endif

static inline uet_cq* uet_cq_from_fid(fid_cq* cq)
{
    return container_of<uet_cq>(cq, &uet_cq::cq);
}

static inline uet_eq* uet_eq_from_fid(fid_eq* eq)
{
    return container_of<uet_eq>(eq, &uet_eq::eq);
}

static inline uet_av* uet_av_from_fid(fid_av* av)
{
    return container_of<uet_av>(av, &uet_av::av);
}

static inline uet_fabric* uet_fabric_from_fid(fid_fabric* fabric)
{
    return container_of<uet_fabric>(fabric, &uet_fabric::fabric);
}

static inline uet_domain* uet_domain_from_fid(fid_domain* domain)
{
    return container_of<uet_domain>(domain, &uet_domain::domain);
}

static inline uet_ep* uet_ep_from_fid(fid_ep* ep)
{
    return container_of<uet_ep>(ep, &uet_ep::ep);
}

static inline uet_mr* uet_mr_from_fid(fid_mr* mr)
{
    return container_of<uet_mr>(mr, &uet_mr::mr);
}

static int uet_rdma_access_from_fi(uint64_t fi_access, int& access_flags)
{
#if UET_HAVE_IBVERBS
    access_flags = IBV_ACCESS_LOCAL_WRITE;
    if (fi_access & FI_REMOTE_READ) access_flags |= IBV_ACCESS_REMOTE_READ;
    if (fi_access & FI_REMOTE_WRITE) access_flags |= IBV_ACCESS_REMOTE_WRITE;
    if (fi_access & FI_WRITE) access_flags |= IBV_ACCESS_LOCAL_WRITE;
    return 0;
#else
    access_flags = 0;
    (void)fi_access;
    return -FI_EOPNOTSUPP;
#endif
}

static void uet_rdma_release_device(uet_rnic_device*& device)
{
    if (!device) return;
#if UET_HAVE_IBVERBS
    if (device->pd) {
        ibv_dealloc_pd(device->pd);
        device->pd = nullptr;
    }
    if (device->device_ctx && device->ctx_owned) {
        ibv_close_device(device->device_ctx);
        device->device_ctx = nullptr;
    }
#endif
    delete device;
    device = nullptr;
}

static int uet_domain_init_rdma_runtime(uet_domain* domain)
{
    if (!domain) return -FI_EINVAL;
    if (domain->backend != uet_backend_kind::rdma) return 0;
    if (domain->rdma_runtime_ready && domain->rdma_device && domain->rdma_device->available) {
        return 0;
    }

#if !UET_HAVE_IBVERBS
    domain->rdma_runtime_ready = false;
    domain->rdma_unavailable_reason = "ibverbs headers not available at build time";
    return -FI_EOPNOTSUPP;
#else
    int num_devices = 0;
    ibv_device** dev_list = ibv_get_device_list(&num_devices);
    if (!dev_list) {
        domain->rdma_runtime_ready = false;
        domain->rdma_unavailable_reason = std::string("ibv_get_device_list failed: ") + std::strerror(errno);
        return -FI_EIO;
    }
    if (num_devices <= 0) {
        ibv_free_device_list(dev_list);
        domain->rdma_runtime_ready = false;
        domain->rdma_unavailable_reason = "no RNIC device found by ibv_get_device_list";
        return -FI_EOPNOTSUPP;
    }

    uet_rnic_device* device = nullptr;
    for (int i = 0; i < num_devices; ++i) {
        auto* cand = new uet_rnic_device();
        cand->device_name = ibv_get_device_name(dev_list[i]);
        cand->transport_type = dev_list[i]->transport_type;
        cand->device_ctx = ibv_open_device(dev_list[i]);
        if (!cand->device_ctx) {
            cand->available = false;
            uet_rdma_release_device(cand);
            continue;
        }
        cand->ctx_owned = true;
        if (ibv_query_device(cand->device_ctx, &cand->device_attr) != 0) {
            cand->available = false;
            uet_rdma_release_device(cand);
            continue;
        }

        bool port_found = false;
        for (uint8_t port = 1; port <= cand->device_attr.phys_port_cnt; ++port) {
            if (ibv_query_port(cand->device_ctx, port, &cand->port_attr) != 0) {
                continue;
            }
            if (cand->port_attr.state == IBV_PORT_ACTIVE || cand->port_attr.state == IBV_PORT_ARMED) {
                cand->port_num = port;
                port_found = true;
                break;
            }
        }

        if (!port_found) {
            cand->available = false;
            uet_rdma_release_device(cand);
            continue;
        }

        if (ibv_query_gid(cand->device_ctx, cand->port_num, 0, &cand->gid) == 0) {
            cand->gid_valid = true;
        }

        cand->pd = ibv_alloc_pd(cand->device_ctx);
        if (!cand->pd) {
            cand->available = false;
            uet_rdma_release_device(cand);
            continue;
        }

        device = cand;
        break;
    }

    if (!device) {
        ibv_free_device_list(dev_list);
        domain->rdma_runtime_ready = false;
        domain->rdma_unavailable_reason = "no active RNIC port found";
        return -FI_EOPNOTSUPP;
    }

    ibv_free_device_list(dev_list);
    device->available = true;
    domain->rdma_device = device;
    domain->rdma_runtime_ready = true;
    domain->rdma_unavailable_reason.clear();
    uet_dbg("rdma", "runtime ready: dev=%s transport=%s port=%u",
            device->device_name.c_str(),
            uet_ibv_transport_name(device->transport_type),
            static_cast<unsigned>(device->port_num));
    return 0;
#endif
}

static void uet_domain_init_backend_state(uet_domain* domain)
{
    if (!domain) return;
    domain->backend = uet_parse_backend();
    domain->rdma_requested = (domain->backend == uet_backend_kind::rdma);
    domain->rdma_runtime_ready = false;
    domain->rdma_unavailable_reason.clear();
    if (domain->backend == uet_backend_kind::rdma) {
        if (uet_domain_init_rdma_runtime(domain) != 0 && domain->rdma_unavailable_reason.empty()) {
            domain->rdma_unavailable_reason = "RDMA runtime initialization failed";
        }
    }
    uet_dbg("backend",
            "domain backend=%s requested=%d runtime_ready=%d reason=%s",
            uet_backend_name(domain->backend),
            static_cast<int>(domain->rdma_requested),
            static_cast<int>(domain->rdma_runtime_ready),
            domain->rdma_unavailable_reason.empty() ? "-" : domain->rdma_unavailable_reason.c_str());
}

static void uet_ep_init_backend_state(uet_ep* uep)
{
    if (!uep) return;
    uep->backend = uep->domain ? uep->domain->backend : uet_backend_kind::soft;
    uep->soft.enabled.store(false);
    uep->soft.stop.store(false);
    uep->rdma.enabled.store(false);
    uep->rdma.stop.store(false);
    uep->rdma.device = uep->domain ? uep->domain->rdma_device : nullptr;
    uep->rdma.requested_mode = uet_parse_rdma_connect_mode();
    uep->rdma.connect_mode = uet_rdma_select_connect_mode(uep);
    uep->rdma.write_completion_mode = uet_parse_write_completion_mode();
    uep->rdma.write_stats_enabled = uet_env_truthy("UET_RDMA_WRITE_STATS");
    uep->rdma.conn = {};
    uep->rdma.cm = {};
    uep->rdma.stats = {};
    uep->rdma.control_recv_buffer.clear();
    uet_dbg("backend", "ep init backend=%s connect_mode=%s requested=%s write_completion=%s",
            uet_backend_name(uep->backend),
            uet_rdma_connect_mode_name(uep->rdma.connect_mode),
            uet_rdma_connect_mode_name(uep->rdma.requested_mode),
            uet_write_completion_mode_name(uep->rdma.write_completion_mode));
}

static int uet_ep_backend_unavailable(uet_ep* uep, const char* op)
{
    const char* reason = (uep && uep->domain && !uep->domain->rdma_unavailable_reason.empty())
                             ? uep->domain->rdma_unavailable_reason.c_str()
                             : "RDMA backend not available";
    uet_dbg("backend", "%s rejected on backend=%s: %s", op, uet_backend_name(uep ? uep->backend : uet_backend_kind::soft), reason);
    return -FI_EOPNOTSUPP;
}

static void uet_domain_insert_local_mr(uet_domain* domain, uet_mr* mr)
{
    if (!domain || !mr) return;
    std::lock_guard<std::mutex> lock(domain->mr_registry_mu);
    domain->local_mr_by_rkey[mr->rkey] = mr;
    domain->local_mr_by_base[reinterpret_cast<uintptr_t>(mr->addr)] = mr;
}

static void uet_domain_remove_local_mr(uet_domain* domain, uet_mr* mr)
{
    if (!domain || !mr) return;
    std::lock_guard<std::mutex> lock(domain->mr_registry_mu);
    domain->local_mr_by_rkey.erase(mr->rkey);
    domain->local_mr_by_base.erase(reinterpret_cast<uintptr_t>(mr->addr));
}

static uet_mr* uet_domain_lookup_local_mr(uet_domain* domain, const void* addr, size_t len)
{
    if (!domain || !addr) return nullptr;
    const uintptr_t base = reinterpret_cast<uintptr_t>(addr);
    const uintptr_t end = base + len;
    std::lock_guard<std::mutex> lock(domain->mr_registry_mu);
    for (const auto& it : domain->local_mr_by_base) {
        auto* mr = it.second;
        if (!mr || !mr->addr) continue;
        const uintptr_t mr_base = reinterpret_cast<uintptr_t>(mr->addr);
        const uintptr_t mr_end = mr_base + mr->len;
        if (base >= mr_base && end <= mr_end) {
            return mr;
        }
    }
    return nullptr;
}

static bool uet_access_allows_local_read(uint64_t access)
{
    return (access & (FI_READ | FI_SEND | FI_RECV | FI_WRITE)) != 0 || access == 0;
}

static bool uet_access_allows_local_write(uint64_t access)
{
    return (access & (FI_WRITE | FI_RECV | FI_READ)) != 0 || access == 0;
}

static int uet_mr_reg_common(uet_domain* domain, const void* buf, size_t len, uint64_t access,
                             uint64_t requested_key, fid_mr** mr_out, void* ctx)
{
    if (!domain || !mr_out || !buf || len == 0) return -FI_EINVAL;

    auto* out = new uet_mr();
    out->mr.fid.fclass = FI_CLASS_MR;
    out->mr.fid.context = ctx;
    out->mr.fid.ops = &out->fid_ops;
    out->mr.mem_desc = const_cast<void*>(buf);
    out->mr.key = requested_key;
    out->fid_ops = fi_ops{
        .size = sizeof(fi_ops),
        .close = uet_fid_close,
        .bind = uet_fid_bind,
        .control = uet_fid_control,
        .ops_open = uet_fid_ops_open,
        .tostr = uet_fid_tostr,
        .ops_set = uet_fid_ops_set,
    };
    out->addr = const_cast<void*>(buf);
    out->len = len;
    out->access = access;
    out->lkey = 0;
    out->reg_epoch = domain->next_reg_epoch.fetch_add(1, std::memory_order_relaxed);
    out->mem_type = uet_mem_type::host;
    out->backend = domain->backend;
    out->hw_mr_handle = nullptr;
    out->domain = domain;

    if (domain->backend == uet_backend_kind::rdma) {
        if (!domain->rdma_runtime_ready || !domain->rdma_device || !domain->rdma_device->available) {
            if (domain->rdma_unavailable_reason.empty()) {
                domain->rdma_unavailable_reason = "RDMA runtime not ready";
            }
            delete out;
            return -FI_EOPNOTSUPP;
        }
        if (requested_key != 0) {
            delete out;
            return -FI_ENOSYS;
        }
#if !UET_HAVE_IBVERBS
        delete out;
        domain->rdma_unavailable_reason = "ibverbs support not compiled in";
        return -FI_EOPNOTSUPP;
#else
        int ibv_access = 0;
        if (uet_rdma_access_from_fi(access, ibv_access) != 0) {
            delete out;
            return -FI_EOPNOTSUPP;
        }
        out->hw_mr_handle = ibv_reg_mr(domain->rdma_device->pd, out->addr, out->len, ibv_access);
        if (!out->hw_mr_handle) {
            delete out;
            domain->rdma_unavailable_reason = std::string("ibv_reg_mr failed: ") + std::strerror(errno);
            return -FI_EIO;
        }
        out->lkey = out->hw_mr_handle->lkey;
        out->rkey = out->hw_mr_handle->rkey;
        out->mr.key = out->rkey;
#endif
    } else {
        out->rkey = requested_key ? static_cast<uint32_t>(requested_key) : domain->next_soft_rkey.fetch_add(1, std::memory_order_relaxed);
        out->mr.key = out->rkey;
    }

    uet_domain_insert_local_mr(domain, out);
    *mr_out = &out->mr;
    return 0;
}

static void cq_push(uet_cq* cq, const uet_cq_entry& e)
{
    if (!cq) return;
    std::lock_guard<std::mutex> lock(cq->mu);
    if (cq->closed) return;
    cq->entries.push(e);
    cq->cv.notify_all();
}

static ssize_t uet_cq_read_locked(uet_cq* cq, void* buf, size_t count, fi_addr_t* src_addr)
{
    if (!cq || !buf || count == 0) return -FI_EINVAL;
    if (src_addr) {
        // Caller must provide enough space for count entries.
        // We only fill src_addr for entries actually returned (n).
    }

    if (cq->entries.empty()) return -FI_EAGAIN;

    size_t n = 0;
    while (n < count && !cq->entries.empty()) {
        const auto e = cq->entries.front();
        cq->entries.pop();

        if (src_addr) {
            src_addr[n] = e.src_addr;
        }

        switch (cq->attr.format) {
            case FI_CQ_FORMAT_CONTEXT: {
                auto* out = static_cast<fi_cq_entry*>(buf);
                out[n].op_context = e.op_context;
                break;
            }
            case FI_CQ_FORMAT_MSG:
            case FI_CQ_FORMAT_UNSPEC: {
                auto* out = static_cast<fi_cq_msg_entry*>(buf);
                out[n].op_context = e.op_context;
                out[n].flags = e.flags;
                out[n].len = e.len;
                break;
            }
            default:
                return -FI_EINVAL;
        }
        n++;
    }

    return static_cast<ssize_t>(n);
}

static ssize_t uet_cq_read(struct fid_cq* cq_fid, void* buf, size_t count)
{
    // 非阻塞读取 CQ：
    // - 若队列为空：返回 -FI_EAGAIN
    // - 若队列有元素：按 attr.format 写入 fi_cq_entry 或 fi_cq_msg_entry
    auto* cq = uet_cq_from_fid(cq_fid);
    if (!buf || count == 0) return -FI_EINVAL;

    // fi_cq_read is a non-blocking API; avoid blocking on the mutex under contention.
    std::unique_lock<std::mutex> lock(cq->mu, std::try_to_lock);
    if (!lock.owns_lock()) return -FI_EAGAIN;
    return uet_cq_read_locked(cq, buf, count, nullptr);
}

static ssize_t uet_cq_readfrom(struct fid_cq* cq_fid, void* buf, size_t count, fi_addr_t* src_addr)
{
    auto* cq = uet_cq_from_fid(cq_fid);
    if (!buf || count == 0 || !src_addr) return -FI_EINVAL;

    // fi_cq_readfrom is also non-blocking; avoid blocking on the mutex under contention.
    std::unique_lock<std::mutex> lock(cq->mu, std::try_to_lock);
    if (!lock.owns_lock()) return -FI_EAGAIN;
    return uet_cq_read_locked(cq, buf, count, src_addr);
}

static ssize_t uet_cq_readerr(struct fid_cq*, struct fi_cq_err_entry*, uint64_t)
{
    return -FI_EAGAIN;
}

static ssize_t uet_cq_sread(struct fid_cq* cq_fid, void* buf, size_t count, const void*, int timeout)
{
    // 阻塞读取 CQ（timeout 单位 ms）：
    // - timeout < 0：一直等到有 completion 或 CQ 被关闭
    // - timeout >= 0：超时返回 -FI_EAGAIN
    auto* cq = uet_cq_from_fid(cq_fid);
    if (!buf || count == 0) return -FI_EINVAL;

    std::unique_lock<std::mutex> lock(cq->mu);
    if (cq->entries.empty()) {
        if (timeout < 0) {
            cq->cv.wait(lock, [&]() { return cq->closed || !cq->entries.empty(); });
        } else {
            cq->cv.wait_for(lock, std::chrono::milliseconds(timeout), [&]() { return cq->closed || !cq->entries.empty(); });
        }
    }
    return uet_cq_read_locked(cq, buf, count, nullptr);
}

static ssize_t uet_cq_sreadfrom(struct fid_cq* cq_fid, void* buf, size_t count, fi_addr_t* src_addr, const void*, int timeout)
{
    auto* cq = uet_cq_from_fid(cq_fid);
    if (!buf || count == 0 || !src_addr) return -FI_EINVAL;

    std::unique_lock<std::mutex> lock(cq->mu);
    if (cq->entries.empty()) {
        if (timeout < 0) {
            cq->cv.wait(lock, [&]() { return cq->closed || !cq->entries.empty(); });
        } else {
            cq->cv.wait_for(lock, std::chrono::milliseconds(timeout), [&]() { return cq->closed || !cq->entries.empty(); });
        }
    }
    return uet_cq_read_locked(cq, buf, count, src_addr);
}

static int uet_cq_signal(struct fid_cq*)
{
    return 0;
}

static const char* uet_cq_strerror(struct fid_cq*, int, const void*, char* buf, size_t len)
{
    if (!buf || len == 0) return "uet_cq";
    std::snprintf(buf, len, "uet_cq");
    return buf;
}

static ssize_t uet_eq_read(struct fid_eq*, uint32_t*, void*, size_t, uint64_t)
{
    return -FI_EAGAIN;
}

static ssize_t uet_eq_readerr(struct fid_eq*, struct fi_eq_err_entry*, uint64_t)
{
    return -FI_EAGAIN;
}

static ssize_t uet_eq_write(struct fid_eq*, uint32_t, const void*, size_t, uint64_t)
{
    return -FI_ENOSYS;
}

static ssize_t uet_eq_sread(struct fid_eq*, uint32_t*, void*, size_t, int, uint64_t)
{
    return -FI_EAGAIN;
}

static const char* uet_eq_strerror(struct fid_eq*, int, const void*, char* buf, size_t len)
{
    if (!buf || len == 0) return "uet_eq";
    std::snprintf(buf, len, "uet_eq");
    return buf;
}

static int uet_av_insert(struct fid_av* av_fid, const void* addr, size_t count, fi_addr_t* fi_addr, uint64_t, void*)
{
    auto* av = uet_av_from_fid(av_fid);
    if (!addr || !fi_addr || count == 0) return -FI_EINVAL;

    const auto* in = static_cast<const sockaddr_in*>(addr);

    std::lock_guard<std::mutex> lock(av->mu);
    for (size_t i = 0; i < count; i++) {
        uet_av_entry e{};
        e.addr = in[i];
        av->entries.push_back(e);
        fi_addr[i] = static_cast<fi_addr_t>(av->entries.size() - 1);
    }
    return static_cast<int>(count);
}

static int uet_av_insertsvc(struct fid_av*, const char*, const char*, fi_addr_t*, uint64_t, void*)
{
    return -FI_ENOSYS;
}

static int uet_av_insertsym(struct fid_av*, const char*, size_t, const char*, size_t, fi_addr_t*, uint64_t, void*)
{
    return -FI_ENOSYS;
}

static int uet_av_remove(struct fid_av*, fi_addr_t*, size_t, uint64_t)
{
    return 0;
}

static int uet_av_lookup(struct fid_av* av_fid, fi_addr_t fi_addr, void* addr, size_t* addrlen)
{
    auto* av = uet_av_from_fid(av_fid);
    if (!addrlen) return -FI_EINVAL;
    if (!addr) {
        *addrlen = sizeof(sockaddr_in);
        return -FI_ETOOSMALL;
    }
    if (*addrlen < sizeof(sockaddr_in)) {
        *addrlen = sizeof(sockaddr_in);
        return -FI_ETOOSMALL;
    }

    std::lock_guard<std::mutex> lock(av->mu);
    if (fi_addr >= av->entries.size()) return -FI_EINVAL;
    std::memcpy(addr, &av->entries[fi_addr].addr, sizeof(sockaddr_in));
    *addrlen = sizeof(sockaddr_in);
    return 0;
}

static const char* uet_av_straddr(struct fid_av*, const void* addr, char* buf, size_t* len)
{
    if (!addr || !len) return nullptr;
    const auto* in = static_cast<const sockaddr_in*>(addr);
    const auto ip = sockaddr_in_to_ip_string(*in);
    const uint16_t port = ntohs(in->sin_port);
    const std::string s = "fi_sockaddr_in://" + ip + ":" + std::to_string(port);

    if (!buf || *len < s.size() + 1) {
        *len = s.size() + 1;
        return nullptr;
    }
    std::snprintf(buf, *len, "%s", s.c_str());
    return buf;
}

static int uet_av_set(struct fid_av*, struct fi_av_set_attr*, struct fid_av_set**, void*)
{
    return -FI_ENOSYS;
}

static int uet_av_insert_auth_key(struct fid_av*, const void*, size_t, fi_addr_t*, uint64_t)
{
    return -FI_ENOSYS;
}

static int uet_av_lookup_auth_key(struct fid_av*, fi_addr_t, void*, size_t*)
{
    return -FI_ENOSYS;
}

static int uet_av_set_user_id(struct fid_av*, fi_addr_t, fi_addr_t, uint64_t)
{
    return -FI_ENOSYS;
}

static std::optional<sockaddr_in> uet_av_resolve(uet_av* av, fi_addr_t addr)
{
    if (!av) return std::nullopt;
    std::lock_guard<std::mutex> lock(av->mu);
    if (addr >= av->entries.size()) return std::nullopt;
    return av->entries[addr].addr;
}

static std::optional<fi_addr_t> uet_av_find_addr(uet_av* av, const sockaddr_in& in)
{
    if (!av) return std::nullopt;
    std::lock_guard<std::mutex> lock(av->mu);
    for (size_t i = 0; i < av->entries.size(); i++) {
        if (sockaddr_in_equal(av->entries[i].addr, in)) {
            return static_cast<fi_addr_t>(i);
        }
    }
    return std::nullopt;
}

static void uet_ep_start_soft_threads(uet_ep* uep)
{
    auto& soft = uep->soft;
    // 线程启动前置条件：
    // - fi_pingpong 的典型流程是：创建 EP -> bind AV/CQ -> fi_enable
    // - 所以这里要求 bound_av / bound_tx_cq / bound_rx_cq 都已绑定
    if (soft.enabled.load()) return;

    if (!uep->bound_av || !uep->bound_tx_cq || !uep->bound_rx_cq) {
        // pingpong binds CQ/AV before enabling
        return;
    }

    if (!uep->local_addr_set) {
        uep->local_addr.sin_family = AF_INET;
        uep->local_addr.sin_addr.s_addr = INADDR_ANY;
        uep->local_addr.sin_port = htons(0);
        uep->local_addr_set = true;
    }
    const in_addr requested_ip = uep->local_addr.sin_addr;
    const bool requested_any = (requested_ip.s_addr == htonl(INADDR_ANY));

    const uint16_t listen_port = ntohs(uep->local_addr.sin_port);
    soft.udp_rx = std::make_unique<UET::NetworkLayer::UDPNetworkLayer>(listen_port);
    soft.udp_tx = std::make_unique<UET::NetworkLayer::UDPNetworkLayer>(0);

    // Update peer map based on receive callback
    soft.udp_rx->setPacketCallback([uep](const PDStoNET_pkt& pkt, const std::string& src_ip, uint16_t src_port) {
        auto& soft_state = uep->soft;
        const uint16_t dst_port = soft_state.udp_rx ? soft_state.udp_rx->getLocalPort() : 0;
        uint8_t opcode = 0;
        if (pkt.SESpkt.bth_type == Standard_Header) {
            opcode = pkt.SESpkt.bth_header.Standard_Header.opcode;
        }
        uet_dbg_v("rx",
                  "udp recv: src=%s:%u dst_port=%u src_fep=%u dst_fep=%u pds=%u bth=%u opcode=%u payload=%zu",
                  src_ip.c_str(),
                  static_cast<unsigned>(src_port),
                  static_cast<unsigned>(dst_port),
                  static_cast<unsigned>(pkt.src_fep),
                  static_cast<unsigned>(pkt.dst_fep),
                  static_cast<unsigned>(pkt.PDS_type),
                  static_cast<unsigned>(pkt.SESpkt.bth_type),
                  static_cast<unsigned>(opcode),
                  pkt.SESpkt.payload.size());
        // 从 UDP 收包回调拿到对端 IP。
        //
        // 关键点（这就是你现在卡住的根因）：
        // - 我们在 provider 里用了两个 socket：udp_rx(监听) + udp_tx(发送)。
        // - 因此“UDP 报文源端口 src_port”通常等于对端的 udp_tx 端口，而不是对端的监听端口 udp_rx。
        // - 但我们第一期的约定是：PDStoNET_pkt.src_fep / dst_fep 就是“对端监听端口(udp_rx port)”。
        // - 所以 peer_by_fep 的映射必须使用 pkt.src_fep（协议里声明的 FEP/port），
        //   不能用 UDP 源端口 src_port，否则会把后续包发到对端 udp_tx 端口上（对端不在那儿 recv），从而卡死。
        // 仅对 FI_MSG (SEND) 的数据包更新 peer_by_fep 映射。
        // 对 RMA/response/ACK 包，src_fep 可能是逻辑 pid_on_fep（非 UDP 端口），
        // 不能用它覆盖已有映射。
        if (!(pkt.SESpkt.bth_type == Standard_Header &&
              pkt.SESpkt.bth_header.Standard_Header.opcode == SEND)) {
            return;
        }

        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        inet_pton(AF_INET, src_ip.c_str(), &sa.sin_addr);
        const uint16_t advertised_port = static_cast<uint16_t>(pkt.src_fep & 0xffffu);
        sa.sin_port = htons(advertised_port);

        if (advertised_port == 0) {
            return;
        }

        if (src_port != advertised_port) {
            uet_dbg_v("rx", "udp src_port=%u != hdr.src_fep(port)=%u (expected with separate udp_tx); map uses hdr port", static_cast<unsigned>(src_port),
                      static_cast<unsigned>(advertised_port));
        }

        std::lock_guard<std::mutex> lock(soft_state.peer_mu);
        soft_state.peer_by_fep[pkt.src_fep] = sa;
        if (uep->bound_av) {
            if (auto found = uet_av_find_addr(uep->bound_av, sa)) {
                soft_state.fiaddr_by_fep[pkt.src_fep] = *found;
            }
        }
    });

    if (!soft.udp_rx->initialize()) {
        return;
    }
    if (!soft.udp_tx->initialize()) {
        return;
    }

    uep->local_addr.sin_family = AF_INET;
    uep->local_addr.sin_addr = requested_ip;
    uep->local_addr.sin_port = htons(soft.udp_rx->getLocalPort());

    // Avoid advertising 0.0.0.0 to peers (fi_pingpong exchanges endpoint names verbatim).
    if (requested_any) {
        in_addr ip{};
        if (uet_pick_default_ipv4(ip)) {
            uep->local_addr.sin_addr = ip;
        }
    }

    soft.stop.store(false);

    // Progress engine: run SES mainChk periodically to advance SES/PDC queues.
    // (In a production provider this would be integrated with libfabric progress model.)
    // 中文说明：
    // - SES/PDC 里很多状态推进依赖 mainChk()（例如从队列取数据、生成 ACK/控制包等）
    // - 第一期开荒我们用一个 1ms 周期线程粗暴驱动它
    soft.ses_thread = std::thread([uep]() {
        auto& soft_state = uep->soft;
        while (!soft_state.stop.load()) {
            // 先把 provider 自己的“线程安全上行队列”里的操作，转交给 SES 处理（单线程）
            // 注意：不要在 fi_send 里直接调用 ses.mainChk/process_send_packet，
            // 否则会和这里的 ses_thread 并发执行，导致 UET 状态机不安全。
            std::queue<uet_pending_send> local;
            {
                std::unique_lock<std::mutex> lock(soft_state.op_mu);
                if (soft_state.op_q.empty()) {
                    // 轻量阻塞，避免空转；同时保持 1ms tick 继续推进 RX/TX 协议逻辑
                    soft_state.op_cv.wait_for(lock, std::chrono::milliseconds(1));
                }
                std::swap(local, soft_state.op_q);
            }

            while (!local.empty()) {
                const auto item = local.front();
                local.pop();

                uet_ctrl_view ctrl{};
                const auto* payload = reinterpret_cast<const uint8_t*>(item.md.payload.start_addr);
                const bool has_ctrl = payload && item.md.payload.length >= sizeof(uet_ctrl_hdr) &&
                                      uet_decode_ctrl_msg(payload, item.md.payload.length, ctrl);
                uet_dbg("tx_flow",
                        "ses_thread dequeue msg_id=%u op=%u len=%zu local_fep=%u dst_fep=%u track_completion=%d has_ctrl=%d type=%s session=0x%" PRIx64,
                        static_cast<unsigned>(item.md.messages_id),
                        static_cast<unsigned>(item.md.op_type),
                        item.md.payload.length,
                        static_cast<unsigned>(item.md.s_pid_on_fep),
                        static_cast<unsigned>(item.md.t_pid_on_fep),
                        static_cast<int>(item.track_completion),
                        static_cast<int>(has_ctrl),
                        has_ctrl ? uet_ctrl_msg_type_name(ctrl.hdr.msg_type) : "RAW",
                        has_ctrl ? static_cast<uint64_t>(ctrl.hdr.session_id) : 0);

                // 1) 先让 UET/SES 把用户 payload 拷贝到自己的 packet payload（vector）
                soft_state.ses.process_send_packet(item.md);

                // 2) 记录“待完成”的 send；等 tx_thread 真正把数据包发到 UDP 之后再投递 CQ completion。
                // 注意：这仍然满足 FI_MSG 语义：因为 payload 已被 SES copy，用户 send buffer 在返回后即可复用；
                // 但 fi_pingpong 等上层会等待 CQ completion，这里确保 completion 代表“已发到网络(至少已调用 sendto)”，避免退出阶段丢包。
                if (item.track_completion) {
                    std::lock_guard<std::mutex> lock(soft_state.txc_mu);
                    const uint16_t msg_id = static_cast<uint16_t>(item.md.messages_id);
                    uint64_t flags = FI_SEND;
                    if (item.md.op_type == WRITE) {
                        flags = FI_WRITE;
                    }
                    soft_state.pending_tx_completions[msg_id] = uet_soft_state::uet_tx_completion{
                        .context = item.context,
                        .len = item.len,
                        .flags = flags,
                    };
                }
            }

            soft_state.ses.mainChk();
        }
    });

    // TX engine: drain SES/PDS -> NET queue and send packets over UDP.
    // 中文说明：
    // - SES/PDC 会把待发送包放入 pds_process_manager 的“发往网络”队列
    // - 本线程就是把队列里的 PDStoNET_pkt 转成 UDP 数据并发出去
    soft.tx_thread = std::thread([uep]() {
        auto& soft_state = uep->soft;
        while (!soft_state.stop.load()) {
            PDStoNET_pkt pkt{};
            if (!soft_state.ses.pds_process_manager.popNetworkPacket(pkt)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                continue;
            }

            uet_dbg("tx_flow",
                    "tx_thread pop pkt pds_type=%u dst_fep=%u src_fep=%u ses_bth=%u",
                    static_cast<unsigned>(pkt.PDS_type),
                    static_cast<unsigned>(pkt.dst_fep),
                    static_cast<unsigned>(pkt.src_fep),
                    static_cast<unsigned>(pkt.SESpkt.bth_type));

            sockaddr_in dest{};
            bool have_dest = false;
            {
                std::lock_guard<std::mutex> lock(soft_state.peer_mu);
                auto it = soft_state.peer_by_fep.find(pkt.dst_fep);
                if (it != soft_state.peer_by_fep.end()) {
                    dest = it->second;
                    have_dest = true;
                }
            }

            if (!have_dest) {
                // Fallback: if only one AV entry exists, use it
                if (uep->bound_av) {
                    auto opt = uet_av_resolve(uep->bound_av, 0);
                    if (opt) {
                        dest = *opt;
                        have_dest = true;
                    }
                }
            }

            if (!have_dest) {
                uet_dbg("tx_flow", "tx_thread drop pkt: no destination mapping for dst_fep=%u",
                        static_cast<unsigned>(pkt.dst_fep));
                continue;
            }

            const std::string ip = sockaddr_in_to_ip_string(dest);
            const uint16_t port = ntohs(dest.sin_port);
            if (pkt.PDS_type == PDS_header_type::RUOD_req_header && pkt.SESpkt.bth_type == Standard_Header) {
                const auto& hdr = pkt.SESpkt.bth_header.Standard_Header;
                uet_dbg("tx_flow",
                        "tx_thread send msg_id=%u opcode=%u som=%u eom=%u req_len=%u payload=%zu -> %s:%u",
                        static_cast<unsigned>(hdr.msg_id),
                        static_cast<unsigned>(hdr.opcode),
                        static_cast<unsigned>(hdr.som),
                        static_cast<unsigned>(hdr.eom),
                        static_cast<unsigned>(hdr.request_length),
                        pkt.SESpkt.payload.size(),
                        ip.c_str(),
                        static_cast<unsigned>(port));
            } else {
                uet_dbg("tx_flow", "tx_thread send raw -> %s:%u", ip.c_str(), static_cast<unsigned>(port));
            }
            const int rc = soft_state.udp_tx->sendPacket(pkt, ip, port);
            uet_dbg("tx_flow", "tx_thread send rc=%d -> %s:%u", rc, ip.c_str(), static_cast<unsigned>(port));

            // 若这是应用层 FI_MSG 的“最后一个分片”（eom=1），则投递对应的 FI_SEND completion。
            // 说明：
            // - 这里用 FIFO 匹配：fi_pingpong/第一期模型是单线程串行 send/recv，消息不会并发交错发送；
            //   因此只要在“发出最后分片”时按顺序完成即可。
            // - 后续若要支持真正的并发 send，需要把 msg_id 映射到 completion（例如把 metadata.messages_id 写入 SES header.msg_id）。
            if (rc >= 0 && pkt.PDS_type == PDS_header_type::RUOD_req_header && pkt.SESpkt.bth_type == Standard_Header) {
                const auto& hdr = pkt.SESpkt.bth_header.Standard_Header;
                if ((hdr.opcode == SEND || hdr.opcode == WRITE) && hdr.eom) {
                    std::optional<uet_soft_state::uet_tx_completion> done;
                    {
                        std::lock_guard<std::mutex> lock(soft_state.txc_mu);
                        auto it = soft_state.pending_tx_completions.find(hdr.msg_id);
                        if (it != soft_state.pending_tx_completions.end()) {
                            done = it->second;
                            soft_state.pending_tx_completions.erase(it);
                        }
                    }
                    if (done) {
                        uet_dbg("tx_flow", "tx cq push msg_id=%u len=%zu ctx=%p flags=0x%" PRIx64,
                                static_cast<unsigned>(hdr.msg_id), done->len, done->context, done->flags);
                        cq_push(uep->bound_tx_cq, uet_cq_entry{
                                                       .op_context = done->context,
                                                       .flags = done->flags,
                                                       .len = done->len,
                                                       .src_addr = FI_ADDR_UNSPEC,
                                                   });
                    }
                }
            }
        }
    });

    // RX engine: receive UDP packets and:
    //  1) push into the UET PDS manager for protocol processing
    //  2) if the packet contains SES Standard_Header + payload, reassemble and complete a posted FI_RECV
    // 中文说明：
    // - 第一步：把收包喂给 PDS/SES 的状态机（维持你们协议逻辑）
    // - 第二步：对 FI_MSG，我们直接把 payload 交付给应用（posted recv），并投递 CQ 完成事件
    soft.rx_thread = std::thread([uep]() {
        auto& soft_state = uep->soft;
        while (!soft_state.stop.load()) {
            PDStoNET_pkt pkt{};
            if (!soft_state.udp_rx->receivePDStoNETPacket(50, pkt)) {
                continue;
            }

            if (pkt.PDS_type == PDS_header_type::RUOD_req_header &&
                pkt.SESpkt.bth_type == Standard_Header) {
                const auto& hdr = pkt.SESpkt.bth_header.Standard_Header;
                uet_dbg("rx", "udp pkt: src_fep=%u dst_fep=%u opcode=%u msg_id=%u som=%u eom=%u total=%u payload=%zu",
                        static_cast<unsigned>(pkt.src_fep),
                        static_cast<unsigned>(pkt.dst_fep),
                        static_cast<unsigned>(hdr.opcode),
                        static_cast<unsigned>(hdr.msg_id),
                        static_cast<unsigned>(hdr.som),
                        static_cast<unsigned>(hdr.eom),
                        static_cast<unsigned>(hdr.request_length),
                        pkt.SESpkt.payload.size());
            } else {
                uet_dbg_v("rx", "udp pkt filtered early: pds_type=%d bth_type=%d payload=%zu src_fep=%u dst_fep=%u",
                          static_cast<int>(pkt.PDS_type),
                          static_cast<int>(pkt.SESpkt.bth_type),
                          pkt.SESpkt.payload.size(),
                          static_cast<unsigned>(pkt.src_fep),
                          static_cast<unsigned>(pkt.dst_fep));
            }

            // Feed protocol state machine
            soft_state.ses.pds_process_manager.pushNetworkPacket(pkt);

            // Handle READ response-with-data for fi_read completion.
            if (pkt.SESpkt.bth_type == Semantic_Response_with_Data_Header) {
                const auto& hdr = pkt.SESpkt.bth_header.Semantic_Response_with_Data_Header;
                const uint16_t req_msg_id = hdr.read_request_msg_id;

                uet_soft_state::uet_read_state st;
                bool have = false;
                {
                    std::lock_guard<std::mutex> lock(soft_state.read_mu);
                    auto it = soft_state.pending_reads.find(req_msg_id);
                    if (it != soft_state.pending_reads.end()) {
                        st = it->second;
                        have = true;
                    }
                }

                if (!have) {
                    continue;
                }

                if (hdr.return_code != static_cast<uint8_t>(RSP_RETURN_CODE::RC_OK)) {
                    std::lock_guard<std::mutex> lock(soft_state.read_mu);
                    soft_state.pending_reads.erase(req_msg_id);
                    cq_push(uep->bound_tx_cq, uet_cq_entry{
                                                   .op_context = st.context,
                                                   .flags = FI_READ,
                                                   .len = 0,
                                                   .src_addr = FI_ADDR_UNSPEC,
                                               });
                    continue;
                }

                const uint32_t total_len = hdr.modified_length;
                const size_t frag_len = std::min<size_t>(pkt.SESpkt.payload.size(), hdr.payload_length);
                const size_t frag_off = hdr.message_offset;

                if (frag_off + frag_len <= st.len && st.buf && frag_len > 0) {
                    std::memcpy(reinterpret_cast<uint8_t*>(st.buf) + frag_off, pkt.SESpkt.payload.data(), frag_len);
                }

                if (st.chunk_size == 0) {
                    st.chunk_size = static_cast<uint32_t>(MAX_MTU - sizeof(SES_Semantic_Response_with_Data_Header));
                }
                if (st.chunk_received.empty() && st.chunk_size > 0 && st.total_len > 0) {
                    const size_t chunks = (static_cast<size_t>(st.total_len) + st.chunk_size - 1) / st.chunk_size;
                    st.chunk_received.assign(chunks, 0);
                }

                if (st.chunk_size > 0 && !st.chunk_received.empty()) {
                    const size_t chunk_idx = frag_off / st.chunk_size;
                    if (chunk_idx < st.chunk_received.size() && st.chunk_received[chunk_idx] == 0) {
                        st.chunk_received[chunk_idx] = 1;
                        st.chunks_done++;
                    }
                }

                bool done = false;
                if (total_len == 0 || st.chunk_received.empty()) {
                    done = true;
                } else if (st.chunks_done == st.chunk_received.size()) {
                    done = true;
                }

                if (done) {
                    std::lock_guard<std::mutex> lock(soft_state.read_mu);
                    soft_state.pending_reads.erase(req_msg_id);
                    const size_t done_len = (total_len > 0) ? std::min<size_t>(st.len, total_len) : st.len;
                    cq_push(uep->bound_tx_cq, uet_cq_entry{
                                                   .op_context = st.context,
                                                   .flags = FI_READ,
                                                   .len = done_len,
                                                   .src_addr = FI_ADDR_UNSPEC,
                                               });
                } else {
                    std::lock_guard<std::mutex> lock(soft_state.read_mu);
                    soft_state.pending_reads[req_msg_id] = std::move(st);
                }

                continue;
            }

            // Only treat RUOD request packets with SES standard header as application data.
            // This matches our phase 1 mapping: FI_MSG payload rides in SES "request" packets.
            if (pkt.PDS_type != PDS_header_type::RUOD_req_header) {
                uet_dbg("rx", "skip packet before FI_MSG delivery: reason=pds_type pds_type=%d src_fep=%u",
                        static_cast<int>(pkt.PDS_type),
                        static_cast<unsigned>(pkt.src_fep));
                continue;
            }
            if (pkt.SESpkt.bth_type != Standard_Header) {
                uet_dbg("rx", "skip packet before FI_MSG delivery: reason=bth_type bth_type=%d src_fep=%u",
                        static_cast<int>(pkt.SESpkt.bth_type),
                        static_cast<unsigned>(pkt.src_fep));
                continue;
            }
            if (pkt.SESpkt.payload.empty()) {
                uet_dbg("rx", "skip packet before FI_MSG delivery: reason=empty_payload src_fep=%u",
                        static_cast<unsigned>(pkt.src_fep));
                continue;
            }

            const auto& hdr = pkt.SESpkt.bth_header.Standard_Header;
            // 仅把 opcode==SEND 的数据包当作 FI_MSG payload 交付给应用层。
            // 这样可以避免未来协议内部携带 payload 的其它 opcode 被误投递到应用 recv buffer。
            if (hdr.opcode != SEND) {
                uet_dbg("rx", "skip packet before FI_MSG delivery: reason=opcode opcode=%u msg_id=%u src_fep=%u",
                        static_cast<unsigned>(hdr.opcode),
                        static_cast<unsigned>(hdr.msg_id),
                        static_cast<unsigned>(pkt.src_fep));
                continue;
            }
            const uint32_t total = hdr.request_length;
            const uint16_t msg_id = hdr.msg_id;
            const uint32_t src_fep = pkt.src_fep;

            const uet_reassembly_key key{src_fep, msg_id};

            size_t frag_off = 0;
            if (!hdr.som) {
                frag_off = hdr.diff.som_false.message_offset;
            }
            const size_t frag_len = pkt.SESpkt.payload.size();

            fi_addr_t src_addr = FI_ADDR_UNSPEC;
            {
                std::lock_guard<std::mutex> lock(soft_state.peer_mu);
                auto it = soft_state.fiaddr_by_fep.find(src_fep);
                if (it != soft_state.fiaddr_by_fep.end()) {
                    src_addr = it->second;
                }
            }

            std::optional<std::vector<uint8_t>> completed;
            {
                std::lock_guard<std::mutex> lock(soft_state.reas_mu);
                auto& st = soft_state.reassembly[key];
                if (st.buffer.empty()) {
                    uet_dbg("rx", "reassembly start: src_fep=%u msg_id=%u total=%u src_addr=%" PRIu64,
                            static_cast<unsigned>(src_fep),
                            static_cast<unsigned>(msg_id),
                            static_cast<unsigned>(total),
                            static_cast<uint64_t>(src_addr));
                    st.total_len = total;
                    st.chunk_size = kUetMaxPayloadPerPacket;
                    const size_t chunks = (static_cast<size_t>(total) + st.chunk_size - 1) / st.chunk_size;
                    st.buffer.resize(total);
                    st.chunk_received.assign(chunks, 0);
                    st.chunks_done = 0;
                    st.saw_eom = false;
                    st.src_addr = src_addr;
                }

                if (frag_off + frag_len <= st.buffer.size()) {
                    std::memcpy(st.buffer.data() + frag_off, pkt.SESpkt.payload.data(), frag_len);
                }

                const size_t chunk_idx = frag_off / st.chunk_size;
                uet_dbg("rx", "reassembly frag: src_fep=%u msg_id=%u off=%zu len=%zu chunk=%zu/%zu som=%u eom=%u",
                        static_cast<unsigned>(src_fep),
                        static_cast<unsigned>(msg_id),
                        frag_off,
                        frag_len,
                        chunk_idx,
                        st.chunk_received.size(),
                        static_cast<unsigned>(hdr.som),
                        static_cast<unsigned>(hdr.eom));
                if (chunk_idx < st.chunk_received.size() && st.chunk_received[chunk_idx] == 0) {
                    st.chunk_received[chunk_idx] = 1;
                    st.chunks_done++;
                }

                if (hdr.eom) {
                    st.saw_eom = true;
                }

                if (st.saw_eom && st.chunks_done == st.chunk_received.size()) {
                    completed = std::move(st.buffer);
                    uet_dbg("rx", "reassembly done: src_fep=%u msg_id=%u total=%u chunks=%zu src_addr=%" PRIu64,
                            static_cast<unsigned>(src_fep),
                            static_cast<unsigned>(msg_id),
                            static_cast<unsigned>(total),
                            st.chunk_received.size(),
                            static_cast<uint64_t>(src_addr));
                    soft_state.reassembly.erase(key);
                }
            }

            if (!completed) {
                uet_dbg("rx", "reassembly pending: src_fep=%u msg_id=%u", static_cast<unsigned>(src_fep),
                        static_cast<unsigned>(msg_id));
                continue;
            }

            uet_ctrl_view ctrl{};
            const bool is_ctrl = uet_decode_ctrl_msg(completed->data(), completed->size(), ctrl);
            if (is_ctrl) {
                uet_dbg("rx", "completed ctrl msg: type=%s peer=%" PRIu64 " session=0x%" PRIx64 " payload=%zu msg_len=%zu",
                        uet_ctrl_msg_type_name(ctrl.hdr.msg_type),
                        static_cast<uint64_t>(src_addr),
                        static_cast<uint64_t>(ctrl.hdr.session_id),
                        ctrl.payload_len,
                        completed->size());
            } else {
                uet_dbg("rx", "completed non-ctrl msg: src_addr=%" PRIu64 " msg_len=%zu",
                        static_cast<uint64_t>(src_addr),
                        completed->size());
            }

            // Cache MRDesc control-plane message (if present), but still deliver to app recv.
            uet_try_cache_mrdesc(uep, *completed, src_addr);
            if (uet_handle_internal_ctrl_msg(uep, *completed, src_addr)) {
                if (is_ctrl) {
                    uet_dbg("rx", "ctrl msg consumed internally: type=%s peer=%" PRIu64,
                            uet_ctrl_msg_type_name(ctrl.hdr.msg_type),
                            static_cast<uint64_t>(src_addr));
                }
                continue;
            }

            std::optional<uet_posted_recv> req;
            {
                std::lock_guard<std::mutex> lock(soft_state.recv_mu);
                if (!soft_state.posted_recvs.empty()) {
                    // Basic matching: FIFO (ignores src_filter in phase 1).
                    req = soft_state.posted_recvs.front();
                    soft_state.posted_recvs.pop_front();
                    if (is_ctrl) {
                        uet_dbg("rx", "ctrl msg matched posted recv: type=%s peer=%" PRIu64 " posted_len=%zu remaining_posted=%zu",
                                uet_ctrl_msg_type_name(ctrl.hdr.msg_type),
                                static_cast<uint64_t>(src_addr),
                                req->len,
                                soft_state.posted_recvs.size());
                    }
                } else {
                    // No posted recv yet: keep message in unexpected queue to avoid dropping.
                    uet_dbg_v("rx", "no posted recv: stash unexpected msg_len=%zu src_addr=%" PRIu64, completed->size(), static_cast<uint64_t>(src_addr));
                    if (is_ctrl) {
                        uet_dbg("rx", "ctrl msg stashed unexpected: type=%s peer=%" PRIu64 " queue_before=%zu",
                                uet_ctrl_msg_type_name(ctrl.hdr.msg_type),
                                static_cast<uint64_t>(src_addr),
                                soft_state.unexpected_msgs.size());
                    }
                    soft_state.unexpected_msgs.push_back(uet_unexpected_msg{
                        .data = std::move(*completed),
                        .src_addr = src_addr,
                    });
                }
            }

            if (!req) continue;

            const size_t copy_len = std::min(req->len, completed->size());
            std::memcpy(req->buf, completed->data(), copy_len);
            uet_dbg_v("rx", "complete recv: msg_len=%zu -> copy_len=%zu ctx=%p src_addr=%" PRIu64, completed->size(), copy_len, req->context, static_cast<uint64_t>(src_addr));
            if (is_ctrl) {
                uet_dbg("rx", "ctrl msg cq_push(FI_RECV): type=%s peer=%" PRIu64 " copy_len=%zu ctx=%p",
                        uet_ctrl_msg_type_name(ctrl.hdr.msg_type),
                        static_cast<uint64_t>(src_addr),
                        copy_len,
                        req->context);
            }

            cq_push(uep->bound_rx_cq, uet_cq_entry{
                                           .op_context = req->context,
                                           .flags = FI_RECV,
                                           .len = copy_len,
                                           .src_addr = src_addr,
                                       });
        }
    });

    soft.enabled.store(true);
}

static int uet_rdma_send_conn_msg(uet_ep* uep, fi_addr_t peer, uint16_t type)
{
#if !UET_HAVE_IBVERBS
    (void)uep;
    (void)peer;
    (void)type;
    return -FI_EOPNOTSUPP;
#else
    if (!uep) return -FI_EINVAL;
    uet_rdma_conn_msg msg{};
    if (uet_rdma_build_local_conn(uep, msg) != 0) {
        return -FI_EIO;
    }
    {
        std::lock_guard<std::mutex> lock(uep->rdma.mu);
        uep->rdma.conn.local = msg;
    }
    uet_dbg("rdma", "%s send: peer=%" PRIu64 " session=0x%" PRIx64 " local={%s}",
            type == UET_CTRL_RDMA_CONN_REQ ? "RDMA_CONN_REQ" : "RDMA_CONN_RESP",
            static_cast<uint64_t>(peer),
            static_cast<uint64_t>(uep->local_session_id),
            uet_rdma_conn_to_string(msg).c_str());
    return uet_ep_queue_ctrl_send(uep, peer, uet_encode_ctrl_msg(type, uep->local_session_id, uep->job_id, 0, &msg, sizeof(msg)));
#endif
}

static bool uet_handle_internal_ctrl_msg(uet_ep* uep, const std::vector<uint8_t>& msg, fi_addr_t src_addr)
{
    if (!uep || src_addr == FI_ADDR_UNSPEC) return false;
    uet_ctrl_view ctrl{};
    if (!uet_decode_ctrl_msg(msg.data(), msg.size(), ctrl)) {
        return false;
    }

    uet_dbg("ctrl", "internal ctrl inspect: type=%s peer=%" PRIu64 " session=0x%" PRIx64 " payload=%zu",
            uet_ctrl_msg_type_name(ctrl.hdr.msg_type),
            static_cast<uint64_t>(src_addr),
            static_cast<uint64_t>(ctrl.hdr.session_id),
            ctrl.payload_len);

    if (ctrl.hdr.msg_type == UET_CTRL_RDMA_CONN_REQ || ctrl.hdr.msg_type == UET_CTRL_RDMA_CONN_RESP) {
#if !UET_HAVE_IBVERBS
        return true;
#else
        if (uep->rdma.connect_mode == uet_rdma_connect_mode::iwarp_cm) {
            uet_dbg("cm", "ignore %s on iwarp_cm path: peer=%" PRIu64 " session=0x%" PRIx64,
                    ctrl.hdr.msg_type == UET_CTRL_RDMA_CONN_REQ ? "RDMA_CONN_REQ" : "RDMA_CONN_RESP",
                    static_cast<uint64_t>(src_addr),
                    static_cast<uint64_t>(ctrl.hdr.session_id));
            return true;
        }
        if (ctrl.payload_len < sizeof(uet_rdma_conn_msg)) {
            return true;
        }
        uet_rdma_conn_msg conn_msg{};
        std::memcpy(&conn_msg, ctrl.payload, sizeof(conn_msg));
        uet_dbg("rdma", "%s recv: peer=%" PRIu64 " session=0x%" PRIx64 " remote={%s}",
                ctrl.hdr.msg_type == UET_CTRL_RDMA_CONN_REQ ? "RDMA_CONN_REQ" : "RDMA_CONN_RESP",
                static_cast<uint64_t>(src_addr),
                static_cast<uint64_t>(ctrl.hdr.session_id),
                uet_rdma_conn_to_string(conn_msg).c_str());
        if (const int rc = uet_rdma_mark_connected(uep, src_addr, ctrl.hdr.session_id, conn_msg); rc != 0) {
            const std::string reason = std::string("mark_connected failed for ") +
                                       (ctrl.hdr.msg_type == UET_CTRL_RDMA_CONN_REQ ? "RDMA_CONN_REQ" : "RDMA_CONN_RESP");
            uet_rdma_fail_conn(uep, rc, reason);
            if (ctrl.hdr.msg_type == UET_CTRL_RDMA_CONN_REQ) {
                (void)uet_ep_queue_ctrl_send(uep, src_addr,
                                             uet_encode_ctrl_msg(UET_CTRL_ERR,
                                                                 uep->local_session_id,
                                                                 uep->job_id,
                                                                 0,
                                                                 reason.data(),
                                                                 reason.size() + 1));
            }
            return true;
        }
        if (ctrl.hdr.msg_type == UET_CTRL_RDMA_CONN_REQ) {
            (void)uet_rdma_send_conn_msg(uep, src_addr, UET_CTRL_RDMA_CONN_RESP);
        }
        return true;
#endif
    }

    if (ctrl.hdr.msg_type == UET_CTRL_ERR) {
        std::string reason = "peer reported ERR";
        if (ctrl.payload_len > 0) {
            const char* p = reinterpret_cast<const char*>(ctrl.payload);
            reason.assign(p, strnlen(p, ctrl.payload_len));
        }
        uet_dbg("rdma", "CTRL_ERR recv: peer=%" PRIu64 " session=0x%" PRIx64 " reason=%s",
                static_cast<uint64_t>(src_addr),
                static_cast<uint64_t>(ctrl.hdr.session_id),
                reason.c_str());
        uet_rdma_fail_conn(uep, -FI_EIO, reason);
        return true;
    }

    if (ctrl.hdr.msg_type == UET_CTRL_WRITE_NOTIFY) {
        if (ctrl.payload_len >= sizeof(uet_write_notify_msg)) {
            uet_write_notify_msg notify{};
            std::memcpy(&notify, ctrl.payload, sizeof(notify));
            uet_write_notify_msg ack = notify;
            ack.status = 1;
            (void)uet_ep_queue_ctrl_send(uep, src_addr, uet_encode_ctrl_msg(UET_CTRL_WRITE_ACK, uep->local_session_id, uep->job_id, 0, &ack, sizeof(ack)));
        }
        return true;
    }

    if (ctrl.hdr.msg_type == UET_CTRL_WRITE_ACK) {
        if (ctrl.payload_len >= sizeof(uet_write_notify_msg)) {
            uet_write_notify_msg ack{};
            std::memcpy(&ack, ctrl.payload, sizeof(ack));
            std::optional<uet_rdma_state::pending_op> done;
            const uint64_t ack_ns = uet_now_ns();
            {
                std::lock_guard<std::mutex> lock(uep->rdma.mu);
                auto it = uep->rdma.pending_ops.find(ack.wr_id);
                if (it != uep->rdma.pending_ops.end()) {
                    done = it->second;
                    if (done->kind == uet_rdma_state::op_kind::write) {
                        ++uep->rdma.stats.remote_ack;
                        if (done->submit_ns != 0 && ack_ns >= done->submit_ns) {
                            uep->rdma.stats.submit_to_ack_ns += (ack_ns - done->submit_ns);
                        }
                        if (done->local_cqe_ns != 0 && ack_ns >= done->local_cqe_ns) {
                            uep->rdma.stats.local_to_ack_ns += (ack_ns - done->local_cqe_ns);
                        }
                    }
                    uep->rdma.pending_ops.erase(it);
                }
            }
            if (done && done->kind == uet_rdma_state::op_kind::write) {
                cq_push(uep->bound_tx_cq, uet_cq_entry{
                                               .op_context = done->context,
                                               .flags = FI_WRITE,
                                               .len = done->len,
                                               .src_addr = FI_ADDR_UNSPEC,
                                           });
            }
        }
        return true;
    }

    uet_dbg("ctrl", "internal ctrl pass-through: type=%s peer=%" PRIu64,
            uet_ctrl_msg_type_name(ctrl.hdr.msg_type),
            static_cast<uint64_t>(src_addr));

    return false;
}

static int uet_ep_start_rdma_progress(uet_ep* uep)
{
    if (!uep || !uep->domain) return -FI_EINVAL;
    uep->rdma.enabled.store(false);
    uep->rdma.stop.store(false);
    if (!uep->domain->rdma_runtime_ready || !uep->domain->rdma_device || !uep->domain->rdma_device->available) {
        if (uep->domain->rdma_unavailable_reason.empty()) {
            uep->domain->rdma_unavailable_reason = "RDMA runtime not ready";
        }
        return -FI_EOPNOTSUPP;
    }

#if !UET_HAVE_IBVERBS
    uep->domain->rdma_unavailable_reason = "ibverbs support not compiled in";
    return -FI_EOPNOTSUPP;
#else
    if (!uep->soft.enabled.load()) {
        uet_ep_start_soft_threads(uep);
    }
    uet_dbg("cm", "CONNECT_MODE select: selected=%s requested=%s transport=%s",
            uet_rdma_connect_mode_name(uep->rdma.connect_mode),
            uet_rdma_connect_mode_name(uep->rdma.requested_mode),
            uep->rdma.device ? uet_ibv_transport_name(uep->rdma.device->transport_type) : "-");
    if (uep->rdma.connect_mode == uet_rdma_connect_mode::manual_rc) {
        const int cq_rc = uet_rdma_ensure_data_cq(uep);
        if (cq_rc != 0) {
            return cq_rc;
        }
        const int qp_rc = uet_rdma_prepare_manual_qp(uep);
        if (qp_rc != 0) {
            return qp_rc;
        }
    } else if (uep->rdma.connect_mode == uet_rdma_connect_mode::iwarp_cm) {
#if !UET_HAVE_RDMACM
        uep->domain->rdma_unavailable_reason = "rdma_cm support not compiled in";
        return -FI_EOPNOTSUPP;
#else
        const int cm_rc = uet_rdma_cm_start_listener(uep);
        if (cm_rc != 0) {
            uep->domain->rdma_unavailable_reason = "rdma_cm listener setup failed";
            return cm_rc;
        }
        const int cq_rc = uet_rdma_ensure_data_cq(uep);
        if (cq_rc != 0) {
            return cq_rc;
        }
#endif
    }

    if (!uep->rdma.cq_progress_thread.joinable()) {
        uep->rdma.cq_progress_thread = std::thread([uep]() {
            while (!uep->rdma.stop.load()) {
                ibv_wc wc[8]{};
                const int n = ibv_poll_cq(uep->rdma.data_cq, 8, wc);
                if (n < 0) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    continue;
                }
                if (n == 0) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    continue;
                }
                for (int i = 0; i < n; ++i) {
                    if (wc[i].status != IBV_WC_SUCCESS) {
                        uet_dbg("rdma", "wc error wr_id=%" PRIu64 " status=%d (%s) opcode=%d vendor_err=%u",
                                static_cast<uint64_t>(wc[i].wr_id),
                                wc[i].status,
                                ibv_wc_status_str(wc[i].status),
                                wc[i].opcode,
                                static_cast<unsigned>(wc[i].vendor_err));
                        uet_rdma_log_qp_snapshot(uep, "wc_error");
                        continue;
                    }
                    std::optional<uet_rdma_state::pending_op> done;
                    const uint64_t local_cqe_ns = uet_now_ns();
                    {
                        std::lock_guard<std::mutex> lock(uep->rdma.mu);
                        auto it = uep->rdma.pending_ops.find(wc[i].wr_id);
                        if (it != uep->rdma.pending_ops.end()) {
                            it->second.local_cqe_seen = true;
                            it->second.local_cqe_ns = local_cqe_ns;
                            if (it->second.kind == uet_rdma_state::op_kind::read) {
                                done = it->second;
                                uep->rdma.pending_ops.erase(it);
                            } else {
                                done = it->second;
                                ++uep->rdma.stats.local_cqe;
                                if (it->second.submit_ns != 0 && local_cqe_ns >= it->second.submit_ns) {
                                    uep->rdma.stats.submit_to_local_ns +=
                                        (local_cqe_ns - it->second.submit_ns);
                                }
                                if (uep->rdma.write_completion_mode ==
                                    uet_write_completion_mode::local_cq) {
                                    uep->rdma.pending_ops.erase(it);
                                }
                            }
                        }
                    }
                    if (!done) {
                        continue;
                    }
                    if (done->kind == uet_rdma_state::op_kind::read) {
                        cq_push(uep->bound_tx_cq, uet_cq_entry{
                                                       .op_context = done->context,
                                                       .flags = FI_READ,
                                                       .len = done->len,
                                                       .src_addr = FI_ADDR_UNSPEC,
                                                   });
                    } else {
                        if (uep->rdma.write_completion_mode ==
                            uet_write_completion_mode::local_cq) {
                            cq_push(uep->bound_tx_cq, uet_cq_entry{
                                                           .op_context = done->context,
                                                           .flags = FI_WRITE,
                                                           .len = done->len,
                                                           .src_addr = FI_ADDR_UNSPEC,
                                                       });
                        } else {
                            uet_write_notify_msg notify{};
                            notify.wr_id = wc[i].wr_id;
                            notify.status = 1;
                            (void)uet_ep_queue_ctrl_send(
                                uep,
                                done->peer,
                                uet_encode_ctrl_msg(UET_CTRL_WRITE_NOTIFY,
                                                    uep->local_session_id,
                                                    uep->job_id,
                                                    0,
                                                    &notify,
                                                    sizeof(notify)));
                        }
                    }
                }
            }
        });
    }

    uep->rdma.enabled.store(true);
    return 0;
#endif
}

static void uet_ep_stop_soft_threads(uet_ep* uep)
{
    auto& soft = uep->soft;
    // 中文说明：
    // - fi_close(ep) 期望 provider 尽快停止所有后台线程，否则应用端会“Terminating test”后迟迟不退出。
    // - 这里做两件事来加速退出：
    //   1) stop=true + notify，尽快让轮询线程退出循环
    //   2) 关闭 UDP socket，让 recvfrom 立刻返回（而不是最多等待 SO_RCVTIMEO 的超时）
    uet_dbg_v("close", "ep stop threads: begin");
    soft.stop.store(true);
    soft.op_cv.notify_all();

    if (soft.udp_rx) soft.udp_rx->close();
    if (soft.udp_tx) soft.udp_tx->close();

    if (soft.rx_thread.joinable()) soft.rx_thread.join();
    if (soft.tx_thread.joinable()) soft.tx_thread.join();
    if (soft.ses_thread.joinable()) soft.ses_thread.join();
    soft.enabled.store(false);
    uet_dbg_v("close", "ep stop threads: done");
}

static void uet_ep_stop_rdma_progress(uet_ep* uep)
{
    if (!uep) return;
    auto& rdma = uep->rdma;
    rdma.stop.store(true);
    if (rdma.cq_progress_thread.joinable()) {
        rdma.cq_progress_thread.join();
    }
#if UET_HAVE_IBVERBS
#if UET_HAVE_RDMACM
    if (rdma.cm.event_thread.joinable()) {
        rdma.cm.event_thread.join();
    }
    if (rdma.cm.data_id && rdma.cm.data_id->qp) {
        rdma_destroy_qp(rdma.cm.data_id);
    }
    rdma_cm_id* active_id = rdma.cm.active_id;
    rdma_cm_id* passive_id = rdma.cm.passive_id;
    rdma_cm_id* listener_id = rdma.cm.listener_id;
    rdma.cm.active_id = nullptr;
    rdma.cm.passive_id = nullptr;
    rdma.cm.listener_id = nullptr;
    if (active_id) {
        rdma_destroy_id(active_id);
    }
    if (passive_id && passive_id != active_id) {
        rdma_destroy_id(passive_id);
    }
    if (listener_id) {
        rdma_destroy_id(listener_id);
    }
    if (rdma.cm.event_channel) {
        rdma_destroy_event_channel(rdma.cm.event_channel);
        rdma.cm.event_channel = nullptr;
    }
    rdma.cm.data_id = nullptr;
#endif
    if (rdma.data_qp && rdma.connect_mode != uet_rdma_connect_mode::iwarp_cm) {
        ibv_destroy_qp(rdma.data_qp);
    }
    rdma.data_qp = nullptr;
    if (rdma.data_cq) {
        ibv_destroy_cq(rdma.data_cq);
        rdma.data_cq = nullptr;
    }
#endif
    rdma.enabled.store(false);
}

static ssize_t uet_ep_recv(struct fid_ep* ep, void* buf, size_t len, void*, fi_addr_t src_addr, void* context)
{
    auto* uep = uet_ep_from_fid(ep);
    if (!uep->soft.enabled.load()) {
        if (uep->backend == uet_backend_kind::soft) {
            uet_ep_start_soft_threads(uep);
        } else if (uep->backend == uet_backend_kind::rdma) {
            const int rc = uet_ep_start_rdma_progress(uep);
            if (rc) return rc;
        }
    }
    auto& soft = uep->soft;
    if (!buf || len == 0) return -FI_EINVAL;
    uet_dbg_v("fi_recv", "post buf=%p len=%zu src_filter=%" PRIu64 " ctx=%p", buf, len, static_cast<uint64_t>(src_addr), context);

    // If we already have an unexpected message, consume it immediately and complete the recv.
    std::optional<uet_unexpected_msg> umsg;
    {
        std::lock_guard<std::mutex> lock(soft.recv_mu);
        if (!soft.unexpected_msgs.empty()) {
            umsg = std::move(soft.unexpected_msgs.front());
            soft.unexpected_msgs.pop_front();
        } else {
            // Otherwise, enqueue the posted recv buffer.
            soft.posted_recvs.push_back(uet_posted_recv{
                .buf = buf,
                .len = len,
                .context = context,
                .src_filter = src_addr,
            });
        }
    }

    if (umsg) {
        const size_t copy_len = std::min(len, umsg->data.size());
        std::memcpy(buf, umsg->data.data(), copy_len);
        uet_dbg_v("fi_recv", "consume unexpected: msg_len=%zu -> copy_len=%zu src_addr=%" PRIu64, umsg->data.size(), copy_len, static_cast<uint64_t>(umsg->src_addr));
        cq_push(uep->bound_rx_cq, uet_cq_entry{
                                       .op_context = context,
                                       .flags = FI_RECV,
                                       .len = copy_len,
                                       .src_addr = umsg->src_addr,
                                   });
    }
    return 0;
}

static ssize_t uet_ep_send(struct fid_ep* ep, const void* buf, size_t len, void*, fi_addr_t dest_addr, void* context)
{
    auto* uep = uet_ep_from_fid(ep);
    if (!uep->soft.enabled.load()) {
        if (uep->backend == uet_backend_kind::soft) {
            uet_ep_start_soft_threads(uep);
        } else if (uep->backend == uet_backend_kind::rdma) {
            const int rc = uet_ep_start_rdma_progress(uep);
            if (rc) return rc;
        }
    }
    auto& soft = uep->soft;
    if (!buf && len) return -FI_EINVAL;
    if (!uep->bound_av) return -FI_EINVAL;

    auto dest = uet_av_resolve(uep->bound_av, dest_addr);
    if (!dest) return -FI_EINVAL;

    const uint16_t remote_port = ntohs(dest->sin_port);
    uet_dbg_v("fi_send", "buf=%p len=%zu dest_fi_addr=%" PRIu64 " -> remote_port=%u ctx=%p", buf, len, static_cast<uint64_t>(dest_addr), static_cast<unsigned>(remote_port), context);

    uet_ctrl_view ctrl{};
    bool has_ctrl = uet_decode_ctrl_msg(reinterpret_cast<const uint8_t*>(buf), len, ctrl);
    if (has_ctrl) {
        if (ctrl.hdr.msg_type == UET_CTRL_HELLO) {
            uet_dbg("ctrl", "send HELLO peer=%" PRIu64 " session=0x%" PRIx64, static_cast<uint64_t>(dest_addr),
                    static_cast<uint64_t>(ctrl.hdr.session_id));
        } else if (ctrl.hdr.msg_type == UET_CTRL_MRDESC && ctrl.payload_len >= sizeof(uet_mrdesc)) {
            uet_mrdesc desc{};
            std::memcpy(&desc, ctrl.payload, sizeof(desc));
            if (desc.magic == kUetMrdescMagic && desc.version == kUetMrdescVersion && desc.len > 0) {
                soft.ses.register_mr(desc.rkey, desc.remote_addr, static_cast<size_t>(desc.len));
                uet_dbg("mrdesc", "register local MR rkey=0x%x addr=0x%" PRIx64 " len=%" PRIu64 " session=0x%" PRIx64,
                        desc.rkey, static_cast<uint64_t>(desc.remote_addr), static_cast<uint64_t>(desc.len),
                static_cast<uint64_t>(ctrl.hdr.session_id));
            }
        }
    }

    // Treat fep id as remote UDP port for routing.
    // This lets us reuse the existing UET packet fields (src_fep/dst_fep) without introducing a new
    // address abstraction in phase 1.
    // 中文说明：
    // - md.payload.start_addr 指向用户 buffer（本地地址），SES 会在 process_send_packet 里 copy 到 pkt.payload
    // - md.t_pid_on_fep 用远端 UDP port，便于现有 PDS/UDP 发送路径按 dst_fep 路由
    OperationMetadata md;
    md.op_type = SEND;
    md.s_pid_on_fep = soft.udp_rx ? soft.udp_rx->getLocalPort() : 0;
    md.t_pid_on_fep = remote_port;
    md.job_id = has_ctrl && ctrl.hdr.job_id ? ctrl.hdr.job_id : uep->job_id;
    md.messages_id = uep->msg_seq.fetch_add(1);
    md.delivery_mode = RUD;
    md.memory.rkey = 1;
    md.payload.start_addr = reinterpret_cast<uint64_t>(buf);
    md.payload.length = len;
    md.has_imm_data = false;
    md.use_optimized_header = false;
    md.relative = false;
    uet_dbg("tx_flow",
            "fi_send queue msg_id=%u len=%zu local_fep=%u remote_port=%u ctx=%p",
            static_cast<unsigned>(md.messages_id),
            len,
            static_cast<unsigned>(md.s_pid_on_fep),
            static_cast<unsigned>(md.t_pid_on_fep),
            context);

    // Cache mapping for internal ACK/response routing.
    {
        std::lock_guard<std::mutex> lock(soft.peer_mu);
        soft.peer_by_fep[md.t_pid_on_fep] = *dest;
        soft.fiaddr_by_fep[md.t_pid_on_fep] = dest_addr;
    }

    // 把上层 send 变成 UET 的 OperationMetadata，交给 ses_thread 单线程处理
    {
        std::lock_guard<std::mutex> lock(soft.op_mu);
        soft.op_q.push(uet_pending_send{
            .md = md,
            .context = context,
            .len = len,
            .track_completion = true,
            .owned_buffer = nullptr,
        });
    }
    soft.op_cv.notify_one();
    return 0;
}

static int uet_rdma_ensure_connected(uet_ep* uep, fi_addr_t peer, uint64_t peer_session)
{
    if (!uep) return -FI_EINVAL;
    if (uep->backend != uet_backend_kind::rdma) return 0;
#if !UET_HAVE_IBVERBS
    (void)peer;
    (void)peer_session;
    return -FI_EOPNOTSUPP;
#else
    if (uep->rdma.connect_mode == uet_rdma_connect_mode::iwarp_cm) {
#if !UET_HAVE_RDMACM
        return -FI_EOPNOTSUPP;
#else
        auto dest = uet_av_resolve(uep->bound_av, peer);
        if (!dest) return -FI_EINVAL;
        bool need_connect = false;
        {
            std::lock_guard<std::mutex> lock(uep->rdma.mu);
            if (uep->rdma.cm.ready) {
                uet_dbg("cm", "ensure_connected fast-path ready: peer=%" PRIu64 " session=0x%" PRIx64,
                        static_cast<uint64_t>(peer),
                        static_cast<uint64_t>(peer_session));
                return 0;
            }
            if (uep->rdma.conn.peer != FI_ADDR_UNSPEC && uep->rdma.conn.peer != peer) {
                return -FI_EBUSY;
            }
            if (uep->rdma.conn.peer == FI_ADDR_UNSPEC || uep->rdma.conn.peer_session != peer_session) {
                uet_rdma_reset_conn_locked(uep->rdma.conn, peer, peer_session);
                uet_rdma_reset_cm_locked(uep->rdma.cm);
            } else {
                uep->rdma.conn.peer = peer;
                uep->rdma.conn.peer_session = peer_session;
            }
            if (uep->rdma.cm.failed) {
                uet_dbg("cm", "ensure_connected clear previous failure: err=%d reason=%s",
                        uep->rdma.cm.last_error_code,
                        uep->rdma.cm.last_error_reason.c_str());
                uet_rdma_reset_cm_locked(uep->rdma.cm);
            }
            need_connect = !uep->rdma.cm.request_sent;
            if (need_connect) {
                uep->rdma.cm.request_sent = true;
            }
        }

        if (need_connect) {
            if (const int rc = uet_rdma_cm_start_listener(uep); rc != 0) {
                uet_rdma_cm_fail(uep, rc, "CM listener not ready");
                return rc;
            }
            if (!uep->rdma.cm.event_channel) {
                uet_rdma_cm_fail(uep, -FI_EIO, "CM event channel missing");
                return -FI_EIO;
            }
            rdma_cm_id* id = nullptr;
            if (rdma_create_id(uep->rdma.cm.event_channel, &id, uep, RDMA_PS_TCP) != 0) {
                uet_rdma_cm_fail(uep, -FI_EIO, "CM create active id failed");
                return -FI_EIO;
            }
            {
                std::lock_guard<std::mutex> lock(uep->rdma.mu);
                uep->rdma.cm.active_id = id;
            }
            sockaddr_in src_addr = uet_rdma_cm_addr_from_endpoint(uep->local_addr);
            src_addr.sin_port = htons(0);
            sockaddr_in cm_dest = uet_rdma_cm_addr_from_endpoint(*dest);
            uet_dbg("cm", "CM resolve addr start: src=%s dst=%s",
                    uet_sockaddr_in_to_string(src_addr).c_str(),
                    uet_sockaddr_in_to_string(cm_dest).c_str());
            if (rdma_resolve_addr(id,
                                  reinterpret_cast<sockaddr*>(&src_addr),
                                  reinterpret_cast<sockaddr*>(&cm_dest),
                                  2000) != 0) {
                uet_rdma_cm_fail(uep, -FI_EIO, "CM resolve addr failed");
                return -FI_EIO;
            }
        } else {
            uet_dbg("cm", "ensure_connected wait existing request: peer=%" PRIu64 " session=0x%" PRIx64,
                    static_cast<uint64_t>(peer),
                    static_cast<uint64_t>(peer_session));
        }

        std::unique_lock<std::mutex> lock(uep->rdma.mu);
        if (!uep->rdma.cv.wait_for(lock, std::chrono::seconds(5), [&]() {
                return uep->rdma.cm.ready || uep->rdma.cm.failed;
            })) {
            uet_dbg("cm", "ensure_connected timeout: peer=%" PRIu64 " session=0x%" PRIx64,
                    static_cast<uint64_t>(peer),
                    static_cast<uint64_t>(peer_session));
            return -FI_ETIMEDOUT;
        }
        if (uep->rdma.cm.failed) {
            uet_dbg("cm", "ensure_connected failed: peer=%" PRIu64 " session=0x%" PRIx64 " err=%d reason=%s",
                    static_cast<uint64_t>(peer),
                    static_cast<uint64_t>(peer_session),
                    uep->rdma.cm.last_error_code,
                    uep->rdma.cm.last_error_reason.c_str());
            return uep->rdma.cm.last_error_code ? uep->rdma.cm.last_error_code : -FI_EIO;
        }
        uet_dbg("cm", "ensure_connected ready: peer=%" PRIu64 " session=0x%" PRIx64,
                static_cast<uint64_t>(peer),
                static_cast<uint64_t>(peer_session));
        uet_rdma_log_qp_snapshot(uep, "ensure_connected_ready");
        return 0;
#endif
    }

    bool need_send_req = false;
    {
        std::lock_guard<std::mutex> lock(uep->rdma.mu);
        if (uep->rdma.conn.ready && uep->rdma.conn.peer == peer) {
            uet_dbg("rdma", "ensure_connected fast-path ready: peer=%" PRIu64 " session=0x%" PRIx64,
                    static_cast<uint64_t>(peer),
                    static_cast<uint64_t>(peer_session));
            return 0;
        }
        if (uep->rdma.conn.peer != FI_ADDR_UNSPEC && uep->rdma.conn.peer != peer) {
            return -FI_EBUSY;
        }
        if (uep->rdma.conn.peer == FI_ADDR_UNSPEC) {
            uet_rdma_reset_conn_locked(uep->rdma.conn, peer, peer_session);
        } else if (uep->rdma.conn.peer == peer && uep->rdma.conn.peer_session != peer_session) {
            uet_dbg("rdma", "ensure_connected reset stale session: peer=%" PRIu64 " old_session=0x%" PRIx64 " new_session=0x%" PRIx64,
                    static_cast<uint64_t>(peer),
                    static_cast<uint64_t>(uep->rdma.conn.peer_session),
                    static_cast<uint64_t>(peer_session));
            uet_rdma_reset_conn_locked(uep->rdma.conn, peer, peer_session);
        } else {
            uep->rdma.conn.peer = peer;
            uep->rdma.conn.peer_session = peer_session;
        }
        if (uep->rdma.conn.failed) {
            uet_dbg("rdma", "ensure_connected clear previous failure: peer=%" PRIu64 " session=0x%" PRIx64 " err=%d reason=%s",
                    static_cast<uint64_t>(peer),
                    static_cast<uint64_t>(peer_session),
                    uep->rdma.conn.last_error_code,
                    uep->rdma.conn.last_error_reason.c_str());
            uep->rdma.conn.failed = false;
            uep->rdma.conn.last_error_code = 0;
            uep->rdma.conn.last_error_reason.clear();
        }
        need_send_req = !uep->rdma.conn.request_sent;
        if (need_send_req) {
            uep->rdma.conn.request_sent = true;
        }
    }

    if (need_send_req) {
        uet_dbg("rdma", "ensure_connected send request: peer=%" PRIu64 " session=0x%" PRIx64,
                static_cast<uint64_t>(peer),
                static_cast<uint64_t>(peer_session));
        if (const int rc = uet_rdma_send_conn_msg(uep, peer, UET_CTRL_RDMA_CONN_REQ); rc != 0) {
            uet_rdma_fail_conn(uep, rc, "RDMA_CONN_REQ send failed");
            return -FI_EIO;
        }
    } else {
        uet_dbg("rdma", "ensure_connected wait existing request: peer=%" PRIu64 " session=0x%" PRIx64,
                static_cast<uint64_t>(peer),
                static_cast<uint64_t>(peer_session));
    }

    std::unique_lock<std::mutex> lock(uep->rdma.mu);
    if (!uep->rdma.cv.wait_for(lock, std::chrono::seconds(5), [&]() {
            return (uep->rdma.conn.ready && uep->rdma.conn.peer == peer) ||
                   (uep->rdma.conn.failed && uep->rdma.conn.peer == peer);
        })) {
        uet_dbg("rdma", "ensure_connected timeout: peer=%" PRIu64 " session=0x%" PRIx64 " request_sent=%d ready=%d failed=%d",
                static_cast<uint64_t>(peer),
                static_cast<uint64_t>(peer_session),
                static_cast<int>(uep->rdma.conn.request_sent),
                static_cast<int>(uep->rdma.conn.ready),
                static_cast<int>(uep->rdma.conn.failed));
        return -FI_ETIMEDOUT;
    }
    if (uep->rdma.conn.failed) {
        uet_dbg("rdma", "ensure_connected failed: peer=%" PRIu64 " session=0x%" PRIx64 " err=%d reason=%s",
                static_cast<uint64_t>(peer),
                static_cast<uint64_t>(peer_session),
                uep->rdma.conn.last_error_code,
                uep->rdma.conn.last_error_reason.c_str());
        return uep->rdma.conn.last_error_code ? uep->rdma.conn.last_error_code : -FI_EIO;
    }
    uet_dbg("rdma", "ensure_connected ready: peer=%" PRIu64 " session=0x%" PRIx64,
            static_cast<uint64_t>(peer),
            static_cast<uint64_t>(peer_session));
    return 0;
#endif
}

static ssize_t uet_ep_write(struct fid_ep* ep, const void* buf, size_t len, void*, fi_addr_t dest_addr, uint64_t addr, uint64_t key, void* context)
{
    auto* uep = uet_ep_from_fid(ep);
    if (!buf && len) return -FI_EINVAL;
    if (!uep->bound_av) return -FI_EINVAL;
    if (len > 0) {
        auto* local_mr = uet_domain_lookup_local_mr(uep->domain, buf, len);
        if (!local_mr || !uet_access_allows_local_read(local_mr->access)) {
            uet_dbg("rma", "write: local buffer not registered buf=%p len=%zu", buf, len);
            return -FI_EINVAL;
        }
        if (uep->backend == uet_backend_kind::rdma && local_mr->backend != uet_backend_kind::rdma) {
            return -FI_EINVAL;
        }
    }

    auto& soft = uep->soft;

    auto dest = uet_av_resolve(uep->bound_av, dest_addr);
    if (!dest) return -FI_EINVAL;

    uint64_t peer_session = 0;
    if (!uet_get_peer_mrdesc_session(uep, dest_addr, peer_session)) {
        uet_dbg("rma", "write: session not established peer=%" PRIu64, static_cast<uint64_t>(dest_addr));
        return -FI_EINVAL;
    }

    uet_mrdesc desc{};
    const auto lookup = uet_lookup_mrdesc(uep, dest_addr, peer_session, key, desc);
    if (lookup == uet_mr_lookup_rc::not_found) {
        uet_dbg("rma", "write: mrdesc not found peer=%" PRIu64 " session=0x%" PRIx64 " rkey=0x%" PRIx64,
                static_cast<uint64_t>(dest_addr), static_cast<uint64_t>(peer_session), static_cast<uint64_t>(key));
        return -FI_EINVAL;
    }
    if (lookup == uet_mr_lookup_rc::key_mismatch) {
        uet_dbg("rma", "write: key mismatch peer=%" PRIu64 " session=0x%" PRIx64 " rkey=0x%" PRIx64,
                static_cast<uint64_t>(dest_addr), static_cast<uint64_t>(peer_session), static_cast<uint64_t>(key));
        return -FI_EINVAL;
    }

    if (addr < desc.remote_addr || (addr + len) > (desc.remote_addr + desc.len)) {
        uet_dbg("rma", "write: addr out of range addr=0x%" PRIx64 " len=%zu base=0x%" PRIx64 " mr_len=%" PRIu64,
                static_cast<uint64_t>(addr), len, static_cast<uint64_t>(desc.remote_addr), static_cast<uint64_t>(desc.len));
        return -FI_EINVAL;
    }

    if (uep->backend == uet_backend_kind::rdma) {
#if !UET_HAVE_IBVERBS
        return uet_ep_backend_unavailable(uep, "fi_write");
#else
        if (!uep->rdma.enabled.load()) {
            const int rc = uet_ep_start_rdma_progress(uep);
            if (rc) return rc;
        }
        auto* local_mr = uet_domain_lookup_local_mr(uep->domain, buf, len);
        if (!local_mr || !local_mr->hw_mr_handle) {
            return -FI_EINVAL;
        }
        const int rc = uet_rdma_ensure_connected(uep, dest_addr, peer_session);
        if (rc) return rc;

        ibv_sge sge{};
        sge.addr = reinterpret_cast<uint64_t>(buf);
        sge.length = static_cast<uint32_t>(len);
        sge.lkey = local_mr->lkey;

        const uint64_t wr_id = uep->rdma.next_wr_id.fetch_add(1, std::memory_order_relaxed);
        ibv_send_wr wr{};
        ibv_send_wr* bad = nullptr;
        wr.wr_id = wr_id;
        wr.sg_list = &sge;
        wr.num_sge = 1;
        wr.opcode = IBV_WR_RDMA_WRITE;
        wr.send_flags = IBV_SEND_SIGNALED;
        wr.wr.rdma.remote_addr = addr;
        wr.wr.rdma.rkey = static_cast<uint32_t>(key);
        {
            std::lock_guard<std::mutex> lock(uep->rdma.mu);
            ++uep->rdma.stats.posted;
            uep->rdma.pending_ops[wr_id] = uet_rdma_state::pending_op{
                .kind = uet_rdma_state::op_kind::write,
                .context = context,
                .len = len,
                .peer = dest_addr,
                .submit_ns = uet_now_ns(),
                .local_cqe_ns = 0,
                .local_cqe_seen = false,
            };
        }
        if (ibv_post_send(uep->rdma.data_qp, &wr, &bad) != 0) {
            std::lock_guard<std::mutex> lock(uep->rdma.mu);
            uep->rdma.pending_ops.erase(wr_id);
            return -FI_EIO;
        }
        return 0;
#endif
    }

    const uint16_t remote_port = ntohs(dest->sin_port);
    const uint64_t buffer_offset = addr - desc.remote_addr;
    const uint32_t target_fep = desc.pid_on_fep ? desc.pid_on_fep : remote_port;

    // Keep routing map consistent for the target pid_on_fep (logical id) and UDP port.
    {
        std::lock_guard<std::mutex> lock(soft.peer_mu);
        soft.peer_by_fep[target_fep] = *dest;
        soft.fiaddr_by_fep[target_fep] = dest_addr;
    }

    // Ensure local SES MR table has this entry (base=0, len=desc.len).
    soft.ses.register_mr(desc.rkey, 0, static_cast<size_t>(desc.len));

    OperationMetadata md;
    md.op_type = WRITE;
    md.s_pid_on_fep = soft.udp_rx ? soft.udp_rx->getLocalPort() : 0;
    md.t_pid_on_fep = target_fep;
    md.job_id = desc.job_id;
    md.messages_id = uep->msg_seq.fetch_add(1);
    md.delivery_mode = RUD;
    md.memory.rkey = static_cast<uint64_t>(key);
    md.payload.start_addr = buffer_offset;
    md.payload.local_addr = reinterpret_cast<uint64_t>(buf);
    md.payload.length = len;
    md.has_imm_data = false;
    md.use_optimized_header = false;
    md.relative = false;
    md.res_index = static_cast<uint16_t>(desc.resource_index);

    uet_dbg("rma", "write: peer=%" PRIu64 " rkey=0x%" PRIx64 " addr=0x%" PRIx64 " off=%" PRIu64 " len=%zu -> dst_fep=%u",
            static_cast<uint64_t>(dest_addr), static_cast<uint64_t>(key), static_cast<uint64_t>(addr),
            static_cast<uint64_t>(buffer_offset), len, static_cast<unsigned>(target_fep));

    {
        std::lock_guard<std::mutex> lock(soft.op_mu);
        soft.op_q.push(uet_pending_send{
            .md = md,
            .context = context,
            .len = len,
            .track_completion = true,
            .owned_buffer = nullptr,
        });
    }
    soft.op_cv.notify_one();
    return 0;
}

static ssize_t uet_ep_writev(struct fid_ep* ep, const struct iovec* iov, void**, size_t count, fi_addr_t dest_addr, uint64_t addr, uint64_t key, void* context)
{
    if (!iov || count == 0) return -FI_EINVAL;
    if (count != 1) return -FI_ENOSYS;
    return uet_ep_write(ep, iov[0].iov_base, iov[0].iov_len, nullptr, dest_addr, addr, key, context);
}

static ssize_t uet_ep_writemsg(struct fid_ep* ep, const struct fi_msg_rma* msg, uint64_t)
{
    if (!msg || !msg->msg_iov || !msg->rma_iov) return -FI_EINVAL;
    if (msg->iov_count != 1 || msg->rma_iov_count != 1) return -FI_ENOSYS;
    const auto& loc = msg->msg_iov[0];
    const auto& rma = msg->rma_iov[0];
    const size_t len = loc.iov_len;
    if (rma.len < len) {
        return -FI_EINVAL;
    }
    return uet_ep_write(ep, loc.iov_base, len, msg->desc ? msg->desc[0] : nullptr, msg->addr, rma.addr, rma.key, msg->context);
}

static ssize_t uet_ep_read(struct fid_ep* ep, void* buf, size_t len, void*, fi_addr_t src_addr, uint64_t addr, uint64_t key, void* context)
{
    auto* uep = uet_ep_from_fid(ep);
    if (!buf && len) return -FI_EINVAL;
    if (!uep->bound_av) return -FI_EINVAL;
    if (len > 0) {
        auto* local_mr = uet_domain_lookup_local_mr(uep->domain, buf, len);
        if (!local_mr || !uet_access_allows_local_write(local_mr->access)) {
            uet_dbg("rma", "read: local buffer not registered buf=%p len=%zu", buf, len);
            return -FI_EINVAL;
        }
        if (uep->backend == uet_backend_kind::rdma && local_mr->backend != uet_backend_kind::rdma) {
            return -FI_EINVAL;
        }
    }

    auto& soft = uep->soft;

    auto dest = uet_av_resolve(uep->bound_av, src_addr);
    if (!dest) return -FI_EINVAL;

    uint64_t peer_session = 0;
    if (!uet_get_peer_mrdesc_session(uep, src_addr, peer_session)) {
        uet_dbg("rma", "read: session not established peer=%" PRIu64, static_cast<uint64_t>(src_addr));
        return -FI_EINVAL;
    }

    uet_mrdesc desc{};
    const auto lookup = uet_lookup_mrdesc(uep, src_addr, peer_session, key, desc);
    if (lookup == uet_mr_lookup_rc::not_found) {
        uet_dbg("rma", "read: mrdesc not found peer=%" PRIu64 " session=0x%" PRIx64 " rkey=0x%" PRIx64,
                static_cast<uint64_t>(src_addr), static_cast<uint64_t>(peer_session), static_cast<uint64_t>(key));
        return -FI_EINVAL;
    }
    if (lookup == uet_mr_lookup_rc::key_mismatch) {
        uet_dbg("rma", "read: key mismatch peer=%" PRIu64 " session=0x%" PRIx64 " rkey=0x%" PRIx64,
                static_cast<uint64_t>(src_addr), static_cast<uint64_t>(peer_session), static_cast<uint64_t>(key));
        return -FI_EINVAL;
    }

    if (addr < desc.remote_addr || (addr + len) > (desc.remote_addr + desc.len)) {
        uet_dbg("rma", "read: addr out of range addr=0x%" PRIx64 " len=%zu base=0x%" PRIx64 " mr_len=%" PRIu64,
                static_cast<uint64_t>(addr), len, static_cast<uint64_t>(desc.remote_addr), static_cast<uint64_t>(desc.len));
        return -FI_EINVAL;
    }

    if (uep->backend == uet_backend_kind::rdma) {
#if !UET_HAVE_IBVERBS
        return uet_ep_backend_unavailable(uep, "fi_read");
#else
        if (!uep->rdma.enabled.load()) {
            const int rc = uet_ep_start_rdma_progress(uep);
            if (rc) return rc;
        }
        auto* local_mr = uet_domain_lookup_local_mr(uep->domain, buf, len);
        if (!local_mr || !local_mr->hw_mr_handle) {
            return -FI_EINVAL;
        }
        const int rc = uet_rdma_ensure_connected(uep, src_addr, peer_session);
        if (rc) return rc;
        uet_dbg("rma",
                "fi_read prep: peer=%" PRIu64 " session=0x%" PRIx64 " remote_addr=0x%" PRIx64 " rkey=0x%" PRIx64 " len=%zu local_lkey=0x%x desc_access=0x%x",
                static_cast<uint64_t>(src_addr),
                static_cast<uint64_t>(peer_session),
                static_cast<uint64_t>(addr),
                static_cast<uint64_t>(key),
                len,
                static_cast<unsigned>(local_mr->lkey),
                desc.access);
        const int read_ready_rc = uet_rdma_validate_read_ready(uep, src_addr, peer_session);
        if (read_ready_rc != 0) {
            uet_dbg("rma", "fi_read readiness failed: peer=%" PRIu64 " session=0x%" PRIx64 " rc=%d",
                    static_cast<uint64_t>(src_addr),
                    static_cast<uint64_t>(peer_session),
                    read_ready_rc);
            return read_ready_rc;
        }

        ibv_sge sge{};
        sge.addr = reinterpret_cast<uint64_t>(buf);
        sge.length = static_cast<uint32_t>(len);
        sge.lkey = local_mr->lkey;

        const uint64_t wr_id = uep->rdma.next_wr_id.fetch_add(1, std::memory_order_relaxed);
        ibv_send_wr wr{};
        ibv_send_wr* bad = nullptr;
        wr.wr_id = wr_id;
        wr.sg_list = &sge;
        wr.num_sge = 1;
        wr.opcode = IBV_WR_RDMA_READ;
        wr.send_flags = IBV_SEND_SIGNALED;
        wr.wr.rdma.remote_addr = addr;
        wr.wr.rdma.rkey = static_cast<uint32_t>(key);
        {
            std::lock_guard<std::mutex> lock(uep->rdma.mu);
            uep->rdma.pending_ops[wr_id] = uet_rdma_state::pending_op{
                .kind = uet_rdma_state::op_kind::read,
                .context = context,
                .len = len,
                .peer = src_addr,
                .local_cqe_seen = false,
            };
        }
        uet_dbg("rma", "fi_read post_send: wr_id=%" PRIu64 " peer=%" PRIu64 " session=0x%" PRIx64 " remote_addr=0x%" PRIx64 " rkey=0x%" PRIx64 " len=%zu",
                wr_id,
                static_cast<uint64_t>(src_addr),
                static_cast<uint64_t>(peer_session),
                static_cast<uint64_t>(addr),
                static_cast<uint64_t>(key),
                len);
        if (ibv_post_send(uep->rdma.data_qp, &wr, &bad) != 0) {
            std::lock_guard<std::mutex> lock(uep->rdma.mu);
            uep->rdma.pending_ops.erase(wr_id);
            uet_dbg("rma", "fi_read ibv_post_send failed: peer=%" PRIu64 " session=0x%" PRIx64 " errno=%d (%s)",
                    static_cast<uint64_t>(src_addr),
                    static_cast<uint64_t>(peer_session),
                    errno,
                    std::strerror(errno));
            return -FI_EIO;
        }
        return 0;
#endif
    }

    const uint64_t buffer_offset = addr - desc.remote_addr;
    const uint32_t target_fep = desc.pid_on_fep;
    if (target_fep == 0) {
        return -FI_EINVAL;
    }

    // Ensure routing map has target pid_on_fep -> peer sockaddr.
    {
        std::lock_guard<std::mutex> lock(soft.peer_mu);
        soft.peer_by_fep[target_fep] = *dest;
        soft.fiaddr_by_fep[target_fep] = src_addr;
    }

    // Register MR table for buffer_offset calculation (base=0, len=desc.len).
    soft.ses.register_mr(desc.rkey, 0, static_cast<size_t>(desc.len));

    const uint16_t msg_id = uep->msg_seq.fetch_add(1);
    {
        std::lock_guard<std::mutex> lock(soft.read_mu);
        uet_soft_state::uet_read_state st;
        st.buf = buf;
        st.len = len;
        st.total_len = static_cast<uint32_t>(len);
        st.chunk_size = static_cast<uint32_t>(MAX_MTU - sizeof(SES_Semantic_Response_with_Data_Header));
        const size_t chunks = (st.chunk_size == 0 || st.total_len == 0)
                                  ? 0
                                  : (static_cast<size_t>(st.total_len) + st.chunk_size - 1) / st.chunk_size;
        st.chunk_received.assign(chunks, 0);
        st.chunks_done = 0;
        st.context = context;
        soft.pending_reads[msg_id] = std::move(st);
    }

    OperationMetadata md;
    md.op_type = READ;
    md.s_pid_on_fep = soft.udp_rx ? soft.udp_rx->getLocalPort() : 0;
    md.t_pid_on_fep = target_fep;
    md.job_id = desc.job_id;
    md.messages_id = msg_id;
    md.delivery_mode = RUD;
    md.memory.rkey = static_cast<uint64_t>(key);
    md.payload.start_addr = buffer_offset;
    md.payload.local_addr = reinterpret_cast<uint64_t>(buf);
    md.payload.length = len;
    md.has_imm_data = false;
    md.use_optimized_header = false;
    md.relative = false;
    md.res_index = static_cast<uint16_t>(desc.resource_index);

    uet_dbg("rma", "read: peer=%" PRIu64 " rkey=0x%" PRIx64 " addr=0x%" PRIx64 " off=%" PRIu64 " len=%zu -> dst_fep=%u",
            static_cast<uint64_t>(src_addr), static_cast<uint64_t>(key), static_cast<uint64_t>(addr),
            static_cast<uint64_t>(buffer_offset), len, static_cast<unsigned>(target_fep));

    {
        std::lock_guard<std::mutex> lock(soft.op_mu);
        soft.op_q.push(uet_pending_send{
            .md = md,
            .context = context,
            .len = len,
            .track_completion = true,
            .owned_buffer = nullptr,
        });
    }
    soft.op_cv.notify_one();
    return 0;
}

static ssize_t uet_ep_readv(struct fid_ep* ep, const struct iovec* iov, void**, size_t count, fi_addr_t src_addr, uint64_t addr, uint64_t key, void* context)
{
    if (!iov || count == 0) return -FI_EINVAL;
    if (count != 1) return -FI_ENOSYS;
    return uet_ep_read(ep, iov[0].iov_base, iov[0].iov_len, nullptr, src_addr, addr, key, context);
}

static ssize_t uet_ep_readmsg(struct fid_ep* ep, const struct fi_msg_rma* msg, uint64_t)
{
    if (!msg || !msg->msg_iov || !msg->rma_iov) return -FI_EINVAL;
    if (msg->iov_count != 1 || msg->rma_iov_count != 1) return -FI_ENOSYS;
    const auto& loc = msg->msg_iov[0];
    const auto& rma = msg->rma_iov[0];
    const size_t len = loc.iov_len;
    if (rma.len < len) {
        return -FI_EINVAL;
    }
    return uet_ep_read(ep, loc.iov_base, len, msg->desc ? msg->desc[0] : nullptr, msg->addr, rma.addr, rma.key, msg->context);
}

static ssize_t uet_ep_recvv(struct fid_ep* ep, const struct iovec* iov, void**, size_t count, fi_addr_t src_addr, void* context)
{
    if (!iov || count == 0) return -FI_EINVAL;
    if (count != 1) return -FI_ENOSYS;
    return uet_ep_recv(ep, iov[0].iov_base, iov[0].iov_len, nullptr, src_addr, context);
}

static ssize_t uet_ep_sendv(struct fid_ep* ep, const struct iovec* iov, void**, size_t count, fi_addr_t dest_addr, void* context)
{
    if (!iov || count == 0) return -FI_EINVAL;
    if (count != 1) return -FI_ENOSYS;
    return uet_ep_send(ep, iov[0].iov_base, iov[0].iov_len, nullptr, dest_addr, context);
}

static ssize_t uet_ep_recvmsg(struct fid_ep* ep, const struct fi_msg* msg, uint64_t)
{
    if (!msg || msg->iov_count == 0) return -FI_EINVAL;
    if (msg->iov_count != 1) return -FI_ENOSYS;
    return uet_ep_recv(ep, msg->msg_iov[0].iov_base, msg->msg_iov[0].iov_len, msg->desc ? msg->desc[0] : nullptr, msg->addr, msg->context);
}

static ssize_t uet_ep_sendmsg(struct fid_ep* ep, const struct fi_msg* msg, uint64_t)
{
    if (!msg || msg->iov_count == 0) return -FI_EINVAL;
    if (msg->iov_count != 1) return -FI_ENOSYS;
    return uet_ep_send(ep, msg->msg_iov[0].iov_base, msg->msg_iov[0].iov_len, msg->desc ? msg->desc[0] : nullptr, msg->addr, msg->context);
}

static ssize_t uet_ep_inject(struct fid_ep* ep, const void* buf, size_t len, fi_addr_t dest_addr)
{
    return uet_ep_send(ep, buf, len, nullptr, dest_addr, nullptr);
}

static ssize_t uet_ep_senddata(struct fid_ep* ep, const void* buf, size_t len, void*, uint64_t, fi_addr_t dest_addr, void* context)
{
    return uet_ep_send(ep, buf, len, nullptr, dest_addr, context);
}

static ssize_t uet_ep_injectdata(struct fid_ep* ep, const void* buf, size_t len, uint64_t, fi_addr_t dest_addr)
{
    return uet_ep_inject(ep, buf, len, dest_addr);
}

static ssize_t uet_ep_cancel(fid_t, void*)
{
    return -FI_ENOSYS;
}

static int uet_ep_getopt(fid_t, int, int, void*, size_t*)
{
    return -FI_ENOSYS;
}

static int uet_ep_setopt(fid_t, int, int, const void*, size_t)
{
    return -FI_ENOSYS;
}

static int uet_ep_tx_ctx(struct fid_ep*, int, struct fi_tx_attr*, struct fid_ep**, void*)
{
    return -FI_ENOSYS;
}

static int uet_ep_rx_ctx(struct fid_ep*, int, struct fi_rx_attr*, struct fid_ep**, void*)
{
    return -FI_ENOSYS;
}

static ssize_t uet_ep_rx_size_left(struct fid_ep*)
{
    return -FI_ENOSYS;
}

static ssize_t uet_ep_tx_size_left(struct fid_ep*)
{
    return -FI_ENOSYS;
}

static int uet_cm_setname(fid_t fid, void* addr, size_t addrlen)
{
    // fi_setname：上层设置“本端名字”（sockaddr_in）。
    // DGRAM 下通常用于指定 bind 的端口（或显式指定本机 IP/port）。
    auto* ep = reinterpret_cast<fid_ep*>(fid);
    auto* uep = uet_ep_from_fid(ep);
    if (!addr || addrlen < sizeof(sockaddr_in)) return -FI_EINVAL;
    if (uep->backend == uet_backend_kind::soft && uep->soft.enabled.load()) return -FI_EBUSY;
    if (uep->backend == uet_backend_kind::rdma && uep->rdma.enabled.load()) return -FI_EBUSY;
    std::memcpy(&uep->local_addr, addr, sizeof(sockaddr_in));
    uep->local_addr_set = true;
    return 0;
}

static int uet_cm_getname(fid_t fid, void* addr, size_t* addrlen)
{
    // fi_getname：返回“本端名字”（sockaddr_in）。
    // fi_pingpong 会把这个 sockaddr 通过控制通道发给对端，对端用 fi_av_insert 插入后才能 fi_send。
    auto* ep = reinterpret_cast<fid_ep*>(fid);
    auto* uep = uet_ep_from_fid(ep);
    if (!addrlen) return -FI_EINVAL;

    if (!uep->local_addr_set) {
        uep->local_addr.sin_family = AF_INET;
        uep->local_addr.sin_addr.s_addr = INADDR_ANY;
        uep->local_addr.sin_port = htons(0);
        uep->local_addr_set = true;
    }

    if (*addrlen < sizeof(sockaddr_in)) {
        *addrlen = sizeof(sockaddr_in);
        return -FI_ETOOSMALL;
    }
    if (!addr) {
        *addrlen = sizeof(sockaddr_in);
        return -FI_ETOOSMALL;
    }

    // fi_pingpong exchanges endpoint names (sockaddr_in) verbatim.
    // Ensure we have a real UDP port by initializing sockets on first getname().
    // 中文说明：如果我们还没 bind socket，就无法知道真实 port（0 表示内核随机分配）。
    // 所以 getname 第一次调用时就触发 soft backend 的线程启动，以完成 bind，并更新 local_addr.sin_port。
    if (!uep->soft.enabled.load()) {
        if (uep->backend == uet_backend_kind::soft) {
            uet_ep_start_soft_threads(uep);
        } else if (uep->backend == uet_backend_kind::rdma) {
            const int rc = uet_ep_start_rdma_progress(uep);
            if (rc) return rc;
        }
    }

    std::memcpy(addr, &uep->local_addr, sizeof(sockaddr_in));
    *addrlen = sizeof(sockaddr_in);
    return 0;
}

static int uet_cm_getpeer(struct fid_ep*, void*, size_t*)
{
    return -FI_ENOSYS;
}

static int uet_cm_connect(struct fid_ep*, const void*, const void*, size_t)
{
    return -FI_ENOSYS;
}

static int uet_cm_listen(struct fid_pep*)
{
    return -FI_ENOSYS;
}

static int uet_cm_accept(struct fid_ep*, const void*, size_t)
{
    return -FI_ENOSYS;
}

static int uet_cm_reject(struct fid_pep*, fid_t, const void*, size_t)
{
    return -FI_ENOSYS;
}

static int uet_cm_shutdown(struct fid_ep*, uint64_t)
{
    return 0;
}

static int uet_cm_join(struct fid_ep*, const void*, uint64_t, struct fid_mc**, void*)
{
    return -FI_ENOSYS;
}

static int uet_fid_bind(struct fid* fid, struct fid* bfid, uint64_t flags)
{
    // fi_bind：把资源绑定到对象上。
    // 这里我们只处理 EP 绑定 AV/CQ：
    // - AV：提供 fi_addr_t -> sockaddr_in 的解析能力（fi_send 需要）
    // - CQ：投递 send/recv 完成（fi_pingpong 会分别 bind TX/RX CQ）
    if (!fid || !bfid) return -FI_EINVAL;

    if (fid->fclass == FI_CLASS_EP) {
        auto* ep = reinterpret_cast<fid_ep*>(fid);
        auto* uep = uet_ep_from_fid(ep);

        if (bfid->fclass == FI_CLASS_AV) {
            uep->bound_av = uet_av_from_fid(reinterpret_cast<fid_av*>(bfid));
            return 0;
        }

        if (bfid->fclass == FI_CLASS_CQ) {
            auto* cq = uet_cq_from_fid(reinterpret_cast<fid_cq*>(bfid));
            if (flags & FI_TRANSMIT) uep->bound_tx_cq = cq;
            if (flags & FI_RECV) uep->bound_rx_cq = cq;
            return 0;
        }

        return -FI_EINVAL;
    }

    return -FI_EINVAL;
}

static int uet_fid_control(struct fid* fid, int command, void* arg)
{
    // fi_control：处理控制命令（最关键是 FI_ENABLE）。
    // - FI_ENABLE 用于激活 endpoint（启动 UDP + 线程进度引擎）
    (void)arg;
    if (!fid) return -FI_EINVAL;

    if (fid->fclass == FI_CLASS_EP) {
        auto* uep = uet_ep_from_fid(reinterpret_cast<fid_ep*>(fid));
        if (command == FI_ENABLE) {
            if (uep->backend == uet_backend_kind::soft) {
                uet_ep_start_soft_threads(uep);
                return uep->soft.enabled.load() ? 0 : -FI_EIO;
            }
            return uet_ep_start_rdma_progress(uep);
        }
        return -FI_ENOSYS;
    }

    return -FI_ENOSYS;
}

static int uet_fid_ops_open(struct fid*, const char*, uint64_t, void**, void*)
{
    return -FI_ENOSYS;
}

static int uet_fid_tostr(const struct fid*, char*, size_t)
{
    return -FI_ENOSYS;
}

static int uet_fid_ops_set(struct fid*, const char*, uint64_t, void*, void*)
{
    return -FI_ENOSYS;
}

static int uet_fid_close(struct fid* fid)
{
    // 释放对象：
    // - EP：需要停止线程（rx/tx/ses）并回收 UDP 资源
    // - CQ/EQ：标记 closed 并唤醒等待者（sread）后 delete
    if (!fid) return -FI_EINVAL;

    uet_dbg_v("close", "fid_close: fclass=%d", fid->fclass);

    switch (fid->fclass) {
        case FI_CLASS_FABRIC: {
            auto* f = uet_fabric_from_fid(reinterpret_cast<fid_fabric*>(fid));
            delete f;
            return 0;
        }
        case FI_CLASS_DOMAIN: {
            auto* d = uet_domain_from_fid(reinterpret_cast<fid_domain*>(fid));
            uet_rdma_release_device(d->rdma_device);
            delete d;
            return 0;
        }
        case FI_CLASS_MR: {
            auto* m = uet_mr_from_fid(reinterpret_cast<fid_mr*>(fid));
            uet_domain_remove_local_mr(m->domain, m);
#if UET_HAVE_IBVERBS
            if (m->hw_mr_handle) {
                ibv_dereg_mr(m->hw_mr_handle);
                m->hw_mr_handle = nullptr;
            }
#endif
            delete m;
            return 0;
        }
        case FI_CLASS_EQ: {
            auto* e = uet_eq_from_fid(reinterpret_cast<fid_eq*>(fid));
            {
                std::lock_guard<std::mutex> lock(e->mu);
                e->closed = true;
                e->cv.notify_all();
            }
            delete e;
            return 0;
        }
        case FI_CLASS_CQ: {
            auto* c = uet_cq_from_fid(reinterpret_cast<fid_cq*>(fid));
            {
                std::lock_guard<std::mutex> lock(c->mu);
                c->closed = true;
                c->cv.notify_all();
            }
            delete c;
            return 0;
        }
        case FI_CLASS_AV: {
            auto* a = uet_av_from_fid(reinterpret_cast<fid_av*>(fid));
            delete a;
            return 0;
        }
        case FI_CLASS_EP: {
            auto* e = uet_ep_from_fid(reinterpret_cast<fid_ep*>(fid));
            uet_dbg_v("close", "ep close: stopping provider threads backend=%s", uet_backend_name(e->backend));
            if (e->backend == uet_backend_kind::soft) {
                // Stop provider threads first (stops polling & closes sockets), then stop UET engine threads.
                uet_ep_stop_soft_threads(e);
                uet_dbg_v("close", "ep close: stopping UET PDSProcessManager");
                e->soft.ses.pds_process_manager.stop();
            } else {
                uet_ep_stop_rdma_progress(e);
                if (e->soft.enabled.load()) {
                    uet_ep_stop_soft_threads(e);
                }
                e->soft.ses.pds_process_manager.stop();
            }
            uet_rdma_log_write_stats(e);
            uet_dbg_v("close", "ep close: delete ep");
            delete e;
            return 0;
        }
        default:
            return -FI_EINVAL;
    }
}

static int uet_fabric_domain(struct fid_fabric* fabric, struct fi_info* info, struct fid_domain** dom, void* context)
{
    // fi_domain：创建 domain 并挂好 ops
    // - domain_ops.av_open：创建 AV
    // - domain_ops.cq_open：创建 CQ
    // - domain_ops.endpoint：创建 EP（FI_EP_DGRAM）
    //
    // 说明：这里大量使用 lambda 直接填充函数指针，是为了让单文件示例更紧凑。
    (void)fabric;
    (void)info;
    if (!dom) return -FI_EINVAL;

    auto* d = new uet_domain();
    uet_domain_init_backend_state(d);
    d->domain.fid.fclass = FI_CLASS_DOMAIN;
    d->domain.fid.context = context;
    d->domain.fid.ops = &d->domain_fid_ops;
    d->domain.ops = &d->domain_ops;
    d->domain.mr = &d->mr_ops;

    d->domain_fid_ops = fi_ops{
        .size = sizeof(fi_ops),
        .close = uet_fid_close,
        .bind = uet_fid_bind,
        .control = uet_fid_control,
        .ops_open = uet_fid_ops_open,
        .tostr = uet_fid_tostr,
        .ops_set = uet_fid_ops_set,
    };

    d->domain_ops = fi_ops_domain{
        .size = sizeof(fi_ops_domain),
        .av_open = nullptr, // set below
        .cq_open = nullptr, // set below
        .endpoint = nullptr,
        .scalable_ep = nullptr,
        .cntr_open = nullptr,
        .poll_open = nullptr,
        .stx_ctx = nullptr,
        .srx_ctx = nullptr,
        .query_atomic = nullptr,
        .query_collective = nullptr,
        .endpoint2 = nullptr,
    };

    d->mr_ops = fi_ops_mr{
        .size = sizeof(fi_ops_mr),
        .reg = [](struct fid* fid, const void* buf, size_t len, uint64_t access, uint64_t, uint64_t requested_key, uint64_t,
                  struct fid_mr** mr, void* ctx) -> int {
            auto* domain = uet_domain_from_fid(reinterpret_cast<fid_domain*>(fid));
            return uet_mr_reg_common(domain, buf, len, access, requested_key, mr, ctx);
        },
        .regv = [](struct fid* fid, const struct iovec* iov, size_t count, uint64_t access, uint64_t, uint64_t requested_key, uint64_t,
                   struct fid_mr** mr, void* ctx) -> int {
            if (!iov || count == 0) return -FI_EINVAL;
            if (count != 1) return -FI_ENOSYS;
            auto* domain = uet_domain_from_fid(reinterpret_cast<fid_domain*>(fid));
            return uet_mr_reg_common(domain, iov[0].iov_base, iov[0].iov_len, access, requested_key, mr, ctx);
        },
        .regattr = [](struct fid* fid, const struct fi_mr_attr* attr, uint64_t flags, struct fid_mr** mr) -> int {
            (void)flags;
            if (!attr || !mr) return -FI_EINVAL;
            if (!attr->mr_iov || attr->iov_count == 0) return -FI_EINVAL;
            if (attr->iov_count != 1) return -FI_ENOSYS;
            if (attr->iface != FI_HMEM_SYSTEM
#ifdef FI_HMEM_UNSPEC
                && attr->iface != FI_HMEM_UNSPEC
#endif
            ) {
                return -FI_EOPNOTSUPP;
            }
            auto* domain = uet_domain_from_fid(reinterpret_cast<fid_domain*>(fid));
            return uet_mr_reg_common(domain,
                                     attr->mr_iov[0].iov_base,
                                     attr->mr_iov[0].iov_len,
                                     attr->access,
                                     attr->requested_key,
                                     mr,
                                     attr->context);
        },
    };

    // av_open
    d->domain_ops.av_open = [](struct fid_domain*, struct fi_av_attr* attr, struct fid_av** av, void* ctx) -> int {
        // AV：地址簿
        // - fi_av_insert(sockaddr_in[]) -> fi_addr_t[]
        // - fi_send/fi_recv 会使用 fi_addr_t 做目的地址/来源地址
        if (!av) return -FI_EINVAL;
        auto* a = new uet_av();
        a->av.fid.fclass = FI_CLASS_AV;
        a->av.fid.context = ctx;
        a->av.fid.ops = &a->av_fid_ops;
        a->av.ops = &a->av_ops;

        a->av_fid_ops = fi_ops{
            .size = sizeof(fi_ops),
            .close = uet_fid_close,
            .bind = uet_fid_bind,
            .control = uet_fid_control,
            .ops_open = uet_fid_ops_open,
            .tostr = uet_fid_tostr,
            .ops_set = uet_fid_ops_set,
        };

        a->av_ops = fi_ops_av{
            .size = sizeof(fi_ops_av),
            .insert = uet_av_insert,
            .insertsvc = uet_av_insertsvc,
            .insertsym = uet_av_insertsym,
            .remove = uet_av_remove,
            .lookup = uet_av_lookup,
            .straddr = uet_av_straddr,
            .av_set = uet_av_set,
            .insert_auth_key = uet_av_insert_auth_key,
            .lookup_auth_key = uet_av_lookup_auth_key,
            .set_user_id = uet_av_set_user_id,
        };

        if (attr) {
            (void)attr;
        }
        *av = &a->av;
        return 0;
    };

    // cq_open
    d->domain_ops.cq_open = [](struct fid_domain*, struct fi_cq_attr* attr, struct fid_cq** cq, void* ctx) -> int {
        // CQ：完成队列
        // - 支持 FI_CQ_FORMAT_MSG / FI_CQ_FORMAT_CONTEXT
        if (!cq) return -FI_EINVAL;
        auto* c = new uet_cq();
        c->cq.fid.fclass = FI_CLASS_CQ;
        c->cq.fid.context = ctx;
        c->cq.fid.ops = &c->cq_fid_ops;
        c->cq.ops = &c->cq_ops;

        c->attr = attr ? *attr : fi_cq_attr{};
        if (c->attr.size == 0) c->attr.size = kDefaultCqSize;
        if (c->attr.format == FI_CQ_FORMAT_UNSPEC) c->attr.format = FI_CQ_FORMAT_MSG;

        c->cq_fid_ops = fi_ops{
            .size = sizeof(fi_ops),
            .close = uet_fid_close,
            .bind = uet_fid_bind,
            .control = uet_fid_control,
            .ops_open = uet_fid_ops_open,
            .tostr = uet_fid_tostr,
            .ops_set = uet_fid_ops_set,
        };

        c->cq_ops = fi_ops_cq{
            .size = sizeof(fi_ops_cq),
            .read = uet_cq_read,
            .readfrom = uet_cq_readfrom,
            .readerr = uet_cq_readerr,
            .sread = uet_cq_sread,
            .sreadfrom = uet_cq_sreadfrom,
            .signal = uet_cq_signal,
            .strerror = uet_cq_strerror,
        };

        *cq = &c->cq;
        return 0;
    };

    // endpoint
    d->domain_ops.endpoint = [](struct fid_domain* dom_fid, struct fi_info* info, struct fid_ep** ep, void* ctx) -> int {
        // 创建 endpoint（仅支持 FI_EP_DGRAM）并挂上：
        // - ep->msg：FI_MSG 相关接口（send/recv）
        // - ep->cm：DGRAM 的 name 交换接口（setname/getname）
        // - ep->ops：少量通用 endpoint ops（cancel/getopt/... 这里大多未实现）
        if (!ep) return -FI_EINVAL;
        if (!info || !info->ep_attr) return -FI_EINVAL;
        if (info->ep_attr->type != FI_EP_DGRAM) return -FI_EINVAL;

        auto* dom = uet_domain_from_fid(dom_fid);
        auto* e = new uet_ep();
        e->domain = dom;
        uet_ep_init_backend_state(e);
        e->local_session_id = uet_new_session_id();
        e->ep.fid.fclass = FI_CLASS_EP;
        e->ep.fid.context = ctx;
        e->ep.fid.ops = &e->ep_fid_ops;
        e->ep.ops = &e->ep_ops;
        e->ep.cm = &e->ep_cm_ops;
        e->ep.msg = &e->ep_msg_ops;
        e->ep.rma = &e->ep_rma_ops;

        // Enable Logger inside provider when verbose debug is requested.
        if (const char* v = std::getenv("UET_PROVIDER_DEBUG_VERBOSE")) {
            if (v[0] != '\0' && std::strcmp(v, "0") != 0) {
                Logger::initialize(
                    "UET_provider_" + std::to_string(static_cast<uint64_t>(getpid())) + ".log",
                    LogLevel::INFO, true, true);
            }
        }

        e->ep_fid_ops = fi_ops{
            .size = sizeof(fi_ops),
            .close = uet_fid_close,
            .bind = uet_fid_bind,
            .control = uet_fid_control,
            .ops_open = uet_fid_ops_open,
            .tostr = uet_fid_tostr,
            .ops_set = uet_fid_ops_set,
        };

        e->ep_ops = fi_ops_ep{
            .size = sizeof(fi_ops_ep),
            .cancel = uet_ep_cancel,
            .getopt = uet_ep_getopt,
            .setopt = uet_ep_setopt,
            .tx_ctx = uet_ep_tx_ctx,
            .rx_ctx = uet_ep_rx_ctx,
            .rx_size_left = uet_ep_rx_size_left,
            .tx_size_left = uet_ep_tx_size_left,
        };

        e->ep_cm_ops = fi_ops_cm{
            .size = sizeof(fi_ops_cm),
            .setname = uet_cm_setname,
            .getname = uet_cm_getname,
            .getpeer = uet_cm_getpeer,
            .connect = uet_cm_connect,
            .listen = uet_cm_listen,
            .accept = uet_cm_accept,
            .reject = uet_cm_reject,
            .shutdown = uet_cm_shutdown,
            .join = uet_cm_join,
        };

        e->ep_msg_ops = fi_ops_msg{
            .size = sizeof(fi_ops_msg),
            .recv = uet_ep_recv,
            .recvv = uet_ep_recvv,
            .recvmsg = uet_ep_recvmsg,
            .send = uet_ep_send,
            .sendv = uet_ep_sendv,
            .sendmsg = uet_ep_sendmsg,
            .inject = uet_ep_inject,
            .senddata = uet_ep_senddata,
            .injectdata = uet_ep_injectdata,
        };

        e->ep_rma_ops = fi_ops_rma{
            .size = sizeof(fi_ops_rma),
            .read = uet_ep_read,
            .readv = uet_ep_readv,
            .readmsg = uet_ep_readmsg,
            .write = uet_ep_write,
            .writev = uet_ep_writev,
            .writemsg = uet_ep_writemsg,
            .inject = nullptr,
            .writedata = nullptr,
            .injectdata = nullptr,
        };

        (void)ctx;
        *ep = &e->ep;
        return 0;
    };

    *dom = &d->domain;
    return 0;
}

static int uet_fabric_eq_open(struct fid_fabric*, struct fi_eq_attr*, struct fid_eq** eq, void* context)
{
    if (!eq) return -FI_EINVAL;
    auto* e = new uet_eq();
    e->eq.fid.fclass = FI_CLASS_EQ;
    e->eq.fid.context = context;
    e->eq.fid.ops = &e->eq_fid_ops;
    e->eq.ops = &e->eq_ops;

    e->eq_fid_ops = fi_ops{
        .size = sizeof(fi_ops),
        .close = uet_fid_close,
        .bind = uet_fid_bind,
        .control = uet_fid_control,
        .ops_open = uet_fid_ops_open,
        .tostr = uet_fid_tostr,
        .ops_set = uet_fid_ops_set,
    };

    e->eq_ops = fi_ops_eq{
        .size = sizeof(fi_ops_eq),
        .read = uet_eq_read,
        .readerr = uet_eq_readerr,
        .write = uet_eq_write,
        .sread = uet_eq_sread,
        .strerror = uet_eq_strerror,
    };

    *eq = &e->eq;
    return 0;
}

static int uet_fabric_wait_open(struct fid_fabric*, struct fi_wait_attr*, struct fid_wait**)
{
    return -FI_ENOSYS;
}

static int uet_fabric_trywait(struct fid_fabric*, struct fid**, int)
{
    return 0;
}

static int uet_fabric_open(struct fi_fabric_attr*, struct fid_fabric** fabric, void* context)
{
    if (!fabric) return -FI_EINVAL;
    auto* f = new uet_fabric();

    f->fabric.fid.fclass = FI_CLASS_FABRIC;
    f->fabric.fid.context = context;
    f->fabric.fid.ops = &f->fabric_fid_ops;
    f->fabric.ops = &f->fabric_ops;
    f->fabric.api_version = kProviderApiVersion;

    f->fabric_fid_ops = fi_ops{
        .size = sizeof(fi_ops),
        .close = uet_fid_close,
        .bind = uet_fid_bind,
        .control = uet_fid_control,
        .ops_open = uet_fid_ops_open,
        .tostr = uet_fid_tostr,
        .ops_set = uet_fid_ops_set,
    };

    f->fabric_ops = fi_ops_fabric{
        .size = sizeof(fi_ops_fabric),
        .domain = uet_fabric_domain,
        .passive_ep = nullptr,
        .eq_open = uet_fabric_eq_open,
        .wait_open = uet_fabric_wait_open,
        .trywait = uet_fabric_trywait,
        .domain2 = nullptr,
    };

    *fabric = &f->fabric;
    return 0;
}

static int uet_getinfo(uint32_t version, const char*, const char*, uint64_t, const struct fi_info* hints, struct fi_info** info_out)
{
    uet_dbg("mark", "provider build mark: 2026-01-28 MRDescWrite TX/RX log");
    const uet_backend_kind backend = uet_parse_backend();
    uet_dbg("backend", "fi_getinfo backend request=%s", uet_backend_name(backend));
    // fi_getinfo：对外宣告 provider 能力与默认属性。
    // 关键点：
    // - 必须“接受更低版本”的调用者：如果调用者传的 version <= provider 支持的版本，应当允许
    // - 必须根据 hints 过滤：如果 hints 里要求 RMA/TAGGED/ATOMIC，我们直接返回 -FI_ENODATA
    if (!info_out) return -FI_EINVAL;
    *info_out = nullptr;

    // Providers must accept callers requesting an older API version.
    if (FI_VERSION_LT(kProviderApiVersion, version)) return -FI_ENODATA;

    if (hints) {
        // 只支持 DGRAM endpoint
        if (hints->ep_attr && hints->ep_attr->type != FI_EP_UNSPEC && hints->ep_attr->type != FI_EP_DGRAM) {
            return -FI_ENODATA;
        }
        // 不支持 tagged/atomic；RMA 仅支持 WRITE，不支持 READ
        if (hints->caps && (hints->caps & (FI_TAGGED | FI_ATOMIC))) {
            return -FI_ENODATA;
        }
        // FI_READ supported now; keep accepting READ in hints.
    }

    fi_info* info = fi_allocinfo();
    if (!info) return -FI_ENOMEM;

    // Advertise only the capabilities implemented in phase 1.
    // 中文说明：只宣告 FI_MSG（send/recv），其余能力不要宣告，否则上层会按宣告去调用导致不可预期行为。
    info->caps = FI_MSG | FI_SEND | FI_RECV | FI_RMA | FI_WRITE | FI_READ;
    info->mode = 0;
    info->addr_format = FI_SOCKADDR_IN;
    info->src_addrlen = sizeof(sockaddr_in);
    info->dest_addrlen = sizeof(sockaddr_in);
    info->src_addr = nullptr;
    info->dest_addr = nullptr;

    // Let libfabric core fill prov_name for external core providers.
    // Setting this here triggers provider-layering assertions in libfabric 2.3 debug builds.
    info->fabric_attr->prov_name = nullptr;
    info->fabric_attr->name = strdup("uet-fabric");
    info->fabric_attr->api_version = kProviderApiVersion;
    info->fabric_attr->prov_version = 1;

    info->domain_attr->name = strdup("uet-domain");
    info->domain_attr->threading = FI_THREAD_SAFE;
    info->domain_attr->progress = FI_PROGRESS_AUTO;
    info->domain_attr->resource_mgmt = FI_RM_ENABLED;
    info->domain_attr->av_type = FI_AV_UNSPEC;
    info->domain_attr->mr_mode = FI_MR_LOCAL | FI_MR_VIRT_ADDR | FI_MR_PROV_KEY;
    info->domain_attr->mr_key_size = 8;
    info->domain_attr->cq_data_size = 0;
    info->domain_attr->cq_cnt = 0;
    info->domain_attr->ep_cnt = 0;
    info->domain_attr->tx_ctx_cnt = 1;
    info->domain_attr->rx_ctx_cnt = 1;

    info->ep_attr->type = FI_EP_DGRAM;
    info->ep_attr->protocol = FI_PROTO_UDP;
    info->ep_attr->protocol_version = 1;
    info->ep_attr->max_msg_size = kUetAdvertisedMaxMsgSize;
    info->ep_attr->msg_prefix_size = 0;

    info->tx_attr->caps = FI_SEND | FI_WRITE | FI_READ;
    info->tx_attr->mode = 0;
    info->tx_attr->op_flags = 0;
    info->tx_attr->msg_order = FI_ORDER_SAR;
    info->tx_attr->inject_size = 0;
    info->tx_attr->size = 256;
    info->tx_attr->iov_limit = 1;
    info->tx_attr->rma_iov_limit = 1;

    info->rx_attr->caps = FI_RECV;
    info->rx_attr->mode = 0;
    info->rx_attr->op_flags = 0;
    info->rx_attr->msg_order = FI_ORDER_SAR;
    info->rx_attr->size = 256;
    info->rx_attr->iov_limit = 1;

    // Expose minimal NIC metadata to help aws-ofi-nccl avoid default NIC fallbacks.
    // This is metadata-only and does not change protocol behavior.
    const int nic_rc = uet_fill_nic_metadata(info);
    if (nic_rc != 0) {
        uet_dbg("nic", "failed to build nic metadata rc=%d, continue with nic=(nil)", nic_rc);
        info->nic = nullptr;
    }

    *info_out = info;
    return 0;
}

static void uet_cleanup()
{
}

static fi_provider uet_provider = {
    // libfabric 会通过 FI_EXT_INI() 拿到这个 fi_provider 结构体指针。
    // 其中最关键的两个回调：
    // - getinfo：返回 fi_info 列表（宣告能力）
    // - fabric：创建 fid_fabric
    .version = kProviderInterfaceVersion,
    .fi_version = kProviderApiVersion,
    .context = {},
    .name = kProviderName,
    .getinfo = uet_getinfo,
    .fabric = [](struct fi_fabric_attr* attr, struct fid_fabric** fabric, void* context) -> int {
        return uet_fabric_open(attr, fabric, context);
    },
    .cleanup = uet_cleanup,
};

} // namespace

extern "C" FI_EXT_INI
{
    // Provider 插件入口：返回 fi_provider*。
    return &uet_provider;
}
