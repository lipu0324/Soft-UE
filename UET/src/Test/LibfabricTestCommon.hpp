#ifndef UET_TEST_LIBFABRIC_TEST_COMMON_HPP
#define UET_TEST_LIBFABRIC_TEST_COMMON_HPP

#include <rdma/fabric.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_errno.h>
#include <rdma/fi_rma.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <climits>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace UET::Test::Libfabric {

inline bool use_rdma_backend()
{
    const char* backend = std::getenv("UET_BACKEND");
    return backend && std::strcmp(backend, "rdma") == 0;
}

constexpr uint32_t kMRDescMagic = 0x4d524443; // "MRDC"
constexpr uint16_t kMRDescVersion = 2;
constexpr uint32_t kCtrlMagic = 0x55435452;   // "UCTR"
constexpr uint16_t kCtrlVersion = 1;
constexpr size_t kCtrlRxBuf = 1024;

enum CtrlMsgType : uint16_t {
    CTRL_HELLO = 1,
    CTRL_MRDESC = 2,
    CTRL_ACK = 3,
    CTRL_ERR = 4,
    CTRL_DONE = 5,
};

struct __attribute__((packed)) CtrlHdr {
    uint32_t magic;
    uint16_t version;
    uint16_t msg_type;
    uint16_t hdr_len;
    uint16_t reserved0;
    uint32_t total_len;
    uint64_t session_id;
    uint32_t job_id;
    uint32_t resource_index;
    uint32_t reserved1;
};

struct HelloMsg {
    uint32_t client_id;
};

struct AckMsg {
    uint32_t status;
};

struct ClientStatusMsg {
    uint32_t client_id;
    uint32_t status;
};

struct MRDesc {
    uint32_t magic;
    uint16_t version;
    uint16_t flags;
    uint32_t job_id;
    uint32_t pid_on_fep;
    uint32_t resource_index;
    uint32_t rkey;
    uint64_t remote_addr;
    uint64_t len;
    uint32_t access;
    uint32_t ri_generation;
    uint64_t reg_epoch;
    uint32_t mem_type;
    uint32_t backend_kind;
};

struct Args {
    std::string mode = "server";
    std::string local_ip = "127.0.0.1";
    std::string peer_ip = "127.0.0.1";
    uint16_t local_port = 4000;
    uint16_t peer_port = 4001;
    uint64_t len = 4096;
    uint64_t offset = 0;
    uint32_t job_id = 12345;
    uint32_t pid_on_fep = 2001;
    uint32_t resource_index = 0;
    uint32_t rkey = 0x7788;
    uint32_t access = 0x3;
    int timeout_ms = 5000;
    uint32_t clients = 1;
    uint32_t client_id = 0;
};

inline const char* ctrl_type_name(uint16_t type)
{
    switch (type) {
        case CTRL_HELLO: return "HELLO";
        case CTRL_MRDESC: return "MRDESC";
        case CTRL_ACK: return "ACK";
        case CTRL_ERR: return "ERR";
        case CTRL_DONE: return "DONE";
        default: return "UNKNOWN";
    }
}

inline bool starts_with(const std::string& s, const std::string& prefix)
{
    return s.rfind(prefix, 0) == 0;
}

inline uint64_t to_u64(const std::string& s)
{
    return static_cast<uint64_t>(std::stoull(s, nullptr, 0));
}

inline Args parse_args(int argc, char** argv, Args args = Args{})
{
    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);
        auto get_val = [&](const std::string& key, std::string& out) -> bool {
            if (starts_with(arg, key + "=")) {
                out = arg.substr(key.size() + 1);
                return true;
            }
            if (arg == key && i + 1 < argc) {
                out = std::string(argv[++i]);
                return true;
            }
            return false;
        };
        std::string v;

        if (arg == "--server") {
            args.mode = "server";
        } else if (arg == "--client") {
            args.mode = "client";
        } else if (get_val("--mode", v)) {
            args.mode = v;
        } else if (get_val("--local-ip", v)) {
            args.local_ip = v;
        } else if (get_val("--peer-ip", v)) {
            args.peer_ip = v;
        } else if (get_val("--local-port", v)) {
            args.local_port = static_cast<uint16_t>(to_u64(v));
        } else if (get_val("--peer-port", v)) {
            args.peer_port = static_cast<uint16_t>(to_u64(v));
        } else if (get_val("--len", v)) {
            args.len = to_u64(v);
        } else if (get_val("--offset", v)) {
            args.offset = to_u64(v);
        } else if (get_val("--job-id", v)) {
            args.job_id = static_cast<uint32_t>(to_u64(v));
        } else if (get_val("--pid-on-fep", v)) {
            args.pid_on_fep = static_cast<uint32_t>(to_u64(v));
        } else if (get_val("--resource-index", v)) {
            args.resource_index = static_cast<uint32_t>(to_u64(v));
        } else if (get_val("--rkey", v)) {
            args.rkey = static_cast<uint32_t>(to_u64(v));
        } else if (get_val("--access", v)) {
            args.access = static_cast<uint32_t>(to_u64(v));
        } else if (get_val("--timeout-ms", v)) {
            args.timeout_ms = static_cast<int>(to_u64(v));
        } else if (get_val("--clients", v)) {
            args.clients = static_cast<uint32_t>(to_u64(v));
        } else if (get_val("--client-id", v)) {
            args.client_id = static_cast<uint32_t>(to_u64(v));
        }
    }
    return args;
}

inline uint64_t make_session_id(uint32_t entropy = 0)
{
    uint64_t v = static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
    v ^= (static_cast<uint64_t>(::getpid()) << 17);
    v ^= static_cast<uint64_t>(entropy);
    if (v == 0) {
        v = 1;
    }
    return v;
}

inline std::vector<uint8_t> build_ctrl_msg(uint16_t type, uint64_t session_id, uint32_t job_id,
                                           uint32_t resource_index, const void* payload,
                                           size_t payload_len)
{
    CtrlHdr hdr{};
    hdr.magic = kCtrlMagic;
    hdr.version = kCtrlVersion;
    hdr.msg_type = type;
    hdr.hdr_len = sizeof(CtrlHdr);
    hdr.total_len = static_cast<uint32_t>(sizeof(CtrlHdr) + payload_len);
    hdr.session_id = session_id;
    hdr.job_id = job_id;
    hdr.resource_index = resource_index;

    std::vector<uint8_t> out(sizeof(CtrlHdr) + payload_len);
    std::memcpy(out.data(), &hdr, sizeof(hdr));
    if (payload && payload_len > 0) {
        std::memcpy(out.data() + sizeof(hdr), payload, payload_len);
    }
    return out;
}

inline bool parse_ctrl_msg(const uint8_t* data, size_t len, CtrlHdr& hdr, const uint8_t*& payload,
                           size_t& payload_len)
{
    if (!data || len < sizeof(CtrlHdr)) return false;
    std::memcpy(&hdr, data, sizeof(hdr));
    if (hdr.magic != kCtrlMagic || hdr.version != kCtrlVersion) return false;
    if (hdr.hdr_len != sizeof(CtrlHdr)) return false;
    if (hdr.total_len != len || hdr.total_len < hdr.hdr_len) return false;
    payload = data + hdr.hdr_len;
    payload_len = len - hdr.hdr_len;
    return true;
}

template <typename T>
inline bool decode_payload_copy(const uint8_t* payload, size_t payload_len, T& out)
{
    if (!payload || payload_len < sizeof(T)) {
        return false;
    }
    std::memcpy(&out, payload, sizeof(T));
    return true;
}

struct FabricCtx {
    fi_info* info = nullptr;
    fid_fabric* fabric = nullptr;
    fid_domain* domain = nullptr;
    fid_ep* ep = nullptr;
    fid_cq* tx_cq = nullptr;
    fid_cq* rx_cq = nullptr;
    fid_av* av = nullptr;
    fid_mr* data_mr = nullptr;
    fi_addr_t peer = FI_ADDR_UNSPEC;
};

inline void cleanup(FabricCtx& ctx)
{
    if (ctx.data_mr) fi_close(&ctx.data_mr->fid);
    if (ctx.ep) fi_close(&ctx.ep->fid);
    if (ctx.av) fi_close(&ctx.av->fid);
    if (ctx.tx_cq) fi_close(&ctx.tx_cq->fid);
    if (ctx.rx_cq) fi_close(&ctx.rx_cq->fid);
    if (ctx.domain) fi_close(&ctx.domain->fid);
    if (ctx.fabric) fi_close(&ctx.fabric->fid);
    if (ctx.info) fi_freeinfo(ctx.info);
}

inline int select_uet_provider_info(fi_info*& info)
{
    fi_info* selected = nullptr;
    for (fi_info* it = info; it; it = it->next) {
        const char* prov_name =
            (it->fabric_attr && it->fabric_attr->prov_name) ? it->fabric_attr->prov_name : nullptr;
        const char* fabric_name =
            (it->fabric_attr && it->fabric_attr->name) ? it->fabric_attr->name : nullptr;
        const char* domain_name =
            (it->domain_attr && it->domain_attr->name) ? it->domain_attr->name : nullptr;
        const bool is_uet = (prov_name && std::strcmp(prov_name, "uet") == 0) ||
                            (fabric_name && std::strcmp(fabric_name, "uet-fabric") == 0) ||
                            (domain_name && std::strcmp(domain_name, "uet-domain") == 0);
        if (is_uet) {
            selected = fi_dupinfo(it);
            break;
        }
    }
    if (!selected) {
        std::cerr << "provider 'uet' not found in fi_getinfo results" << std::endl;
        int idx = 0;
        for (fi_info* it = info; it; it = it->next, ++idx) {
            const char* prov_name =
                (it->fabric_attr && it->fabric_attr->prov_name) ? it->fabric_attr->prov_name : "<null>";
            const char* fabric_name =
                (it->fabric_attr && it->fabric_attr->name) ? it->fabric_attr->name : "<null>";
            const char* domain_name =
                (it->domain_attr && it->domain_attr->name) ? it->domain_attr->name : "<null>";
            const long long ep_type = it->ep_attr ? static_cast<long long>(it->ep_attr->type) : -1;
            std::cerr << "  [" << idx << "] prov=" << prov_name << " fabric=" << fabric_name
                      << " domain=" << domain_name << " ep_type=" << ep_type << " caps=0x"
                      << std::hex << static_cast<unsigned long long>(it->caps) << std::dec
                      << std::endl;
        }
        return -1;
    }
    fi_freeinfo(info);
    info = selected;
    return 0;
}

inline int register_data_mr(FabricCtx& ctx, void* buf, size_t len, uint64_t access)
{
    if (ctx.data_mr) {
        fi_close(&ctx.data_mr->fid);
        ctx.data_mr = nullptr;
    }
    const int ret = fi_mr_reg(ctx.domain, buf, len, access, 0, 0, 0, &ctx.data_mr, nullptr);
    if (ret) {
        std::cerr << "fi_mr_reg failed: " << fi_strerror(-ret) << std::endl;
        return ret;
    }
    return 0;
}

inline int setup_fabric(const Args& args, FabricCtx& ctx, uint64_t caps)
{
    fi_info* hints = fi_allocinfo();
    if (!hints) {
        std::cerr << "fi_allocinfo failed" << std::endl;
        return -1;
    }
    // Try discovery with the requested capabilities first so runtime bring-up
    // matches the actual test path. Some environments only enumerate "uet"
    // when caps such as FI_MSG are present. Keep a relaxed retry for older
    // cases that were sensitive to stricter hints.
    hints->caps = caps;
    hints->ep_attr->type = FI_EP_DGRAM;

    int ret = fi_getinfo(FI_VERSION(1, 5), nullptr, nullptr, 0, hints, &ctx.info);
    if (ret == -FI_ENODATA && caps != 0) {
        hints->caps = 0;
        ret = fi_getinfo(FI_VERSION(1, 5), nullptr, nullptr, 0, hints, &ctx.info);
    }
    fi_freeinfo(hints);
    if (ret) {
        std::cerr << "fi_getinfo failed: " << fi_strerror(-ret) << std::endl;
        return ret;
    }
    ret = select_uet_provider_info(ctx.info);
    if (ret) {
        return ret;
    }

    ret = fi_fabric(ctx.info->fabric_attr, &ctx.fabric, nullptr);
    if (ret) {
        std::cerr << "fi_fabric failed: " << fi_strerror(-ret) << std::endl;
        return ret;
    }
    ret = fi_domain(ctx.fabric, ctx.info, &ctx.domain, nullptr);
    if (ret) {
        std::cerr << "fi_domain failed: " << fi_strerror(-ret) << std::endl;
        return ret;
    }

    fi_cq_attr cq_attr{};
    cq_attr.format = FI_CQ_FORMAT_MSG;
    ret = fi_cq_open(ctx.domain, &cq_attr, &ctx.tx_cq, nullptr);
    if (ret) {
        std::cerr << "fi_cq_open(tx) failed: " << fi_strerror(-ret) << std::endl;
        return ret;
    }
    ret = fi_cq_open(ctx.domain, &cq_attr, &ctx.rx_cq, nullptr);
    if (ret) {
        std::cerr << "fi_cq_open(rx) failed: " << fi_strerror(-ret) << std::endl;
        return ret;
    }

    fi_av_attr av_attr{};
    ret = fi_av_open(ctx.domain, &av_attr, &ctx.av, nullptr);
    if (ret) {
        std::cerr << "fi_av_open failed: " << fi_strerror(-ret) << std::endl;
        return ret;
    }

    ret = fi_endpoint(ctx.domain, ctx.info, &ctx.ep, nullptr);
    if (ret) {
        std::cerr << "fi_endpoint failed: " << fi_strerror(-ret) << std::endl;
        return ret;
    }

    ret = fi_ep_bind(ctx.ep, &ctx.av->fid, 0);
    if (ret) {
        std::cerr << "fi_ep_bind(av) failed: " << fi_strerror(-ret) << std::endl;
        return ret;
    }
    ret = fi_ep_bind(ctx.ep, &ctx.tx_cq->fid, FI_TRANSMIT);
    if (ret) {
        std::cerr << "fi_ep_bind(tx_cq) failed: " << fi_strerror(-ret) << std::endl;
        return ret;
    }
    ret = fi_ep_bind(ctx.ep, &ctx.rx_cq->fid, FI_RECV);
    if (ret) {
        std::cerr << "fi_ep_bind(rx_cq) failed: " << fi_strerror(-ret) << std::endl;
        return ret;
    }

    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_port = htons(args.local_port);
    if (inet_pton(AF_INET, args.local_ip.c_str(), &local.sin_addr) != 1) {
        std::cerr << "inet_pton local failed" << std::endl;
        return -1;
    }
    ret = fi_setname(&ctx.ep->fid, &local, sizeof(local));
    if (ret) {
        std::cerr << "fi_setname failed: " << fi_strerror(-ret) << std::endl;
        return ret;
    }

    ret = fi_enable(ctx.ep);
    if (ret) {
        std::cerr << "fi_enable failed: " << fi_strerror(-ret) << std::endl;
        return ret;
    }

    sockaddr_in peer{};
    peer.sin_family = AF_INET;
    peer.sin_port = htons(args.peer_port);
    if (inet_pton(AF_INET, args.peer_ip.c_str(), &peer.sin_addr) != 1) {
        std::cerr << "inet_pton peer failed" << std::endl;
        return -1;
    }

    ret = fi_av_insert(ctx.av, &peer, 1, &ctx.peer, 0, nullptr);
    if (ret != 1) {
        std::cerr << "fi_av_insert failed: " << fi_strerror(ret < 0 ? -ret : ret) << std::endl;
        return ret < 0 ? ret : -1;
    }

    return 0;
}

inline bool wait_cq(fid_cq* cq, int timeout_ms, const char* name)
{
    fi_cq_msg_entry entry{};
    const int ret = fi_cq_sread(cq, &entry, 1, nullptr, timeout_ms);
    if (ret == 1) {
        return true;
    }
    if (ret == -FI_EAGAIN) {
        std::cerr << name << " timeout" << std::endl;
        return false;
    }
    std::cerr << name << " error: " << fi_strerror(-ret) << std::endl;
    return false;
}

inline bool wait_cq_with_len(fid_cq* cq, int timeout_ms, const char* name, size_t& out_len)
{
    fi_cq_msg_entry entry{};
    const int ret = fi_cq_sread(cq, &entry, 1, nullptr, timeout_ms);
    if (ret == 1) {
        out_len = entry.len;
        return true;
    }
    if (ret == -FI_EAGAIN) {
        std::cerr << name << " timeout" << std::endl;
        return false;
    }
    std::cerr << name << " error: " << fi_strerror(-ret) << std::endl;
    return false;
}

inline bool send_ctrl_msg(fid_ep* ep, fid_cq* tx_cq, fi_addr_t peer, const std::vector<uint8_t>& msg,
                          int timeout_ms, const char* tag)
{
    const int ret = fi_send(ep, msg.data(), msg.size(), nullptr, peer,
                            const_cast<uint8_t*>(msg.data()));
    if (ret) {
        std::cerr << "fi_send(" << tag << ") failed: " << fi_strerror(-ret) << std::endl;
        return false;
    }
    return wait_cq(tx_cq, timeout_ms, "TX CQ");
}

template <typename T>
inline bool recv_ctrl_typed(fid_ep* ep, fid_cq* cq, int timeout_ms, uint16_t expected_type, T& out,
                            CtrlHdr& hdr)
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (true) {
        std::vector<uint8_t> rx(kCtrlRxBuf, 0);
        const int ret = fi_recv(ep, rx.data(), rx.size(), nullptr, FI_ADDR_UNSPEC, rx.data());
        if (ret) {
            std::cerr << "fi_recv(ctrl) failed: " << fi_strerror(-ret) << std::endl;
            return false;
        }

        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            std::cerr << "RX CQ timeout" << std::endl;
            return false;
        }
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        size_t rx_len = 0;
        if (!wait_cq_with_len(cq, static_cast<int>(std::max<int64_t>(1, remaining)), "RX CQ", rx_len)) {
            return false;
        }

        rx.resize(rx_len);
        const uint8_t* payload = nullptr;
        size_t payload_len = 0;
        if (!parse_ctrl_msg(rx.data(), rx.size(), hdr, payload, payload_len)) {
            std::cerr << "invalid ctrl message" << std::endl;
            return false;
        }
        if (hdr.msg_type != expected_type) {
            std::cerr << "ignore ctrl msg type=" << ctrl_type_name(hdr.msg_type)
                      << " while waiting for " << ctrl_type_name(expected_type)
                      << " payload_len=" << payload_len << std::endl;
            continue;
        }
        if (payload_len < sizeof(T)) {
            std::cerr << "unexpected ctrl payload_len=" << payload_len
                      << " for type=" << ctrl_type_name(expected_type) << std::endl;
            return false;
        }
        return decode_payload_copy(payload, payload_len, out);
    }
}

inline int compute_timeout_ms(uint64_t len, uint32_t clients)
{
    constexpr int kBaseMs = 5000;
    constexpr int kPerChunkMs = 200;
    constexpr uint64_t kChunk = 4096;
    const uint64_t chunks = (len + kChunk - 1) / kChunk;
    const uint64_t scaled = chunks * kPerChunkMs * clients;
    const uint64_t total = static_cast<uint64_t>(kBaseMs) + scaled;
    return total > static_cast<uint64_t>(INT32_MAX) ? INT32_MAX
                                                    : static_cast<int>(total);
}

inline void fill_pattern(std::vector<uint8_t>& buf, uint8_t value)
{
    std::fill(buf.begin(), buf.end(), value);
}

inline bool verify_pattern(const std::vector<uint8_t>& buf, uint8_t value)
{
    for (auto b : buf) {
        if (b != value) return false;
    }
    return true;
}

inline bool verify_range_pattern(const std::vector<uint8_t>& buf, uint64_t offset, uint64_t len,
                                 uint8_t value)
{
    if (offset + len > buf.size()) return false;
    for (uint64_t i = 0; i < len; ++i) {
        if (buf[static_cast<size_t>(offset + i)] != value) {
            return false;
        }
    }
    return true;
}

inline void dump_range_sample(const std::vector<uint8_t>& buf, uint64_t offset, uint64_t len)
{
    if (offset + len > buf.size()) {
        std::cerr << "dump_range_sample: out of range" << std::endl;
        return;
    }
    const uint64_t sample_len = std::min<uint64_t>(len, 16);
    const size_t off = static_cast<size_t>(offset);
    std::cerr << "range sample [offset=" << offset << " len=" << len << "]:";
    for (uint64_t i = 0; i < sample_len; ++i) {
        const uint8_t v = buf[off + static_cast<size_t>(i)];
        std::cerr << " " << std::hex << static_cast<int>(v);
    }
    std::cerr << std::dec << std::endl;
}

inline void dump_range_diagnostics(const std::vector<uint8_t>& buf, uint64_t offset, uint64_t len,
                                   uint8_t value)
{
    if (offset + len > buf.size()) {
        std::cerr << "range diag: out of range offset=" << offset
                  << " len=" << len
                  << " buf_size=" << buf.size() << std::endl;
        return;
    }
    uint64_t first_bad = UINT64_MAX;
    uint64_t mismatch = 0;
    for (uint64_t i = 0; i < len; ++i) {
        if (buf[static_cast<size_t>(offset + i)] != value) {
            if (first_bad == UINT64_MAX) {
                first_bad = offset + i;
            }
            ++mismatch;
        }
    }
    std::cerr << "range diag: offset=" << offset
              << " len=" << len
              << " mismatch=" << mismatch;
    if (first_bad != UINT64_MAX) {
        std::cerr << " first_bad=" << first_bad;
    } else {
        std::cerr << " first_bad=none";
    }
    std::cerr << std::endl;

    dump_range_sample(buf, offset, len);
    if (len > 16) {
        const uint64_t tail_off = offset + len - std::min<uint64_t>(len, 16);
        dump_range_sample(buf, tail_off, std::min<uint64_t>(len, 16));
    }
}

inline bool wait_range_ok(const std::vector<uint8_t>& buf, uint64_t offset, uint64_t len,
                          uint8_t value, int timeout_ms)
{
    const auto start = std::chrono::steady_clock::now();
    while (true) {
        if (verify_range_pattern(buf, offset, len, value)) {
            return true;
        }
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start);
        if (elapsed.count() >= timeout_ms) {
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

} // namespace UET::Test::Libfabric

#endif
