#include <rdma/fabric.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_errno.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "../Network_Layer/UDP_Network_Layer.hpp"
#include "../SES/SES.hpp"
#include "../logger/Logger.hpp"

using namespace UET::NetworkLayer;

namespace {

constexpr uint32_t kMRDescMagic = 0x4d524443; // "MRDC"
constexpr uint16_t kMRDescVersion = 1;

struct MRDesc {
    uint32_t magic;
    uint16_t version;
    uint16_t flags;
    uint32_t job_id;
    uint32_t pid_on_fep;
    uint32_t resource_index;
    uint32_t rkey;
    uint64_t remote_base;
    uint64_t len;
    uint32_t access;
    uint32_t ri_generation;
};

struct Args {
    std::string mode = "server";
    std::string peer_ip = "127.0.0.1";
    uint16_t ctrl_local_port = 4000;
    uint16_t ctrl_peer_port = 4001;
    uint16_t data_server_port = 2990;
    uint16_t data_client_port = 2991;
    uint32_t job_id = 12345;
    uint32_t server_fep = 2001;
    uint32_t client_fep = 1000;
    uint32_t resource_index = 0;
    uint32_t rkey = 0x7788;
    uint64_t len = 4096;
    uint32_t access = 0x3; // READ|WRITE
    uint32_t msg_id = 7;
    size_t segment_len = 1024;
    size_t offset = 0;
    int timeout_ms = 5000;
};

static bool starts_with(const std::string& s, const std::string& prefix)
{
    return s.rfind(prefix, 0) == 0;
}

static uint64_t to_u64(const std::string& s)
{
    return static_cast<uint64_t>(std::stoull(s, nullptr, 0));
}

static void fill_pattern(std::vector<uint8_t>& buf, uint8_t seed)
{
    for (size_t i = 0; i < buf.size(); ++i) {
        buf[i] = static_cast<uint8_t>((i + seed) & 0xFF);
    }
}

static Args parse_args(int argc, char** argv)
{
    Args args;
    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);
        auto get_val = [&](const std::string& key) -> std::string {
            if (starts_with(arg, key + "=")) {
                return arg.substr(key.size() + 1);
            }
            if (arg == key && i + 1 < argc) {
                return std::string(argv[++i]);
            }
            return {};
        };

        if (auto v = get_val("--mode"); !v.empty()) {
            args.mode = v;
        } else if (auto v = get_val("--peer-ip"); !v.empty()) {
            args.peer_ip = v;
        } else if (auto v = get_val("--ctrl-local-port"); !v.empty()) {
            args.ctrl_local_port = static_cast<uint16_t>(to_u64(v));
        } else if (auto v = get_val("--ctrl-peer-port"); !v.empty()) {
            args.ctrl_peer_port = static_cast<uint16_t>(to_u64(v));
        } else if (auto v = get_val("--data-server-port"); !v.empty()) {
            args.data_server_port = static_cast<uint16_t>(to_u64(v));
        } else if (auto v = get_val("--data-client-port"); !v.empty()) {
            args.data_client_port = static_cast<uint16_t>(to_u64(v));
        } else if (auto v = get_val("--job-id"); !v.empty()) {
            args.job_id = static_cast<uint32_t>(to_u64(v));
        } else if (auto v = get_val("--server-fep"); !v.empty()) {
            args.server_fep = static_cast<uint32_t>(to_u64(v));
        } else if (auto v = get_val("--client-fep"); !v.empty()) {
            args.client_fep = static_cast<uint32_t>(to_u64(v));
        } else if (auto v = get_val("--resource-index"); !v.empty()) {
            args.resource_index = static_cast<uint32_t>(to_u64(v));
        } else if (auto v = get_val("--rkey"); !v.empty()) {
            args.rkey = static_cast<uint32_t>(to_u64(v));
        } else if (auto v = get_val("--len"); !v.empty()) {
            args.len = to_u64(v);
        } else if (auto v = get_val("--access"); !v.empty()) {
            args.access = static_cast<uint32_t>(to_u64(v));
        } else if (auto v = get_val("--msg-id"); !v.empty()) {
            args.msg_id = static_cast<uint32_t>(to_u64(v));
        } else if (auto v = get_val("--segment-len"); !v.empty()) {
            args.segment_len = static_cast<size_t>(to_u64(v));
        } else if (auto v = get_val("--offset"); !v.empty()) {
            args.offset = static_cast<size_t>(to_u64(v));
        } else if (auto v = get_val("--timeout-ms"); !v.empty()) {
            args.timeout_ms = static_cast<int>(to_u64(v));
        }
    }
    return args;
}

struct FabricCtx {
    fi_info* info = nullptr;
    fid_fabric* fabric = nullptr;
    fid_domain* domain = nullptr;
    fid_ep* ep = nullptr;
    fid_cq* tx_cq = nullptr;
    fid_cq* rx_cq = nullptr;
    fid_av* av = nullptr;
    fi_addr_t peer = FI_ADDR_UNSPEC;
};

static void cleanup(FabricCtx& ctx)
{
    if (ctx.ep) fi_close(&ctx.ep->fid);
    if (ctx.av) fi_close(&ctx.av->fid);
    if (ctx.tx_cq) fi_close(&ctx.tx_cq->fid);
    if (ctx.rx_cq) fi_close(&ctx.rx_cq->fid);
    if (ctx.domain) fi_close(&ctx.domain->fid);
    if (ctx.fabric) fi_close(&ctx.fabric->fid);
    if (ctx.info) fi_freeinfo(ctx.info);
}

static int setup_fabric(const Args& args, FabricCtx& ctx)
{
    fi_info* hints = fi_allocinfo();
    if (!hints) {
        std::cerr << "fi_allocinfo failed" << std::endl;
        return -1;
    }
    hints->caps = FI_MSG | FI_SEND | FI_RECV;
    hints->ep_attr->type = FI_EP_DGRAM;
    hints->fabric_attr->prov_name = strdup("uet");

    int ret = fi_getinfo(FI_VERSION(1, 5), nullptr, nullptr, 0, hints, &ctx.info);
    fi_freeinfo(hints);
    if (ret) {
        std::cerr << "fi_getinfo failed: " << fi_strerror(-ret) << std::endl;
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
    local.sin_port = htons(args.ctrl_local_port);
    if (inet_pton(AF_INET, "127.0.0.1", &local.sin_addr) != 1) {
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
    peer.sin_port = htons(args.ctrl_peer_port);
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

static bool wait_cq(fid_cq* cq, int timeout_ms, const char* name)
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

static int run_server(const Args& args)
{
    Logger::initialize("MRDescWrite_server.log", LogLevel::INFO, 1, 1);

    FabricCtx ctx;
    if (setup_fabric(args, ctx) != 0) {
        cleanup(ctx);
        return 1;
    }

    SESManager ses_manager;
    UDPNetworkLayer udp_rx(args.data_server_port);
    UDPNetworkLayer udp_tx(0);
    if (!udp_rx.initialize() || !udp_tx.initialize()) {
        std::cerr << "UDP init failed" << std::endl;
        cleanup(ctx);
        return 1;
    }

    std::vector<uint8_t> mr(static_cast<size_t>(args.len), 0);
    ses_manager.register_mr(args.rkey, reinterpret_cast<uint64_t>(mr.data()), mr.size());

    MRDesc desc{};
    desc.magic = kMRDescMagic;
    desc.version = kMRDescVersion;
    desc.job_id = args.job_id;
    desc.pid_on_fep = args.server_fep;
    desc.resource_index = args.resource_index;
    desc.rkey = args.rkey;
    desc.remote_base = reinterpret_cast<uint64_t>(mr.data());
    desc.len = args.len;
    desc.access = args.access;
    desc.ri_generation = 0;

    char ack_buf[16] = {};
    fi_recv(ctx.ep, ack_buf, sizeof(ack_buf), nullptr, FI_ADDR_UNSPEC, ack_buf);
    fi_send(ctx.ep, &desc, sizeof(desc), nullptr, ctx.peer, &desc);
    if (!wait_cq(ctx.tx_cq, args.timeout_ms, "CTRL TX CQ")) {
        cleanup(ctx);
        return 1;
    }
    if (!wait_cq(ctx.rx_cq, args.timeout_ms, "CTRL RX CQ")) {
        cleanup(ctx);
        return 1;
    }
    std::cout << "MRDesc sent, ack=" << ack_buf << std::endl;

    std::atomic<bool> rx_running{true};
    std::thread rx_thread([&]() {
        while (rx_running.load()) {
            PDStoNET_pkt rx_pkt;
            if (udp_rx.receivePDStoNETPacket(50, rx_pkt)) {
                ses_manager.pds_process_manager.pushNetworkPacket(rx_pkt);
            }
        }
    });

    if (args.offset + args.segment_len > mr.size()) {
        std::cerr << "Invalid offset/length: offset=" << args.offset
                  << " len=" << args.segment_len
                  << " mr_size=" << mr.size() << std::endl;
        cleanup(ctx);
        return 1;
    }

    std::vector<uint8_t> expected(args.segment_len);
    fill_pattern(expected, 0x10);

    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(args.timeout_ms);
    bool ok = false;
    while (std::chrono::steady_clock::now() < deadline) {
        ses_manager.mainChk();

        PDStoNET_pkt out_pkt;
        while (ses_manager.pds_process_manager.popNetworkPacket(out_pkt)) {
            udp_tx.sendPacket(out_pkt, "127.0.0.1", args.data_client_port);
        }

        const size_t off = args.offset;
        if (std::memcmp(mr.data() + off, expected.data(), args.segment_len) == 0) {
            const auto status = ses_manager.pds_process_manager.getQueueStatus();
            const bool rsp_queues_empty =
                status.pdc_to_net_count == 0 &&
                status.ses_rsp_count == 0 &&
                status.pdc_to_ses_rsp_count == 0;
            if (rsp_queues_empty) {
                ok = true;
                break;
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    rx_running.store(false);
    rx_thread.join();
    cleanup(ctx);

    if (ok) {
        LOG_INFO(__FUNCTION__, "MRDescWrite server PASS");
    } else {
        LOG_INFO(__FUNCTION__, "MRDescWrite server FAIL");
    }
    std::cout << (ok ? "MRDescWrite server PASS" : "MRDescWrite server FAIL") << std::endl;
    return ok ? 0 : 1;
}

static int run_client(const Args& args)
{
    Logger::initialize("MRDescWrite_client.log", LogLevel::INFO, 1, 1);

    FabricCtx ctx;
    if (setup_fabric(args, ctx) != 0) {
        cleanup(ctx);
        return 1;
    }

    MRDesc desc{};
    fi_recv(ctx.ep, &desc, sizeof(desc), nullptr, FI_ADDR_UNSPEC, &desc);
    if (!wait_cq(ctx.rx_cq, args.timeout_ms, "CTRL RX CQ")) {
        cleanup(ctx);
        return 1;
    }
    if (desc.magic != kMRDescMagic || desc.version != kMRDescVersion) {
        std::cerr << "MRDesc invalid magic/version" << std::endl;
        cleanup(ctx);
        return 1;
    }

    const char ack_msg[] = "OK";
    fi_send(ctx.ep, ack_msg, sizeof(ack_msg), nullptr, ctx.peer, (void*)ack_msg);
    wait_cq(ctx.tx_cq, args.timeout_ms, "CTRL TX CQ");

    std::cout << "MRDesc received: job_id=" << desc.job_id
              << " pid_on_fep=" << desc.pid_on_fep
              << " ri=" << desc.resource_index
              << " rkey=0x" << std::hex << desc.rkey << std::dec
              << " remote_base=0x" << std::hex << desc.remote_base << std::dec
              << " len=" << desc.len
              << " access=0x" << std::hex << desc.access << std::dec
              << std::endl;

    SESManager ses_manager;
    UDPNetworkLayer udp_rx(args.data_client_port);
    UDPNetworkLayer udp_tx(0);
    if (!udp_rx.initialize() || !udp_tx.initialize()) {
        std::cerr << "UDP init failed" << std::endl;
        cleanup(ctx);
        return 1;
    }

    if (args.offset + args.segment_len > desc.len) {
        std::cerr << "Invalid offset/length: offset=" << args.offset
                  << " len=" << args.segment_len
                  << " mr_len=" << desc.len << std::endl;
        cleanup(ctx);
        return 1;
    }

    ses_manager.register_mr(desc.rkey, 0, desc.len);

    std::vector<uint8_t> src(args.segment_len);
    fill_pattern(src, 0x10);

    const uint64_t remote_addr = desc.remote_base + args.offset;
    const uint64_t buffer_offset = remote_addr - desc.remote_base;

    OperationMetadata md;
    md.op_type = WRITE;
    md.s_pid_on_fep = args.client_fep;
    md.t_pid_on_fep = desc.pid_on_fep;
    md.job_id = desc.job_id;
    md.messages_id = args.msg_id;
    md.memory.rkey = desc.rkey;
    md.payload.start_addr = buffer_offset;
    md.payload.local_addr = reinterpret_cast<uint64_t>(src.data());
    md.payload.length = src.size();
    md.has_imm_data = false;
    md.use_optimized_header = false;
    md.relative = false;
    md.res_index = desc.resource_index;

    ses_manager.lfbric_ses_q.push(md);
    ses_manager.mainChk();

    std::atomic<bool> got_rsp{false};
    std::atomic<bool> rsp_ok{false};
    std::atomic<bool> rsp_len_ok{false};
    std::atomic<bool> rx_running{true};
    std::thread rx_thread([&]() {
        while (rx_running.load() && !got_rsp.load()) {
            PDStoNET_pkt rx_pkt;
            if (!udp_rx.receivePDStoNETPacket(50, rx_pkt)) {
                continue;
            }
            if (rx_pkt.SESpkt.bth_type != Semantic_Response_Header) {
                continue;
            }
            const auto& rsp = rx_pkt.SESpkt.bth_header.Semantic_Response_Header;
            if (rsp.message_id != args.msg_id) {
                continue;
            }
            rsp_ok.store(rsp.return_code == static_cast<uint8_t>(RSP_RETURN_CODE::RC_OK));
            rsp_len_ok.store(rsp.modified_length == args.segment_len);
            got_rsp.store(true);
        }
    });

    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(args.timeout_ms);
    while (std::chrono::steady_clock::now() < deadline && !got_rsp.load()) {
        PDStoNET_pkt tx_pkt;
        if (ses_manager.pds_process_manager.popNetworkPacket(tx_pkt)) {
            udp_tx.sendPacket(tx_pkt, "127.0.0.1", args.data_server_port);
        }
        ses_manager.mainChk();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    rx_running.store(false);
    rx_thread.join();
    cleanup(ctx);

    const bool ok = (got_rsp.load() && rsp_ok.load() && rsp_len_ok.load());
    if (ok) {
        LOG_INFO(__FUNCTION__, "MRDescWrite client PASS");
    } else {
        LOG_INFO(__FUNCTION__, "MRDescWrite client FAIL");
    }
    std::cout << (ok ? "MRDescWrite client PASS" : "MRDescWrite client FAIL") << std::endl;
    return 0;
}

} // namespace

int main(int argc, char** argv)
{
    const Args args = parse_args(argc, argv);
    if (args.mode == "server") {
        return run_server(args);
    }
    if (args.mode == "client") {
        return run_client(args);
    }
    std::cerr << "Unknown mode: " << args.mode << std::endl;
    return 1;
}
