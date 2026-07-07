#include "LibfabricTestCommon.hpp"

#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

using namespace UET::Test::Libfabric;

static const char* ctrl_type_name(uint16_t type)
{
    switch (type) {
    case CTRL_HELLO: return "HELLO";
    case CTRL_MRDESC: return "MRDESC";
    case CTRL_ACK: return "ACK";
    case CTRL_ERR: return "ERR";
    default: return "UNKNOWN";
    }
}

static void trace(const std::string& role, const std::string& msg)
{
    std::cerr << "[MRDescTest][" << role << "] " << msg << std::endl;
}

static std::string endpoint_desc(const Args& args)
{
    std::ostringstream os;
    os << "local=" << args.local_ip << ":" << args.local_port
       << " peer=" << args.peer_ip << ":" << args.peer_port
       << " timeout_ms=" << args.timeout_ms
       << " backend=" << (use_rdma_backend() ? "rdma" : "soft");
    return os.str();
}

static int setup_fabric_traced(const Args& args, FabricCtx& ctx)
{
    trace(args.mode, "setup_fabric begin: " + endpoint_desc(args));
    const int rc = setup_fabric(args, ctx, FI_MSG | FI_SEND | FI_RECV);
    if (rc == 0) {
        trace(args.mode, "setup_fabric ready");
    }
    return rc;
}

static bool wait_cq_traced(const std::string& role, fid_cq* cq, int timeout_ms, const char* name)
{
    trace(role, std::string("wait ") + name + "...");
    const bool ok = wait_cq(cq, timeout_ms, name);
    if (ok) {
        trace(role, std::string(name) + " complete");
    }
    return ok;
}

static bool wait_cq_with_len_traced(const std::string& role, fid_cq* cq, int timeout_ms, const char* name,
                                    size_t& out_len)
{
    trace(role, std::string("wait ") + name + "...");
    const bool ok = wait_cq_with_len(cq, timeout_ms, name, out_len);
    if (ok) {
        trace(role, std::string(name) + " complete len=" + std::to_string(out_len));
    }
    return ok;
}

static bool recv_ctrl_msg(FabricCtx& ctx, int timeout_ms, uint16_t expected_type, CtrlHdr& hdr,
                          std::vector<uint8_t>& payload)
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (true) {
        std::vector<uint8_t> rx(kCtrlRxBuf, 0);
        trace("recv", "post fi_recv(ctrl) buf_len=" + std::to_string(rx.size()));
        const int ret = fi_recv(ctx.ep, rx.data(), rx.size(), nullptr, FI_ADDR_UNSPEC, rx.data());
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
        if (!wait_cq_with_len_traced("recv", ctx.rx_cq, static_cast<int>(std::max<int64_t>(1, remaining)),
                                     "RX CQ", rx_len)) {
            return false;
        }

        rx.resize(rx_len);
        const uint8_t* pl = nullptr;
        size_t pl_len = 0;
        if (!parse_ctrl_msg(rx.data(), rx.size(), hdr, pl, pl_len)) {
            std::cerr << "invalid ctrl message" << std::endl;
            return false;
        }
        if (hdr.msg_type != expected_type) {
            trace("recv", std::string("ignore ctrl msg type=") + ctrl_type_name(hdr.msg_type) +
                              " while waiting for " + ctrl_type_name(expected_type));
            continue;
        }
        payload.assign(pl, pl + pl_len);
        trace("recv", std::string("ctrl msg ok type=") + ctrl_type_name(hdr.msg_type) +
                          " total_len=" + std::to_string(hdr.total_len) +
                          " payload_len=" + std::to_string(payload.size()) +
                          " session_id=" + std::to_string(hdr.session_id));
        return true;
    }
}

static bool send_ctrl_msg(FabricCtx& ctx, fi_addr_t peer, const std::vector<uint8_t>& msg, int timeout_ms,
                          const char* tag)
{
    trace("send", std::string("post fi_send(") + tag + ") len=" + std::to_string(msg.size()));
    const int ret = fi_send(ctx.ep, msg.data(), msg.size(), nullptr, peer,
                            const_cast<uint8_t*>(msg.data()));
    if (ret) {
        std::cerr << "fi_send(" << tag << ") failed: " << fi_strerror(-ret) << std::endl;
        return false;
    }
    return wait_cq_traced("send", ctx.tx_cq, timeout_ms, "TX CQ");
}

static int run_server(const Args& args)
{
    trace("server", "run_server start");
    FabricCtx ctx{};
    if (setup_fabric_traced(args, ctx) != 0) {
        cleanup(ctx);
        return 1;
    }

    std::vector<uint8_t> mr(static_cast<size_t>(args.len), 0);
    MRDesc desc{};
    desc.magic = kMRDescMagic;
    desc.version = kMRDescVersion;
    desc.job_id = args.job_id;
    desc.pid_on_fep = args.pid_on_fep;
    desc.resource_index = args.resource_index;
    desc.rkey = args.rkey;
    desc.remote_addr = reinterpret_cast<uint64_t>(mr.data());
    desc.len = args.len;
    desc.access = args.access;
    desc.ri_generation = 0;
    desc.reg_epoch = 1;
    desc.mem_type = 1;
    desc.backend_kind = use_rdma_backend() ? 2u : 1u;

    const uint64_t server_session = make_session_id();
    trace("server", "server_session=" + std::to_string(server_session));

    CtrlHdr hello_hdr{};
    std::vector<uint8_t> hello_payload;
    trace("server", "waiting for HELLO");
    if (!recv_ctrl_msg(ctx, args.timeout_ms, CTRL_HELLO, hello_hdr, hello_payload)) {
        cleanup(ctx);
        return 1;
    }
    if (hello_payload.size() < sizeof(HelloMsg)) {
        std::cerr << "invalid HELLO ctrl message" << std::endl;
        cleanup(ctx);
        return 1;
    }

    auto mrdesc_msg = build_ctrl_msg(CTRL_MRDESC, server_session, desc.job_id, desc.resource_index, &desc,
                                     sizeof(desc));
    trace("server", "sending MRDESC");
    if (!send_ctrl_msg(ctx, ctx.peer, mrdesc_msg, args.timeout_ms, "MRDESC")) {
        cleanup(ctx);
        return 1;
    }

    CtrlHdr ack_hdr{};
    std::vector<uint8_t> ack_payload;
    trace("server", "waiting for ACK");
    if (!recv_ctrl_msg(ctx, args.timeout_ms, CTRL_ACK, ack_hdr, ack_payload)) {
        cleanup(ctx);
        return 1;
    }
    if (ack_payload.size() < sizeof(AckMsg)) {
        std::cerr << "invalid ACK ctrl message" << std::endl;
        cleanup(ctx);
        return 1;
    }
    AckMsg ack{};
    decode_payload_copy(ack_payload.data(), ack_payload.size(), ack);
    const char* ack_text = ack.status == 1 ? "OK" : "ERR";

    std::cout << "MRDesc sent, ack=" << ack_text << std::endl;
    cleanup(ctx);
    return ack.status == 1 ? 0 : 1;
}

static int run_client(const Args& args)
{
    trace("client", "run_client start");
    FabricCtx ctx{};
    if (setup_fabric_traced(args, ctx) != 0) {
        cleanup(ctx);
        return 1;
    }

    const uint64_t client_session = make_session_id();
    trace("client", "client_session=" + std::to_string(client_session));
    HelloMsg hello{.client_id = 0};
    auto hello_msg = build_ctrl_msg(CTRL_HELLO, client_session, args.job_id, args.resource_index, &hello,
                                    sizeof(hello));
    trace("client", "sending HELLO");
    if (!send_ctrl_msg(ctx, ctx.peer, hello_msg, args.timeout_ms, "HELLO")) {
        cleanup(ctx);
        return 1;
    }

    CtrlHdr mr_hdr{};
    std::vector<uint8_t> mr_payload;
    trace("client", "waiting for MRDESC");
    if (!recv_ctrl_msg(ctx, args.timeout_ms, CTRL_MRDESC, mr_hdr, mr_payload)) {
        cleanup(ctx);
        return 1;
    }
    if (mr_payload.size() < sizeof(MRDesc)) {
        std::cerr << "invalid MRDESC ctrl message" << std::endl;
        cleanup(ctx);
        return 1;
    }
    MRDesc desc{};
    decode_payload_copy(mr_payload.data(), mr_payload.size(), desc);

    if (desc.magic != kMRDescMagic || desc.version != kMRDescVersion) {
        std::cerr << "MRDesc invalid magic/version" << std::endl;
        cleanup(ctx);
        return 1;
    }

    std::cout << "MRDesc received:"
              << " job_id=" << desc.job_id
              << " pid_on_fep=" << desc.pid_on_fep
              << " ri=" << desc.resource_index
              << " rkey=0x" << std::hex << desc.rkey << std::dec
              << " remote_addr=0x" << std::hex << desc.remote_addr << std::dec
              << " len=" << desc.len
              << " access=0x" << std::hex << desc.access << std::dec
              << " reg_epoch=" << desc.reg_epoch
              << std::endl;

    AckMsg ack{.status = 1};
    auto ack_msg = build_ctrl_msg(CTRL_ACK, client_session, desc.job_id, desc.resource_index, &ack,
                                  sizeof(ack));
    trace("client", "sending ACK");
    if (!send_ctrl_msg(ctx, ctx.peer, ack_msg, args.timeout_ms, "ACK")) {
        cleanup(ctx);
        return 1;
    }

    cleanup(ctx);
    return 0;
}

} // namespace

int main(int argc, char** argv)
{
    UET::Test::Libfabric::Args defaults;
    defaults.timeout_ms = 15000;
    const auto args = UET::Test::Libfabric::parse_args(argc, argv, defaults);
    if (args.mode == "server") {
        return run_server(args);
    }
    if (args.mode == "client") {
        return run_client(args);
    }
    std::cerr << "Unknown mode: " << args.mode << std::endl;
    return 1;
}
