#include "LibfabricTestCommon.hpp"
#include "../logger/Logger.hpp"

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

namespace {

using namespace UET::Test::Libfabric;

constexpr uint8_t kReadPattern = 0xA5;

int run_server(const Args& args)
{
    Logger::initialize("MRDescRead_server.log", LogLevel::INFO, 1, 1);

    FabricCtx ctx{};
    if (setup_fabric(args, ctx, FI_MSG | FI_SEND | FI_RECV | FI_RMA | FI_READ)) {
        cleanup(ctx);
        return 1;
    }

    const uint64_t total_len = args.offset + (args.len * args.clients);
    std::vector<uint8_t> mr(total_len);
    fill_pattern(mr, kReadPattern);

    MRDesc desc{};
    desc.magic = kMRDescMagic;
    desc.version = kMRDescVersion;
    desc.flags = 0;
    desc.job_id = args.job_id;
    desc.pid_on_fep = args.pid_on_fep;
    desc.resource_index = args.resource_index;
    desc.rkey = args.rkey;
    desc.remote_addr = reinterpret_cast<uint64_t>(mr.data());
    desc.len = total_len;
    desc.access = args.access;
    desc.ri_generation = 0;
    desc.reg_epoch = 1;
    desc.mem_type = 1;
    desc.backend_kind = 1;

    if (register_data_mr(ctx, mr.data(), mr.size(), FI_REMOTE_READ | FI_READ)) {
        cleanup(ctx);
        return 1;
    }
    if (use_rdma_backend()) {
        desc.rkey = static_cast<uint32_t>(fi_mr_key(ctx.data_mr));
    }
    desc.backend_kind = use_rdma_backend() ? 2u : 1u;

    std::vector<fi_addr_t> peers(args.clients, FI_ADDR_UNSPEC);
    for (uint32_t i = 0; i < args.clients; ++i) {
        sockaddr_in peer{};
        peer.sin_family = AF_INET;
        peer.sin_port = htons(static_cast<uint16_t>(args.peer_port + i));
        if (inet_pton(AF_INET, args.peer_ip.c_str(), &peer.sin_addr) != 1) {
            std::cerr << "inet_pton peer failed" << std::endl;
            cleanup(ctx);
            return 1;
        }
        fi_addr_t addr = FI_ADDR_UNSPEC;
        const int ret = fi_av_insert(ctx.av, &peer, 1, &addr, 0, nullptr);
        if (ret != 1) {
            std::cerr << "fi_av_insert failed: " << fi_strerror(ret < 0 ? -ret : ret) << std::endl;
            cleanup(ctx);
            return ret < 0 ? ret : 1;
        }
        peers[i] = addr;
    }

    const uint64_t server_session = make_session_id(0);
    std::vector<bool> got_hello(args.clients, false);
    std::vector<uint64_t> client_sessions(args.clients, 0);
    for (uint32_t i = 0; i < args.clients; ++i) {
        HelloMsg hello{};
        CtrlHdr hello_hdr{};
        if (!recv_ctrl_typed(ctx.ep, ctx.rx_cq, args.timeout_ms, CTRL_HELLO, hello, hello_hdr)) {
            cleanup(ctx);
            return 1;
        }
        if (hello.client_id >= args.clients || got_hello[hello.client_id]) {
            std::cerr << "Invalid HELLO" << std::endl;
            cleanup(ctx);
            return 1;
        }
        got_hello[hello.client_id] = true;
        client_sessions[hello.client_id] = hello_hdr.session_id;

        auto msg = build_ctrl_msg(CTRL_MRDESC, server_session, desc.job_id + hello.client_id,
                                  desc.resource_index, &desc, sizeof(desc));
        if (!send_ctrl_msg(ctx.ep, ctx.tx_cq, peers[hello.client_id], msg, args.timeout_ms, "MRDESC")) {
            cleanup(ctx);
            return 1;
        }
    }

    std::vector<bool> done_ok(args.clients, false);
    for (uint32_t i = 0; i < args.clients; ++i) {
        ClientStatusMsg done{};
        CtrlHdr done_hdr{};
        if (!recv_ctrl_typed(ctx.ep, ctx.rx_cq, args.timeout_ms, CTRL_DONE, done, done_hdr)) {
            cleanup(ctx);
            return 1;
        }
        if (done.client_id >= args.clients) {
            std::cerr << "Invalid DONE" << std::endl;
            cleanup(ctx);
            return 1;
        }
        if (client_sessions[done.client_id] != 0 && done_hdr.session_id != client_sessions[done.client_id]) {
            std::cerr << "DONE session mismatch" << std::endl;
            cleanup(ctx);
            return 1;
        }
        done_ok[done.client_id] = (done.status == 1);
    }

    bool all_ok = true;
    for (bool ok : done_ok) {
        if (!ok) {
            all_ok = false;
            break;
        }
    }

    if (all_ok) {
        LOG_INFO(__FUNCTION__, "MRDescReadLibfabric server PASS");
    } else {
        LOG_INFO(__FUNCTION__, "MRDescReadLibfabric server FAIL");
    }
    std::cout << (all_ok ? "MRDescReadLibfabric server PASS" : "MRDescReadLibfabric server FAIL")
              << std::endl;
    cleanup(ctx);
    return all_ok ? 0 : 1;
}

int run_client(const Args& args)
{
    Logger::initialize("MRDescRead_client.log", LogLevel::INFO, 1, 1);

    FabricCtx ctx{};
    if (setup_fabric(args, ctx, FI_MSG | FI_SEND | FI_RECV | FI_RMA | FI_READ)) {
        cleanup(ctx);
        return 1;
    }

    const uint64_t client_session = make_session_id(args.client_id);
    HelloMsg hello{};
    hello.client_id = args.client_id;
    auto hello_msg = build_ctrl_msg(CTRL_HELLO, client_session, args.job_id + args.client_id,
                                    args.resource_index, &hello, sizeof(hello));
    if (!send_ctrl_msg(ctx.ep, ctx.tx_cq, ctx.peer, hello_msg, args.timeout_ms, "HELLO")) {
        cleanup(ctx);
        return 1;
    }

    MRDesc desc{};
    CtrlHdr desc_hdr{};
    if (!recv_ctrl_typed(ctx.ep, ctx.rx_cq, args.timeout_ms, CTRL_MRDESC, desc, desc_hdr)) {
        cleanup(ctx);
        return 1;
    }

    if (desc.magic != kMRDescMagic || desc.version != kMRDescVersion) {
        std::cerr << "Invalid MRDesc" << std::endl;
        cleanup(ctx);
        return 1;
    }

    const uint64_t client_offset = args.offset + (args.len * args.client_id);
    if (client_offset + args.len > desc.len) {
        std::cerr << "Invalid offset/len: offset=" << client_offset
                  << " len=" << args.len
                  << " mr_len=" << desc.len << std::endl;
        cleanup(ctx);
        return 1;
    }

    std::vector<uint8_t> dst(args.len, 0);
    if (register_data_mr(ctx, dst.data(), dst.size(), FI_WRITE | FI_READ | FI_RECV)) {
        cleanup(ctx);
        return 1;
    }

    const uint64_t remote_addr = desc.remote_addr + client_offset;
    const int ret = fi_read(ctx.ep, dst.data(), dst.size(), fi_mr_desc(ctx.data_mr), ctx.peer,
                            remote_addr, desc.rkey, dst.data());
    if (ret) {
        std::cerr << "fi_read failed: " << fi_strerror(-ret) << std::endl;
        cleanup(ctx);
        return 1;
    }

    if (!wait_cq(ctx.tx_cq, args.timeout_ms, "TX CQ")) {
        cleanup(ctx);
        return 1;
    }

    const bool data_ok = verify_pattern(dst, kReadPattern);
    ClientStatusMsg done{};
    done.client_id = args.client_id;
    done.status = data_ok ? 1 : 0;
    auto done_msg = build_ctrl_msg(CTRL_DONE, client_session, args.job_id + args.client_id,
                                   args.resource_index, &done, sizeof(done));
    if (!send_ctrl_msg(ctx.ep, ctx.tx_cq, ctx.peer, done_msg, args.timeout_ms, "DONE")) {
        cleanup(ctx);
        return 1;
    }

    if (data_ok) {
        LOG_INFO(__FUNCTION__, "MRDescReadLibfabric client PASS");
    } else {
        LOG_INFO(__FUNCTION__, "MRDescReadLibfabric client FAIL");
    }
    std::cout << (data_ok ? "MRDescReadLibfabric client PASS" : "MRDescReadLibfabric client FAIL")
              << std::endl;
    cleanup(ctx);
    return data_ok ? 0 : 1;
}

} // namespace

int main(int argc, char** argv)
{
    auto args = UET::Test::Libfabric::parse_args(argc, argv);
    if (args.mode == "server") {
        return run_server(args);
    }
    return run_client(args);
}
