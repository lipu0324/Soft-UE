#include "LibfabricTestCommon.hpp"
#include "../logger/Logger.hpp"

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace {

using namespace UET::Test::Libfabric;

constexpr uint8_t kWritePattern = 0x5A;

static void trace(const std::string& role, const std::string& msg)
{
    std::cerr << "[MRDescWrite][" << role << "] " << msg << std::endl;
}

int run_server(const Args& args)
{
    Logger::initialize(
        "MRDescWrite_server_" + std::to_string(static_cast<uint64_t>(getpid())) + ".log",
        LogLevel::INFO, 1, 1);

    trace("server", "run_server start");
    const int timeout_ms = std::max(args.timeout_ms, compute_timeout_ms(args.len, args.clients));
    FabricCtx ctx{};
    if (setup_fabric(args, ctx, FI_MSG | FI_SEND | FI_RECV | FI_RMA | FI_WRITE)) {
        cleanup(ctx);
        return 1;
    }
    trace("server", "setup_fabric ready");

    const uint64_t total_len = args.offset + (args.len * args.clients);
    std::vector<uint8_t> mr(total_len, 0);

    MRDesc desc_base{};
    desc_base.magic = kMRDescMagic;
    desc_base.version = kMRDescVersion;
    desc_base.flags = 0;
    desc_base.job_id = args.job_id;
    desc_base.pid_on_fep = args.pid_on_fep;
    desc_base.resource_index = args.resource_index;
    desc_base.rkey = args.rkey;
    desc_base.remote_addr = reinterpret_cast<uint64_t>(mr.data());
    desc_base.len = total_len;
    desc_base.access = args.access;
    desc_base.ri_generation = 0;
    desc_base.reg_epoch = 1;
    desc_base.mem_type = 1;
    if (register_data_mr(ctx, mr.data(), mr.size(), FI_REMOTE_WRITE | FI_READ | FI_WRITE)) {
        cleanup(ctx);
        return 1;
    }
    trace("server", "register_data_mr ok len=" + std::to_string(mr.size()));
    if (use_rdma_backend()) {
        desc_base.rkey = static_cast<uint32_t>(fi_mr_key(ctx.data_mr));
    }
    desc_base.backend_kind = use_rdma_backend() ? 2u : 1u;

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
    trace("server", "server_session=" + std::to_string(server_session));
    std::vector<bool> got_hello(args.clients, false);
    std::vector<uint64_t> client_sessions(args.clients, 0);
    for (uint32_t i = 0; i < args.clients; ++i) {
        HelloMsg hello{};
        CtrlHdr hello_hdr{};
        trace("server", "waiting for HELLO");
        if (!recv_ctrl_typed(ctx.ep, ctx.rx_cq, timeout_ms, CTRL_HELLO, hello, hello_hdr)) {
            cleanup(ctx);
            return 1;
        }
        trace("server", "HELLO received client_id=" + std::to_string(hello.client_id) +
                            " session=" + std::to_string(hello_hdr.session_id));
        if (hello.client_id >= args.clients || got_hello[hello.client_id]) {
            std::cerr << "Invalid HELLO" << std::endl;
            cleanup(ctx);
            return 1;
        }
        got_hello[hello.client_id] = true;
        client_sessions[hello.client_id] = hello_hdr.session_id;

        MRDesc desc = desc_base;
        desc.job_id = args.job_id + hello.client_id;
        auto msg = build_ctrl_msg(CTRL_MRDESC, server_session, desc.job_id, desc.resource_index, &desc,
                                  sizeof(desc));
        trace("server", "sending MRDESC client_id=" + std::to_string(hello.client_id));
        if (!send_ctrl_msg(ctx.ep, ctx.tx_cq, peers[hello.client_id], msg, timeout_ms, "MRDESC")) {
            cleanup(ctx);
            return 1;
        }
    }

    std::vector<bool> done_ok(args.clients, false);
    std::vector<ClientStatusMsg> done_msgs(args.clients);
    std::vector<bool> got_done(args.clients, false);
    for (uint32_t i = 0; i < args.clients; ++i) {
        ClientStatusMsg done{};
        CtrlHdr done_hdr{};
        trace("server", "waiting for DONE");
        if (!recv_ctrl_typed(ctx.ep, ctx.rx_cq, timeout_ms, CTRL_DONE, done, done_hdr)) {
            cleanup(ctx);
            return 1;
        }
        trace("server", "DONE received client_id=" + std::to_string(done.client_id) +
                            " status=" + std::to_string(done.status));
        if (done.client_id >= args.clients || got_done[done.client_id]) {
            std::cerr << "Invalid DONE" << std::endl;
            cleanup(ctx);
            return 1;
        }
        if (client_sessions[done.client_id] != 0 && done_hdr.session_id != client_sessions[done.client_id]) {
            std::cerr << "DONE session mismatch" << std::endl;
            cleanup(ctx);
            return 1;
        }
        got_done[done.client_id] = true;
        done_msgs[done.client_id] = done;
    }

    std::mutex ack_mu;
    std::vector<std::thread> workers;
    workers.reserve(args.clients);
    for (uint32_t i = 0; i < args.clients; ++i) {
        workers.emplace_back([&, i]() {
            const auto& done = done_msgs[i];
            const uint64_t client_offset = args.offset + (args.len * done.client_id);
            const bool ok = (done.status == 1) &&
                wait_range_ok(mr, client_offset, args.len, kWritePattern, timeout_ms);
            if (!ok) {
                std::cerr << "wait_range_ok timeout/fail: client_id=" << done.client_id
                          << " offset=" << client_offset
                          << " len=" << args.len
                          << " timeout_ms=" << timeout_ms << std::endl;
                dump_range_diagnostics(mr, client_offset, args.len, kWritePattern);
            }
            done_ok[done.client_id] = ok;

            ClientStatusMsg ack{};
            ack.client_id = done.client_id;
            ack.status = ok ? 1 : 0;
            {
                std::lock_guard<std::mutex> lock(ack_mu);
                auto ack_msg = build_ctrl_msg(CTRL_ACK, server_session, args.job_id + done.client_id,
                                              args.resource_index, &ack, sizeof(ack));
                trace("server", "sending ACK client_id=" + std::to_string(done.client_id) +
                                    " status=" + std::to_string(ack.status));
                if (!send_ctrl_msg(ctx.ep, ctx.tx_cq, peers[done.client_id], ack_msg, timeout_ms, "ACK")) {
                    return;
                }
            }
            std::cerr << "ACK sent: client_id=" << done.client_id
                      << " status=" << ack.status << std::endl;
        });
    }

    for (auto& worker : workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }

    bool all_ok = true;
    for (bool ok : done_ok) {
        if (!ok) {
            all_ok = false;
            break;
        }
    }

    std::cout << (all_ok ? "MRDescWriteLibfabric server PASS" : "MRDescWriteLibfabric server FAIL")
              << std::endl;
    cleanup(ctx);
    return all_ok ? 0 : 1;
}

int run_client(const Args& args)
{
    Logger::initialize(
        "MRDescWrite_client" + std::to_string(args.client_id) + "_" +
            std::to_string(static_cast<uint64_t>(getpid())) + ".log",
        LogLevel::INFO, 1, 1);

    trace("client", "run_client start");
    const int base_timeout_ms = std::max(args.timeout_ms, compute_timeout_ms(args.len, args.clients));
    const int timeout_ms = std::min(base_timeout_ms * 2, INT32_MAX);
    FabricCtx ctx{};
    if (setup_fabric(args, ctx, FI_MSG | FI_SEND | FI_RECV | FI_RMA | FI_WRITE)) {
        cleanup(ctx);
        return 1;
    }
    trace("client", "setup_fabric ready");

    const uint64_t client_session = make_session_id(args.client_id);
    trace("client", "client_session=" + std::to_string(client_session));
    HelloMsg hello{};
    hello.client_id = args.client_id;
    auto hello_msg = build_ctrl_msg(CTRL_HELLO, client_session, args.job_id + args.client_id,
                                    args.resource_index, &hello, sizeof(hello));
    trace("client", "sending HELLO");
    if (!send_ctrl_msg(ctx.ep, ctx.tx_cq, ctx.peer, hello_msg, timeout_ms, "HELLO")) {
        cleanup(ctx);
        return 1;
    }

    MRDesc desc{};
    CtrlHdr desc_hdr{};
    trace("client", "waiting for MRDESC");
    if (!recv_ctrl_typed(ctx.ep, ctx.rx_cq, timeout_ms, CTRL_MRDESC, desc, desc_hdr)) {
        cleanup(ctx);
        return 1;
    }
    trace("client", "MRDESC received job_id=" + std::to_string(desc.job_id) +
                        " rkey=0x" + [&]() {
                            std::ostringstream os;
                            os << std::hex << desc.rkey;
                            return os.str();
                        }());

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

    std::vector<uint8_t> src(args.len);
    fill_pattern(src, kWritePattern);

    if (register_data_mr(ctx, src.data(), src.size(), FI_READ | FI_WRITE | FI_SEND)) {
        cleanup(ctx);
        return 1;
    }
    trace("client", "register_data_mr ok len=" + std::to_string(src.size()));

    const uint64_t remote_addr = desc.remote_addr + client_offset;
    trace("client", "posting fi_write remote_addr=" + std::to_string(remote_addr));
    const int ret = fi_write(ctx.ep, src.data(), src.size(), fi_mr_desc(ctx.data_mr), ctx.peer,
                             remote_addr, desc.rkey, src.data());
    if (ret) {
        std::cerr << "fi_write failed: " << fi_strerror(-ret) << std::endl;
        cleanup(ctx);
        return 1;
    }

    trace("client", "waiting for TX CQ (WRITE)");
    if (!wait_cq(ctx.tx_cq, timeout_ms, "TX CQ")) {
        cleanup(ctx);
        return 1;
    }

    ClientStatusMsg done{};
    done.client_id = args.client_id;
    done.status = 1;
    auto done_msg = build_ctrl_msg(CTRL_DONE, client_session, args.job_id + args.client_id,
                                   args.resource_index, &done, sizeof(done));
    trace("client", "sending DONE");
    if (!send_ctrl_msg(ctx.ep, ctx.tx_cq, ctx.peer, done_msg, timeout_ms, "DONE")) {
        cleanup(ctx);
        return 1;
    }

    ClientStatusMsg ack{};
    CtrlHdr ack_hdr{};
    trace("client", "waiting for ACK");
    if (!recv_ctrl_typed(ctx.ep, ctx.rx_cq, timeout_ms, CTRL_ACK, ack, ack_hdr)) {
        cleanup(ctx);
        return 1;
    }
    trace("client", "ACK received client_id=" + std::to_string(ack.client_id) +
                        " status=" + std::to_string(ack.status));
    if (ack.client_id != args.client_id) {
        std::cerr << "Invalid ACK" << std::endl;
        cleanup(ctx);
        return 1;
    }
    if (ack.status == 1) {
        std::cout << "MRDescWriteLibfabric client PASS" << std::endl;
    } else {
        std::cout << "MRDescWriteLibfabric client FAIL" << std::endl;
        cleanup(ctx);
        return 1;
    }

    cleanup(ctx);
    return 0;
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
