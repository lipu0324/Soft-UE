#include "LibfabricTestCommon.hpp"
#include "../logger/Logger.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace {

using namespace UET::Test::Libfabric;

struct BenchArgs {
    Args common{};
    uint32_t iters = 1000;
    uint32_t warmup_iters = 10;
    uint32_t window = 16;
    bool verify = true;
};

struct ThroughputDoneMsg {
    uint32_t client_id;
    uint32_t status;
    uint64_t total_bytes;
    uint64_t elapsed_ns;
    uint32_t iters;
    uint32_t warmup_iters;
    uint32_t window;
    uint32_t reserved;
};

constexpr uint8_t kSlotPatternBase = 0xA0;

static void trace(const std::string& role, const std::string& msg)
{
    std::cerr << "[MRDescWriteTP][" << role << "] " << msg << std::endl;
}

static std::string format_bw_gbps(uint64_t bytes, uint64_t elapsed_ns)
{
    std::ostringstream os;
    if (elapsed_ns == 0) {
        os << "inf";
        return os.str();
    }
    const double sec = static_cast<double>(elapsed_ns) / 1e9;
    const double gbps = (static_cast<double>(bytes) / sec) / 1e9;
    os << std::fixed << std::setprecision(3) << gbps;
    return os.str();
}

static std::string format_mops(uint64_t iters, uint64_t elapsed_ns)
{
    std::ostringstream os;
    if (elapsed_ns == 0) {
        os << "inf";
        return os.str();
    }
    const double sec = static_cast<double>(elapsed_ns) / 1e9;
    const double mops = (static_cast<double>(iters) / sec) / 1e6;
    os << std::fixed << std::setprecision(3) << mops;
    return os.str();
}

static BenchArgs parse_bench_args(int argc, char** argv)
{
    BenchArgs out;
    out.common = parse_args(argc, argv);
    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);
        auto get_val = [&](const std::string& key, std::string& v) -> bool {
            if (starts_with(arg, key + "=")) {
                v = arg.substr(key.size() + 1);
                return true;
            }
            if (arg == key && i + 1 < argc) {
                v = std::string(argv[++i]);
                return true;
            }
            return false;
        };
        std::string v;
        if (get_val("--iters", v)) {
            out.iters = static_cast<uint32_t>(to_u64(v));
        } else if (get_val("--warmup-iters", v)) {
            out.warmup_iters = static_cast<uint32_t>(to_u64(v));
        } else if (get_val("--window", v)) {
            out.window = static_cast<uint32_t>(to_u64(v));
        } else if (arg == "--no-verify") {
            out.verify = false;
        }
    }
    out.window = std::max<uint32_t>(1, out.window);
    return out;
}

static void fill_slot_patterns(std::vector<uint8_t>& buf, uint64_t len, uint32_t window)
{
    for (uint32_t slot = 0; slot < window; ++slot) {
        const uint8_t value = static_cast<uint8_t>(kSlotPatternBase + (slot & 0x1F));
        const size_t off = static_cast<size_t>(slot * len);
        std::fill(buf.begin() + off, buf.begin() + off + static_cast<size_t>(len), value);
    }
}

static bool verify_slots(const std::vector<uint8_t>& buf, uint64_t len, uint32_t window)
{
    for (uint32_t slot = 0; slot < window; ++slot) {
        const uint8_t value = static_cast<uint8_t>(kSlotPatternBase + (slot & 0x1F));
        if (!verify_range_pattern(buf, static_cast<uint64_t>(slot) * len, len, value)) {
            std::cerr << "slot verify failed: slot=" << slot
                      << " value=0x" << std::hex << static_cast<int>(value) << std::dec
                      << " len=" << len << std::endl;
            dump_range_diagnostics(buf, static_cast<uint64_t>(slot) * len, len, value);
            return false;
        }
    }
    return true;
}

static bool drain_tx_cq(fid_cq* tx_cq, uint32_t count, int timeout_ms)
{
    for (uint32_t i = 0; i < count; ++i) {
        if (!wait_cq(tx_cq, timeout_ms, "TX CQ")) {
            return false;
        }
    }
    return true;
}

static bool run_write_bench(fid_ep* ep, fid_cq* tx_cq, fi_addr_t peer, fid_mr* data_mr,
                            const MRDesc& desc, uint64_t len, uint32_t iters, uint32_t window,
                            int timeout_ms, std::vector<uint8_t>& src, uint64_t& elapsed_ns)
{
    uint32_t outstanding = 0;
    const auto start = std::chrono::steady_clock::now();
    for (uint32_t i = 0; i < iters; ++i) {
        const uint32_t slot = i % window;
        const uint64_t slot_off = static_cast<uint64_t>(slot) * len;
        void* local_desc = fi_mr_desc(data_mr);
        const int ret =
            fi_write(ep, src.data() + slot_off, len, local_desc, peer, desc.remote_addr + slot_off,
                     desc.rkey, src.data() + slot_off);
        if (ret) {
            std::cerr << "fi_write failed at iter=" << i << ": " << fi_strerror(-ret) << std::endl;
            return false;
        }
        ++outstanding;
        if (outstanding == window) {
            if (!drain_tx_cq(tx_cq, outstanding, timeout_ms)) {
                return false;
            }
            outstanding = 0;
        }
    }
    if (outstanding != 0 && !drain_tx_cq(tx_cq, outstanding, timeout_ms)) {
        return false;
    }
    elapsed_ns = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - start)
            .count());
    return true;
}

int run_server(const BenchArgs& args)
{
    Logger::initialize(
        "MRDescWriteTP_server_" + std::to_string(static_cast<uint64_t>(getpid())) + ".log",
        LogLevel::INFO, 1, 1);

    trace("server", "run_server start");
    const int timeout_ms =
        std::max(args.common.timeout_ms, compute_timeout_ms(args.common.len * args.window, args.common.clients));
    FabricCtx ctx{};
    if (setup_fabric(args.common, ctx, FI_MSG | FI_SEND | FI_RECV | FI_RMA | FI_WRITE)) {
        cleanup(ctx);
        return 1;
    }
    trace("server", "setup_fabric ready");

    const uint64_t client_region_len = args.common.len * args.window;
    const uint64_t total_len = client_region_len * args.common.clients;
    std::vector<uint8_t> mr(total_len, 0);
    if (register_data_mr(ctx, mr.data(), mr.size(), FI_REMOTE_WRITE | FI_READ | FI_WRITE)) {
        cleanup(ctx);
        return 1;
    }
    trace("server", "register_data_mr ok len=" + std::to_string(mr.size()));

    std::vector<fi_addr_t> peers(args.common.clients, FI_ADDR_UNSPEC);
    for (uint32_t i = 0; i < args.common.clients; ++i) {
        sockaddr_in peer{};
        peer.sin_family = AF_INET;
        peer.sin_port = htons(static_cast<uint16_t>(args.common.peer_port + i));
        if (inet_pton(AF_INET, args.common.peer_ip.c_str(), &peer.sin_addr) != 1) {
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
    std::vector<uint64_t> client_sessions(args.common.clients, 0);
    for (uint32_t i = 0; i < args.common.clients; ++i) {
        HelloMsg hello{};
        CtrlHdr hello_hdr{};
        trace("server", "waiting for HELLO");
        if (!recv_ctrl_typed(ctx.ep, ctx.rx_cq, timeout_ms, CTRL_HELLO, hello, hello_hdr)) {
            cleanup(ctx);
            return 1;
        }
        if (hello.client_id >= args.common.clients) {
            std::cerr << "invalid HELLO client_id=" << hello.client_id << std::endl;
            cleanup(ctx);
            return 1;
        }
        client_sessions[hello.client_id] = hello_hdr.session_id;

        MRDesc desc{};
        desc.magic = kMRDescMagic;
        desc.version = kMRDescVersion;
        desc.flags = 0;
        desc.job_id = args.common.job_id + hello.client_id;
        desc.pid_on_fep = args.common.pid_on_fep;
        desc.resource_index = args.common.resource_index;
        desc.rkey = use_rdma_backend() ? static_cast<uint32_t>(fi_mr_key(ctx.data_mr)) : args.common.rkey;
        desc.remote_addr = reinterpret_cast<uint64_t>(mr.data()) +
                           (static_cast<uint64_t>(hello.client_id) * client_region_len);
        desc.len = client_region_len;
        desc.access = args.common.access;
        desc.ri_generation = 0;
        desc.reg_epoch = 1;
        desc.mem_type = 1;
        desc.backend_kind = use_rdma_backend() ? 2u : 1u;

        auto msg = build_ctrl_msg(CTRL_MRDESC, server_session, desc.job_id, desc.resource_index, &desc,
                                  sizeof(desc));
        trace("server", "sending MRDESC client_id=" + std::to_string(hello.client_id));
        if (!send_ctrl_msg(ctx.ep, ctx.tx_cq, peers[hello.client_id], msg, timeout_ms, "MRDESC")) {
            cleanup(ctx);
            return 1;
        }
    }

    std::vector<ThroughputDoneMsg> done_msgs(args.common.clients);
    std::vector<bool> done_ok(args.common.clients, false);
    for (uint32_t i = 0; i < args.common.clients; ++i) {
        ThroughputDoneMsg done{};
        CtrlHdr done_hdr{};
        trace("server", "waiting for DONE");
        if (!recv_ctrl_typed(ctx.ep, ctx.rx_cq, timeout_ms, CTRL_DONE, done, done_hdr)) {
            cleanup(ctx);
            return 1;
        }
        if (done.client_id >= args.common.clients) {
            std::cerr << "invalid DONE client_id=" << done.client_id << std::endl;
            cleanup(ctx);
            return 1;
        }
        if (client_sessions[done.client_id] != 0 && done_hdr.session_id != client_sessions[done.client_id]) {
            std::cerr << "DONE session mismatch" << std::endl;
            cleanup(ctx);
            return 1;
        }
        done_msgs[done.client_id] = done;
    }

    uint64_t sum_bytes = 0;
    uint64_t max_elapsed_ns = 0;
    for (uint32_t i = 0; i < args.common.clients; ++i) {
        const auto& done = done_msgs[i];
        const uint64_t client_off = static_cast<uint64_t>(i) * client_region_len;
        bool ok = (done.status == 1);
        if (ok && args.verify) {
            const std::vector<uint8_t> client_view(
                mr.begin() + static_cast<std::ptrdiff_t>(client_off),
                mr.begin() + static_cast<std::ptrdiff_t>(client_off + client_region_len));
            ok = verify_slots(client_view, args.common.len, args.window);
        }
        done_ok[i] = ok;
        sum_bytes += done.total_bytes;
        max_elapsed_ns = std::max(max_elapsed_ns, done.elapsed_ns);

        ClientStatusMsg ack{};
        ack.client_id = i;
        ack.status = ok ? 1 : 0;
        auto ack_msg = build_ctrl_msg(CTRL_ACK, server_session, args.common.job_id + i,
                                      args.common.resource_index, &ack, sizeof(ack));
        trace("server", "sending ACK client_id=" + std::to_string(i) +
                            " status=" + std::to_string(ack.status));
        if (!send_ctrl_msg(ctx.ep, ctx.tx_cq, peers[i], ack_msg, timeout_ms, "ACK")) {
            cleanup(ctx);
            return 1;
        }

        std::cout << "client_id=" << i
                  << " bytes=" << done.total_bytes
                  << " elapsed_ns=" << done.elapsed_ns
                  << " gbps=" << format_bw_gbps(done.total_bytes, done.elapsed_ns)
                  << " mops=" << format_mops(done.iters, done.elapsed_ns)
                  << " iters=" << done.iters
                  << " warmup=" << done.warmup_iters
                  << " window=" << done.window
                  << " status=" << (ok ? "OK" : "FAIL")
                  << std::endl;
    }

    bool all_ok = std::all_of(done_ok.begin(), done_ok.end(), [](bool v) { return v; });
    std::cout << "aggregate bytes=" << sum_bytes
              << " elapsed_ns=" << max_elapsed_ns
              << " gbps=" << format_bw_gbps(sum_bytes, max_elapsed_ns)
              << " clients=" << args.common.clients
              << std::endl;
    std::cout << (all_ok ? "MRDescWriteThroughputLibfabric server PASS"
                         : "MRDescWriteThroughputLibfabric server FAIL")
              << std::endl;

    cleanup(ctx);
    return all_ok ? 0 : 1;
}

int run_client(const BenchArgs& args)
{
    Logger::initialize(
        "MRDescWriteTP_client" + std::to_string(args.common.client_id) + "_" +
            std::to_string(static_cast<uint64_t>(getpid())) + ".log",
        LogLevel::INFO, 1, 1);

    trace("client", "run_client start");
    const int timeout_ms =
        std::max(args.common.timeout_ms, compute_timeout_ms(args.common.len * args.window, 1));
    FabricCtx ctx{};
    if (setup_fabric(args.common, ctx, FI_MSG | FI_SEND | FI_RECV | FI_RMA | FI_WRITE)) {
        cleanup(ctx);
        return 1;
    }
    trace("client", "setup_fabric ready");

    const uint64_t client_session = make_session_id(args.common.client_id);
    HelloMsg hello{};
    hello.client_id = args.common.client_id;
    auto hello_msg = build_ctrl_msg(CTRL_HELLO, client_session, args.common.job_id + args.common.client_id,
                                    args.common.resource_index, &hello, sizeof(hello));
    if (!send_ctrl_msg(ctx.ep, ctx.tx_cq, ctx.peer, hello_msg, timeout_ms, "HELLO")) {
        cleanup(ctx);
        return 1;
    }

    MRDesc desc{};
    CtrlHdr desc_hdr{};
    if (!recv_ctrl_typed(ctx.ep, ctx.rx_cq, timeout_ms, CTRL_MRDESC, desc, desc_hdr)) {
        cleanup(ctx);
        return 1;
    }
    if (desc.magic != kMRDescMagic || desc.version != kMRDescVersion) {
        std::cerr << "invalid MRDesc" << std::endl;
        cleanup(ctx);
        return 1;
    }
    if (desc.len < args.common.len * args.window) {
        std::cerr << "MRDesc too small: desc.len=" << desc.len
                  << " need=" << (args.common.len * args.window) << std::endl;
        cleanup(ctx);
        return 1;
    }

    std::vector<uint8_t> src(args.common.len * args.window, 0);
    fill_slot_patterns(src, args.common.len, args.window);
    if (register_data_mr(ctx, src.data(), src.size(), FI_READ | FI_WRITE | FI_SEND)) {
        cleanup(ctx);
        return 1;
    }
    trace("client", "register_data_mr ok len=" + std::to_string(src.size()));

    uint64_t warmup_elapsed_ns = 0;
    if (args.warmup_iters != 0) {
        trace("client", "warmup start");
        if (!run_write_bench(ctx.ep, ctx.tx_cq, ctx.peer, ctx.data_mr, desc, args.common.len,
                             args.warmup_iters, args.window, timeout_ms, src, warmup_elapsed_ns)) {
            cleanup(ctx);
            return 1;
        }
        trace("client", "warmup done elapsed_ns=" + std::to_string(warmup_elapsed_ns));
    }

    uint64_t elapsed_ns = 0;
    if (!run_write_bench(ctx.ep, ctx.tx_cq, ctx.peer, ctx.data_mr, desc, args.common.len, args.iters,
                         args.window, timeout_ms, src, elapsed_ns)) {
        cleanup(ctx);
        return 1;
    }

    const uint64_t total_bytes = static_cast<uint64_t>(args.iters) * args.common.len;
    std::cout << "bytes=" << total_bytes
              << " elapsed_ns=" << elapsed_ns
              << " gbps=" << format_bw_gbps(total_bytes, elapsed_ns)
              << " mops=" << format_mops(args.iters, elapsed_ns)
              << " len=" << args.common.len
              << " iters=" << args.iters
              << " warmup=" << args.warmup_iters
              << " window=" << args.window
              << std::endl;

    ThroughputDoneMsg done{};
    done.client_id = args.common.client_id;
    done.status = 1;
    done.total_bytes = total_bytes;
    done.elapsed_ns = elapsed_ns;
    done.iters = args.iters;
    done.warmup_iters = args.warmup_iters;
    done.window = args.window;
    auto done_msg = build_ctrl_msg(CTRL_DONE, client_session, args.common.job_id + args.common.client_id,
                                   args.common.resource_index, &done, sizeof(done));
    if (!send_ctrl_msg(ctx.ep, ctx.tx_cq, ctx.peer, done_msg, timeout_ms, "DONE")) {
        cleanup(ctx);
        return 1;
    }

    ClientStatusMsg ack{};
    CtrlHdr ack_hdr{};
    if (!recv_ctrl_typed(ctx.ep, ctx.rx_cq, timeout_ms, CTRL_ACK, ack, ack_hdr)) {
        cleanup(ctx);
        return 1;
    }
    if (ack.client_id != args.common.client_id || ack.status != 1) {
        std::cerr << "invalid ACK status=" << ack.status
                  << " client_id=" << ack.client_id << std::endl;
        cleanup(ctx);
        return 1;
    }

    std::cout << "MRDescWriteThroughputLibfabric client PASS" << std::endl;
    cleanup(ctx);
    return 0;
}

} // namespace

int main(int argc, char** argv)
{
    const BenchArgs args = parse_bench_args(argc, argv);
    if (args.common.mode == "server") {
        return run_server(args);
    }
    return run_client(args);
}
