#include <atomic>
#include <cerrno>
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

struct Args {
    std::string mode = "server";
    uint16_t port = 2990;
    uint16_t server_port = 2990;
    uint16_t client_port_base = 3000;
    int clients = 2;
    int client_id = 0;
    size_t segment_len = 1024;
    uint64_t rkey = 0x7788;
    uint32_t job_id = 12345;
    uint32_t msg_id = 7;
    uint32_t src_fep = 0;
    uint32_t dst_fep = 2001;
    uint32_t client_fep_base = 1000;
    int timeout_ms = 3000;
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
        } else if (auto v = get_val("--port"); !v.empty()) {
            args.port = static_cast<uint16_t>(to_u64(v));
        } else if (auto v = get_val("--server-port"); !v.empty()) {
            args.server_port = static_cast<uint16_t>(to_u64(v));
        } else if (auto v = get_val("--client-port-base"); !v.empty()) {
            args.client_port_base = static_cast<uint16_t>(to_u64(v));
        } else if (auto v = get_val("--clients"); !v.empty()) {
            args.clients = static_cast<int>(to_u64(v));
        } else if (auto v = get_val("--client-id"); !v.empty()) {
            args.client_id = static_cast<int>(to_u64(v));
        } else if (auto v = get_val("--segment-len"); !v.empty()) {
            args.segment_len = static_cast<size_t>(to_u64(v));
        } else if (auto v = get_val("--rkey"); !v.empty()) {
            args.rkey = to_u64(v);
        } else if (auto v = get_val("--job-id"); !v.empty()) {
            args.job_id = static_cast<uint32_t>(to_u64(v));
        } else if (auto v = get_val("--msg-id"); !v.empty()) {
            args.msg_id = static_cast<uint32_t>(to_u64(v));
        } else if (auto v = get_val("--src-fep"); !v.empty()) {
            args.src_fep = static_cast<uint32_t>(to_u64(v));
        } else if (auto v = get_val("--dst-fep"); !v.empty()) {
            args.dst_fep = static_cast<uint32_t>(to_u64(v));
        } else if (auto v = get_val("--client-fep-base"); !v.empty()) {
            args.client_fep_base = static_cast<uint32_t>(to_u64(v));
        } else if (auto v = get_val("--timeout-ms"); !v.empty()) {
            args.timeout_ms = static_cast<int>(to_u64(v));
        }
    }
    return args;
}

static bool map_fep_to_port(uint32_t fep,
                            uint32_t base_fep,
                            uint16_t base_port,
                            uint16_t& out_port)
{
    if (fep < base_fep) {
        return false;
    }
    const uint64_t port = static_cast<uint64_t>(base_port) +
                          static_cast<uint64_t>(fep - base_fep);
    if (port > 0xFFFFu) {
        return false;
    }
    out_port = static_cast<uint16_t>(port);
    return true;
}

static int run_server(const Args& args)
{
    Logger::initialize("WRITE_MultiProc_server.log", LogLevel::DEBUG, 1, 1);
    SESManager ses_manager;

    UDPNetworkLayer udp_rx(args.port);
    UDPNetworkLayer udp_tx(0);
    if (!udp_rx.initialize()) {
        std::cerr << "UDP RX initialization failed" << std::endl;
        return 1;
    }
    if (!udp_tx.initialize()) {
        std::cerr << "UDP TX initialization failed" << std::endl;
        return 1;
    }

    const size_t total_len = args.segment_len * static_cast<size_t>(args.clients);
    std::vector<uint8_t> mr(total_len, 0);
    ses_manager.register_mr(args.rkey, reinterpret_cast<uint64_t>(mr.data()), mr.size());

    std::vector<std::vector<uint8_t>> expected;
    expected.reserve(static_cast<size_t>(args.clients));
    for (int i = 0; i < args.clients; ++i) {
        std::vector<uint8_t> seg(args.segment_len);
        fill_pattern(seg, static_cast<uint8_t>(0x10 + i));
        expected.push_back(std::move(seg));
    }

    std::atomic<bool> rx_running{true};
    std::thread rx_thread([&]() {
        while (rx_running.load()) {
            PDStoNET_pkt rx_pkt;
            if (udp_rx.receivePDStoNETPacket(50, rx_pkt)) {
                LOG_DEBUG(__FUNCTION__,
                          "RX packet payload_len=" +
                              std::to_string(rx_pkt.SESpkt.payload.size()));
                ses_manager.pds_process_manager.pushNetworkPacket(rx_pkt);
            }
        }
    });

    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(args.timeout_ms);
    bool ok = false;
    while (std::chrono::steady_clock::now() < deadline) {
        ses_manager.mainChk();

        PDStoNET_pkt out_pkt;
        while (ses_manager.pds_process_manager.popNetworkPacket(out_pkt)) {
            uint16_t dest_port = 0;
            bool has_port = map_fep_to_port(out_pkt.dst_fep,
                                            args.client_fep_base,
                                            args.client_port_base,
                                            dest_port);
            if (!has_port) {
                has_port = map_fep_to_port(out_pkt.src_fep,
                                           args.client_fep_base,
                                           args.client_port_base,
                                           dest_port);
            }
            if (!has_port) {
                LOG_ERROR(__FUNCTION__, "Cannot map response FEP to client port");
                continue;
            }
            LOG_DEBUG(__FUNCTION__,
                      "TX rsp dst_fep=" + std::to_string(out_pkt.dst_fep) +
                          " src_fep=" + std::to_string(out_pkt.src_fep) +
                          " port=" + std::to_string(dest_port));
            const int sent = udp_tx.sendPacket(out_pkt, "127.0.0.1", dest_port);
            if (sent < 0) {
                LOG_ERROR(__FUNCTION__, "Failed to send response packet");
            }
        }

        bool all_ok = true;
        for (int i = 0; i < args.clients; ++i) {
            const size_t off = static_cast<size_t>(i) * args.segment_len;
            if (off + args.segment_len > mr.size()) {
                all_ok = false;
                break;
            }
            if (std::memcmp(mr.data() + off, expected[static_cast<size_t>(i)].data(),
                            args.segment_len) != 0) {
                all_ok = false;
                break;
            }
        }
        const auto status = ses_manager.pds_process_manager.getQueueStatus();
        const bool rsp_queues_empty =
            status.pdc_to_net_count == 0 &&
            status.ses_rsp_count == 0 &&
            status.pdc_to_ses_rsp_count == 0;
        if (all_ok && rsp_queues_empty) {
            ok = true;
            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    rx_running.store(false);
    rx_thread.join();

    if (ok) {
        LOG_INFO(__FUNCTION__, "WRITE multiproc server PASS");
    } else {
        LOG_ERROR(__FUNCTION__, "WRITE multiproc server FAIL");
    }
    std::cout << (ok ? "WRITE multiproc server PASS" : "WRITE multiproc server FAIL")
              << std::endl;
    return ok ? 0 : 1;
}

static int run_client(const Args& args)
{
    Logger::initialize("WRITE_MultiProc_client.log", LogLevel::DEBUG, 1, 1);
    SESManager ses_manager;

    const uint32_t client_fep = (args.src_fep != 0)
                                    ? args.src_fep
                                    : static_cast<uint32_t>(args.client_fep_base + args.client_id);
    uint16_t client_port = 0;
    if (!map_fep_to_port(client_fep, args.client_fep_base, args.client_port_base, client_port)) {
        std::cerr << "Invalid client FEP/port mapping" << std::endl;
        return 1;
    }
    LOG_INFO(__FUNCTION__,
             "Client listen port=" + std::to_string(client_port) +
                 " fep=" + std::to_string(client_fep));

    UDPNetworkLayer udp_rx(client_port);
    UDPNetworkLayer udp_tx(0);
    if (!udp_rx.initialize()) {
        std::cerr << "UDP RX initialization failed" << std::endl;
        return 1;
    }
    if (!udp_tx.initialize()) {
        std::cerr << "UDP TX initialization failed" << std::endl;
        return 1;
    }

    const size_t total_len = args.segment_len * static_cast<size_t>(args.clients);
    ses_manager.register_mr(args.rkey, 0, total_len);

    std::vector<uint8_t> src(args.segment_len);
    fill_pattern(src, static_cast<uint8_t>(0x10 + args.client_id));

    const size_t offset = static_cast<size_t>(args.client_id) * args.segment_len;

    OperationMetadata md;
    md.op_type = WRITE;
    md.s_pid_on_fep = client_fep;
    md.t_pid_on_fep = args.dst_fep;
    md.job_id = args.job_id;
    md.messages_id = args.msg_id; // same msg_id across clients to test key isolation
    md.memory.rkey = args.rkey;
    md.payload.start_addr = static_cast<uint64_t>(offset);
    md.payload.local_addr = reinterpret_cast<uint64_t>(src.data());
    md.payload.length = src.size();
    md.has_imm_data = false;
    md.use_optimized_header = false;
    md.relative = false;
    md.res_index = 0;

    ses_manager.lfbric_ses_q.push(md);
    ses_manager.mainChk();

    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(args.timeout_ms);
    int idle_rounds = 0;
    int sent_packets = 0;
    bool send_failed = false;
    std::atomic<bool> got_rsp{false};
    std::atomic<bool> rsp_ok{false};
    std::atomic<bool> rx_running{true};

    std::thread rx_thread([&]() {
        while (rx_running.load() && !got_rsp.load()) {
            PDStoNET_pkt rx_pkt;
            if (!udp_rx.receivePDStoNETPacket(50, rx_pkt)) {
                continue;
            }
            LOG_DEBUG(__FUNCTION__,
                      "RX pkt bth_type=" + std::to_string(rx_pkt.SESpkt.bth_type) +
                          " msg_id=" +
                          std::to_string(rx_pkt.SESpkt.bth_header.Semantic_Response_Header.message_id) +
                          " rc=" +
                          std::to_string(rx_pkt.SESpkt.bth_header.Semantic_Response_Header.return_code));
            if (rx_pkt.SESpkt.bth_type != Semantic_Response_Header) {
                continue;
            }
            const auto& rsp = rx_pkt.SESpkt.bth_header.Semantic_Response_Header;
            if (rsp.message_id != args.msg_id) {
                continue;
            }
            rsp_ok.store(rsp.return_code == static_cast<uint8_t>(RSP_RETURN_CODE::RC_OK));
            got_rsp.store(true);
        }
    });

    while (std::chrono::steady_clock::now() < deadline && !got_rsp.load()) {
        bool did_work = false;
        PDStoNET_pkt tx_pkt;
        if (ses_manager.pds_process_manager.popNetworkPacket(tx_pkt)) {
            const int sent = udp_tx.sendPacket(tx_pkt, "127.0.0.1", args.server_port);
            if (sent < 0) {
                const int err = errno;
                LOG_ERROR(__FUNCTION__, "sendPacket failed: errno=" + std::to_string(err) +
                                            " strerror=" + std::string(std::strerror(err)));
                std::cerr << "sendPacket failed" << std::endl;
                send_failed = true;
                break;
            }
            LOG_INFO(__FUNCTION__, "TX bytes=" + std::to_string(sent));
            sent_packets++;
            did_work = true;
        }

        ses_manager.mainChk();

        const auto status = ses_manager.pds_process_manager.getQueueStatus();
        did_work = did_work ||
                   status.pdc_to_net_count != 0 ||
                   status.pdc_to_ses_req_count != 0 ||
                   status.pdc_to_ses_rsp_count != 0 ||
                   status.ses_req_count != 0 ||
                   status.ses_rsp_count != 0;

        if (did_work) {
            idle_rounds = 0;
        } else {
            idle_rounds++;
        }

        if (sent_packets == 0 && idle_rounds >= 50) {
            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    rx_running.store(false);
    if (rx_thread.joinable()) {
        rx_thread.join();
    }

    if (!send_failed && sent_packets > 0 && got_rsp.load() && rsp_ok.load()) {
        LOG_INFO(__FUNCTION__, "WRITE multiproc client PASS");
        std::cout << "WRITE multiproc client PASS" << std::endl;
    } else {
        LOG_ERROR(__FUNCTION__, "WRITE multiproc client FAIL");
        std::cout << "WRITE multiproc client FAIL" << std::endl;
    }
    return 0;
}

int main(int argc, char** argv)
{
    const Args args = parse_args(argc, argv);
    if (args.mode == "server") {
        return run_server(args);
    }
    if (args.mode == "client") {
        return run_client(args);
    }
    std::cerr << "Unknown --mode, use server|client" << std::endl;
    return 1;
}
