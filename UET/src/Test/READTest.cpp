#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <thread>
#include <vector>

#include "../Network_Layer/UDP_Network_Layer.hpp"
#include "../SES/SES.hpp"
#include "../logger/Logger.hpp"

using namespace UET::NetworkLayer;

static void fill_pattern(std::vector<uint8_t>& buf)
{
    for (size_t i = 0; i < buf.size(); ++i) {
        buf[i] = static_cast<uint8_t>(i & 0xFF);
    }
}

static bool should_reorder_packet(const PDStoNET_pkt& pkt)
{
    if (pkt.PDS_type != RUOD_ack_header) {
        return false;
    }
    return pkt.PDS_header.RUOD_ack_header.next_hdr == UET_HDR_RESPONSE_DATA ||
           pkt.PDS_header.RUOD_ack_header.next_hdr == UET_HDR_RESPONSE_DATA_SMALL;
}

static bool send_one_packet(UDPNetworkLayer& udp_tx,
                            UDPNetworkLayer& udp_rx,
                            const PDStoNET_pkt& pkt)
{
    return udp_tx.sendPacket(pkt, "127.0.0.1", udp_rx.getLocalPort()) >= 0;
}

int main()
{
    Logger::initialize("READTest.log", LogLevel::DEBUG, 1, 1);
    SESManager ses_manager;
    resetRudRuntimeStats();

    constexpr uint16_t kListenPort = 2889;
    UDPNetworkLayer udp_rx(kListenPort);
    UDPNetworkLayer udp_tx(0);

    if (!udp_rx.initialize()) {
        std::cerr << "UDP RX initialization failed" << std::endl;
        return 1;
    }
    if (!udp_tx.initialize()) {
        std::cerr << "UDP TX initialization failed" << std::endl;
        return 1;
    }

    const size_t read_len = 8192; // 强制分片，验证 response-with-data 重组。
    std::vector<uint8_t> read_src(read_len);
    std::vector<uint8_t> read_dst(read_len, 0);
    fill_pattern(read_src);

    const uint64_t rkey = 0x1234;
    // 注册 MR：目标端 READ 时从这里取数据。
    ses_manager.register_mr(rkey, reinterpret_cast<uint64_t>(read_src.data()), read_src.size());

    std::atomic<bool> rx_running{true};
    std::thread rx_thread([&]() {
        while (rx_running.load()) {
            PDStoNET_pkt rx_pkt;
            if (udp_rx.receivePDStoNETPacket(50, rx_pkt)) {
                ses_manager.pds_process_manager.pushNetworkPacket(rx_pkt);
            }
        }
    });

    OperationMetadata md;
    md.op_type = READ;
    md.s_pid_on_fep = 1001;
    md.t_pid_on_fep = 2001;
    md.job_id = 12345;
    md.messages_id = 42;
    md.memory.rkey = rkey;
    // start_addr 表示远端 MR 基地址（用于计算 buffer_offset），local_addr 为本地接收缓冲区。
    md.payload.start_addr = reinterpret_cast<uint64_t>(read_src.data());
    md.payload.local_addr = reinterpret_cast<uint64_t>(read_dst.data());
    md.payload.length = read_len;
    md.has_imm_data = false;
    md.use_optimized_header = false;
    md.relative = false;
    md.res_index = 0;
    md.delivery_mode = RUD;

    // 发起 READ 请求（走 SES -> PDS -> UDP -> PDS -> SES 回环）
    ses_manager.lfbric_ses_q.push(md);
    ses_manager.mainChk();

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    int idle_rounds = 0;
    bool has_held_rsp = false;
    PDStoNET_pkt held_rsp{};
    while (std::chrono::steady_clock::now() < deadline && idle_rounds < 50) {
        bool did_work = false;
        PDStoNET_pkt tx_pkt;
        if (ses_manager.pds_process_manager.popNetworkPacket(tx_pkt)) {
            if (should_reorder_packet(tx_pkt)) {
                if (!has_held_rsp) {
                    held_rsp = tx_pkt;
                    has_held_rsp = true;
                } else {
                    if (!send_one_packet(udp_tx, udp_rx, tx_pkt) ||
                        !send_one_packet(udp_tx, udp_rx, held_rsp)) {
                        std::cerr << "sendPacket failed" << std::endl;
                        break;
                    }
                    has_held_rsp = false;
                }
            } else {
                if (has_held_rsp) {
                    if (!send_one_packet(udp_tx, udp_rx, held_rsp)) {
                        std::cerr << "sendPacket failed" << std::endl;
                        break;
                    }
                    has_held_rsp = false;
                }
                if (!send_one_packet(udp_tx, udp_rx, tx_pkt)) {
                    std::cerr << "sendPacket failed" << std::endl;
                    break;
                }
            }
            did_work = true;
        }

        ses_manager.mainChk();

        const auto status = ses_manager.pds_process_manager.getQueueStatus();
        did_work = did_work ||
                   status.pdc_to_net_count != 0 ||
                   status.net_pkt_count != 0 ||
                   status.pdc_to_ses_req_count != 0 ||
                   status.pdc_to_ses_rsp_count != 0 ||
                   status.ses_req_count != 0 ||
                   status.ses_rsp_count != 0;

        if (did_work) {
            idle_rounds = 0;
        } else {
            idle_rounds++;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    if (has_held_rsp) {
        if (!send_one_packet(udp_tx, udp_rx, held_rsp)) {
            std::cerr << "sendPacket failed" << std::endl;
            rx_running.store(false);
            rx_thread.join();
            return 1;
        }
        const auto flush_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(300);
        while (std::chrono::steady_clock::now() < flush_deadline && read_dst != read_src) {
            ses_manager.mainChk();
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }

    rx_running.store(false);
    rx_thread.join();

    // 期望 read_dst 完全等于 read_src
    const RudRuntimeStats stats = getRudRuntimeStats();
    const bool ok = (read_dst == read_src) &&
                    stats.read_response_complete_success == 1 &&
                    stats.failure_rc_no_match == 0 &&
                    stats.failure_rc_partial_write == 0 &&
                    stats.failure_rc_protocol_error == 0 &&
                    stats.failure_rc_no_buffer == 0 &&
                    stats.failure_uet_no_bitmap == 0;
    std::cout << (ok ? "READ test PASS" : "READ test FAIL") << std::endl;
    return ok ? 0 : 1;
}
