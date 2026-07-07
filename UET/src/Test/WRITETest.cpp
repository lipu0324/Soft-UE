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

static void fill_pattern(std::vector<uint8_t>& buf, uint8_t seed)
{
    for (size_t i = 0; i < buf.size(); ++i) {
        buf[i] = static_cast<uint8_t>((i + seed) & 0xFF);
    }
}

static bool should_reorder_packet(const PDStoNET_pkt& pkt, bool enable_reorder)
{
    if (!enable_reorder) {
        return false;
    }
    if (pkt.PDS_type != RUOD_req_header) {
        return false;
    }
    return pkt.PDS_header.RUOD_req_header.type == RUD_REQ &&
           pkt.PDS_header.RUOD_req_header.flags.syn == 0;
}

static bool send_one_packet(UDPNetworkLayer& udp_tx,
                            UDPNetworkLayer& udp_rx,
                            const PDStoNET_pkt& pkt)
{
    return udp_tx.sendPacket(pkt, "127.0.0.1", udp_rx.getLocalPort()) >= 0;
}

static bool run_write_case(SESManager& ses_manager,
                           UDPNetworkLayer& udp_tx,
                           UDPNetworkLayer& udp_rx,
                           const std::vector<uint8_t>& src,
                           std::vector<uint8_t>& dst,
                           uint64_t rkey,
                           uint32_t msg_id,
                           uint8_t delivery_mode,
                           bool reorder_data_pkts)
{
    OperationMetadata md;
    md.op_type = WRITE;
    md.s_pid_on_fep = 1001;
    md.t_pid_on_fep = 2001;
    md.job_id = 12345;
    md.messages_id = msg_id;
    md.memory.rkey = rkey;
    // 远端目标地址 + 本地源地址（WRITE 使用 local_addr 作为源数据指针）
    md.payload.start_addr = reinterpret_cast<uint64_t>(dst.data());
    md.payload.local_addr = reinterpret_cast<uint64_t>(src.data());
    md.payload.length = src.size();
    md.has_imm_data = false;
    md.use_optimized_header = false;
    md.relative = false;
    md.res_index = 0;
    md.delivery_mode = delivery_mode;

    ses_manager.lfbric_ses_q.push(md);
    ses_manager.mainChk();

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    int idle_rounds = 0;
    bool has_held_pkt = false;
    PDStoNET_pkt held_pkt{};
    while (std::chrono::steady_clock::now() < deadline && idle_rounds < 50) {
        if (dst == src) {
            if (has_held_pkt && !send_one_packet(udp_tx, udp_rx, held_pkt)) {
                return false;
            }
            return true;
        }

        bool did_work = false;
        PDStoNET_pkt tx_pkt;
        if (ses_manager.pds_process_manager.popNetworkPacket(tx_pkt)) {
            if (should_reorder_packet(tx_pkt, reorder_data_pkts)) {
                if (!has_held_pkt) {
                    held_pkt = tx_pkt;
                    has_held_pkt = true;
                } else {
                    if (!send_one_packet(udp_tx, udp_rx, tx_pkt) ||
                        !send_one_packet(udp_tx, udp_rx, held_pkt)) {
                        std::cerr << "sendPacket failed" << std::endl;
                        break;
                    }
                    has_held_pkt = false;
                }
            } else {
                if (has_held_pkt) {
                    if (!send_one_packet(udp_tx, udp_rx, held_pkt)) {
                        std::cerr << "sendPacket failed" << std::endl;
                        break;
                    }
                    has_held_pkt = false;
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

    if (has_held_pkt) {
        if (!send_one_packet(udp_tx, udp_rx, held_pkt)) {
            return false;
        }
        const auto flush_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(300);
        while (std::chrono::steady_clock::now() < flush_deadline && dst != src) {
            ses_manager.mainChk();
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    return dst == src;
}

int main()
{
    Logger::initialize("WRITETest.log", LogLevel::DEBUG, 1, 1);
    SESManager ses_manager;

    constexpr uint16_t kListenPort = 2888;
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

    std::atomic<bool> rx_running{true};
    std::thread rx_thread([&]() {
        while (rx_running.load()) {
            PDStoNET_pkt rx_pkt;
            if (udp_rx.receivePDStoNETPacket(50, rx_pkt)) {
                ses_manager.pds_process_manager.pushNetworkPacket(rx_pkt);
            }
        }
    });

    // 单包 WRITE
    const size_t small_len = 128;
    std::vector<uint8_t> src_small(small_len);
    std::vector<uint8_t> dst_small(small_len, 0);
    fill_pattern(src_small, 0x11);

    const uint64_t rkey_small = 0x2233;
    ses_manager.register_mr(rkey_small,
                            reinterpret_cast<uint64_t>(dst_small.data()),
                            dst_small.size());
    resetRudRuntimeStats();
    const bool ok_small = run_write_case(ses_manager,
                                         udp_tx,
                                         udp_rx,
                                         src_small,
                                         dst_small,
                                         rkey_small,
                                         101,
                                         ROD,
                                         false);

    // 分片 WRITE，RUD 下对数据包做受控乱序。
    const size_t large_len = static_cast<size_t>(MAX_MTU) * 2;
    std::vector<uint8_t> src_large(large_len);
    std::vector<uint8_t> dst_large(large_len, 0);
    fill_pattern(src_large, 0x33);

    const uint64_t rkey_large = 0x3344;
    ses_manager.register_mr(rkey_large,
                            reinterpret_cast<uint64_t>(dst_large.data()),
                            dst_large.size());
    resetRudRuntimeStats();
    const bool ok_large = run_write_case(ses_manager,
                                         udp_tx,
                                         udp_rx,
                                         src_large,
                                         dst_large,
                                         rkey_large,
                                         102,
                                         RUD,
                                         true);

    rx_running.store(false);
    rx_thread.join();

    const RudRuntimeStats stats = getRudRuntimeStats();
    const bool ok = ok_small && ok_large &&
                    stats.write_complete_success == 1 &&
                    stats.failure_rc_no_match == 0 &&
                    stats.failure_rc_partial_write == 0 &&
                    stats.failure_rc_protocol_error == 0 &&
                    stats.failure_rc_no_buffer == 0 &&
                    stats.failure_uet_no_bitmap == 0;
    std::cout << (ok ? "WRITE test PASS" : "WRITE test FAIL") << std::endl;
    return ok ? 0 : 1;
}
