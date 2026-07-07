/*******************************************************************************
 * Copyright 2025 Soft UE Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ******************************************************************************/

/**
 * @file             SESTest.cpp
 * @brief            SESTest.cpp
 * @author           softuegroup@gmail.com
 * @version          1.0.0
 * @date             2025-10-29
 * @copyright        Apache License Version 2.0
 *
 * @details
 * SESTest.cpp
 */


using namespace std;
#include <iostream>
#include <algorithm>
#include <atomic>
#include <vector>
#include <thread>
#include <chrono>
#include "../Network_Layer/UDP_Network_Layer.hpp"
using namespace UET::NetworkLayer;
#include "../SES/SES.hpp"
#include "../logger/Logger.hpp"

static bool should_reorder_send_packet(const PDStoNET_pkt& pkt)
{
    if (pkt.PDS_type != RUOD_req_header) {
        return false;
    }
    return pkt.PDS_header.RUOD_req_header.type == RUD_REQ &&
           pkt.PDS_header.RUOD_req_header.flags.syn == 0;
}

static bool is_send_default_response(const PDStoNET_pkt& pkt)
{
    return pkt.PDS_type == RUOD_ack_header &&
           pkt.PDS_header.RUOD_ack_header.next_hdr == UET_HDR_RESPONSE &&
           pkt.SESpkt.bth_type == Semantic_Response_Header;
}

static bool send_one_packet(UDPNetworkLayer& udp_tx,
                            UDPNetworkLayer& udp_rx,
                            const PDStoNET_pkt& pkt)
{
    return udp_tx.sendPacket(pkt, "127.0.0.1", udp_rx.getLocalPort()) >= 0;
}

// Packet receive callback function
void packetCallback(const PDStoNET_pkt& packet, const std::string& source_ip, uint16_t source_port) {
    std::cout << "\n=== Packet Received ===" << std::endl;
    std::cout << "Source: " << source_ip << ":" << source_port << std::endl;
    std::cout << "Source FEP: 0x" << std::hex << packet.src_fep << std::dec << std::endl;
    std::cout << "Destination FEP: 0x" << std::hex << packet.dst_fep << std::dec << std::endl;
    std::cout << "PDS Header Type: " << static_cast<int>(packet.PDS_type) << std::endl;
    std::cout << "SES BTH Type: " << static_cast<int>(packet.SESpkt.bth_type) << std::endl;
    std::cout << "Payload bytes: " << packet.SESpkt.payload.size() << std::endl;
    if (!packet.SESpkt.payload.empty()) {
        const size_t preview = std::min<size_t>(packet.SESpkt.payload.size(), 16);
        std::cout << "Payload preview:";
        for (size_t i = 0; i < preview; i++) {
            std::cout << " " << static_cast<int>(packet.SESpkt.payload[i]);
        }
        std::cout << std::endl;
    }

    // Display detailed information based on header type
    switch (packet.PDS_type) {
        case PDS_header_type::RUOD_req_header:
            std::cout << "Type: RUOD Request" << std::endl;
            std::cout << "PSN: " << packet.PDS_header.RUOD_req_header.psn << std::endl;
            std::cout << "SPDCID: " << packet.PDS_header.RUOD_req_header.spdcid << std::endl;
            std::cout << "DPDCID: " << packet.PDS_header.RUOD_req_header.dpdcid << std::endl;
            break;
        case PDS_header_type::RUOD_ack_header:
            std::cout << "Type: RUOD Acknowledgment" << std::endl;
            std::cout << "CACK_PSN: " << packet.PDS_header.RUOD_ack_header.cack_psn << std::endl;
            break;
        case PDS_header_type::RUOD_cp_header:
            std::cout << "Type: RUOD Control Packet" << std::endl;
            std::cout << "PSN: " << packet.PDS_header.RUOD_cp_header.psn << std::endl;
            break;
        case PDS_header_type::nack_header:
            std::cout << "Type: NACK" << std::endl;
            std::cout << "NACK Code: 0x" << std::hex
                      << static_cast<int>(packet.PDS_header.nack_header.nack_code)
                      << std::dec << std::endl;
            break;
        default:
            std::cout << "Type: Unknown" << std::endl;
            break;
    }
    std::cout << "==================" << std::endl;
}


int main()
{
    Logger::initialize("SESTest.log", LogLevel::DEBUG, 1, 1);
    SESManager ses_manager;
    // OperationMetadata packet configuration for establishing new connection
    OperationMetadata conn_metadata;
    constexpr uint16_t kListenPort = 2887;

    // Create UDP network instances:
    // - RX binds to the well-known port and feeds packets back into PDS
    // - TX binds to an ephemeral port and sends PDStoNET packets over UDP
    //
    // This is essentially a "manual progress engine" for the prototype:
    //   upper-layer metadata -> SES -> PDS -> (popNetworkPacket) -> UDP send
    //   UDP recv -> (pushNetworkPacket) -> PDS -> SES
    UDPNetworkLayer udp_rx(kListenPort);
    UDPNetworkLayer udp_tx(0);

    udp_rx.setPacketCallback(packetCallback);

    if (!udp_rx.initialize()) {
        std::cerr << "Initialization failed" << std::endl;
        return 1;
    }
    if (!udp_tx.initialize()) {
        std::cerr << "Initialization failed" << std::endl;
        return 1;
    }

    std::atomic<bool> rx_running{true};
    std::thread rx_thread([&]() {
        while (rx_running.load()) {
            PDStoNET_pkt rx_pkt;
            if (udp_rx.receivePDStoNETPacket(50, rx_pkt)) {
                // Feed packets received from UDP back into the PDS manager,
                // so SES/PDC state machines can consume them during mainChk().
                ses_manager.pds_process_manager.pushNetworkPacket(rx_pkt);
            }
        }
    });

    // Operation type: Use SEND operation to establish connection
    conn_metadata.op_type = SEND; // SEND = 1
    // Endpoint information
    conn_metadata.s_pid_on_fep = 1001; // Source endpoint process ID
    conn_metadata.t_pid_on_fep = 2001; // Target endpoint process ID
    // Job identifier
    conn_metadata.job_id = 12345;  // Job ID for connection session
    conn_metadata.messages_id = 1; // Message identifier (connection request)
    // Memory region configuration
    conn_metadata.memory.rkey = 0x1234567890ABCDEF; // Memory key
    conn_metadata.memory.idempotent_safe = true;    // Idempotent operation safe
    // Payload configuration (connection request data)
    std::vector<uint8_t> send_buf(8192);
    std::vector<uint8_t> recv_buf(send_buf.size(), 0);
    for (size_t i = 0; i < send_buf.size(); i++) {
        send_buf[i] = static_cast<uint8_t>(i & 0xFF);
    }
    conn_metadata.payload.start_addr = reinterpret_cast<uint64_t>(send_buf.data());
    conn_metadata.payload.length = send_buf.size();
    conn_metadata.payload.imm_data = 0xDEADBEEF; // Immediate data (connection parameters)
    // Operation flag bits
    //conn_metadata.realtive = false;             // Absolute addressing
    conn_metadata.use_optimized_header = false; // Use standard header
    conn_metadata.has_imm_data = true;          // Carry immediate data
    conn_metadata.delivery_mode = RUD;          // RUD SEND with controlled packet reordering
    // Resource index
    conn_metadata.res_index = 0; // Default resource index
    PostedRecvEntry recv_entry{};
    recv_entry.completion_key = 0xABCDEF;
    recv_entry.base_addr = reinterpret_cast<uint64_t>(recv_buf.data());
    recv_entry.buffer_len = static_cast<uint32_t>(recv_buf.size());
    recv_entry.job_id = conn_metadata.job_id;
    recv_entry.pdc_id = 0;
    recv_entry.src_fep = conn_metadata.s_pid_on_fep;
    ses_manager.postRecv(recv_entry);
    LOG_INFO(__FUNCTION__, "Upper layer packet has been forwarded to SES, entering processing");
    ses_manager.lfbric_ses_q.push(conn_metadata);
    ses_manager.mainChk();

    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    int idle_rounds = 0;
    bool has_held_pkt = false;
    bool response_seen = false;
    bool response_before_missing_chunk = false;
    PDStoNET_pkt held_pkt{};
    while (std::chrono::steady_clock::now() < deadline && idle_rounds < 50) {
        bool did_work = false;
        PDStoNET_pkt tx_pkt;
        if (ses_manager.pds_process_manager.popNetworkPacket(tx_pkt)) {
            if (is_send_default_response(tx_pkt)) {
                response_seen = true;
                if (has_held_pkt) {
                    response_before_missing_chunk = true;
                }
            }
            // Drain PDS->NET queue and send over UDP.
            if (should_reorder_send_packet(tx_pkt)) {
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

        // Drive SES/PDC processing (state transitions, ACK generation, etc.)
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
            std::cerr << "sendPacket failed" << std::endl;
        } else {
            const auto flush_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(300);
            while (std::chrono::steady_clock::now() < flush_deadline && !response_seen) {
                bool did_work = false;
                PDStoNET_pkt tx_pkt;
                if (ses_manager.pds_process_manager.popNetworkPacket(tx_pkt)) {
                    if (is_send_default_response(tx_pkt)) {
                        response_seen = true;
                    }
                    if (!send_one_packet(udp_tx, udp_rx, tx_pkt)) {
                        break;
                    }
                    did_work = true;
                }
                ses_manager.mainChk();
                if (!did_work) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
            }
        }
    }

    rx_running.store(false);
    rx_thread.join();

    const bool payload_ok = (recv_buf == send_buf);
    const bool ok = response_seen && !response_before_missing_chunk && payload_ok;
    std::cout << "response_seen=" << response_seen
              << " response_before_missing_chunk=" << response_before_missing_chunk
              << " payload_ok=" << payload_ok << std::endl;
    std::cout << (ok ? "SEND test PASS" : "SEND test FAIL") << std::endl;
    return ok ? 0 : 1;
}
