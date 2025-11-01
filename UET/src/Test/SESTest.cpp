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
#include <thread>
#include <chrono>
#include "../Network_Layer/UDP_Network_Layer.hpp"
using namespace UET::NetworkLayer;
#include "../SES/SES.hpp"
#include "../logger/Logger.hpp"
// Packet receive callback function
void packetCallback(const PDStoNET_pkt& packet, const std::string& source_ip, uint16_t source_port) {
    std::cout << "\n=== Packet Received ===" << std::endl;
    std::cout << "Source: " << source_ip << ":" << source_port << std::endl;
    std::cout << "Source FEP: 0x" << std::hex << packet.src_fep << std::dec << std::endl;
    std::cout << "Destination FEP: 0x" << std::hex << packet.dst_fep << std::dec << std::endl;
    std::cout << "PDS Header Type: " << static_cast<int>(packet.PDS_type) << std::endl;

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
    // Create UDP network instance
    UDPNetworkLayer udp_forwarder(2887);
    // Set callback function
    udp_forwarder.setPacketCallback(packetCallback);
    // Initialize
    if (!udp_forwarder.initialize()) {
        std::cerr << "Initialization failed" << std::endl;
        return 1;
    }
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
    conn_metadata.payload.start_addr = 0x1000;   // Data start address
    conn_metadata.payload.length = 8192;           // Connection request data length (bytes)
    conn_metadata.payload.imm_data = 0xDEADBEEF; // Immediate data (connection parameters)
    // Operation flag bits
    //conn_metadata.realtive = false;             // Absolute addressing
    conn_metadata.use_optimized_header = false; // Use standard header
    conn_metadata.has_imm_data = true;          // Carry immediate data
    // Resource index
    conn_metadata.res_index = 0; // Default resource index
    LOG_INFO(__FUNCTION__, "Upper layer packet has been forwarded to SES, entering processing");
    ses_manager.lfbric_ses_q.push(conn_metadata);
    ses_manager.mainChk();

    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    LOG_INFO(__FUNCTION__, "Remaining packets in PDStoNET queue: " + std::to_string(ses_manager.pds_process_manager.getQueueStatus().pdc_to_net_count));
    LOG_INFO(__FUNCTION__, "Remaining packets in NETtoPDS queue: " + std::to_string(ses_manager.pds_process_manager.getQueueStatus().net_pkt_count));
    LOG_INFO(__FUNCTION__, "Remaining packets in PDS_ses_req queue: " + std::to_string(ses_manager.pds_process_manager.getQueueStatus().pdc_to_ses_req_count));
    LOG_INFO(__FUNCTION__, "Remaining packets in PDS_ses_rsp queue: " + std::to_string(ses_manager.pds_process_manager.getQueueStatus().pdc_to_ses_rsp_count));
    LOG_INFO(__FUNCTION__, "Remaining packets in SES_PDS_req queue: " + std::to_string(ses_manager.pds_process_manager.getQueueStatus().ses_req_count));
    LOG_INFO(__FUNCTION__, "Remaining packets in SES_PDS_rsp queue: " + std::to_string(ses_manager.pds_process_manager.getQueueStatus().ses_rsp_count));

    while(ses_manager.pds_process_manager.getQueueStatus().pdc_to_net_count != 0){
        PDStoNET_pkt pkt;
        ses_manager.pds_process_manager.popNetworkPacket(pkt);
        LOG_INFO(__FUNCTION__, "Packet popped from network layer: ");
        LOG_INFO(__FUNCTION__, "Source FEP: " + std::to_string(pkt.src_fep));
        LOG_INFO(__FUNCTION__, "Destination FEP: " + std::to_string(pkt.dst_fep));
        LOG_INFO(__FUNCTION__, "PDS Header Type: " + std::to_string(static_cast<int>(pkt.PDS_type)));
        ses_manager.pds_process_manager.pushNetworkPacket(pkt);
        LOG_INFO(__FUNCTION__, "Pushed packet into network layer queue");
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        LOG_INFO(__FUNCTION__, "Remaining packets in PDStoNET queue: " + std::to_string(ses_manager.pds_process_manager.getQueueStatus().pdc_to_net_count));
        LOG_INFO(__FUNCTION__, "Remaining packets in NETtoPDS queue: " + std::to_string(ses_manager.pds_process_manager.getQueueStatus().net_pkt_count));
        LOG_INFO(__FUNCTION__, "Remaining packets in PDS_ses_req queue: " + std::to_string(ses_manager.pds_process_manager.getQueueStatus().pdc_to_ses_req_count));
        LOG_INFO(__FUNCTION__, "Remaining packets in PDS_ses_rsp queue: " + std::to_string(ses_manager.pds_process_manager.getQueueStatus().pdc_to_ses_rsp_count));
        LOG_INFO(__FUNCTION__, "Remaining packets in SES_PDS_req queue: " + std::to_string(ses_manager.pds_process_manager.getQueueStatus().ses_req_count));
        LOG_INFO(__FUNCTION__, "Remaining packets in SES_PDS_rsp queue: " + std::to_string(ses_manager.pds_process_manager.getQueueStatus().ses_rsp_count));

        LOG_INFO(__FUNCTION__, "Checking SES queues");
        ses_manager.mainChk();
        LOG_INFO(__FUNCTION__, "Check completed");
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        
    }

    return 0;
}