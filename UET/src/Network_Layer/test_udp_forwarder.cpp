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
 * @file             test_udp_forwarder.cpp
 * @brief            test_udp_forwarder.cpp
 * @author           softuegroup@gmail.com
 * @version          1.0.0
 * @date             2025-10-29
 * @copyright        Apache License Version 2.0
 *
 * @details
 * This file implements a UDP network layer forwarder test program for PDS packet self-testing.
 */


#include <iostream>
#include <thread>
#include <chrono>
#include "UDP_Network_Layer.hpp"
//#include "../Transport_Layer.hpp"

using namespace UET::NetworkLayer;

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

int main() {
    std::cout << "UDP Network Layer Forwarder Test Program" << std::endl;
    std::cout << "=======================================" << std::endl;
    std::cout << "Implementing UDP encapsulation and self-testing for PDS packets" << std::endl;

    // Create UDP network layer instance
    UDPNetworkLayer udp_forwarder(2887);

    // Set callback function
    udp_forwarder.setPacketCallback(packetCallback);

    // Initialize
    if (!udp_forwarder.initialize()) {
        std::cerr << "Initialization failed" << std::endl;
        return 1;
    }

    std::cout << "UDP forwarder initialized successfully, starting test..." << std::endl;

    // Create test packet
    PDStoNET_pkt test_packet{};
    test_packet.src_fep = 0x12345678;  // Test source FEP
    test_packet.dst_fep = 0x87654321;  // Test destination FEP
    test_packet.PDS_type = PDS_header_type::RUOD_req_header;

    // Fill RUOD request header
    PDS_RUOD_req_header& req_header = test_packet.PDS_header.RUOD_req_header;
    req_header.type = PDS_type::ROD_REQ;
    req_header.next_hdr = PDS_next_hdr::UET_HDR_REQUEST_STD;
    req_header.flags.rsvd = 0;
    req_header.flags.retx = 0;
    req_header.flags.ar = 1;  // Request ACK
    req_header.flags.syn = 0;
    req_header.flags.rsvd1 = 0;
    req_header.clear_psn_off = 0;
    req_header.psn = 1000;
    req_header.spdcid = 1234;
    req_header.dpdcid = 5678;
    req_header.pdc_info = 0;
    req_header.psn_off = 0;

    int test_count = 0;
    const int max_tests = 5;

    std::cout << "\nStarting self-send and self-receive test..." << std::endl;
    std::cout << "Will send " << max_tests << " test packets to localhost" << std::endl;

    while (test_count < max_tests) {
        // Send test packet
        std::cout << "\nSending test packet #" << (test_count + 1) << std::endl;
        int sent_bytes = udp_forwarder.sendPacket(test_packet, "127.0.0.1", 2887);

        if (sent_bytes > 0) {
            std::cout << "Send successful: " << sent_bytes << " bytes" << std::endl;

            // Try to receive packet (wait 1 second)
            std::cout << "Waiting for response..." << std::endl;
            bool received = udp_forwarder.receivePacket(1000);

            if (!received) {
                std::cout << "No response received (possibly timeout)" << std::endl;
            }
        } else {
            std::cout << "Send failed" << std::endl;
        }

        test_count++;

        // If not the last test, wait a bit
        if (test_count < max_tests) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

    std::cout << "\nTest completed!" << std::endl;
    std::cout << "Total sent " << test_count << " test packets" << std::endl;

    // Close UDP forwarder
    udp_forwarder.close();
    std::cout << "UDP forwarder closed" << std::endl;

    return 0;
}