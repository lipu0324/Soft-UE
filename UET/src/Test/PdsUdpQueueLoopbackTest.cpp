#include "../Network_Layer/PdsQueueTransport.hpp"
#include "../Network_Layer/UdpChannel.hpp"

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>

namespace {

PDStoNET_pkt make_packet(uint8_t marker, uint16_t message_id) {
    PDStoNET_pkt packet{};
    packet.src_fep = 11;
    packet.dst_fep = 22;
    packet.PDS_type = RUOD_req_header;
    packet.PDS_header.RUOD_req_header.type = ROD_REQ;
    packet.PDS_header.RUOD_req_header.next_hdr = UET_HDR_REQUEST_STD;
    packet.PDS_header.RUOD_req_header.flags.syn = 1;
    packet.PDS_header.RUOD_req_header.psn = marker;
    packet.PDS_header.RUOD_req_header.spdcid = 3;
    packet.PDS_header.RUOD_req_header.dpdcid = 4;
    packet.SESpkt.bth_type = Standard_Header;
    packet.SESpkt.bth_header.Standard_Header.som = 1;
    packet.SESpkt.bth_header.Standard_Header.eom = 1;
    packet.SESpkt.bth_header.Standard_Header.opcode = 1;
    packet.SESpkt.bth_header.Standard_Header.version = 1;
    packet.SESpkt.bth_header.Standard_Header.msg_id = message_id;
    packet.SESpkt.bth_header.Standard_Header.request_length = 4;
    packet.SESpkt.payload = {marker, static_cast<uint8_t>(marker + 1),
                             static_cast<uint8_t>(marker + 2),
                             static_cast<uint8_t>(marker + 3)};
    return packet;
}

void check_packet(const PDStoNET_pkt& actual, const PDStoNET_pkt& expected,
                  const char* direction) {
    if (actual.SESpkt.payload != expected.SESpkt.payload ||
        actual.SESpkt.bth_header.Standard_Header.opcode !=
            expected.SESpkt.bth_header.Standard_Header.opcode ||
        actual.SESpkt.bth_header.Standard_Header.version !=
            expected.SESpkt.bth_header.Standard_Header.version)
        throw std::runtime_error(std::string(direction) + " packet mismatch");
}

} // namespace

int main(int argc, char** argv) {
    try {
        bool server = false;
        bool role_set = false;
        uint16_t port = 0;
        std::string peer_ip = "127.0.0.1";
        for (int i = 1; i < argc; ++i) {
            const std::string arg = argv[i];
            if (arg == "--server" || arg == "--client") {
                server = arg == "--server";
                role_set = true;
            } else if (arg == "--port" && i + 1 < argc) {
                port = static_cast<uint16_t>(std::stoul(argv[++i]));
            } else if (arg == "--peer" && i + 1 < argc) {
                peer_ip = argv[++i];
            } else {
                throw std::invalid_argument("usage: --server|--client --port PORT [--peer IP]");
            }
        }
        if (!role_set || port == 0)
            throw std::invalid_argument("usage: --server|--client --port PORT [--peer IP]");

        UET::NetworkLayer::UdpChannel channel(server, port, peer_ip);
        ThreadSafeQueue<PDStoNET_pkt> outbound(4), inbound(4);
        UET::NetworkLayer::PdsQueueTransport bridge(outbound, inbound, channel);
        const auto request = make_packet(0x31, 17);
        const auto response = make_packet(0x71, 27);

        if (server) {
            // Deliberately queue the response before the server has received a
            // packet. The first progress call must learn the peer from the
            // client's request, then a later call sends this queued packet.
            if (!outbound.push(response))
                throw std::runtime_error("server response queue rejected packet");
            bool received_request = false;
            bool sent_response = false;
            const auto deadline = std::chrono::steady_clock::now() +
                                  std::chrono::seconds(5);
            while (std::chrono::steady_clock::now() < deadline) {
                bridge.progress(std::chrono::milliseconds(50));
                PDStoNET_pkt received{};
                if (inbound.pop(received)) {
                    check_packet(received, request, "server request");
                    received_request = true;
                }
                if (received_request && outbound.empty()) {
                    sent_response = true;
                    break;
                }
            }
            if (!received_request || !sent_response)
                throw std::runtime_error("UDP server did not learn peer and send queued packet");
        } else {
            if (!outbound.push(request))
                throw std::runtime_error("client request queue rejected packet");
            bool received_response = false;
            const auto deadline = std::chrono::steady_clock::now() +
                                  std::chrono::seconds(5);
            while (std::chrono::steady_clock::now() < deadline) {
                bridge.progress(std::chrono::milliseconds(50));
                PDStoNET_pkt received{};
                if (inbound.pop(received)) {
                    check_packet(received, response, "client response");
                    received_response = true;
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            if (!received_response)
                throw std::runtime_error("UDP client did not receive queued server packet");
        }

        std::cout << "PASS: UDP prequeued outbound peer learning" << std::endl;
        return EXIT_SUCCESS;
    } catch (const std::exception& e) {
        std::cerr << "FAIL: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
}
