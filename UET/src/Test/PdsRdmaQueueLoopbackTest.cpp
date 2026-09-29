#include "../Network_Layer/RdmaChannel.hpp"
#include "../Network_Layer/PdsQueueTransport.hpp"

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {
PDStoNET_pkt packet() {
    PDStoNET_pkt p{};
    p.src_fep = 11; p.dst_fep = 22; p.PDS_type = RUOD_req_header;
    p.PDS_header.RUOD_req_header.type = ROD_REQ;
    p.PDS_header.RUOD_req_header.next_hdr = UET_HDR_REQUEST_STD;
    p.PDS_header.RUOD_req_header.flags.syn = 1;
    p.PDS_header.RUOD_req_header.psn = 100;
    p.PDS_header.RUOD_req_header.spdcid = 3;
    p.PDS_header.RUOD_req_header.dpdcid = 4;
    p.SESpkt.bth_type = Standard_Header;
    p.SESpkt.bth_header.Standard_Header.som = 1;
    p.SESpkt.bth_header.Standard_Header.eom = 1;
    p.SESpkt.bth_header.Standard_Header.msg_id = 7;
    p.SESpkt.bth_header.Standard_Header.request_length = 257;
    p.SESpkt.payload.resize(257);
    for (size_t i = 0; i < p.SESpkt.payload.size(); ++i)
        p.SESpkt.payload[i] = static_cast<uint8_t>((i * 29u + 7u) & 0xffu);
    return p;
}
}

int main(int argc, char** argv) {
    try {
        UET::NetworkLayer::RdmaChannel::Config config;
        bool role = false;
        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--server" || arg == "--client") { config.server = arg == "--server"; role = true; }
            else if (arg == "--peer" && i + 1 < argc) config.peer_ip = argv[++i];
            else if (arg == "--port" && i + 1 < argc) config.tcp_port = static_cast<uint16_t>(std::stoi(argv[++i]));
            else if (arg == "--device" && i + 1 < argc) config.device = argv[++i];
            else throw std::invalid_argument("invalid arguments");
        }
        if (!role) throw std::invalid_argument("select --server or --client");
        UET::NetworkLayer::RdmaChannel channel(config);
        ThreadSafeQueue<PDStoNET_pkt> outbound(8), inbound(8);
        UET::NetworkLayer::PdsQueueTransport bridge(outbound, inbound, channel);
        const auto expected = packet();
        if (!config.server) outbound.push(expected);
        bool got = false;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
        while (std::chrono::steady_clock::now() < deadline) {
            bridge.progress(std::chrono::milliseconds(10));
            PDStoNET_pkt received{};
            if (inbound.pop(received)) {
                if (received.SESpkt.payload != expected.SESpkt.payload)
                    throw std::runtime_error("PDS payload mismatch");
                got = true;
                if (config.server) {
                    outbound.push(received);
                    bridge.progress(std::chrono::milliseconds(100));
                    break;
                } else break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        if (!got) throw std::runtime_error("PDS queue RDMA loopback timed out");
        std::cout << "PASS: PDS queue TX/RX over mlx5_1" << std::endl;
        return EXIT_SUCCESS;
    } catch (const std::exception& e) {
        std::cerr << "FAIL: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
}
