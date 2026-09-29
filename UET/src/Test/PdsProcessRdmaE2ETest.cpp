#include "../Network_Layer/RdmaChannel.hpp"
#include "../PDS/PDS_Manager/process/PDSProcessManager.hpp"
#include "../logger/Logger.hpp"

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

constexpr uint32_t kSourceFep = 11;
constexpr uint32_t kDestinationFep = 22;
constexpr uint32_t kJobId = 0x1234;
constexpr uint16_t kMessageId = 7;

std::vector<uint8_t> payload() {
    std::vector<uint8_t> bytes(257);
    for (size_t i = 0; i < bytes.size(); ++i)
        bytes[i] = static_cast<uint8_t>((i * 29u + 7u) & 0xffu);
    return bytes;
}

SES_PDS_req connection_request(const std::vector<uint8_t>& bytes) {
    SES_PDS_req request{};
    request.src_fep = kSourceFep;
    request.dst_fep = kDestinationFep;
    request.mode = ROD;
    request.rod_context = 1;
    request.next_hdr = UET_HDR_REQUEST_STD;
    request.tc = 1;
    request.lock_pdc = true;
    request.tx_pkt_handle = 1;
    request.tss_context = 1;
    request.rsv_pdc_context = 1;
    request.rsv_ccc_context = 1;
    request.pkt.bth_type = Standard_Header;
    auto& header = request.pkt.bth_header.Standard_Header;
    header.som = 1;
    header.eom = 1;
    header.msg_id = kMessageId;
    header.job_id = kJobId;
    header.PIDonFEP = 1;
    header.resource_index = 1;
    header.request_length = static_cast<uint32_t>(bytes.size());
    header.buffer_offset = 1;
    header.initiator = 1;
    header.match_bits = 1;
    request.pkt.payload = bytes;
    request.pkt_len = static_cast<uint16_t>(sizeof(SES_Standard_Header) + bytes.size());
    return request;
}

struct Options {
    UET::NetworkLayer::RdmaChannel::Config rdma;
    bool role_set = false;
};

Options parse_options(int argc, char** argv) {
    Options options;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--server" || arg == "--client") {
            options.rdma.server = arg == "--server";
            options.role_set = true;
        } else if (arg == "--peer" && i + 1 < argc) {
            options.rdma.peer_ip = argv[++i];
        } else if (arg == "--port" && i + 1 < argc) {
            const int port = std::stoi(argv[++i]);
            if (port < 1 || port > 65535)
                throw std::invalid_argument("invalid TCP port");
            options.rdma.tcp_port = static_cast<uint16_t>(port);
        } else if (arg == "--device" && i + 1 < argc) {
            options.rdma.device = argv[++i];
        } else {
            throw std::invalid_argument(
                "usage: pds_process_rdma_e2e_test --server|--client "
                "[--peer IPv4] [--port N] [--device mlx5_1]");
        }
    }
    if (!options.role_set)
        throw std::invalid_argument("select --server or --client");
    return options;
}

bool wait_for(const std::function<bool()>& condition,
              std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (condition()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return condition();
}

} // namespace

int main(int argc, char** argv) {
    try {
        Logger::initialize("pds_process_rdma_e2e.log", LogLevel::DEBUG, true, false);
        const Options options = parse_options(argc, argv);
        UET::NetworkLayer::RdmaChannel channel(options.rdma);
        PDSProcessManager manager;
        manager.setNetworkChannel(channel);
        if (!manager.start())
            throw std::runtime_error("PDS process manager start failed");

        const auto expected = payload();
        if (!options.rdma.server) {
            if (!manager.pushSESRequest(connection_request(expected)))
                throw std::runtime_error("PDS rejected SES connection request");
        }

        const bool established = wait_for(
            [&] { return manager.hasEstablishedPDC(); },
            std::chrono::seconds(15));
        if (!established) {
            const auto queues = manager.getQueueStatus();
            const auto status = manager.getPDSStatus();
            std::cerr << "debug state=" << static_cast<int>(status.state)
                      << " open=" << status.open_cnt
                      << " event=" << status.event_cnt
                      << " net_rx=" << queues.net_pkt_count
                      << " pdc_to_net=" << queues.pdc_to_net_count
                      << " pdc_to_ses=" << queues.pdc_to_ses_req_count
                      << std::endl;
            throw std::runtime_error("formal PDS/RDMA handshake timed out");
        }

        if (options.rdma.server) {
            PDC_SES_req received{};
            const bool delivered = wait_for(
                [&] { return manager.popSESRequest(received); },
                std::chrono::seconds(5));
            if (!delivered)
                throw std::runtime_error("server PDS did not forward packet to SES");
            if (received.pkt.payload != expected)
                throw std::runtime_error("server SES payload mismatch");
            std::cout << "PASS: formal PDS loop + local RDMA handshake and payload"
                      << std::endl;
            // The TPDC worker enqueues its ACK asynchronously. Keep the
            // formal PDS loop alive long enough for progressNetwork() to
            // transfer that ACK over the real RDMA channel before teardown.
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        } else {
            std::cout << "PASS: formal PDS loop + local RDMA handshake" << std::endl;
        }
        manager.stop();
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << std::endl;
        return EXIT_FAILURE;
    }
}
