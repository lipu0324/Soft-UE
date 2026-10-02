#include "../Network_Layer/RdmaChannel.hpp"
#include "../Network_Layer/PacketCodec.hpp"
#include "../Network_Layer/UdpChannel.hpp"
#include "../SES/MessageEndpoint.hpp"

#include <cstdlib>
#include <chrono>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

std::vector<uint8_t> example(size_t length, uint32_t seed) {
    std::vector<uint8_t> data(length);
    for (size_t i = 0; i < length; ++i)
        data[i] = static_cast<uint8_t>((i * 131u + seed * 17u) & 0xffu);
    return data;
}

void interactive_chat(UET::SES::MessageEndpoint& endpoint, bool local_turn) {
    // Keep the chat turn based so the channel remains single threaded: the
    // caller selects the first speaker, and each peer replies after displaying
    // the received line.
    std::cout << "Interactive RDMA chat. Type /quit or quit to close."
              << std::endl;
    for (;;) {
        if (local_turn) {
            std::cout << "you> " << std::flush;
            std::string line;
            if (!std::getline(std::cin, line)) line = "/quit";
            if (line.size() > UET::NetworkLayer::PacketCodec::kMaxMessageSize)
                throw std::length_error("line exceeds the configured maximum");
            endpoint.send(std::vector<uint8_t>(line.begin(), line.end()),
                          std::chrono::seconds(60));
            if (line == "/quit" || line == "quit") return;
        } else {
            const auto bytes = endpoint.receive(std::chrono::hours(24));
            const std::string line(bytes.begin(), bytes.end());
            std::cout << "\npeer> " << line << std::endl;
            if (line == "/quit" || line == "quit") return;
        }
        local_turn = !local_turn;
    }
}

} // namespace

int main(int argc, char** argv) {
    try {
        UET::NetworkLayer::RdmaChannel::Config config;
        bool role_set = false;
        bool udp = false;
        bool interactive = false;
        std::string first_speaker = "server";
        for (int i = 1; i < argc; ++i) {
            const std::string arg = argv[i];
            if (arg == "--server" || arg == "--client") {
                config.server = arg == "--server";
                role_set = true;
            } else if (arg == "--udp") {
                udp = true;
            } else if (arg == "--interactive") {
                interactive = true;
            } else if (arg == "--first" && i + 1 < argc) {
                first_speaker = argv[++i];
                if (first_speaker != "server" && first_speaker != "client")
                    throw std::invalid_argument("--first must be server or client");
            } else if (arg == "--peer" && i + 1 < argc) {
                config.peer_ip = argv[++i];
            } else if (arg == "--port" && i + 1 < argc) {
                const int port = std::stoi(argv[++i]);
                if (port < 1 || port > 65535) throw std::invalid_argument("invalid TCP port");
                config.tcp_port = static_cast<uint16_t>(port);
            } else if (arg == "--device" && i + 1 < argc) {
                config.device = argv[++i];
            } else {
                throw std::invalid_argument("usage: rdma_message_test --server|--client [--interactive] [--first server|client] [--udp] [--peer IPv4] [--port N] [--device mlx5_1]");
            }
        }
        if (!role_set) throw std::invalid_argument("select --server or --client");
        std::unique_ptr<UET::NetworkLayer::PacketChannel> channel;
        if (udp)
            channel = std::make_unique<UET::NetworkLayer::UdpChannel>(
                config.server, config.tcp_port, config.peer_ip);
        else
            channel = std::make_unique<UET::NetworkLayer::RdmaChannel>(config);
        UET::SES::MessageEndpoint endpoint(*channel, config.server ? 2 : 1,
                                           config.server ? 1 : 2);
        if (interactive) {
            const bool local_turn = first_speaker == (config.server ? "server" : "client");
            interactive_chat(endpoint, local_turn);
            return EXIT_SUCCESS;
        }
        const std::vector<size_t> lengths = udp
            ? std::vector<size_t>{0, 1, 4060, 4061, 65537}
            : std::vector<size_t>{0, 1, 4060, 4061, 65537, 1024 * 1024};
        for (size_t i = 0; i < lengths.size(); ++i) {
            const auto expected = example(lengths[i], static_cast<uint32_t>(i));
            if (config.server) {
                const auto received = endpoint.receive(std::chrono::seconds(15));
                if (received != expected) throw std::runtime_error("server payload mismatch");
                endpoint.send(received, std::chrono::seconds(15));
            } else {
                endpoint.send(expected, std::chrono::seconds(15));
                const auto received = endpoint.receive(std::chrono::seconds(15));
                if (received != expected) throw std::runtime_error("client payload mismatch");
            }
            std::cout << "PASS message " << i + 1 << ": " << lengths[i]
                      << " bytes" << std::endl;
        }
        return EXIT_SUCCESS;
    } catch (const std::exception& e) {
        std::cerr << "FAIL: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
}
