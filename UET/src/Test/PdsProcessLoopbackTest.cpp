#include "../PDS/PDS_Manager/process/PDSProcessManager.hpp"

#include <chrono>
#include <condition_variable>
#include <deque>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>

namespace {
class CountingLoopback final : public UET::NetworkLayer::PacketChannel {
public:
    void send_packet(const std::vector<uint8_t>& bytes, std::chrono::milliseconds) override {
        std::lock_guard<std::mutex> lock(mu_);
        packets_.push_back(bytes);
        ++sent_;
        cv_.notify_one();
    }
    std::vector<uint8_t> receive_packet(std::chrono::milliseconds timeout) override {
        std::unique_lock<std::mutex> lock(mu_);
        if (!cv_.wait_for(lock, timeout, [&] { return !packets_.empty(); }))
            throw UET::NetworkLayer::PacketTimeout("process loopback receive timed out");
        auto bytes = std::move(packets_.front());
        packets_.pop_front();
        ++received_;
        return bytes;
    }
    size_t sent() const { std::lock_guard<std::mutex> lock(mu_); return sent_; }
    size_t received() const { std::lock_guard<std::mutex> lock(mu_); return received_; }
private:
    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::deque<std::vector<uint8_t>> packets_;
    size_t sent_ = 0;
    size_t received_ = 0;
};

PDStoNET_pkt sample() {
    PDStoNET_pkt packet{};
    packet.src_fep = 11; packet.dst_fep = 22; packet.PDS_type = RUOD_req_header;
    packet.PDS_header.RUOD_req_header.type = ROD_REQ;
    packet.PDS_header.RUOD_req_header.next_hdr = UET_HDR_REQUEST_STD;
    packet.PDS_header.RUOD_req_header.flags.syn = 1;
    packet.PDS_header.RUOD_req_header.psn = 100;
    packet.PDS_header.RUOD_req_header.spdcid = 3;
    packet.PDS_header.RUOD_req_header.dpdcid = 4;
    packet.SESpkt.bth_type = Standard_Header;
    packet.SESpkt.bth_header.Standard_Header.som = 1;
    packet.SESpkt.bth_header.Standard_Header.eom = 1;
    packet.SESpkt.bth_header.Standard_Header.msg_id = 7;
    packet.SESpkt.bth_header.Standard_Header.request_length = 64;
    packet.SESpkt.payload.resize(64, 0x5a);
    return packet;
}
}

int main() {
    try {
        CountingLoopback channel;
        PDSProcessManager manager;
        manager.setNetworkChannel(channel);
        if (!manager.start()) throw std::runtime_error("PDS process manager start failed");
        if (!manager.hasNetworkChannel()) throw std::runtime_error("PDS network channel was not attached");
        if (!manager.pushNetworkTxPacket(sample()))
            throw std::runtime_error("PDS TX queue rejected packet");

        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (std::chrono::steady_clock::now() < deadline && channel.received() == 0)
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        manager.stop();
        if (channel.sent() == 0 || channel.received() == 0)
            throw std::runtime_error("formal PDS process loop did not drive TX/RX");
        std::cout << "PASS: formal PDS process TX/RX loopback" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "FAIL: " << e.what() << std::endl;
        return 1;
    }
}
