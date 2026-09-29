#include "../Network_Layer/PdsPacketCodec.hpp"
#include "../Network_Layer/PdsQueueTransport.hpp"
#include "../PDS/PDS_Manager/PDSManager.hpp"

#include <cassert>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <vector>

namespace {

class LoopbackChannel final : public UET::NetworkLayer::PacketChannel {
public:
    void send_packet(const std::vector<uint8_t>& bytes,
                     std::chrono::milliseconds) override {
        {
            std::lock_guard<std::mutex> lock(mu_);
            packets_.push_back(bytes);
        }
        cv_.notify_one();
    }

    std::vector<uint8_t> receive_packet(std::chrono::milliseconds timeout) override {
        std::unique_lock<std::mutex> lock(mu_);
        if (!cv_.wait_for(lock, timeout, [&] { return !packets_.empty(); }))
            throw UET::NetworkLayer::PacketTimeout("loopback receive timed out");
        auto packet = std::move(packets_.front());
        packets_.pop_front();
        return packet;
    }

private:
    std::mutex mu_;
    std::condition_variable cv_;
    std::deque<std::vector<uint8_t>> packets_;
};

PDStoNET_pkt sample_packet() {
    PDStoNET_pkt packet{};
    packet.src_fep = 11;
    packet.dst_fep = 22;
    packet.PDS_type = RUOD_req_header;
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
    packet.SESpkt.bth_header.Standard_Header.request_length = 32;
    packet.SESpkt.payload.resize(32);
    for (size_t i = 0; i < packet.SESpkt.payload.size(); ++i)
        packet.SESpkt.payload[i] = static_cast<uint8_t>(i ^ 0xa5u);
    return packet;
}

} // namespace

int main() {
    LoopbackChannel channel;
    PDS_Manager manager;
    if (!manager.initPDSM()) throw std::runtime_error("PDS manager initialization failed");
    manager.attachNetworkChannel(channel);

    const auto expected = sample_packet();
    if (!manager.PDStoNet.push(expected)) throw std::runtime_error("TX queue push failed");
    if (manager.progressNetwork(std::chrono::milliseconds(100)) != 2)
        throw std::runtime_error("PDS network progress did not complete TX/RX loopback");

    PDStoNET_pkt actual{};
    if (!manager.Net_rx_pkt_q.pop(actual))
        throw std::runtime_error("PDS RX queue did not receive loopback packet");
    assert(actual.src_fep == expected.src_fep);
    assert(actual.dst_fep == expected.dst_fep);
    assert(actual.PDS_header.RUOD_req_header.psn == expected.PDS_header.RUOD_req_header.psn);
    assert(actual.SESpkt.payload == expected.SESpkt.payload);

    manager.TPDC_Processmanager.stop();
    manager.IPDC_Processmanager.stop();
    std::cout << "PASS: formal PDS queue TX/RX loopback" << std::endl;
}
