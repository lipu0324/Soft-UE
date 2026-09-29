#include "../Network_Layer/PacketCodec.hpp"
#include "../Network_Layer/PdsPacketCodec.hpp"
#include "../Network_Layer/PdsQueueTransport.hpp"
#include "../SES/MessageEndpoint.hpp"

#include <cassert>
#include <chrono>
#include <deque>
#include <functional>
#include <iostream>
#include <stdexcept>

namespace {

class MemoryChannel : public UET::NetworkLayer::PacketChannel {
public:
    void send_packet(const std::vector<uint8_t>& bytes,
                     std::chrono::milliseconds) override { packets.push_back(bytes); }
    std::vector<uint8_t> receive_packet(std::chrono::milliseconds) override {
        if (packets.empty()) throw UET::NetworkLayer::PacketTimeout("no frame available");
        auto bytes = std::move(packets.front());
        packets.pop_front();
        return bytes;
    }
    std::deque<std::vector<uint8_t>> packets;
};

void rejects(const std::function<void()>& operation) {
    bool rejected = false;
    try { operation(); } catch (const std::exception&) { rejected = true; }
    assert(rejected);
}

std::vector<uint8_t> sample(size_t length) {
    std::vector<uint8_t> bytes(length);
    for (size_t i = 0; i < length; ++i)
        bytes[i] = static_cast<uint8_t>((i * 17u) & 255u);
    return bytes;
}

} // namespace

int main() {
    using UET::NetworkLayer::PacketCodec;
    MemoryChannel wire;
    UET::SES::MessageEndpoint tx(wire, 1, 2);
    UET::SES::MessageEndpoint rx(wire, 2, 1);
    for (size_t size : {size_t{0}, size_t{1}, size_t{4060}, size_t{4061},
                        size_t{65537}, size_t{1024 * 1024}}) {
        const auto expected = sample(size);
        tx.send(expected);
        assert(rx.receive() == expected);
        assert(wire.packets.empty());
    }

    tx.send(sample(17));
    auto good = wire.packets.front();
    good[PacketCodec::kHeaderSize] ^= 1;
    wire.packets.front() = good;
    rejects([&] { rx.receive(); });

    tx.send(sample(17));
    wire.packets.front().pop_back();
    rejects([&] { rx.receive(); });

    tx.send(sample(4061));
    wire.packets.pop_front();
    rejects([&] { rx.receive(); });
    wire.packets.clear();

    rejects([&] { tx.send(sample(PacketCodec::kMaxMessageSize + 1)); });
    rejects([&] { PacketCodec::decode(nullptr, 0); });

    PDStoNET_pkt packet{};
    packet.src_fep = 11;
    packet.dst_fep = 22;
    packet.PDS_type = RUOD_req_header;
    packet.PDS_header.RUOD_req_header.type = ROD_REQ;
    packet.PDS_header.RUOD_req_header.next_hdr = UET_HDR_REQUEST_STD;
    packet.PDS_header.RUOD_req_header.flags.syn = 1;
    packet.PDS_header.RUOD_req_header.flags.ar = 1;
    packet.PDS_header.RUOD_req_header.psn = 7;
    packet.PDS_header.RUOD_req_header.spdcid = 3;
    packet.PDS_header.RUOD_req_header.dpdcid = 4;
    packet.SESpkt.bth_type = Standard_Header;
    packet.SESpkt.bth_header.Standard_Header.som = 1;
    packet.SESpkt.bth_header.Standard_Header.eom = 1;
    packet.SESpkt.bth_header.Standard_Header.msg_id = 5;
    packet.SESpkt.bth_header.Standard_Header.request_length = 5;
    packet.SESpkt.payload = {1, 2, 3, 4, 5};
    const auto wire_packet = UET::NetworkLayer::PdsPacketCodec::encode(packet);
    const auto decoded = UET::NetworkLayer::PdsPacketCodec::decode(
        wire_packet.data(), wire_packet.size());
    assert(decoded.src_fep == packet.src_fep && decoded.dst_fep == packet.dst_fep);
    assert(decoded.PDS_header.RUOD_req_header.psn == 7);
    assert(decoded.PDS_header.RUOD_req_header.flags.syn == 1);
    assert(decoded.SESpkt.payload == packet.SESpkt.payload);

    auto bad_reserved = wire_packet;
    bad_reserved[7] = 1;
    rejects([&] { UET::NetworkLayer::PdsPacketCodec::decode(
        bad_reserved.data(), bad_reserved.size()); });
    auto bad_pds_length = wire_packet;
    bad_pds_length[16] = 0;
    bad_pds_length[17] = 15;
    rejects([&] { UET::NetworkLayer::PdsPacketCodec::decode(
        bad_pds_length.data(), bad_pds_length.size()); });
    auto bad_fragment = packet;
    bad_fragment.SESpkt.bth_header.Standard_Header.som = 0;
    bad_fragment.SESpkt.bth_header.Standard_Header.eom = 1;
    bad_fragment.SESpkt.bth_header.Standard_Header.diff.som_false.payload_length = 4;
    bad_fragment.SESpkt.bth_header.Standard_Header.diff.som_false.message_offset = 0;
    rejects([&] { UET::NetworkLayer::PdsPacketCodec::encode(bad_fragment); });

    ThreadSafeQueue<PDStoNET_pkt> outbound(4), inbound(4);
    outbound.push(packet);
    UET::NetworkLayer::PdsQueueTransport bridge(outbound, inbound, wire);
    assert(bridge.pump_outbound(std::chrono::milliseconds(100)));
    assert(bridge.pump_inbound(std::chrono::milliseconds(100)));
    PDStoNET_pkt roundtrip{};
    assert(inbound.pop(roundtrip));
    assert(roundtrip.SESpkt.payload == packet.SESpkt.payload);

    ThreadSafeQueue<PDStoNET_pkt> progress_out(2), progress_in(2);
    MemoryChannel progress_wire;
    UET::NetworkLayer::PdsQueueTransport progress_bridge(progress_out, progress_in,
                                                          progress_wire);
    progress_out.push(packet);
    assert(progress_bridge.progress(std::chrono::milliseconds(100)) == 2);
    assert(progress_in.pop(roundtrip));
    assert(progress_bridge.progress(std::chrono::milliseconds(1)) == 0);

    packet.SESpkt.payload.assign(4052, 0xa5);
    packet.SESpkt.bth_header.Standard_Header.request_length = 4052;
    const auto large_wire = UET::NetworkLayer::PdsPacketCodec::encode(packet);
    assert(large_wire.size() <= UET::NetworkLayer::PdsPacketCodec::kMaxPacketSize);
    const auto large_decoded = UET::NetworkLayer::PdsPacketCodec::decode(
        large_wire.data(), large_wire.size());
    assert(large_decoded.SESpkt.payload == packet.SESpkt.payload);
    std::cout << "PASS: bounded binary framing, reassembly, checksum, truncation and order"
              << std::endl;
}
