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
    packet.SESpkt.bth_header.Standard_Header.opcode = 1; // SEND
    packet.SESpkt.bth_header.Standard_Header.version = 2;
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
    assert(decoded.SESpkt.bth_header.Standard_Header.opcode == 1); // SEND
    assert(decoded.SESpkt.bth_header.Standard_Header.version == 2);
    assert(decoded.SESpkt.payload == packet.SESpkt.payload);

    PDStoNET_pkt response{};
    response.src_fep = 22;
    response.dst_fep = 11;
    response.PDS_type = RUOD_ack_header;
    response.PDS_header.RUOD_ack_header.type = ACK;
    response.PDS_header.RUOD_ack_header.next_hdr = UET_HDR_RESPONSE;
    response.PDS_header.RUOD_ack_header.spdcid = 4;
    response.PDS_header.RUOD_ack_header.dpdcid = 3;
    response.SESpkt.bth_type = Semantic_Response_Header;
    response.SESpkt.bth_header.Semantic_Response_Header.list = 1;
    response.SESpkt.bth_header.Semantic_Response_Header.opcode = 1; // default response
    response.SESpkt.bth_header.Semantic_Response_Header.version = 2;
    response.SESpkt.bth_header.Semantic_Response_Header.return_code =
        static_cast<uint8_t>(RSP_RETURN_CODE::RC_OK);
    response.SESpkt.bth_header.Semantic_Response_Header.message_id = 5;
    response.SESpkt.bth_header.Semantic_Response_Header.job_id = 0x123456;
    response.SESpkt.bth_header.Semantic_Response_Header.modified_length = 5;
    const auto response_wire = UET::NetworkLayer::PdsPacketCodec::encode(response);
    const auto response_decoded = UET::NetworkLayer::PdsPacketCodec::decode(
        response_wire.data(), response_wire.size());
    assert(response_decoded.SESpkt.bth_type == Semantic_Response_Header);
    assert(response_decoded.SESpkt.bth_header.Semantic_Response_Header.opcode ==
           1); // default response
    assert(response_decoded.SESpkt.bth_header.Semantic_Response_Header.version == 2);
    assert(response_decoded.SESpkt.bth_header.Semantic_Response_Header.job_id ==
           0x123456);

    PDStoNET_pkt response_with_data = response;
    response_with_data.SESpkt.bth_type = Semantic_Response_with_Data_Header;
    response_with_data.SESpkt.bth_header.Semantic_Response_with_Data_Header.list = 1;
    response_with_data.SESpkt.bth_header.Semantic_Response_with_Data_Header.opcode = 2;
    response_with_data.SESpkt.bth_header.Semantic_Response_with_Data_Header.version = 1;
    response_with_data.SESpkt.bth_header.Semantic_Response_with_Data_Header.return_code =
        static_cast<uint8_t>(RSP_RETURN_CODE::RC_OK);
    response_with_data.SESpkt.bth_header.Semantic_Response_with_Data_Header.response_message_id = 5;
    response_with_data.SESpkt.bth_header.Semantic_Response_with_Data_Header.job_id = 0xabcdef;
    response_with_data.SESpkt.bth_header.Semantic_Response_with_Data_Header.read_request_msg_id = 9;
    response_with_data.SESpkt.bth_header.Semantic_Response_with_Data_Header.payload_length = 3;
    response_with_data.SESpkt.bth_header.Semantic_Response_with_Data_Header.modified_length = 0;
    response_with_data.SESpkt.bth_header.Semantic_Response_with_Data_Header.message_offset = 2;
    response_with_data.SESpkt.payload = {9, 8, 7};
    const auto response_data_wire = UET::NetworkLayer::PdsPacketCodec::encode(response_with_data);
    const auto response_data_decoded = UET::NetworkLayer::PdsPacketCodec::decode(
        response_data_wire.data(), response_data_wire.size());
    assert(response_data_decoded.SESpkt.bth_type == Semantic_Response_with_Data_Header);
    assert(response_data_decoded.SESpkt.bth_header.Semantic_Response_with_Data_Header.opcode == 2);
    assert(response_data_decoded.SESpkt.bth_header.Semantic_Response_with_Data_Header.job_id ==
           0xabcdef);
    assert(response_data_decoded.SESpkt.payload == response_with_data.SESpkt.payload);

    PDStoNET_pkt optimized_response = response_with_data;
    optimized_response.SESpkt.bth_type = Optimized_Response_with_Data_Header;
    optimized_response.SESpkt.bth_header.Optimized_Response_with_Data_Header.list = 0;
    optimized_response.SESpkt.bth_header.Optimized_Response_with_Data_Header.opcode = 3;
    optimized_response.SESpkt.bth_header.Optimized_Response_with_Data_Header.version = 2;
    optimized_response.SESpkt.bth_header.Optimized_Response_with_Data_Header.payload_length = 3;
    optimized_response.SESpkt.bth_header.Optimized_Response_with_Data_Header.job_id = 0x654321;
    optimized_response.SESpkt.bth_header.Optimized_Response_with_Data_Header.original_request_psn = 77;
    const auto optimized_wire = UET::NetworkLayer::PdsPacketCodec::encode(optimized_response);
    const auto optimized_decoded = UET::NetworkLayer::PdsPacketCodec::decode(
        optimized_wire.data(), optimized_wire.size());
    assert(optimized_decoded.SESpkt.bth_type == Optimized_Response_with_Data_Header);
    assert(optimized_decoded.SESpkt.bth_header.Optimized_Response_with_Data_Header.opcode == 3);
    assert(optimized_decoded.SESpkt.bth_header.Optimized_Response_with_Data_Header.job_id ==
           0x654321);
    assert(optimized_decoded.SESpkt.payload == optimized_response.SESpkt.payload);

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
