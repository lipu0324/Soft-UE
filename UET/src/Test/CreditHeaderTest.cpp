#include "Check.hpp"
#include "../Network_Layer/UetWireCodec.hpp"
#include <iostream>

using namespace UET::NetworkLayer;

namespace {
// These literal PDS bytes come from Figures 3-69/3-91/3-92/3-129.
// Compare the encoder against them before using its output as a decoder input.
void check_wire(const PDStoNET_pkt& packet, const std::vector<uint8_t>& expected) {
    for (const bool ipv6 : {false, true})
        for (const bool udp : {false, true})
            for (const bool crc : {false, true}) {
                WireOptions options;
                options.ipv6=ipv6;
                options.udp=udp;
                options.crc=crc;
                options.native_ip_protocol=253;
                const auto encoded=UetWireCodec::encode(packet, options);
                const size_t pds_offset=14+(ipv6 ? 40 : 20)+(udp ? 8 : 4);
                CHECK(std::vector<uint8_t>(encoded.begin()+pds_offset,
                    encoded.begin()+pds_offset+expected.size())==expected);
                const auto decoded=UetWireCodec::decode(encoded.data(), encoded.size(), crc, 253).packet;
                CHECK(decoded.PDS_type==packet.PDS_type);
                if (packet.PDS_type==RUOD_req_header) {
                    CHECK(decoded.PDS_header.RUOD_req_header.type==packet.PDS_header.RUOD_req_header.type);
                    CHECK(decoded.credit_request.ccc_id==0x5a);
                    CHECK(decoded.credit_request.credit_target_units==0xabcdef);
                } else if (packet.PDS_type==RUOD_ack_header) {
                    CHECK(decoded.congestion_ack.type==1);
                    CHECK(decoded.congestion_ack.credit_units==0xabcdef);
                    CHECK(decoded.congestion_ack.received_byte_units==0);
                    CHECK(decoded.congestion_ack.service_time==0);
                    CHECK(decoded.congestion_ack.out_of_order_count==0xffff);
                    // Credit bits must never be overwritten with NSCC service time.
                    auto timestamped=encoded;
                    CHECK(!UetWireCodec::stamp_service_time(timestamped, 1000, 100, crc, 253));
                    CHECK(timestamped==encoded);
                    if (!crc) {
                        auto reserved=encoded;
                        reserved[pds_offset+27]=0xff;
                        reserved[pds_offset+28]=0x12;
                        reserved[pds_offset+29]=0x34;
                        const auto ignored=UetWireCodec::decode(reserved.data(), reserved.size(), false, 253).packet;
                        CHECK(ignored.congestion_ack.credit_units==0xabcdef);
                        CHECK(ignored.congestion_ack.received_byte_units==0);
                    }
                } else {
                    CHECK(decoded.PDS_header.RUOD_cp_header.payload==packet.PDS_header.RUOD_cp_header.payload);
                    CHECK(decoded.PDS_header.RUOD_cp_header.psn==0);
                    CHECK(!decoded.PDS_header.RUOD_cp_header.flags.ar);
                }
                for (size_t truncated_size=0; truncated_size<encoded.size(); ++truncated_size)
                    check_throws<std::invalid_argument>([&] {
                        UetWireCodec::decode(encoded.data(), truncated_size, crc, 253);
                    });
            }
}

void request_headers() {
    for (const auto type : {RUD_CC_REQ, ROD_CC_REQ}) {
        PDStoNET_pkt packet{};
        packet.PDS_type=RUOD_req_header;
        auto& request=packet.PDS_header.RUOD_req_header;
        request.type=type;
        request.next_hdr=UET_HDR_NONE; // Isolate the PDS extension from SES parsing.
        request.flags.syn=1;
        request.psn=0x01020304;
        request.spdcid=0x11;
        request.psn_off=7;
        packet.credit_request.ccc_id=0x5a;
        packet.credit_request.credit_target_units=0xabcdef;
        check_wire(packet, {static_cast<uint8_t>(type==RUD_CC_REQ ? 0x68 : 0x70), 4,
            0, 0, 1, 2, 3, 4, 0, 0x11, 0, 7, 0x5a, 0xab, 0xcd, 0xef});
        packet.credit_request.credit_target_units=0x1000000;
        check_throws<std::invalid_argument>([&] { UetWireCodec::encode(packet, {}); });
    }
}

void acknowledgement_header() {
    PDStoNET_pkt packet{};
    packet.PDS_type=RUOD_ack_header;
    auto& ack=packet.PDS_header.RUOD_ack_header;
    ack.type=ACK_CC;
    ack.next_hdr=UET_HDR_NONE;
    ack.cack_psn=0x01020304;
    ack.spdcid=0x11;
    ack.dpdcid=0x22;
    auto& state=packet.congestion_ack;
    state.type=1;
    state.mpr=3;
    state.credit_units=0xabcdef;
    // Poison inactive NSCC fields: they must neither be emitted nor validated.
    state.received_byte_units=0xffffffff;
    state.service_time=0x1234;
    state.receiver_window_penalty=255;
    check_wire(packet, {0x40, 0, 0, 0, 1, 2, 3, 4, 0, 0x11, 0, 0x22,
        0x10, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0xab, 0xcd, 0xef, 0, 0, 0, 0xff, 0xff});
    state.credit_units=0x1000000;
    check_throws<std::invalid_argument>([&] { UetWireCodec::encode(packet, {}); });
    state.type=2;
    check_throws<std::invalid_argument>([&] { UetWireCodec::encode(packet, {}); });
}

void credit_controls() {
    for (const auto subtype : {Credit, Credit_req}) {
        PDStoNET_pkt packet{};
        packet.PDS_type=RUOD_cp_header;
        auto& control=packet.PDS_header.RUOD_cp_header;
        control.type=CP;
        control.ctl_type=subtype;
        control.spdcid=0x11;
        control.dpdcid=0x22;
        // Credit: credit[23:0], reserved[7:0]. Request: CCC_ID, target[23:0].
        control.payload=subtype==Credit ? 0xabcdef00 : 0x5aabcdef;
        check_wire(packet, {static_cast<uint8_t>(subtype==Credit ? 0x5b : 0x5c),
            static_cast<uint8_t>(subtype==Credit ? 0x80 : 0),
            0, 0, 0, 0, 0, 0, 0, 0x11, 0, 0x22,
            static_cast<uint8_t>(subtype==Credit ? 0xab : 0x5a),
            static_cast<uint8_t>(subtype==Credit ? 0xcd : 0xab),
            static_cast<uint8_t>(subtype==Credit ? 0xef : 0xcd),
            static_cast<uint8_t>(subtype==Credit ? 0 : 0xef)});
    }
}
}

int main() {
    try {
        request_headers();
        acknowledgement_header();
        credit_controls();
        std::cout << "40 credit header carrier/golden cases and bounds passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
