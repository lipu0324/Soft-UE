#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../Runtime/PdsHost.hpp"
#include <iostream>
#include <limits>

using namespace UET::Runtime;
using namespace UET::NetworkLayer;

namespace {
size_t pds_offset(const WireOptions& network) {
    return 14+(network.ipv6?40:20)+(network.udp?8:4);
}
void repair_crc(std::vector<uint8_t>& bytes,const WireOptions& network) {
    if (!network.crc) return;
    const size_t protected_start=14+(network.ipv6?8:12);
    const auto checksum=UetWireCodec::crc32c(bytes.data()+protected_start,bytes.size()-protected_start-4);
    for (size_t index=0;index<4;++index) bytes[bytes.size()-4+index]=checksum>>(24-index*8);
}
PDStoNET_pkt noop(uint32_t sequence=1000,bool syn=true) {
    PDStoNET_pkt packet{}; packet.PDS_type=RUOD_cp_header;
    auto& control=packet.PDS_header.RUOD_cp_header;
    control.type=CP; control.ctl_type=Noop; control.flags.syn=syn; control.flags.ar=1;
    control.spdcid=7; control.dpdcid=512; control.psn=sequence;
    return packet;
}
void decode_classification() {
    for (const bool ipv6:{false,true}) for (const bool udp:{false,true}) for (const bool crc:{false,true}) {
        WireOptions network; network.ipv6=ipv6; network.udp=udp; network.crc=crc;
        const auto canonical=UetWireCodec::encode(noop(),network);
        const auto offset=pds_offset(network);
        for (unsigned type=0;type<32;++type) {
            // Preserve a structurally complete transport header. The second
            // prologue field is zero, valid as either NONE or NOOP.
            auto changed=canonical; changed[offset]=type<<3; changed[offset+1]=0;
            repair_crc(changed,network);
            bool unknown_type=false;
            try { UetWireCodec::decode(changed.data(),changed.size(),crc); }
            catch (const PdsDecodeError& error) {
                CHECK(error.reason()==PdsDecodeError::Reason::UnknownType && error.value()==type);
                unknown_type=true;
            } catch (const std::invalid_argument&) {}
            CHECK(unknown_type==(type==0 || type>=16));
        }
        for (unsigned control_type=10;control_type<16;++control_type) {
            auto changed=canonical;
            changed[offset]|=control_type>>1;
            changed[offset+1]|=(control_type&1)<<7;
            repair_crc(changed,network);
            bool rejected=false;
            try { UetWireCodec::decode(changed.data(),changed.size(),crc); }
            catch (const PdsDecodeError& error) {
                CHECK(error.reason()==PdsDecodeError::Reason::UnknownControlType && error.value()==control_type);
                rejected=true;
            }
            CHECK(rejected);
            if (crc) {
                changed.back()^=1;
                bool invalid_crc=false;
                try { UetWireCodec::decode(changed.data(),changed.size(),true); }
                catch (const PdsDecodeError&) { CHECK(false); }
                catch (const std::invalid_argument&) { invalid_crc=true; }
                CHECK(invalid_crc); // Integrity validation precedes error classification.
            }
        }
    }
}

void unknown_control_does_not_change_context(bool established,bool direct_queue) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& source=fabric.add_host(1); auto& destination=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost target(2,loop,trace,destination); std::vector<PDStoNET_pkt> responses;
    uint16_t remote_context=0;
    source.set_receiver([&](Frame frame) { responses.push_back(UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet); });
    const auto send=[&](PDStoNET_pkt packet) {
        if (!packet.PDS_header.RUOD_cp_header.flags.syn)
            packet.PDS_header.RUOD_cp_header.dpdcid=remote_context;
        if (direct_queue) {
            packet.src_fep=1; packet.dst_fep=2;
            CHECK(target.manager().pushNetworkPacket(packet)); target.wake();
        } else {
            WireOptions network; network.source.ip[3]=1; network.destination.ip[3]=2;
            Frame frame; frame.source=1; frame.destination=2; frame.bytes=UetWireCodec::encode(packet,network);
            CHECK(source.try_send(frame)==SendResult::Accepted);
        }
        loop.run();
    };
    if (established) {
        send(noop()); CHECK(responses.size()==1 && responses.front().PDS_type==RUOD_ack_header);
        remote_context=responses.front().PDS_header.RUOD_ack_header.spdcid;
        responses.clear();
    }
    for (const bool syn:{false,true}) for (unsigned type=10;type<16;++type)
        for (const uint32_t sequence:{0u,established?1001u:1000u}) {
        // A valid next PSN and a forged peer ID must both remain harmless.
        auto unknown=noop(sequence,syn);
        unknown.PDS_header.RUOD_cp_header.ctl_type=type;
        unknown.PDS_header.RUOD_cp_header.spdcid=900;
        send(unknown);
        CHECK(responses.empty());
        CHECK(target.manager().getPDSStatus().open_cnt==(established?1:0));
    }
    CHECK(target.pds_error_counters().pds_ctl_type_invalid==24);
    CHECK(target.pds_error_counters().pds_type_invalid==0);
    send(noop(established?1001:1000,!established));
    CHECK(responses.size()==1 && responses.front().PDS_type==RUOD_ack_header);
    CHECK(responses.front().PDS_header.RUOD_ack_header.cack_psn==(established?1001u:1000u));
    target.clear_pds_error_counters();
    CHECK(target.pds_error_counters().pds_ctl_type_invalid==0);
    target.close(); CHECK(loop.pending()==0);
}

void host_counters_and_crc() {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& source=fabric.add_host(1); auto& destination=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost sender(1,loop,trace,source),target(2,loop,trace,destination);
    WireOptions network; network.source.ip[3]=1; network.destination.ip[3]=2;
    Frame frame; frame.source=1; frame.destination=2;
    const auto canonical=UetWireCodec::encode(noop(),network);
    for (unsigned type=0;type<32;++type) {
        if (type && type<16) continue;
        frame.bytes=canonical; frame.bytes[pds_offset(network)]=type<<3;
        repair_crc(frame.bytes,network);
        CHECK(source.try_send(frame)==SendResult::Accepted); loop.run();
    }
    CHECK(target.pds_error_counters().pds_type_invalid==17);
    CHECK(sender.pds_error_counters().pds_type_invalid==0);
    CHECK(target.manager().getPDSStatus().open_cnt==0 && sender.manager().getPDSStatus().open_cnt==0);
    frame.bytes.back()^=1;
    CHECK(source.try_send(frame)==SendResult::Accepted); loop.run();
    CHECK(target.pds_error_counters().pds_type_invalid==17);
    CHECK(std::count_if(trace.events().begin(),trace.events().end(),[](const auto& event) {
        return event.node==2 && event.event=="pds_type_invalid";
    })==17);
    auto& counters=target.services().pds_error_counters;
    counters.pds_type_invalid=counters.pds_ctl_type_invalid=std::numeric_limits<uint16_t>::max();
    counters.record_invalid_type(); counters.record_invalid_control_type();
    CHECK(counters.pds_type_invalid==65535 && counters.pds_ctl_type_invalid==65535);
    target.clear_pds_error_counters(); CHECK(target.pds_error_counters().pds_type_invalid==0);
    sender.close(); target.close(); CHECK(loop.pending()==0);
}
} // namespace
int main() {
    try {
        decode_classification(); host_counters_and_crc();
        for (const bool established:{false,true}) for (const bool direct_queue:{false,true})
            unknown_control_does_not_change_context(established,direct_queue);
        std::cout<<"PASS unknown PDS/control types, silent drop, integrity-first counters and context isolation\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
