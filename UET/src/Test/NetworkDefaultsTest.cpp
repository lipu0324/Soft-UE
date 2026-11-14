#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>

using namespace UET::NetworkLayer;
using namespace UET::Runtime;
using namespace UET::SES;

PDStoNET_pkt opening_control() {
    PDStoNET_pkt packet{}; packet.PDS_type=RUOD_cp_header;
    auto& control=packet.PDS_header.RUOD_cp_header;
    control.type=CP; control.ctl_type=Noop; control.flags.syn=control.flags.ar=1;
    control.flags.pdc_type=1; control.spdcid=7; control.psn=1000;
    return packet;
}

void default_and_explicit_protocols() {
    WireOptions network;
    CHECK(network.udp && network.udp_destination_port==4793 && !network.native_ip_protocol);
    const auto default_frame=UetWireCodec::encode(opening_control(),network);
    CHECK(default_frame[23]==17 && default_frame[36]==0x12 && default_frame[37]==0xb9);
    CHECK(UetWireCodec::decode(default_frame.data(),default_frame.size()).network.udp);
    network.udp=false;
    check_throws<std::invalid_argument>([&] { UetWireCodec::encode(opening_control(),network); });

    // Table 3-35 permits the full configurable byte range. No native number is
    // assigned by UE 1.1; these values are test fabric settings, not IANA claims.
    for (const bool ipv6:{false,true}) for (const bool crc:{false,true})
        for (unsigned protocol=0;protocol<=255;++protocol) {
        network.ipv6=ipv6; network.crc=crc; network.native_ip_protocol=protocol;
        const auto frame=UetWireCodec::encode(opening_control(),network);
        CHECK(frame[ipv6?20:23]==protocol);
        const auto decoded=UetWireCodec::decode(frame.data(),frame.size(),crc,
            network.native_ip_protocol,{},4793,false);
        CHECK(!decoded.network.udp && decoded.network.native_ip_protocol==protocol);
        CHECK(UetWireCodec::encode(decoded.packet,decoded.network)==frame);
        check_throws<std::invalid_argument>([&] {
            UetWireCodec::decode(frame.data(),frame.size(),crc,
                static_cast<uint8_t>(protocol+1),{},4793,false);
        });
        if (protocol!=17) check_throws<std::invalid_argument>([&] {
            UetWireCodec::decode(frame.data(),frame.size(),crc);
        });
        auto trimmed=frame; TrimmingOptions trimming;
        CHECK(UetWireCodec::trim_packet(trimmed,trimming));
        CHECK(UetWireCodec::decode(trimmed.data(),trimmed.size(),crc,
            network.native_ip_protocol,trimming,4793,false).packet.trimmed);
    }
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& port=fabric.add_host(1);
    network.native_ip_protocol.reset();
    check_throws<std::invalid_argument>([&] {
        PdsHost host(1,loop,trace,port,PdsHost::WireFormat::Uet11,network);
    });
    CHECK(loop.pending()==0);
}

void end_to_end(WireOptions network) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward,PdsHost::WireFormat::Uet11,network),
        target_host(2,loop,trace,reverse,PdsHost::WireFormat::Uet11,network);
    // Exercise ingress and the MAC-time ACK_CC stamp with the same configured
    // mode. A native protocol byte of 17 must not be mistaken for a UDP header.
    auto congestion=UET::CMS::NsccConfig::for_link(12000,12500000000ULL,12500000000ULL,
        1024+12+44+(network.udp?8:4)+(network.crc?4:0)+40);
    source_host.enable_nscc(congestion); target_host.enable_nscc(congestion);
    Endpoint source(1,source_host,loop,trace),target(2,target_host,loop,trace);
    source.memory().add_job(1); target.memory().add_job(1);
    const auto region=target.memory().register_region(1,1,4096,7);
    Operation write; write.type=OperationType::Write; write.peer=2; write.remote_key=region.key;
    write.payload.resize(2049);
    for (size_t index=0;index<write.payload.size();++index) write.payload[index]=index*13;
    source.submit(write); loop.run(100000);
    Completion completion{};
    CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Success);
    CHECK(!source.poll_completion(completion));
    CHECK(target.memory().read(1,1,region.key,0,write.payload.size())==write.payload);
    CHECK(std::none_of(trace.events().begin(),trace.events().end(),[](const auto& event) {
        return event.event=="malformed_frame";
    }));
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(loop.pending()==0);
}

int main() {
    try {
        default_and_explicit_protocols();
        for (const bool ipv6:{false,true}) for (const bool crc:{false,true}) {
            WireOptions network; network.ipv6=ipv6; network.crc=crc;
            end_to_end(network);
            for (const uint8_t protocol:{0,17,252,253,254,255}) {
                network.udp=false; network.native_ip_protocol=protocol; end_to_end(network);
            }
        }
        std::cout<<"PASS: UDP/4793 default, explicit native protocol 0..255, trim and NSCC WRITE\n";
        return 0;
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
