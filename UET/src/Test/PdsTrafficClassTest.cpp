#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
#include <set>

using namespace UET::Runtime;
using namespace UET::SES;
using namespace UET::NetworkLayer;

void control_traffic_classes(pdc_mode mode,bool congestion,bool trimming_enabled,bool negotiation,bool target_close) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& source_port=fabric.add_host(1); auto& target_port=fabric.add_host(2);
    LinkConfig link; TrimmingOptions trimming;
    if (trimming_enabled) link.trimming=trimming;
    fabric.add_link(1,2,link); fabric.add_link(2,1,link);
    PdsHost source_host(1,loop,trace,source_port),target_host(2,loop,trace,target_port);
    if (trimming_enabled) { source_host.configure_trimming(trimming); target_host.configure_trimming(trimming); }
    if (congestion) { source_host.enable_nscc({}); target_host.enable_nscc({}); }
    Endpoint source(1,source_host,loop,trace),target(2,target_host,loop,trace);
    source.memory().add_job(1); target.memory().add_job(1);
    const auto region=target.memory().register_region(1,1,16,7);
    std::set<unsigned> control_types; size_t acknowledgments=0,data_packets=0;
    std::optional<uint16_t> target_context;
    fabric.set_capture([&](Time,const Frame& frame) {
        const auto decoded=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size());
        const auto& packet=decoded.packet;
        if (packet.PDS_type==RUOD_cp_header) {
            const auto type=packet.PDS_header.RUOD_cp_header.ctl_type;
            control_types.insert(type);
            const bool numbered=type==Noop || type==Negotiation || type==Close_cmd || type==Close_req;
            const bool request_class=mode==ROD && numbered;
            if (frame.traffic_class!=(request_class?0:1))
                throw std::runtime_error("CP TC mismatch: mode="+std::to_string(mode)+
                    ", ctl_type="+std::to_string(type)+", TC="+std::to_string(frame.traffic_class));
            CHECK(decoded.network.dscp==(request_class?(trimming_enabled?trimming.no_trim_dscp:0):48));
            if (trimming_enabled) {
                auto copy=frame.bytes;
                CHECK(!UetWireCodec::trim_packet(copy,trimming)); // Same TC does not mean trimmable.
            }
        } else if (packet.PDS_type==RUOD_ack_header || packet.PDS_type==nack_header) {
            ++acknowledgments;
            CHECK(frame.traffic_class==1 && decoded.network.dscp==48);
            if (frame.source==2 && packet.PDS_type==RUOD_ack_header)
                target_context=packet.PDS_header.RUOD_ack_header.spdcid;
        } else if (packet.PDS_type==RUOD_req_header) {
            ++data_packets; CHECK(frame.traffic_class==0);
            CHECK(decoded.network.dscp==(trimming_enabled?trimming.trimmable_dscp:0));
        }
    });
    const auto local_context=source_host.open_connection(2,1,mode,negotiation);
    CHECK(local_context!=UINT16_MAX); loop.run_until(kMillisecond);
    CHECK(target_context.has_value());
    Operation write; write.type=OperationType::Write; write.peer=2; write.delivery_mode=mode;
    write.remote_key=region.key; write.payload={1,2,3}; source.submit(write);
    loop.run_until(2*kMillisecond);
    Completion completion{}; CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Success);
    CHECK(target.memory().read(1,1,region.key,0,3)==write.payload);
    CHECK(source_host.request_connection_probe(local_context,0)); loop.run_until(3*kMillisecond);
    CHECK((target_close?target_host.request_connection_close(*target_context):source_host.request_connection_close(local_context)));
    loop.run();
    CHECK(source_host.manager().getPDSStatus().open_cnt==0 && target_host.manager().getPDSStatus().open_cnt==0);
    CHECK(control_types.count(negotiation?Negotiation:Noop));
    CHECK(control_types.count(Close_cmd) && control_types.count(Clear_cmd) && control_types.count(Probe));
    CHECK(control_types.count(Close_req)==(target_close?1u:0u));
    CHECK(acknowledgments && data_packets==1);
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(loop.pending()==0);
}
int main() {
    try {
        for (const auto mode:{RUD,ROD}) for (const bool congestion:{false,true})
            for (const bool trimming:{false,true}) for (const bool negotiation:{false,true})
                for (const bool target_close:{false,true})
                    control_traffic_classes(mode,congestion,trimming,negotiation,target_close);
        TrimmingOptions invalid;
        invalid.no_trim_dscp=invalid.trimmable_dscp;
        check_throws<std::invalid_argument>([&] { invalid.validate(); });
        invalid.no_trim_dscp=64;
        check_throws<std::invalid_argument>([&] { invalid.validate(); });
        std::cout<<"PASS numbered ROD controls share request TC without trimming, ACK isolation and both close directions\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
