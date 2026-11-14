#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
#include <set>

using namespace UET::Runtime;
using namespace UET::SES;
using namespace UET::CMS;
using namespace UET::NetworkLayer;

namespace {
TrimmingOptions class_three_policy() {
    TrimmingOptions policy;
    policy.data_traffic_class=3;
    policy.trimmable_dscp=3;
    policy.trimmed_dscp=11;
    policy.last_hop_dscp=19;
    policy.no_trim_dscp=35;
    return policy;
}

// Cross a simulated adapter boundary that does not transport local queue IDs.
// The fabric must recover DATA/NO_TRIM/TRIMMED classes from actual IP DSCP.
class WithoutQueueMetadata final : public IPacketPort {
public:
    explicit WithoutQueueMetadata(IPacketPort& lower):lower_(lower) {}
    SendResult try_send(const Frame& frame) override {
        const auto dscp=UetWireCodec::packet_dscp(frame.bytes);
        CHECK(dscp);
        if (*dscp==0 || *dscp==32) CHECK(frame.traffic_class==0);
        else if (*dscp==3 || *dscp==35) CHECK(frame.traffic_class==3);
        else CHECK(*dscp==48 && frame.traffic_class==1);
        auto transported=frame;
        transported.traffic_class=0;
        return lower_.try_send(transported);
    }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
private:
    IPacketPort& lower_;
};

void configuration_boundaries() {
    const TrimmingOptions zero;
    const auto three=class_three_policy();
    validate_trimming_policy_set({zero,three});
    check_throws<std::invalid_argument>([&] { validate_trimming_policy_set({zero,zero}); });
    auto invalid=three; invalid.control_dscp=47;
    check_throws<std::invalid_argument>([&] { validate_trimming_policy_set({zero,invalid}); });
    invalid=three; invalid.no_trim_dscp=zero.trimmed_dscp;
    check_throws<std::invalid_argument>([&] { validate_trimming_policy_set({zero,invalid}); });
    invalid=three; invalid.data_traffic_class=8;
    check_throws<std::invalid_argument>([&] { invalid.validate(); });
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,71);
    auto& port=fabric.add_host(1); fabric.add_host(2);
    PdsHost host(1,loop,trace,port);
    host.configure_trimming(zero); host.configure_trimming(three);
    CHECK(host.supports_data_traffic_class(3));
    check_throws<std::invalid_argument>([&] { host.configure_data_traffic_class(3,4); });
    check_throws<std::invalid_argument>([&] { host.configure_data_traffic_class(4,11); });
    invalid=zero; invalid.trimmed_dscp=3;
    check_throws<std::invalid_argument>([&] { host.configure_trimming(invalid); });
    // Failed candidates leave both original roles intact; valid reapplication
    // succeeds and an invalid link must not consume its directed-link identity.
    host.configure_trimming(zero); host.configure_trimming(three);
    LinkConfig link; link.trimming=zero; link.additional_trimming={invalid};
    check_throws<std::invalid_argument>([&] { fabric.add_link(1,2,link); });
    link.additional_trimming={three}; fabric.add_link(1,2,link);
    host.close(); CHECK(loop.pending()==0);
}

void retained_credit_header_boundaries() {
    const auto trimming=class_three_policy();
    for (const auto type:{RUD_CC_REQ,ROD_CC_REQ})
    for (const bool ipv6:{false,true}) for (const bool udp:{false,true}) for (const bool crc:{false,true}) {
        PDStoNET_pkt packet{};
        packet.PDS_type=RUOD_req_header;
        auto& request=packet.PDS_header.RUOD_req_header;
        request.type=type; request.next_hdr=UET_HDR_REQUEST_STD;
        request.psn=0x10203040; request.spdcid=17; request.dpdcid=512;
        packet.credit_request.ccc_id=0xa5;
        packet.credit_request.credit_target_units=0x123456;
        packet.SESpkt.bth_type=Standard_Header;
        auto& semantic=packet.SESpkt.bth_header.Standard_Header;
        semantic.opcode=1; semantic.som=semantic.eom=semantic.rel=1;
        semantic.job_id=1; semantic.PIDonFEP=1; semantic.resource_index=1; semantic.request_length=64;
        packet.SESpkt.payload.assign(64,0x55);
        WireOptions network; network.ipv6=ipv6; network.udp=udp; network.crc=crc;
        network.native_ip_protocol=253; network.dscp=3;
        auto frame=UetWireCodec::encode(packet,network);
        CHECK(UetWireCodec::trim_packet(frame,trimming,true));
        const auto decoded=UetWireCodec::decode(frame.data(),frame.size(),crc,253,trimming);
        CHECK(decoded.packet.trimmed && decoded.packet.trimmed_last_hop);
        CHECK(decoded.packet.PDS_header.RUOD_req_header.type==type);
        CHECK(decoded.packet.PDS_header.RUOD_req_header.psn==request.psn);
        CHECK(decoded.packet.credit_request.ccc_id==0xa5 && decoded.packet.credit_request.credit_target_units==0x123456);
        CHECK(decoded.packet.SESpkt.payload.empty() && decoded.nominal_packet_size==0);
        const size_t pds_begin=14+(ipv6?40:20)+(udp?8:4);
        // A credit-carrying request requires all 16 retained PDS bytes, not
        // merely the 12-byte ordinary request prefix (§3.5.15.1).
        for (size_t retained=0;retained<16;++retained)
            check_throws<std::invalid_argument>([&] {
                UetWireCodec::decode(frame.data(),pds_begin+retained,crc,253,trimming);
            });
    }
}

void recover_one_congested_class(pdc_mode mode,bool nscc,bool tfc,bool ipv6_native) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,73);
    WithoutQueueMetadata source_port(fabric.add_host(1)),target_port(fabric.add_host(2));
    LinkConfig link;
    link.rate_bps=1000000000; link.mtu=200; link.buffer_bytes=250;
    link.trimming=TrimmingOptions{}; link.additional_trimming={class_three_policy()};
    fabric.add_link(1,2,link); fabric.add_link(2,1,link);
    WireOptions network; network.ipv6=ipv6_native; network.udp=!ipv6_native; network.native_ip_protocol=253;
    PdsHost source_host(1,loop,trace,source_port,PdsHost::WireFormat::Uet11,network);
    PdsHost target_host(2,loop,trace,target_port,PdsHost::WireFormat::Uet11,network);
    for (auto* host:{&source_host,&target_host}) {
        host->configure_trimming(*link.trimming);
        host->configure_trimming(link.additional_trimming.front());
        if (nscc) {
            auto congestion=NsccConfig::for_link(12000,12500000000ULL,125000000,196);
            congestion.initial_maximum_window=4*congestion.nominal_mtu;
            host->enable_nscc(congestion);
        }
        if (tfc) {
            TfcEngineConfig credit;
            credit.outgoing.payload_mtu_bytes=credit.incoming.payload_mtu_bytes=64;
            credit.outgoing.initial_credit_bytes=credit.incoming.initial_credit_bytes=1024;
            credit.receive_context_bytes=2048; credit.receive_pool_bytes=8192;
            host->enable_tfc(credit);
        }
    }
    Endpoint source(1,source_host,loop,trace,64),target(2,target_host,loop,trace,64);
    source.memory().add_job(1); target.memory().add_job(1);
    const auto region=target.memory().register_region(1,1,192,7);
    CHECK(source_host.open_connection(2,1,mode,false,{},0)!=UINT16_MAX);
    CHECK(source_host.open_connection(2,1,mode,false,{},3)!=UINT16_MAX);
    loop.run_until(20*1000);
    size_t trimmed_three=0,untrimmed_zero=0;
    fabric.set_link_capture([&](Time,uint32_t from,uint32_t to,const Frame& frame) {
        if (from!=1 || to!=2) return;
        const auto dscp=UetWireCodec::packet_dscp(frame.bytes);
        CHECK(dscp);
        if (*dscp==19) {
            ++trimmed_three;
            CHECK(frame.traffic_class==1);
            const auto decoded=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size(),true,253,class_three_policy());
            CHECK(decoded.packet.trimmed && decoded.packet.SESpkt.payload.empty());
            if (tfc) CHECK(decoded.packet.PDS_header.RUOD_req_header.type==(mode==ROD?ROD_CC_REQ:RUD_CC_REQ));
        } else if (*dscp==0) { ++untrimmed_zero; CHECK(frame.traffic_class==0); }
        else if (*dscp==3 || *dscp==35) CHECK(frame.traffic_class==3);
        else if (*dscp==48) CHECK(frame.traffic_class==1);
        else CHECK(*dscp==32 && frame.traffic_class==0);
    });
    Operation write;
    write.type=OperationType::Write; write.peer=2; write.delivery_mode=mode; write.remote_key=region.key;
    write.traffic_class=3; write.payload.assign(128,0x33);
    const auto congested=source.submit(write);
    write.traffic_class=0; write.remote_offset=128; write.payload.assign(64,0x11);
    const auto independent=source.submit(write);
    loop.run_until(100*kMillisecond);
    Completion completion{}; std::set<uint64_t> completed;
    while (source.poll_completion(completion)) {
        CHECK(completion.status==CompletionStatus::Success);
        CHECK(completion.length==(completion.operation==congested?128u:64u));
        CHECK(completed.insert(completion.operation).second);
    }
    if (completed.size()!=2 || !trimmed_three) {
        std::cerr<<"mode="<<mode<<" nscc="<<nscc<<" tfc="<<tfc<<" ipv6="<<ipv6_native
            <<" completions="<<completed.size()<<" trimmed3="<<trimmed_three<<'\n';
    }
    CHECK(completed.size()==2 && completed.count(congested) && completed.count(independent));
    CHECK(trimmed_three && untrimmed_zero && fabric.stats(1,2).trimmed==trimmed_three);
    CHECK(target.memory().read(1,1,region.key,0,128)==std::vector<uint8_t>(128,0x33));
    CHECK(target.memory().read(1,1,region.key,128,64)==std::vector<uint8_t>(64,0x11));
    CHECK(std::any_of(trace.events().begin(),trace.events().end(),[](const auto& event) {
        return event.node==1 && event.event=="pds_nack" && event.value==UET_TRIMMED_LASTHOP;
    }));
    CHECK(!source.pending() && !source.queued_fragments());
    source.close(); target.close(); source_host.close(); target_host.close();
    CHECK(loop.pending()==0);
}
} // namespace

int main() {
    configuration_boundaries(); retained_credit_header_boundaries();
    for (const auto mode:{RUD,ROD}) for (const bool nscc:{false,true})
    for (const bool tfc:{false,true}) for (const bool ipv6_native:{false,true})
        recover_one_congested_class(mode,nscc,tfc,ipv6_native);
    std::cout<<"PASS multi-TC DSCP reconstruction, trimmed credit headers and original PDS recovery\n";
}
