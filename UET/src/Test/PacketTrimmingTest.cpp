#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;
using namespace UET::NetworkLayer;

PDStoNET_pkt trim_request() {
    PDStoNET_pkt packet{}; packet.PDS_type=RUOD_req_header;
    auto& request=packet.PDS_header.RUOD_req_header;
    request.type=RUD_REQ; request.next_hdr=UET_HDR_REQUEST_STD;
    request.psn=0x01020304; request.clear_psn_off=-1; request.spdcid=17; request.dpdcid=512;
    request.flags.retx=1;
    packet.SESpkt.bth_type=Standard_Header;
    auto& semantic=packet.SESpkt.bth_header.Standard_Header;
    semantic.opcode=1; semantic.som=1; semantic.eom=1; semantic.rel=1;
    semantic.job_id=1; semantic.PIDonFEP=1; semantic.resource_index=1; semantic.request_length=1024;
    packet.SESpkt.payload.resize(1024,99);
    return packet;
}
WireOptions addresses(bool ipv6=false,bool udp=true) {
    WireOptions options; options.ipv6=ipv6; options.udp=udp; options.native_ip_protocol=253; options.ecn=2; options.entropy=0x1234;
    if (ipv6) { options.source.ip[0]=options.destination.ip[0]=0xfd; }
    options.source.ip[ipv6?15:3]=1; options.destination.ip[ipv6?15:3]=2;
    return options;
}
class TrimFirstSynPort final : public IPacketPort {
public:
    TrimFirstSynPort(IPacketPort& lower,TrimmingOptions options,bool enabled)
        :lower_(lower),options_(options),enabled_(enabled) {}
    size_t trimmed=0;
    SendResult try_send(const Frame& frame) override {
        if (enabled_) {
            const auto packet=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size(),true,253).packet;
            if (packet.PDS_type==RUOD_req_header && packet.PDS_header.RUOD_req_header.flags.syn) {
                enabled_=false; ++trimmed;
                auto notification=frame; CHECK(UetWireCodec::trim_packet(notification.bytes,options_));
                return lower_.try_send(notification);
            }
        }
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
private:
    IPacketPort& lower_; TrimmingOptions options_; bool enabled_;
};
class HoldAcknowledgments final : public IPacketPort {
public:
    explicit HoldAcknowledgments(IPacketPort& lower):lower_(lower) {}
    std::vector<Frame> held;
    SendResult try_send(const Frame& frame) override {
        const auto packet=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size(),true,253).packet;
        if (holding_ && packet.PDS_type==RUOD_ack_header) { held.push_back(frame); return SendResult::Accepted; }
        return lower_.try_send(frame);
    }
    void release() { holding_=false; for (const auto& frame:held) lower_.try_send(frame); held.clear(); }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
private:
    IPacketPort& lower_; bool holding_=true;
};
void repair_ipv4_checksum(std::vector<uint8_t>& bytes) {
    bytes[24]=bytes[25]=0; uint32_t sum=0;
    for (size_t position=14;position<34;position+=2) sum+=(uint16_t{bytes[position]}<<8)|bytes[position+1];
    while (sum>>16) sum=(sum&0xffff)+(sum>>16);
    const auto checksum=static_cast<uint16_t>(~sum); bytes[24]=checksum>>8; bytes[25]=checksum&255;
}

void wire_boundaries() {
    TrimmingOptions trimming;
    for (const auto ipv6:{false,true}) for (const auto udp:{false,true}) for (const auto crc:{false,true}) {
        auto options=addresses(ipv6,udp); options.crc=crc;
        const auto full=UetWireCodec::encode(trim_request(),options);
        auto truncated=full; CHECK(UetWireCodec::trim_packet(truncated,trimming,true));
        CHECK(UetWireCodec::packet_dscp(truncated)==trimming.last_hop_dscp);
        const size_t payload_begin=14+(ipv6?40:20),pds_begin=payload_begin+(udp?8:4);
        CHECK(truncated.size()==payload_begin+24);
        CHECK(std::equal(truncated.begin()+payload_begin,truncated.end(),full.begin()+payload_begin));
        const auto decoded=UetWireCodec::decode(truncated.data(),truncated.size(),crc,253,trimming);
        CHECK(decoded.packet.trimmed && decoded.packet.trimmed_last_hop);
        CHECK(decoded.packet.PDS_header.RUOD_req_header.psn==0x01020304);
        CHECK(decoded.packet.PDS_header.RUOD_req_header.spdcid==17 && decoded.packet.PDS_header.RUOD_req_header.dpdcid==512);
        CHECK(decoded.packet.SESpkt.payload.empty() && decoded.nominal_packet_size==0);
        check_throws<std::invalid_argument>([&] { UetWireCodec::encode(decoded.packet,options); });
        check_throws<std::invalid_argument>([&] { UetWireCodec::decode(truncated.data(),truncated.size(),crc,253); });
        CHECK(!UetWireCodec::trim_packet(truncated,trimming)); // Already trimmed is not trimmed a second time.
        for (size_t length=0;length<pds_begin+12;++length)
            check_throws<std::invalid_argument>([&] { UetWireCodec::decode(truncated.data(),length,crc,253,trimming); });
        // IP/UDP lengths must not be trusted/verified on the FEP trim path.
        // This deliberately differs from the switch's valid-IP admission rule.
        if (ipv6) { truncated[18]=0xff; truncated[19]=0xff; }
        else { truncated[16]=0; truncated[17]=1; repair_ipv4_checksum(truncated); }
        if (udp) { truncated[payload_begin+4]=0; truncated[payload_begin+5]=1; }
        CHECK(UetWireCodec::decode(truncated.data(),truncated.size(),crc,253,trimming).packet.trimmed);
        if (!ipv6) {
            truncated[24]^=1;
            check_throws<std::invalid_argument>([&] { UetWireCodec::decode(truncated.data(),truncated.size(),crc,253,trimming); });
        }
    }
    auto invalid=trimming; invalid.minimum_ip_payload=23;
    check_throws<std::invalid_argument>([&] { invalid.validate(); });
    invalid=trimming; invalid.last_hop_dscp=invalid.trimmed_dscp;
    check_throws<std::invalid_argument>([&] { invalid.validate(); });
}

void trimmed_syn_cannot_create_or_deliver() {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,51);
    auto& source=fabric.add_host(1); auto& target=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    TrimmingOptions trimming;
    PdsHost host(2,loop,trace,target); host.configure_trimming(trimming);
    Endpoint endpoint(2,host,loop,trace); endpoint.memory().add_job(1);
    const auto region=endpoint.memory().register_region(1,1,1024,7);
    std::vector<PDStoNET_pkt> replies;
    source.set_receiver([&](Frame frame) { replies.push_back(UetWireCodec::decode(frame.bytes.data(),frame.bytes.size(),true,253).packet); });
    auto request=trim_request(); request.SESpkt.bth_header.Standard_Header.match_bits=region.key;
    request.PDS_header.RUOD_req_header.flags.syn=1; request.PDS_header.RUOD_req_header.psn_off=0;
    const auto send_trimmed=[&](PDStoNET_pkt packet) {
        Frame frame; frame.source=1; frame.destination=2; frame.bytes=UetWireCodec::encode(packet,addresses());
        CHECK(UetWireCodec::trim_packet(frame.bytes,trimming)); source.try_send(frame); loop.run();
    };
    send_trimmed(request);
    CHECK(replies.size()==1 && replies.front().PDS_type==nack_header);
    const auto& nack=replies.front().PDS_header.nack_header;
    CHECK(nack.nack_code==UET_TRIMMED && nack.spdcid==0 && nack.dpdcid==17 && nack.nack_psn==0x01020304);
    CHECK(host.manager().getPDSStatus().open_cnt==0 && endpoint.retained_receive_messages()==0);
    CHECK(region.storage->allocated_pages()==0);
    auto control=request; control.SESpkt={}; control.PDS_type=RUOD_cp_header; control.PDS_header={};
    control.PDS_header.RUOD_cp_header.type=CP; control.PDS_header.RUOD_cp_header.ctl_type=Noop;
    control.PDS_header.RUOD_cp_header.flags.syn=1; control.PDS_header.RUOD_cp_header.spdcid=17;
    send_trimmed(control); CHECK(replies.size()==1 && host.manager().getPDSStatus().open_cnt==0);
    auto ack=control; ack.PDS_type=RUOD_ack_header; ack.PDS_header={};
    ack.PDS_header.RUOD_ack_header.type=ACK; ack.PDS_header.RUOD_ack_header.cack_psn=UINT32_MAX;
    ack.PDS_header.RUOD_ack_header.next_hdr=UET_HDR_NONE;
    send_trimmed(ack); CHECK(replies.size()==1); // A trimmed ACK cannot clear anything or elicit a NACK.
    Completion completion{}; CHECK(!endpoint.poll_completion(completion));
    endpoint.close(); host.close(); CHECK(loop.pending()==0);
}

void trimmed_ack_cannot_complete_live_operation() {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,57);
    auto& source_port=fabric.add_host(1); auto& target_port=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    HoldAcknowledgments delayed(target_port);
    PdsHost source_host(1,loop,trace,source_port),target_host(2,loop,trace,delayed);
    TrimmingOptions trimming; source_host.configure_trimming(trimming); target_host.configure_trimming(trimming);
    Endpoint source(1,source_host,loop,trace),target(2,target_host,loop,trace);
    source.memory().add_job(1); target.memory().add_job(1);
    const auto region=target.memory().register_region(1,1,32,7);
    Operation write; write.type=OperationType::Write; write.peer=2; write.remote_key=region.key; write.payload={1,2,3};
    const auto operation=source.submit(write); loop.run_until(10000);
    Completion completion{}; CHECK(!source.poll_completion(completion) && !delayed.held.empty());
    CHECK(source_host.manager().getPDSStatus().open_cnt==1 && source.transport_pending(operation));
    auto forged_receipt=delayed.held.front();
    auto decoded=UetWireCodec::decode(forged_receipt.bytes.data(),forged_receipt.bytes.size(),true,253);
    // Fault injection: a control packet incorrectly assigned to TRIMMABLE
    // may also be truncated. The preserved ACK_PSN/CACK must not retire data.
    decoded.network.dscp=trimming.trimmable_dscp;
    forged_receipt.bytes=UetWireCodec::encode(decoded.packet,decoded.network);
    CHECK(UetWireCodec::trim_packet(forged_receipt.bytes,trimming));
    target_port.try_send(forged_receipt); loop.run_until(20000);
    CHECK(!source.poll_completion(completion) && source.transport_pending(operation));
    CHECK(source_host.manager().getPDSStatus().open_cnt==1);
    delayed.release(); loop.run_until(100000);
    CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Success);
    CHECK(!source.poll_completion(completion));
    CHECK(target.memory().read(1,1,region.key,0,3)==write.payload);
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(loop.pending()==0);
}

void congested_switch_recovery(bool ordered,bool udp,bool last_hop,bool trim_first_syn=false,bool ipv6=false) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,53);
    auto& source_port=fabric.add_host(1); auto& target_port=fabric.add_host(2); fabric.add_switch(10);
    LinkConfig fast; fast.mtu=512;
    fabric.add_link(1,10,fast); fabric.add_link(2,10,fast); fabric.add_link(10,1,fast);
    TrimmingOptions trimming; if (!last_hop) trimming.last_hop_dscp.reset();
    TrimFirstSynPort source_adapter(source_port,trimming,trim_first_syn);
    LinkConfig congested=fast; congested.rate_bps=1000000000; congested.buffer_bytes=512; congested.trimming=trimming;
    fabric.add_link(10,2,congested);
    auto network=addresses(ipv6,udp); network.source={}; network.destination={};
    PdsHost source_host(1,loop,trace,source_adapter,PdsHost::WireFormat::Uet11,network);
    PdsHost target_host(2,loop,trace,target_port,PdsHost::WireFormat::Uet11,network);
    for (auto* host:{&source_host,&target_host}) {
        host->configure_trimming(trimming);
        // Four 1 us propagation hops plus the MTU packet's bottleneck
        // serialization and ACK serialization fit in a 6 us empty-path RTT.
        auto nscc=UET::CMS::NsccConfig::for_link(6000,12500000000ULL,125000000,udp?172:168,true);
        nscc.initial_maximum_window=4*nscc.nominal_mtu; host->enable_nscc(nscc);
    }
    Endpoint source(1,source_host,loop,trace,64),target(2,target_host,loop,trace,64);
    source.memory().add_job(1); target.memory().add_job(1);
    const auto region=target.memory().register_region(1,1,4096,7);
    Operation write; write.type=OperationType::Write; write.delivery_mode=ordered?ROD:RUD;
    write.peer=2; write.remote_key=region.key; write.payload.resize(4096);
    for (size_t byte=0;byte<write.payload.size();++byte) write.payload[byte]=static_cast<uint8_t>(byte*11);
    source.submit(write); loop.run_until(50*kMillisecond);
    Completion completion{}; const bool completed=source.poll_completion(completion);
    if (!completed || completion.status!=CompletionStatus::Success) {
        std::cerr<<"Trim recovery ordered="<<ordered<<" udp="<<udp<<" ipv6="<<ipv6<<" last_hop="<<last_hop
            <<" completed="<<completed<<" status="<<static_cast<int>(completion.status)<<" code="<<unsigned(completion.remote_code)<<'\n';
        for (const auto& event:trace.events()) std::cerr<<event.time<<' '<<event.node<<' '<<event.event<<' '<<event.value<<'\n';
    }
    CHECK(completed && completion.status==CompletionStatus::Success && !source.poll_completion(completion));
    CHECK(target.memory().read(1,1,region.key,0,4096)==write.payload);
    CHECK(source_adapter.trimmed==(trim_first_syn?1u:0u));
    CHECK(fabric.stats(10,2).trimmed>0 && fabric.stats(10,2).trimmed_bytes>0);
    CHECK(std::any_of(trace.events().begin(),trace.events().end(),[&](const auto& event) {
        return event.node==1 && event.event=="pds_nack" && event.value==uint64_t(last_hop?UET_TRIMMED_LASTHOP:UET_TRIMMED);
    }));
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(loop.pending()==0);
}

int main() {
    wire_boundaries(); trimmed_syn_cannot_create_or_deliver();
    trimmed_ack_cannot_complete_live_operation();
    for (const auto ordered:{false,true}) for (const auto udp:{false,true}) for (const auto last_hop:{false,true}) for (const auto ipv6:{false,true})
        congested_switch_recovery(ordered,udp,last_hop,false,ipv6);
    congested_switch_recovery(false,false,false,true);
    congested_switch_recovery(true,false,false,true);
    std::cout<<"PASS real queue trimming, unchanged UDP fields, untrusted-header isolation and NSCC/PDS recovery\n";
}
