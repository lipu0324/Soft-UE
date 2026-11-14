#include "Check.hpp"
#include "../SES/Endpoint.hpp"
#include "../Runtime/Fabric.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;
using namespace UET::NetworkLayer;

enum class RudiFault { None, RequestLoss, ResponseLoss, RequestDuplicate, ResponseDuplicate, RequestDelay, RequestTrim, ResponseTrim, Ecn };
class RudiFaultPort final : public IPacketPort {
public:
    RudiFaultPort(IPacketPort& lower,EventLoop& loop,bool source,WireOptions wire)
        : lower_(lower),loop_(loop),source_(source),wire_(wire) {}
    bool provides_transmit_timing() const override { return lower_.provides_transmit_timing(); }
    SendResult try_send(const Frame& frame) override {
        const auto decoded=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size(),wire_.crc,wire_.native_ip_protocol);
        const auto& packet=decoded.packet;
        if (packet.PDS_type!=RUDI_header && packet.PDS_type!=nack_header) { ++unexpected_transport; return lower_.try_send(frame); }
        if (packet.PDS_type==nack_header) { CHECK(packet.PDS_header.nack_header.flags.nt); ++nacks; return lower_.try_send(frame); }
        const bool request=packet.PDS_header.RUDI_header.type==RUDI_REQ;
        const bool data=request || packet.SESpkt.bth_type==Semantic_Response_with_Data_Header;
        // Table3-86: WRITE results are control, READ results are trimmable.
        // Local policy separates uncontrolled RUDI data from NSCC's data TC.
        CHECK(frame.traffic_class==(data?2:1));
        CHECK(decoded.network.dscp==(data?TrimmingOptions{}.trimmable_dscp:TrimmingOptions{}.control_dscp));
        if (request) { ++requests; request_ids.insert(packet.PDS_header.RUDI_header.pkt_id); }
        else { ++responses; marked_responses+=packet.PDS_header.RUDI_header.flags.m; }
        const auto ordinal=request?requests:responses;
        if (ordinal!=1 || request!=source_) return lower_.try_send(frame);
        if ((request && fault==RudiFault::RequestLoss) || (!request && fault==RudiFault::ResponseLoss))
            return drop_after_departure(frame);
        if ((request && fault==RudiFault::RequestDuplicate) || (!request && fault==RudiFault::ResponseDuplicate))
            CHECK(lower_.try_send(frame)==SendResult::Accepted);
        if (request && fault==RudiFault::RequestDelay) {
            loop_.after(200000,[this,frame] { CHECK(lower_.try_send(frame)==SendResult::Accepted); });
            return SendResult::Accepted;
        }
        if ((request && fault==RudiFault::RequestTrim) || (!request && fault==RudiFault::ResponseTrim)) {
            auto trimmed=frame; CHECK(UetWireCodec::trim_packet(trimmed.bytes,TrimmingOptions{}));
            return lower_.try_send(trimmed);
        }
        if (request && fault==RudiFault::Ecn) {
            auto marked=frame; CHECK(UetWireCodec::mark_ecn(marked.bytes)); return lower_.try_send(marked);
        }
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable writable) override { lower_.set_writable_handler(std::move(writable)); }
    RudiFault fault=RudiFault::None;
    size_t requests=0,responses=0,nacks=0,unexpected_transport=0,marked_responses=0;
    std::set<uint32_t> request_ids;
private:
    IPacketPort& lower_; EventLoop& loop_; bool source_; WireOptions wire_;
    SendResult drop_after_departure(const Frame& frame) {
        // Loss happens after the NIC sends, so the source RTO must actually
        // start. Keep this fixture independent of the lower link's delivery.
        if (frame.transmission_event) frame.transmission_event(loop_.now(),TransmitOutcome::Started);
        return SendResult::Accepted;
    }
};
static void transaction(bool read,bool ipv6,bool udp,bool congestion,uint32_t length,RudiFault fault) {
    constexpr size_t mtu=64;
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    WireOptions wire; wire.ipv6=ipv6; wire.udp=udp; wire.native_ip_protocol=253;
    RudiFaultPort forward(fabric.add_host(1),loop,true,wire),reverse(fabric.add_host(2),loop,false,wire);
    forward.fault=reverse.fault=fault;
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward,PdsHost::WireFormat::Uet11,wire);
    PdsHost target_host(2,loop,trace,reverse,PdsHost::WireFormat::Uet11,wire);
    source_host.configure_trimming({}); target_host.configure_trimming({});
    if (congestion) {
        const auto config=UET::CMS::NsccConfig::for_link(12000,12500000000ULL,12500000000ULL,1132);
        source_host.enable_nscc(config); target_host.enable_nscc(config);
    }
    Endpoint source(1,source_host,loop,trace,mtu),target(2,target_host,loop,trace,mtu);
    source.memory().add_job(1); target.memory().add_job(1);
    const auto remote=target.memory().register_region(1,1,uint64_t{length}+64,Access::Read|Access::Write,true);
    const auto local=source.memory().register_region(1,1,uint64_t{length}+64,Access::Read|Access::Write);
    std::vector<uint8_t> expected(length);
    for (size_t index=0;index<expected.size();++index) expected[index]=index*7+3;
    if (read) target.memory().write(1,1,remote.key,7,expected);
    Operation operation; operation.type=read?OperationType::Read:OperationType::Write; operation.delivery_mode=RUDI;
    operation.peer=2; operation.remote_key=remote.key; operation.remote_offset=7; operation.context=99;
    if (read) { operation.read_length=length; operation.read_result=ReadResultBuffer{local.key,11,length}; }
    else operation.payload=expected;
    const auto id=source.submit(operation); loop.run_until(8*kMillisecond);
    Completion completion{}; CHECK(source.poll_completion(completion));
    CHECK(completion.operation==id && completion.context==99 && completion.status==CompletionStatus::Success && completion.length==length);
    CHECK(!source.poll_completion(completion) && !target.poll_completion(completion));
    CHECK(!source.pending() && !source.leased_message_ids() && !source.queued_fragments());
    CHECK(!target.retained_receive_messages() && !target.retained_read_packets() && !target.pending_read_returns());
    CHECK(!source_host.manager().getPDSStatus().open_cnt && !target_host.manager().getPDSStatus().open_cnt);
    CHECK(!forward.unexpected_transport && !reverse.unexpected_transport);
    const auto placed=read?source.memory().read(1,1,local.key,11,length):target.memory().read(1,1,remote.key,7,length);
    CHECK(placed==expected);
    const size_t packets=std::max<size_t>(1,(length+mtu-1)/mtu);
    CHECK(forward.request_ids.size()==packets);
    if (fault==RudiFault::RequestLoss || fault==RudiFault::ResponseLoss || fault==RudiFault::RequestTrim || fault==RudiFault::ResponseTrim)
        CHECK(forward.requests>packets);
    if (fault==RudiFault::RequestTrim) CHECK(reverse.nacks==1);
    if (fault==RudiFault::ResponseTrim) CHECK(!forward.nacks && !reverse.nacks);
    if (fault==RudiFault::Ecn) CHECK(reverse.marked_responses==1);
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(!loop.pending());
}
int main() {
    try {
        size_t cases=0;
        for (bool read:{false,true}) for (bool ipv6:{false,true}) for (bool udp:{false,true}) for (bool congestion:{false,true})
            for (uint32_t length:{0u,1u,73u,1025u}) { transaction(read,ipv6,udp,congestion,length,RudiFault::None); ++cases; }
        for (bool read:{false,true}) for (bool udp:{false,true}) for (auto fault:{RudiFault::RequestLoss,RudiFault::ResponseLoss,
            RudiFault::RequestDuplicate,RudiFault::ResponseDuplicate,RudiFault::RequestDelay,RudiFault::RequestTrim,RudiFault::ResponseTrim,RudiFault::Ecn}) {
            if (!read && fault==RudiFault::ResponseTrim) continue; // WRITE control responses cannot be trimmed by this fabric policy.
            transaction(read,false,udp,true,257,fault); ++cases;
        }
        std::cout<<"PASS"<<cases<<" RUDI native registered READ/WRITE, carriers, NSCC coexistence and per-packet recovery without PDC/target state\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
