#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
#include <set>

using namespace UET::CMS;
using namespace UET::Runtime;
using namespace UET::SES;
using namespace UET::NetworkLayer;

namespace {
enum class Fault { None, FirstData, FirstCredit };

class CreditFaultPort final : public IPacketPort {
public:
    CreditFaultPort(IPacketPort& lower,EventLoop& loop,WireOptions network,Fault fault,bool nscc)
        : lower_(lower),loop_(loop),network_(network),fault_(fault),nscc_(nscc) {}
    size_t data_packets=0,retransmissions=0,credit_requests=0,credit_packets=0,lost=0;
    std::set<uint16_t> data_paths;
    std::map<uint16_t,uint8_t> context_identifiers;
    SendResult try_send(const Frame& frame) override {
        const auto decoded=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size(),network_.crc,253);
        const auto& packet=decoded.packet;
        if (packet.PDS_type==RUOD_req_header) {
            CHECK(packet.PDS_header.RUOD_req_header.type==RUD_CC_REQ || packet.PDS_header.RUOD_req_header.type==ROD_CC_REQ);
            CHECK(packet.credit_request.credit_target_units>0);
            ++data_packets;
            retransmissions+=packet.PDS_header.RUOD_req_header.flags.retx;
            data_paths.insert(decoded.network.entropy);
            context_identifiers[packet.PDS_header.RUOD_req_header.spdcid]=packet.credit_request.ccc_id;
            if (fault_==Fault::FirstData) { fault_=Fault::None; return discard(frame); }
        }
        if (packet.PDS_type==RUOD_cp_header) {
            const auto& control=packet.PDS_header.RUOD_cp_header;
            if (control.ctl_type==Credit || control.ctl_type==Credit_req) {
                CHECK(!control.psn && !control.flags.syn && !control.flags.ar);
                if (control.ctl_type==Credit_req) ++credit_requests;
                else {
                    ++credit_packets;
                    if (fault_==Fault::FirstCredit && nscc_) { fault_=Fault::None; return discard(frame); }
                }
            }
        }
        if (!nscc_ && fault_==Fault::FirstCredit && packet.PDS_type==RUOD_ack_header &&
            packet.PDS_header.RUOD_ack_header.type==ACK_CC && packet.congestion_ack.type==1 &&
            packet.congestion_ack.credit_units) {
            // Deliver the ordinary PDS/SES receipt but lose its credit field.
            // A data RTO can no longer rescue this stall; the credit timer must.
            fault_=Fault::None;
            ++lost;
            auto receipt=packet;
            receipt.PDS_header.RUOD_ack_header.type=ACK;
            auto changed=frame;
            changed.bytes=UetWireCodec::encode(receipt,decoded.network);
            return lower_.try_send(changed);
        }
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable writable) override { lower_.set_writable_handler(std::move(writable)); }
private:
    IPacketPort& lower_;
    EventLoop& loop_;
    WireOptions network_;
    Fault fault_;
    bool nscc_;
    SendResult discard(const Frame& frame) {
        ++lost;
        if (frame.transmission_event) frame.transmission_event(loop_.now(),TransmitOutcome::Started);
        return SendResult::Accepted;
    }
};

void transaction(bool ordered,bool nscc,Fault fault,RequestHeaderFormat format,bool ipv6_native) {
    EventLoop loop;
    Trace trace(loop);
    Fabric fabric(loop,trace,37);
    WireOptions network;
    network.ipv6=ipv6_native;
    network.udp=!ipv6_native;
    network.native_ip_protocol=253;
    CreditFaultPort forward(fabric.add_host(1),loop,network,fault==Fault::FirstData ? fault : Fault::None,nscc);
    CreditFaultPort reverse(fabric.add_host(2),loop,network,fault==Fault::FirstCredit ? fault : Fault::None,nscc);
    LinkConfig link;
    link.delay_ns=1000;
    fabric.add_link(1,2,link);
    fabric.add_link(2,1,link);
    PdsHost source_host(1,loop,trace,forward,PdsHost::WireFormat::Uet11,network);
    PdsHost target_host(2,loop,trace,reverse,PdsHost::WireFormat::Uet11,network);
    if (nscc) {
        auto congestion=NsccConfig::for_link(10000,12500000000ULL,12500000000ULL,176);
        congestion.initial_maximum_window=176;
        source_host.enable_nscc(congestion);
        target_host.enable_nscc(congestion);
    }
    TfcEngineConfig flow;
    flow.outgoing.payload_mtu_bytes=64;
    flow.incoming.payload_mtu_bytes=64;
    flow.receive_context_bytes=1024;
    flow.receive_pool_bytes=4096;
    source_host.enable_tfc(flow);
    target_host.enable_tfc(flow);
    Endpoint source(1,source_host,loop,trace,64),target(2,target_host,loop,trace,64);
    source.memory().add_job(1);
    target.memory().add_job(1);
    const auto region=target.memory().register_region(1,1,512,7);
    Operation write;
    write.type=OperationType::Write;
    write.header_format=format;
    write.peer=2;
    write.delivery_mode=ordered ? ROD : RUD;
    write.remote_key=region.key;
    write.payload.resize(512);
    for (size_t byte=0; byte<write.payload.size(); ++byte) write.payload[byte]=static_cast<uint8_t>(byte*17+3);
    source.submit(write);
    loop.run_until(999);
    CHECK(forward.data_packets==1); // No reverse feedback can have returned.
    loop.run_until(100*kMillisecond);
    Completion completion{};
    if (!source.poll_completion(completion)) {
        std::cerr << "TFC incomplete ordered=" << ordered << " nscc=" << nscc << " fault=" << int(fault)
                  << " format=" << int(format) << " ipv6=" << ipv6_native << '\n';
        for (const auto& event:trace.events())
            std::cerr << event.time << ' ' << event.node << ' ' << event.event << ' ' << event.value << '\n';
        throw std::runtime_error("TFC transaction did not complete");
    }
    CHECK(completion.status==CompletionStatus::Success && completion.length==512);
    CHECK(!source.poll_completion(completion));
    CHECK(target.memory().read(1,1,region.key,0,512)==write.payload);
    CHECK(target_host.tfc()->reserved_receive_bytes()<=flow.receive_pool_bytes);
    CHECK(ordered ? forward.data_paths.size()==1 : forward.data_paths.size()>1);
    if (fault==Fault::FirstData) CHECK(forward.lost==1 && forward.retransmissions>0);
    if (fault==Fault::FirstCredit) {
        CHECK(reverse.lost==1 && forward.credit_requests>0 && reverse.credit_packets>0);
        CHECK(std::any_of(trace.events().begin(),trace.events().end(),[](const auto& event) {
            return event.event=="tfc_credit_timer";
        }));
    }
    source.close();
    target.close();
    source_host.close();
    target_host.close();
    CHECK(source_host.tfc()->source_connection_count()==0);
    CHECK(source_host.tfc()->reserved_receive_bytes()==0 && target_host.tfc()->reserved_receive_bytes()==0);
    CHECK(target_host.tfc()->destination_context_count()==0);
    CHECK(loop.pending()==0);
}

void real_last_member_quiesce() {
    EventLoop loop;
    Trace trace(loop);
    Fabric fabric(loop,trace,37);
    CreditFaultPort forward(fabric.add_host(1),loop,{},Fault::None,false);
    auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{});
    fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    TfcEngineConfig flow;
    flow.outgoing.payload_mtu_bytes=flow.incoming.payload_mtu_bytes=64;
    flow.receive_context_bytes=1024;
    flow.receive_pool_bytes=4096;
    source_host.enable_tfc(flow);
    target_host.enable_tfc(flow);
    Endpoint source(1,source_host,loop,trace,64),target(2,target_host,loop,trace,64);
    for (uint32_t job=1; job<=2; ++job) {
        source.memory().add_job(job);
        target.memory().add_job(job);
        const auto region=target.memory().register_region(job,1,64,7);
        if (job==2) {
            CHECK(forward.context_identifiers.size()==1);
            // This call synchronously enters the original I_PDC QUIESCE.
            // Its 65 ms SYN close guard keeps the old CCC alive while a new
            // Job creates another RUD PDC on the same peer and data TC.
            CHECK(source_host.request_connection_close(forward.context_identifiers.begin()->first));
        }
        Operation write;
        write.type=OperationType::Write;
        write.peer=2;
        write.job=job;
        write.delivery_mode=RUD;
        write.remote_key=region.key;
        write.payload.assign(64,static_cast<uint8_t>(job));
        source.submit(write);
        loop.run_until(job*kMillisecond);
        Completion completion{};
        CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Success);
        CHECK(target.memory().read(job,1,region.key,0,64)==write.payload);
    }
    CHECK(forward.context_identifiers.size()==2);
    auto first=forward.context_identifiers.begin();
    auto second=std::next(first);
    CHECK(first->second!=second->second);
    source.close();
    target.close();
    source_host.close();
    target_host.close();
    CHECK(source_host.tfc()->source_connection_count()==0 && target_host.tfc()->reserved_receive_bytes()==0);
    CHECK(loop.pending()==0);
}
}

int main() {
    try {
        for (const bool ordered : {false,true})
            for (const bool nscc : {false,true})
                for (const auto fault : {Fault::None,Fault::FirstData,Fault::FirstCredit})
                    for (const auto format : {RequestHeaderFormat::Standard,RequestHeaderFormat::Medium})
                        for (const bool ipv6_native : {false,true})
                            transaction(ordered,nscc,fault,format,ipv6_native);
        real_last_member_quiesce();
        std::cout << "48 original SES/PDS TFC wire/loss/NSCC cases plus real last-member QUIESCE passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
