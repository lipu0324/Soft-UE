#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;
using UET::NetworkLayer::UetWireCodec;

class CloseFaultPort : public IPacketPort {
public:
    CloseFaultPort(IPacketPort& lower,EventLoop& loop,bool target):lower_(lower),loop_(loop),target_(target) {}
    SendResult try_send(const Frame& frame) override {
        auto decoded=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size());
        auto& packet=decoded.packet;
        if (target_ && packet.PDS_type==RUOD_ack_header) local_pdc=packet.PDS_header.RUOD_ack_header.spdcid;
        if (target_ && packet.PDS_type==RUOD_ack_header &&
            packet.PDS_header.RUOD_ack_header.next_hdr==UET_HDR_CP_ACK && strip_close_payload) {
            strip_close_payload=false;
            packet.PDS_header.RUOD_ack_header.next_hdr=UET_HDR_NONE;
            Frame changed=frame; changed.bytes=UetWireCodec::encode(packet,decoded.network);
            return lower_.try_send(changed);
        }
        if (packet.PDS_type==RUOD_cp_header && packet.PDS_header.RUOD_cp_header.ctl_type==Close_req) {
            const auto& control=packet.PDS_header.RUOD_cp_header;
            CHECK(control.flags.ar && !control.flags.syn && !control.flags.isrod && !control.payload);
            if (requests.empty()) CHECK(!control.flags.retx);
            else CHECK(control.flags.retx && control.psn==requests.front());
            requests.push_back(control.psn);
            if (isolate || (inject_loss && requests.size()==1)) return SendResult::Accepted;
        }
        if (!target_ && packet.PDS_type==RUOD_ack_header && packet.PDS_header.RUOD_ack_header.next_hdr==UET_HDR_NONE) {
            ++plain_acks;
            if (inject_loss && plain_acks==1) return SendResult::Accepted;
        }
        if (packet.PDS_type==RUOD_cp_header && packet.PDS_header.RUOD_cp_header.ctl_type==Close_cmd) {
            const auto& control=packet.PDS_header.RUOD_cp_header;
            if (!commands.empty()) CHECK(control.psn==commands.front() && control.flags.retx);
            commands.push_back(control.psn);
            if (inject_loss && loop_.now()<8*kMillisecond) {
                loop_.at(8*kMillisecond,[this,frame] { CHECK(lower_.try_send(frame)==SendResult::Accepted); });
                return SendResult::Accepted;
            }
        }
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
    bool inject_loss=false,isolate=false,strip_close_payload=false;
    uint16_t local_pdc=UINT16_MAX;
    size_t plain_acks=0;
    std::vector<uint32_t> requests,commands;
private:
    IPacketPort& lower_; EventLoop& loop_; bool target_;
};

void target_requested_close(pdc_mode mode,bool lose_controls,bool silent_initiator,bool malformed_close_ack=false) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    CloseFaultPort source_port(forward,loop,false),target_port(reverse,loop,true);
    source_port.inject_loss=target_port.inject_loss=lose_controls;
    target_port.isolate=silent_initiator;
    target_port.strip_close_payload=malformed_close_ack;
    PdsHost source_host(1,loop,trace,source_port),target_host(2,loop,trace,target_port);
    Endpoint source(1,source_host,loop,trace),target(2,target_host,loop,trace);
    source.memory().add_job(1); target.memory().add_job(1);
    Operation noop; noop.type=OperationType::Noop; noop.peer=2; noop.delivery_mode=mode;
    source.submit(noop); loop.run(100000);
    Completion completion{};
    CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Success);
    CHECK(target_port.local_pdc>=512 && target_port.local_pdc<1024);
    CHECK(target_host.request_connection_close(target_port.local_pdc));
    CHECK(target_host.request_connection_close(target_port.local_pdc)); // Repeated local request is idempotent.
    loop.run(100000);
    CHECK(target_host.manager().getPDSStatus().open_cnt==0);
    CHECK(!target_port.requests.empty() && target_port.requests.front()==1000);
    if (silent_initiator) {
        CHECK(target_port.requests.size()>1 && source_port.commands.empty());
        source.submit(noop); loop.run(100000);
        CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::RemoteError);
    } else {
        CHECK(source_host.manager().getPDSStatus().open_cnt==0);
        CHECK(source_port.plain_acks>0 && !source_port.commands.empty());
        if (lose_controls) CHECK(target_port.requests.size()>=3 && source_port.commands.size()>1);
        else CHECK(target_port.requests.size()==1 && source_port.commands.size()==(malformed_close_ack?2:1));
        source.submit(noop); loop.run(100000);
        CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Success);
    }
    CHECK(!source.poll_completion(completion));
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(loop.pending()==0);
}

int main() {
    try {
        for (const auto mode:{ROD,RUD}) {
            target_requested_close(mode,false,false);
            target_requested_close(mode,true,false);
            target_requested_close(mode,false,true);
            target_requested_close(mode,false,false,true);
        }
        std::cout<<"PASS: target Close Request, plain ACK, cached PSN retries, silent-peer termination and context reuse\n";
        return 0;
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
