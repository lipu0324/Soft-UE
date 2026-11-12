#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>

using namespace UET::Runtime;
using namespace UET::SES;
using UET::NetworkLayer::UetWireCodec;

struct CloseFaults {
    bool closing_started=false;
    bool drop_command=false;
    bool drop_acknowledgement=false;
    uint16_t source_pdc=UINT16_MAX;
    size_t commands=0, dropped=0;
};

class CloseObservationPort : public IPacketPort {
public:
    CloseObservationPort(IPacketPort& lower,CloseFaults& faults,bool source)
        : lower_(lower),faults_(faults),source_(source) {}
    SendResult try_send(const Frame& frame) override {
        const auto packet=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        if (source_ && packet.PDS_type==RUOD_req_header)
            faults_.source_pdc=packet.PDS_header.RUOD_req_header.spdcid;
        if (source_ && packet.PDS_type==RUOD_cp_header &&
            packet.PDS_header.RUOD_cp_header.ctl_type==Close_cmd) {
            faults_.closing_started=true; ++faults_.commands;
            if (faults_.drop_command) {
                faults_.drop_command=false; ++faults_.dropped;
                return SendResult::Accepted;
            }
        }
        if (!source_ && faults_.closing_started && packet.PDS_type==RUOD_ack_header) {
            CHECK(packet.PDS_header.RUOD_ack_header.next_hdr==UET_HDR_CP_ACK);
            CHECK(packet.control_ack.cp_ack_type==Close_cmd && packet.control_ack.cp_ack_length==2);
        }
        if (!source_ && faults_.closing_started && faults_.drop_acknowledgement &&
            packet.PDS_type==RUOD_ack_header) {
            faults_.drop_acknowledgement=false; ++faults_.dropped;
            return SendResult::Accepted;
        }
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
private:
    IPacketPort& lower_;
    CloseFaults& faults_;
    bool source_;
};

void close_connection(bool lose_command,bool lose_acknowledgement) {
    EventLoop event_loop; Trace trace(event_loop); Fabric fabric(event_loop,trace,42);
    auto& source_port=fabric.add_host(1); auto& target_port=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    CloseFaults faults; faults.drop_command=lose_command; faults.drop_acknowledgement=lose_acknowledgement;
    CloseObservationPort source_faults(source_port,faults,true),target_faults(target_port,faults,false);
    PdsHost source_host(1,event_loop,trace,source_faults),target_host(2,event_loop,trace,target_faults);
    Endpoint source(1,source_host,event_loop,trace),target(2,target_host,event_loop,trace);
    source.memory().add_job(1); target.memory().add_job(1);
    Operation noop; noop.type=OperationType::Noop; noop.peer=2;
    source.submit(noop); event_loop.run_until(kMillisecond/10);
    Completion completion{};
    CHECK(source.poll_completion(completion)); CHECK(completion.status==CompletionStatus::Success);
    CHECK(faults.source_pdc!=UINT16_MAX);
    CHECK(source_host.request_connection_close(faults.source_pdc));
    event_loop.run_until(20*kMillisecond,10000);
    CHECK(source_host.manager().getPDSStatus().open_cnt==0);
    CHECK(target_host.manager().getPDSStatus().open_cnt==0);
    CHECK(faults.commands>=1);
    CHECK(faults.dropped==size_t(lose_command)+size_t(lose_acknowledgement));
    CHECK(event_loop.pending()==0);
    CHECK(!source.poll_completion(completion));
    source.close(); target.close(); source_host.close(); target_host.close();
}

int main() {
    try {
        close_connection(false,false);
        close_connection(true,false);
        close_connection(false,true);
        close_connection(true,true);
        std::cout<<"PASS: graceful PDC close, lost Close Command, lost close ACK and context/timer cleanup\n";
        return 0;
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
