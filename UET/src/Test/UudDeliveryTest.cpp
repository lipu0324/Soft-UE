#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>

using namespace UET::Runtime;
using namespace UET::SES;
using UET::NetworkLayer::UetWireCodec;

class DatagramObservationPort : public IPacketPort {
public:
    DatagramObservationPort(IPacketPort& lower, bool drop) : lower_(lower),drop_(drop) {}
    SendResult try_send(const Frame& frame) override {
        ++transmitted_frames;
        const auto decoded=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size());
        CHECK(decoded.packet.PDS_type==UUD_req_header);
        const auto& header=decoded.packet.SESpkt.bth_header.Standard_Header;
        CHECK(header.msg_id==0 && header.opcode==7 && !header.dc && header.som && header.eom);
        // Independent check of the four-byte compact UUD header.
        CHECK(frame.bytes[38]==0x31 && frame.bytes[39]==0x80);
        CHECK(frame.bytes[40]==0 && frame.bytes[41]==0);
        return drop_ ? SendResult::Accepted : lower_.try_send(frame);
    }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
    size_t transmitted_frames=0;
private:
    IPacketPort& lower_;
    bool drop_;
};

void datagram_delivery(bool drop, bool post_receive) {
    EventLoop event_loop; Trace trace(event_loop); Fabric fabric(event_loop,trace,42);
    auto& source_port=fabric.add_host(1); auto& target_port=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    DatagramObservationPort datagram_port(source_port,drop);
    PdsHost source_host(1,event_loop,trace,datagram_port),target_host(2,event_loop,trace,target_port);
    Endpoint source(1,source_host,event_loop,trace,64),target(2,target_host,event_loop,trace,64);
    source.memory().add_job(1); target.memory().add_job(1);
    const auto region=target.memory().register_region(1,1,64,7);
    if (post_receive) target.post_receive(1,1,region.key,0,64,99);
    Operation datagram; datagram.type=OperationType::DatagramSend; datagram.peer=2;
    datagram.payload={0x11,0x22,0x33}; source.submit(datagram);
    event_loop.run_until(100*kMillisecond);
    Completion completion{};
    CHECK(source.poll_completion(completion));
    CHECK(completion.status==CompletionStatus::LocalSuccess);
    CHECK(!source.poll_completion(completion));
    CHECK(datagram_port.transmitted_frames==1); // No retransmission or probing.
    CHECK(source_host.manager().getPDSStatus().open_cnt==0);
    CHECK(target_host.manager().getPDSStatus().open_cnt==0);
    CHECK(target.poll_completion(completion)==(!drop && post_receive));
    if (!drop && post_receive) {
        CHECK(completion.receive && completion.context==99);
        CHECK(target.memory().read(1,1,region.key,0,3)==datagram.payload);
    } else CHECK(target.memory().read(1,1,region.key,0,3)==std::vector<uint8_t>(3,0));
    CHECK(!target.poll_completion(completion));
    CHECK(fabric.stats(2,1).packets==0); // No transport/semantic ACK path.
    source.close(); target.close(); source_host.close(); target_host.close();
    CHECK(event_loop.pending()==0);
}

int main() {
    try {
        datagram_delivery(false,true);
        datagram_delivery(true,true);
        datagram_delivery(false,false);
        std::cout<<"PASS: UUD local completion, loss without retry, compact wire format and no PDC allocation\n";
        return 0;
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
