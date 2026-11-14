#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

class OptimizedReadResultPort final : public IPacketPort {
public:
    OptimizedReadResultPort(IPacketPort& lower,EventLoop& loop):lower_(lower),loop_(loop) {}
    bool provides_transmit_timing() const override { return lower_.provides_transmit_timing(); }
    SendResult try_send(const Frame& frame) override {
        const auto packet=UET::NetworkLayer::UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        if (packet.SESpkt.bth_type==Optimized_Response_with_Data_Header) {
            CHECK(packet.PDS_type==RUOD_req_header || packet.PDS_type==RUOD_ack_header);
            ++results;
            if (lose_first && results==1) {
                if (frame.transmission_event) frame.transmission_event(loop_.now(),TransmitOutcome::Started);
                if (after_loss) after_loss();
                return SendResult::Accepted;
            }
        }
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable handler) override { lower_.set_writable_handler(std::move(handler)); }
    bool lose_first=false;
    size_t results=0;
    std::function<void()> after_loss;
private:
    IPacketPort& lower_; EventLoop& loop_;
};
static void read(RequestHeaderFormat format,pdc_mode mode,bool congestion,uint32_t ack_limit,uint32_t length,bool loss=false) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); OptimizedReadResultPort reverse(fabric.add_host(2),loop);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    source_host.configure_read_ack_data(ack_limit); target_host.configure_read_ack_data(ack_limit);
    source_host.configure_retransmission_timeout(100000); target_host.configure_retransmission_timeout(100000);
    if (congestion) { source_host.enable_nscc({}); target_host.enable_nscc({}); }
    Endpoint source(1,source_host,loop,trace,128),target(2,target_host,loop,trace,128);
    source.memory().add_job(1); target.memory().add_job(1);
    RegionOptions options; const bool small=format==RequestHeaderFormat::Small;
    if (small) {
        options.requested_key=MemoryKeyFormat::Optimized|3; options.idempotent_safe=congestion;
        target.resources().configure_resource(1,3,ResourceSpace::Rma);
    }
    const auto remote=target.memory().register_region(1,1,256,7,options);
    const auto local=source.memory().register_region(1,1,256,7);
    std::vector<uint8_t> expected(length);
    for (size_t index=0;index<length;++index) expected[index]=0x33+index*7;
    remote.storage->write(13,expected.data(),expected.size());
    const bool return_direction=length>ack_limit && ack_limit<128;
    reverse.lose_first=loss;
    reverse.after_loss=[&] {
        CHECK(length); const uint8_t newer=0x77; remote.storage->write(13,&newer,1);
        // §3.5.17: an ACK-data READ is re-executed; reverse data is retained
        // by its own PDS TX window until accepted, so that payload stays old.
        if (!return_direction) expected[0]=newer;
    };
    size_t data_acks=0,return_packets=0;
    fabric.set_capture([&](Time,const Frame& frame) {
        const auto packet=UET::NetworkLayer::UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        if (packet.SESpkt.bth_type==Optimized_Response_with_Data_Header) {
            const auto& data=packet.SESpkt.bth_header.Optimized_Response_with_Data_Header;
            CHECK(data.opcode==2 && data.payload_length==length && packet.SESpkt.payload.size()==length);
            if (packet.PDS_type==RUOD_ack_header) {
                CHECK(data.original_request_psn==packet.PDS_header.RUOD_ack_header.cack_psn+
                    packet.PDS_header.RUOD_ack_header.ack_psn_off); ++data_acks;
            } else { CHECK(packet.PDS_type==RUOD_req_header); ++return_packets; }
        }
        if (packet.PDS_type==RUOD_ack_header && packet.SESpkt.bth_type==Semantic_Response_Header)
            CHECK(!packet.SESpkt.bth_header.Semantic_Response_Header.message_id);
    });
    Operation operation; operation.type=OperationType::Read; operation.header_format=format;
    operation.delivery_mode=mode; operation.peer=2; operation.remote_key=remote.key; operation.remote_offset=13;
    operation.read_length=length; operation.read_result=ReadResultBuffer{local.key,17,length,1,1}; operation.context=99;
    const auto id=source.submit(operation); loop.run_until(10*kMillisecond);
    Completion completion{};
    if (!source.poll_completion(completion) || completion.status!=CompletionStatus::Success)
        throw std::runtime_error("optimized READ failed: format="+std::to_string(unsigned(format))+" mode="+
            std::to_string(mode)+" ack="+std::to_string(ack_limit)+" length="+std::to_string(length)+" loss="+std::to_string(loss));
    CHECK(completion.operation==id && completion.context==99 && completion.length==length);
    CHECK(source.memory().read(1,1,local.key,17,length)==expected && !source.poll_completion(completion) && !target.poll_completion(completion));
    CHECK((return_direction?return_packets:data_acks)>=1 && (return_direction?!data_acks:!return_packets));
    CHECK(!source.pending() && !source.leased_message_ids() && !target.retained_receive_messages() &&
        !target.pending_read_returns() && !target.retained_read_packets());
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(!loop.pending());
}
int main() {
    try {
        size_t scenarios=0;
        for (auto format:{RequestHeaderFormat::Small,RequestHeaderFormat::Medium}) for (auto mode:{RUD,ROD})
            for (bool congestion:{false,true}) {
                for (uint32_t ack_limit:{0u,64u,128u}) for (uint32_t length:{0u,1u,73u,128u}) {
                    read(format,mode,congestion,ack_limit,length); ++scenarios;
                }
                for (uint32_t ack_limit:{0u,128u}) { read(format,mode,congestion,ack_limit,73,true); ++scenarios; }
            }
        CHECK(scenarios==112);
        std::cout<<"PASS112 optimized READ DATA_SMALL ACK/return channels, zero/MTU/threshold boundaries and loss recovery\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
