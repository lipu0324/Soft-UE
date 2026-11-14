#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

class TaggedAtomicAckPort final : public IPacketPort {
public:
    TaggedAtomicAckPort(IPacketPort& lower,EventLoop& loop):lower_(lower),loop_(loop) {}
    bool provides_transmit_timing() const override { return lower_.provides_transmit_timing(); }
    SendResult try_send(const Frame& frame) override {
        const auto packet=UET::NetworkLayer::UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        if (lose_first && !dropped && packet.PDS_type==RUOD_ack_header &&
            (!fetching || packet.SESpkt.bth_type==Semantic_Response_with_Data_Header ||
             packet.SESpkt.bth_type==Optimized_Response_with_Data_Header)) {
            dropped=true;
            if (frame.transmission_event) frame.transmission_event(loop_.now(),TransmitOutcome::Started);
            return SendResult::Accepted;
        }
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable handler) override { lower_.set_writable_handler(std::move(handler)); }
    bool lose_first=false,fetching=false,dropped=false;
private:
    IPacketPort& lower_; EventLoop& loop_;
};

static void transaction(OperationType type,RequestHeaderFormat format,pdc_mode mode,bool congestion,
                        bool late,bool loss,IntegerAtomicDatatype datatype) {
    constexpr uint64_t tag=0xf0aabbccdd000042ULL;
    const bool fetching=type==OperationType::TaggedFetchingAtomic;
    const auto width=integer_atomic_width(datatype);
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); TaggedAtomicAckPort reverse(fabric.add_host(2),loop);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    source_host.configure_retransmission_timeout(100000); target_host.configure_retransmission_timeout(100000);
    if (congestion) { source_host.enable_nscc({}); target_host.enable_nscc({}); }
    Endpoint source(1,source_host,loop,trace,64),target(2,target_host,loop,trace,64);
    source.memory().add_job(1); target.memory().add_job(1);
    target.resources().configure_resource(1,2,ResourceSpace::Tagged,7);
    RegionOptions options; options.local_placement_only=true; options.resource_index=2;
    const auto remote=target.memory().register_region(1,1,256,7,options);
    const auto local=source.memory().register_region(1,1,32,7);
    // The wire tag deliberately bears no relation to this private MR key.
    // Buffer authority comes from one consumed local posting (§3.4.2.5.4).
    CHECK(remote.key!=tag);
    const uint64_t requested_offset=format==RequestHeaderFormat::Standard?width:0;
    const uint64_t placement=16+requested_offset;
    std::vector<uint8_t> expected(256,0),previous(width,0);
    if (fetching) { previous[0]=3; remote.storage->write(placement,previous.data(),previous.size()); }
    const uint32_t length=fetching?32:format==RequestHeaderFormat::Standard?136:32;
    if (fetching) expected[placement]=7;
    else for (uint32_t offset=0;offset<length;offset+=width) expected[placement+offset]=1;
    const auto post=[&] { target.post_tagged_receive(1,1,remote.key,16,240,{tag&~uint64_t{0xff},0xff,77},99,2); };
    if (!late) post();
    reverse.lose_first=loss; reverse.fetching=fetching;
    Operation operation; operation.type=type; operation.peer=2; operation.delivery_mode=mode;
    operation.header_format=format; operation.tag=tag; operation.initiator_id=77;
    operation.target_resource=2; operation.target_generation=7; operation.remote_offset=requested_offset;
    operation.atomic_datatype=datatype;
    if (fetching) {
        operation.atomic_operation=IntegerAtomicOperation::CompareSwapEqual;
        operation.payload.assign(width,0); operation.payload[0]=7;
        operation.atomic_compare=previous; operation.atomic_result=AtomicResultBuffer{local.key,0,static_cast<uint32_t>(width),1,1};
    } else {
        operation.payload.assign(length,0);
        for (uint32_t offset=0;offset<length;offset+=width) operation.payload[offset]=1;
    }
    const auto identifier=source.submit(operation);
    if (late) {
        loop.run_until(10000);
        Completion completion{}; CHECK(!source.poll_completion(completion) && !target.poll_completion(completion));
        CHECK(target.unexpected_bytes()==length); post();
    }
    loop.run_until(90*kMillisecond);
    Completion completion{};
    if (!source.poll_completion(completion) || completion.status!=CompletionStatus::Success)
        throw std::runtime_error("tagged atomic failed: fetching="+std::to_string(fetching)+" format="+
            std::to_string(unsigned(format))+" mode="+std::to_string(mode)+" late="+std::to_string(late)+
            " datatype="+std::to_string(unsigned(datatype))+" code="+std::to_string(completion.remote_code));
    CHECK(completion.operation==identifier && completion.length==length && completion.remote_generation==7);
    if (fetching) CHECK(source.memory().read(1,1,local.key,0,width)==previous);
    CHECK(target.poll_completion(completion) && completion.receive && completion.context==99 &&
        completion.status==CompletionStatus::Success && completion.tag==tag && completion.length==(fetching?width:length));
    if (fetching) CHECK(completion.original_length==32);
    std::vector<uint8_t> actual(256); remote.storage->read(0,actual.data(),actual.size()); CHECK(actual==expected);
    CHECK(!source.poll_completion(completion) && !target.poll_completion(completion));
    CHECK(!loss || reverse.dropped);
    CHECK(!source.pending() && !source.leased_message_ids() && !target.retained_receive_messages() && !target.unexpected_bytes());
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(!loop.pending());
}

int main() {
    try {
        size_t scenarios=0;
        for (auto format:{RequestHeaderFormat::Standard,RequestHeaderFormat::Medium}) for (auto mode:{RUD,ROD})
            for (bool congestion:{false,true}) for (bool loss:{false,true}) for (bool late:{false,true}) {
                if (late && mode!=ROD) continue;
                for (auto datatype:{IntegerAtomicDatatype::Int8,IntegerAtomicDatatype::Uint16,IntegerAtomicDatatype::Int32,IntegerAtomicDatatype::Uint64}) {
                    transaction(OperationType::TaggedAtomic,format,mode,congestion,late,loss,datatype); ++scenarios;
                }
                for (auto datatype:{IntegerAtomicDatatype::Uint8,IntegerAtomicDatatype::Int16,IntegerAtomicDatatype::Uint32,
                                    IntegerAtomicDatatype::Int64,IntegerAtomicDatatype::Uint128}) {
                    transaction(OperationType::TaggedFetchingAtomic,format,mode,congestion,late,loss,datatype); ++scenarios;
                }
            }
        CHECK(scenarios==216);
        std::cout << "PASS216 tagged atomic posting authority, wildcard/rank selection, fragmentation, delayed posting and result replay\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
