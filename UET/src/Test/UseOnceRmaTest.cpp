#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

class UseOnceResultPort final : public IPacketPort {
public:
    UseOnceResultPort(IPacketPort& lower,EventLoop& loop):lower_(lower),loop_(loop) {}
    bool provides_transmit_timing() const override { return lower_.provides_transmit_timing(); }
    SendResult try_send(const Frame& frame) override {
        const auto packet=UET::NetworkLayer::UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        if (packet.SESpkt.bth_type==Semantic_Response_with_Data_Header ||
            packet.SESpkt.bth_type==Optimized_Response_with_Data_Header) {
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

static void transfer(OperationType type,RequestHeaderFormat format,pdc_mode mode,bool congestion,
                     uint32_t ack_limit,bool loss,bool zero_length=false) {
    constexpr uint32_t mtu=64;
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); UseOnceResultPort reverse(fabric.add_host(2),loop);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    source_host.configure_read_ack_data(ack_limit); target_host.configure_read_ack_data(ack_limit);
    source_host.configure_retransmission_timeout(100000); target_host.configure_retransmission_timeout(100000);
    if (congestion) { source_host.enable_nscc({}); target_host.enable_nscc({}); }
    Endpoint source(1,source_host,loop,trace,mtu),target(2,target_host,loop,trace,mtu);
    source.memory().add_job(1); target.memory().add_job(1);
    RegionOptions options; options.use_once=true; options.idempotent_safe=congestion;
    if (format==RequestHeaderFormat::Small) {
        options.requested_key=MemoryKeyFormat::Optimized|3;
        target.resources().configure_resource(1,3,ResourceSpace::Rma);
    }
    const auto remote=target.memory().register_region(1,1,256,7,options);
    const auto local=source.memory().register_region(1,1,256,7);
    const uint32_t length=zero_length?0:type==OperationType::FetchingAtomic?8:
        format==RequestHeaderFormat::Standard?136:16;
    std::vector<uint8_t> original(256,0),expected=original;
    if (type==OperationType::Read) {
        for (uint32_t index=0;index<length;++index) original[8+index]=0x31+index*7;
        expected=original;
    }
    remote.storage->write(0,original.data(),original.size());
    Operation operation; operation.type=type; operation.delivery_mode=mode; operation.header_format=format;
    operation.peer=2; operation.remote_key=remote.key; operation.remote_offset=8;
    if (type==OperationType::Read) {
        operation.read_length=length; operation.read_result=ReadResultBuffer{local.key,16,length,1,1};
    } else {
        operation.payload.assign(length,0);
        if (type==OperationType::Write) {
            std::fill(operation.payload.begin(),operation.payload.end(),0x72);
            std::fill(expected.begin()+8,expected.begin()+8+length,0x72);
        } else {
            for (uint32_t index=0;index<length;index+=8) operation.payload[index]=1;
            for (uint32_t index=0;index<length;index+=8) expected[8+index]=1;
            if (type==OperationType::FetchingAtomic) operation.atomic_result=AtomicResultBuffer{local.key,16,length,1,1};
        }
    }
    reverse.lose_first=loss;
    reverse.after_loss=[&] {
        // ACK-data READ re-executes against the same live grant. Reverse
        // return data and fetching atomics replay their retained old value.
        CHECK(target.memory().retained_use_once_claims()==1);
        if (type==OperationType::Read) {
            const uint8_t newer=0x99; remote.storage->write(8,&newer,1); expected[8]=newer;
        }
    };
    const auto identifier=source.submit(operation); loop.run_until(90*kMillisecond);
    Completion completion{};
    if (!source.poll_completion(completion) || completion.status!=CompletionStatus::Success)
        throw std::runtime_error("use-once RMA failed: type="+std::to_string(unsigned(type))+" format="+
            std::to_string(unsigned(format))+" mode="+std::to_string(mode)+" length="+std::to_string(length)+
            " loss="+std::to_string(loss)+" code="+std::to_string(completion.remote_code));
    CHECK(completion.operation==identifier && completion.length==length && !source.poll_completion(completion));
    std::vector<uint8_t> actual(256); remote.storage->read(0,actual.data(),actual.size());
    CHECK(actual==expected);
    if (type==OperationType::Read) {
        auto result=source.memory().read(1,1,local.key,16,length);
        auto returned=original;
        if (loss && ack_limit>=mtu) returned[8]=0x99;
        CHECK(result==std::vector<uint8_t>(returned.begin()+8,returned.begin()+8+length));
    } else if (type==OperationType::FetchingAtomic)
        CHECK(source.memory().read(1,1,local.key,16,length)==std::vector<uint8_t>(length,0));
    CHECK(!target.memory().retained_use_once_claims() && !target.retained_receive_messages());
    // A second logical message cannot reuse the grant after real EOM Clear.
    // A failed READ can still have reverse data in flight. Its MID remains
    // leased until real connection retirement, including plaintext SYN safety.
    source.submit(operation); loop.run_until(180*kMillisecond);
    CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::RemoteError &&
        completion.remote_code==static_cast<uint8_t>(SemanticReturnCode::BadMemoryKey));
    CHECK(!source.poll_completion(completion) && !target.poll_completion(completion));
    std::vector<uint8_t> unchanged(256); remote.storage->read(0,unchanged.data(),unchanged.size()); CHECK(unchanged==actual);
    if (source.pending() || source.leased_message_ids() || target.retained_receive_messages() ||
        target.retained_read_packets() || target.pending_read_returns() || target.memory().retained_use_once_claims())
        throw std::runtime_error("use-once retirement failed: type="+std::to_string(unsigned(type))+" format="+
            std::to_string(unsigned(format))+" mode="+std::to_string(mode)+" ack="+std::to_string(ack_limit)+
            " loss="+std::to_string(loss)+" pending="+std::to_string(source.pending())+
            " leases="+std::to_string(source.leased_message_ids())+" receives="+std::to_string(target.retained_receive_messages())+
            " packets="+std::to_string(target.retained_read_packets())+" returns="+std::to_string(target.pending_read_returns())+
            " grants="+std::to_string(target.memory().retained_use_once_claims()));
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(!loop.pending());
}

static void rudi_cannot_consume_a_message_grant(OperationType type,bool congestion) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    if (congestion) { source_host.enable_nscc({}); target_host.enable_nscc({}); }
    Endpoint source(1,source_host,loop,trace,64),target(2,target_host,loop,trace,64);
    source.memory().add_job(1); target.memory().add_job(1);
    RegionOptions options; options.use_once=true; options.idempotent_safe=true;
    const auto region=target.memory().register_region(1,1,8,7,options);
    const auto result=source.memory().register_region(1,1,8,7);
    Operation operation; operation.type=type; operation.delivery_mode=RUDI; operation.peer=2; operation.remote_key=region.key;
    if (type==OperationType::Read) { operation.read_length=8; operation.read_result=ReadResultBuffer{result.key,0,8,1,1}; }
    else operation.payload.assign(8,0x71);
    source.submit(operation); loop.run_until(kMillisecond);
    Completion completion{};
    CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::RemoteError &&
        completion.remote_code==static_cast<uint8_t>(SemanticReturnCode::BadMemoryKey));
    CHECK(!target.memory().retained_use_once_claims());
    // Rejecting ownerless RUDI must leave the buffer available for a reliable
    // logical message, even though its key advertises idempotent-safe effects.
    operation.delivery_mode=RUD; source.submit(operation); loop.run_until(2*kMillisecond);
    CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Success);
    CHECK(!source.poll_completion(completion) && !target.memory().retained_use_once_claims());
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(!loop.pending());
}

int main() {
    try {
        size_t scenarios=0;
        for (auto format:{RequestHeaderFormat::Standard,RequestHeaderFormat::Small,RequestHeaderFormat::Medium})
            for (auto mode:{RUD,ROD}) for (bool congestion:{false,true}) {
                for (auto type:{OperationType::Write,OperationType::Atomic,OperationType::FetchingAtomic}) {
                    transfer(type,format,mode,congestion,64,false); ++scenarios;
                }
                for (uint32_t ack_limit:{0u,64u}) for (bool loss:{false,true}) {
                    transfer(OperationType::Read,format,mode,congestion,ack_limit,loss); ++scenarios;
                }
                transfer(OperationType::Write,format,mode,congestion,64,false,true); ++scenarios;
                transfer(OperationType::Read,format,mode,congestion,64,false,true); ++scenarios;
                transfer(OperationType::FetchingAtomic,format,mode,congestion,64,true); ++scenarios;
            }
        CHECK(scenarios==120);
        for (auto type:{OperationType::Write,OperationType::Read}) for (bool congestion:{false,true})
            rudi_cannot_consume_a_message_grant(type,congestion);
        std::cout << "PASS124 native use-once WRITE/READ/atomics, fragmentation, loss, zero lengths, Clear and ownerless RUDI rejection\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
