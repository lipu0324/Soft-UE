#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

enum class FetchFault { None, LostResult, DuplicateResult, DelayedResult, WrongOriginalPsn };
class FetchConcurrencyPort final : public IPacketPort {
public:
    FetchConcurrencyPort(IPacketPort& lower,EventLoop& loop):lower_(lower),loop_(loop) {}
    bool provides_transmit_timing() const override { return lower_.provides_transmit_timing(); }
    SendResult try_send(const Frame& frame) override {
        auto decoded=UET::NetworkLayer::UetWireCodec::decode(frame.bytes.data(),frame.bytes.size());
        const auto& packet=decoded.packet;
        if (packet.PDS_type!=RUOD_ack_header || packet.SESpkt.bth_type!=Optimized_Response_with_Data_Header)
            return lower_.try_send(frame);
        ++results;
        if (results!=1 || fault==FetchFault::None) return lower_.try_send(frame);
        if (fault==FetchFault::WrongOriginalPsn) {
            ++decoded.packet.SESpkt.bth_header.Optimized_Response_with_Data_Header.original_request_psn;
            auto changed=frame; changed.bytes=UET::NetworkLayer::UetWireCodec::encode(decoded.packet,decoded.network);
            return lower_.try_send(changed);
        }
        if (fault==FetchFault::DuplicateResult) {
            CHECK(lower_.try_send(frame)==SendResult::Accepted); return lower_.try_send(frame);
        }
        if (frame.transmission_event) frame.transmission_event(loop_.now(),TransmitOutcome::Started);
        if (fault==FetchFault::DelayedResult) {
            auto delayed=frame; delayed.transmission_event={};
            loop_.after(200000,[this,delayed] { CHECK(lower_.try_send(delayed)==SendResult::Accepted); });
        }
        return SendResult::Accepted; // Loss/delay happens after actual MAC departure.
    }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable handler) override { lower_.set_writable_handler(std::move(handler)); }
    FetchFault fault=FetchFault::None;
    size_t results=0;
private:
    IPacketPort& lower_; EventLoop& loop_;
};
class FetchCountedStorage final : public MemoryStorage {
public:
    uint64_t size() const override { return backing_.size(); }
    size_t allocated_pages() const override { return backing_.allocated_pages(); }
    void read(uint64_t offset,uint8_t* bytes,size_t count) const override { backing_.read(offset,bytes,count); }
    void write(uint64_t offset,const uint8_t* bytes,size_t count) override { ++writes; backing_.write(offset,bytes,count); }
    size_t writes=0;
private:
    SparseMemory backing_{256};
};
static void concurrent(RequestHeaderFormat format,pdc_mode mode,bool congestion,FetchFault fault) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); FetchConcurrencyPort reverse(fabric.add_host(2),loop);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    source_host.configure_retransmission_timeout(100000); target_host.configure_retransmission_timeout(100000);
    if (congestion) { source_host.enable_nscc({}); target_host.enable_nscc({}); }
    Endpoint source(1,source_host,loop,trace,128),target(2,target_host,loop,trace,128);
    source.memory().add_job(1); target.memory().add_job(1);
    auto storage=std::make_shared<FetchCountedStorage>(); RegionOptions options;
    const bool small=format==RequestHeaderFormat::Small;
    if (small) {
        options.requested_key=MemoryKeyFormat::Optimized|3;
        target.resources().configure_resource(1,3,ResourceSpace::Rma);
    }
    const auto remote=target.memory().register_storage(1,1,storage,7,options);
    const auto local=source.memory().register_region(1,1,256,7);
    for (uint8_t index=0;index<8;++index) {
        std::vector<uint8_t> old_value(8); old_value[0]=10+index;
        storage->write(index*8,old_value.data(),old_value.size());
    }
    storage->writes=0;
    CHECK(source_host.open_connection(2,1,mode,false,{1,1,static_cast<uint16_t>(small?3:1)})!=UINT16_MAX);
    loop.run_until(kMillisecond); reverse.fault=fault;
    std::set<uint64_t> operation_ids;
    for (uint8_t index=0;index<8;++index) {
        Operation operation; operation.type=OperationType::FetchingAtomic; operation.header_format=format;
        operation.delivery_mode=mode; operation.peer=2; operation.remote_key=remote.key;
        operation.remote_offset=index*8; operation.context=index; operation.payload.assign(8,0); operation.payload[0]=1;
        operation.atomic_result=AtomicResultBuffer{local.key,uint64_t{index}*8,8,1,1};
        operation_ids.insert(source.submit(operation));
    }
    loop.run_until(5*kMillisecond); Completion completion{}; size_t completed=0;
    while (source.poll_completion(completion)) {
        CHECK(operation_ids.erase(completion.operation)==1 && completion.status==CompletionStatus::Success &&
            completion.length==8 && completion.context<8); ++completed;
    }
    CHECK(completed==8 && operation_ids.empty() && storage->writes==8 && !target.poll_completion(completion));
    for (uint8_t index=0;index<8;++index) {
        std::vector<uint8_t> expected_old(8),expected_new(8),actual(8);
        expected_old[0]=10+index; expected_new[0]=11+index;
        CHECK(source.memory().read(1,1,local.key,index*8,8)==expected_old);
        storage->read(index*8,actual.data(),actual.size()); CHECK(actual==expected_new);
    }
    CHECK(!source.pending() && !source.leased_message_ids() && !target.retained_receive_messages());
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(!loop.pending());
}
int main() {
    try {
        for (auto format:{RequestHeaderFormat::Small,RequestHeaderFormat::Medium}) for (auto mode:{RUD,ROD})
            for (bool congestion:{false,true}) for (auto fault:{FetchFault::None,FetchFault::LostResult,
                FetchFault::DuplicateResult,FetchFault::DelayedResult,FetchFault::WrongOriginalPsn})
                concurrent(format,mode,congestion,fault);
        std::cout<<"PASS40 optimized eight-operation fetching concurrency, result PSN binding and exactly-once execution\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
