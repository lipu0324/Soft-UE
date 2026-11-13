#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <algorithm>
#include <array>
#include <iostream>
#include <functional>
#include <optional>

using namespace UET::Runtime;
using namespace UET::SES;
using namespace UET::NetworkLayer;

class ObservedAtomicStorage final : public MemoryStorage {
public:
    ObservedAtomicStorage() { bytes.fill(0x5a); }
    uint64_t size() const override { return bytes.size(); }
    size_t allocated_pages() const override { return 1; }
    void read(uint64_t offset,uint8_t* destination,size_t count) const override {
        CHECK(offset<=bytes.size() && count<=bytes.size()-offset);
        if (!count) { ++zero_reads; last_zero_offset=offset; }
        else { ++normal_reads; std::copy_n(bytes.data()+offset,count,destination); }
    }
    void write(uint64_t offset,const uint8_t* source,size_t count) override {
        CHECK(offset<=bytes.size() && count<=bytes.size()-offset); ++writes;
        if (count) std::copy_n(source,count,bytes.data()+offset);
    }
    std::array<uint8_t,32> bytes;
    mutable size_t zero_reads=0,normal_reads=0;
    mutable uint64_t last_zero_offset=UINT64_MAX;
    size_t writes=0;
};

class ZeroDataAckPort final : public IPacketPort {
public:
    explicit ZeroDataAckPort(IPacketPort& lower):lower_(lower) {}
    SendResult try_send(const Frame& frame) override {
        const auto packet=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        if (packet.PDS_type==RUOD_ack_header && packet.SESpkt.bth_type==Semantic_Response_with_Data_Header &&
            packet.SESpkt.bth_header.Semantic_Response_with_Data_Header.modified_length==0) {
            CHECK(packet.SESpkt.payload.empty() && !packet.SESpkt.bth_header.Semantic_Response_with_Data_Header.payload_length);
            CHECK(packet.PDS_header.RUOD_ack_header.flags.req&1); ++zero_acks;
            if (drop_next) { drop_next=false; if (on_drop) on_drop(); return SendResult::Accepted; }
        }
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver callback) override { lower_.set_receiver(std::move(callback)); }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
    bool drop_next=false;
    size_t zero_acks=0;
    std::function<void()> on_drop;
private:
    IPacketPort& lower_;
};

void zero_operations(pdc_mode mode,bool congestion) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); ZeroDataAckPort reverse(fabric.add_host(2));
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    source_host.configure_read_ack_data(0); target_host.configure_read_ack_data(0);
    if (congestion) {
        const auto config=UET::CMS::NsccConfig::for_link(12000,12500000000ULL,12500000000ULL,1132);
        source_host.enable_nscc(config); target_host.enable_nscc(config);
    }
    Endpoint source(1,source_host,loop,trace),target(2,target_host,loop,trace);
    source.memory().add_job(1); target.memory().add_job(1);
    const auto storage=std::make_shared<ObservedAtomicStorage>();
    const auto remote=target.memory().register_storage(1,1,storage,7);
    Operation operation; operation.type=OperationType::Atomic; operation.peer=2; operation.delivery_mode=mode;
    operation.remote_key=remote.key; operation.remote_offset=32; operation.atomic_operation=IntegerAtomicOperation::Write;
    const auto execute=[&](Operation request,CompletionStatus status=CompletionStatus::Success,uint8_t code=1) {
        const auto submitted=source.submit(std::move(request)); loop.run(100000);
        Completion completion{}; CHECK(source.poll_completion(completion) && completion.operation==submitted &&
            completion.status==status && completion.remote_code==code && !source.poll_completion(completion));
        return completion.length;
    };
    CHECK(execute(operation)==0); CHECK(!storage->zero_reads && !storage->normal_reads && !storage->writes);
    operation.type=OperationType::FetchingAtomic; operation.zero_length_atomic=true;
    operation.atomic_operation=IntegerAtomicOperation::Read;
    reverse.drop_next=true;
    CHECK(execute(operation)==0); // No local result registration is needed.
    CHECK(storage->zero_reads==1 && storage->last_zero_offset==32 && reverse.zero_acks>=2);
    operation.atomic_operation=IntegerAtomicOperation::Write;
    CHECK(execute(operation)==0 && storage->zero_reads==1 && !storage->writes);
    std::array<uint8_t,16> zero_destination; zero_destination.fill(0xee);
    RegionOptions local_only; local_only.local_placement_only=true; local_only.requested_key=0x1234;
    const auto zero_result=source.memory().register_buffer(1,1,zero_destination.data(),zero_destination.size(),Access::Read|Access::Write,local_only);
    std::optional<Region> replacement;
    operation.atomic_operation=IntegerAtomicOperation::Read;
    operation.atomic_result=AtomicResultBuffer{zero_result.key,16,0,1,1};
    reverse.on_drop=[&] {
        source.memory().deregister(zero_result);
        replacement=source.memory().register_region(1,1,16,Access::Read|Access::Write,local_only);
        source.memory().write_registration(*replacement,1,1,0,std::vector<uint8_t>(16,0xa5),1);
    };
    reverse.drop_next=true;
    CHECK(execute(operation,CompletionStatus::LocalError,0)==0);
    CHECK(storage->zero_reads==2 && std::all_of(zero_destination.begin(),zero_destination.end(),[](auto byte) { return byte==0xee; }));
    std::array<uint8_t,16> replacement_bytes{};
    replacement->storage->read(0,replacement_bytes.data(),replacement_bytes.size());
    CHECK(std::all_of(replacement_bytes.begin(),replacement_bytes.end(),[](auto byte) { return byte==0xa5; }));
    reverse.on_drop={}; operation.atomic_result.reset();
    auto invalid=operation; invalid.atomic_operation=IntegerAtomicOperation::Sum;
    CHECK(execute(invalid,CompletionStatus::InvalidRequest,0)==0);
    invalid=operation; invalid.atomic_operation=IntegerAtomicOperation::Read; invalid.remote_offset=40;
    CHECK(execute(invalid,CompletionStatus::RemoteError,0x1d)==0 && storage->zero_reads==2);
    const auto denied=target.memory().register_region(1,1,32,Access::Read|Access::Write);
    invalid=operation; invalid.remote_key=denied.key;
    CHECK(execute(invalid,CompletionStatus::RemoteError,0x18)==0);
    // Default atomic READ still returns one whole element when its ignored
    // input operand is omitted; only the explicit flag selects a zero GET.
    const auto local=source.memory().register_region(1,1,16,Access::Read|Access::Write);
    operation.zero_length_atomic=false; operation.atomic_operation=IntegerAtomicOperation::Read; operation.remote_offset=0;
    operation.atomic_result=AtomicResultBuffer{local.key,0,8,1,1};
    CHECK(execute(operation)==8 && storage->normal_reads==1 && !storage->writes);
    CHECK(source.memory().read(1,1,local.key,0,8)==std::vector<uint8_t>(8,0x5a));
    CHECK(std::all_of(storage->bytes.begin(),storage->bytes.end(),[](auto byte) { return byte==0x5a; }));
    CHECK(source.leased_message_ids()==0 && target.retained_receive_messages()==0);
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(loop.pending()==0);
}

int main() {
    try {
        for (const auto mode:{RUD,ROD}) for (const bool congestion:{false,true}) zero_operations(mode,congestion);
        std::cout<<"PASS zero-byte atomic put/get, real zero read, cached empty ACK, authority, bounds and normal READ distinction\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
