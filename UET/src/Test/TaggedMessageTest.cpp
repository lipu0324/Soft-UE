#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <algorithm>
#include <array>
#include <iostream>

using namespace UET::Runtime;
using namespace UET::SES;
using UET::NetworkLayer::UetWireCodec;

// Faults touch the real wire path. They provide no ACK, matching or recovery
// service; the original PDS must deduplicate/retry and retire every operation.
class TaggedFaultPort final : public IPacketPort {
public:
    TaggedFaultPort(IPacketPort& lower,EventLoop& loop):lower_(lower),loop_(loop) {}
    SendResult try_send(const Frame& frame) override {
        const auto decoded=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size());
        auto packet=decoded.packet;
        if (packet.PDS_type==RUOD_req_header && packet.SESpkt.bth_type==Standard_Header &&
            packet.SESpkt.bth_header.Standard_Header.opcode==9) {
            const auto& header=packet.SESpkt.bth_header.Standard_Header;
            ++tagged_requests;
            if (delay_first && header.som && !header.eom) {
                delay_first=false;
                loop_.after(kMillisecond,[this,frame] { CHECK(lower_.try_send(frame)==SendResult::Accepted); });
                return SendResult::Accepted;
            }
            if (change_fragment_tag && !header.som) {
                packet.SESpkt.bth_header.Standard_Header.match_bits^=1;
                auto changed=frame; changed.bytes=UetWireCodec::encode(packet,decoded.network);
                return lower_.try_send(changed);
            }
            if (duplicate_first) { duplicate_first=false; CHECK(lower_.try_send(frame)==SendResult::Accepted); }
        }
        if (drop_result && packet.PDS_type==RUOD_ack_header && packet.SESpkt.bth_type==Semantic_Response_Header) {
            drop_result=false; ++dropped_results; return SendResult::Accepted;
        }
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
    bool delay_first=false,duplicate_first=false,change_fragment_tag=false,drop_result=false;
    size_t tagged_requests=0,dropped_results=0;
private:
    IPacketPort& lower_;
    EventLoop& loop_;
};

struct TaggedFixture {
    EventLoop loop;
    Trace trace{loop};
    Fabric fabric{loop,trace,42};
    TaggedFaultPort forward{fabric.add_host(1),loop},reverse{fabric.add_host(2),loop};
    PdsHost source_host{1,loop,trace,forward},target_host{2,loop,trace,reverse};
    Endpoint source{1,source_host,loop,trace,16};
    Endpoint target;
    Region destination;
    pdc_mode delivery;
    TaggedFixture(pdc_mode mode,bool congestion=false,size_t unexpected_budget=256)
        :target(2,target_host,loop,trace,16,100*kMillisecond,nullptr,8,4096,unexpected_budget),delivery(mode) {
        fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
        source.memory().add_job(1); target.memory().add_job(1);
        destination=target.memory().register_region(1,1,256,7);
        if (congestion) {
            const auto config=UET::CMS::NsccConfig::for_link(12000,12500000000ULL,12500000000ULL,1132);
            source_host.enable_nscc(config); target_host.enable_nscc(config);
        }
    }
    Operation message(uint64_t tag,uint8_t value,size_t length=1,uint32_t rank=0) const {
        Operation operation; operation.type=OperationType::TaggedSend; operation.peer=2; operation.delivery_mode=delivery;
        operation.tag=tag; operation.initiator_id=rank; operation.payload.assign(length,value);
        return operation;
    }
    void post(uint64_t offset,uint32_t capacity,TaggedReceiveMatch match,uint64_t context) {
        target.post_tagged_receive(1,1,destination.key,offset,capacity,match,context);
    }
    Completion source_completion(CompletionStatus status=CompletionStatus::Success,uint8_t code=1) {
        Completion completion{};
        CHECK(source.poll_completion(completion) && !completion.receive && completion.status==status && completion.remote_code==code);
        return completion;
    }
    Completion target_completion(uint64_t context,uint64_t tag,CompletionStatus status=CompletionStatus::Success) {
        Completion completion{};
        CHECK(target.poll_completion(completion) && completion.receive && completion.context==context && completion.tag==tag && completion.status==status);
        return completion;
    }
    void run() { loop.run(100000); }
    void close() {
        Completion completion{}; CHECK(!source.poll_completion(completion) && !target.poll_completion(completion));
        CHECK(!source.pending() && !source.leased_message_ids() && !target.retained_receive_messages() && !target.unexpected_bytes());
        source.close(); target.close(); source_host.close(); target_host.close(); loop.run(10000); CHECK(!loop.pending());
    }
};

void fifo_and_source_matching(pdc_mode mode,bool congestion) {
    TaggedFixture fixture(mode,congestion);
    // The older wildcard must win over the newer exact posting. Ignored bits
    // are still reported as the actual tag, rather than the posting template.
    fixture.post(0,8,{0,UINT64_MAX,{}},10);
    fixture.post(16,8,{UINT64_MAX,0,uint32_t{0}},11);
    fixture.source.submit(fixture.message(UINT64_MAX,0x11)); fixture.run();
    fixture.source_completion(); fixture.target_completion(10,UINT64_MAX);
    fixture.source.submit(fixture.message(UINT64_MAX,0x22)); fixture.run();
    fixture.source_completion(); fixture.target_completion(11,UINT64_MAX);
    fixture.post(32,8,{0x1230,0xf,uint32_t{UINT32_MAX}},12);
    fixture.post(48,8,{0x1230,0xf,{}},13);
    fixture.source.submit(fixture.message(0x123a,0x33,1,0)); fixture.run();
    fixture.source_completion(); fixture.target_completion(13,0x123a);
    fixture.source.submit(fixture.message(0x123b,0x44,1,UINT32_MAX)); fixture.run();
    fixture.source_completion(); fixture.target_completion(12,0x123b);
    for (const auto [offset,value]:{std::pair<uint64_t,uint8_t>{0,0x11},{16,0x22},{32,0x44},{48,0x33}})
        CHECK(fixture.target.memory().read(1,1,fixture.destination.key,offset,1)==std::vector<uint8_t>{value});
    fixture.close();
}

void independent_spaces_and_generations(pdc_mode mode) {
    TaggedFixture fixture(mode);
    fixture.target.resources().configure_resource(1,1,ResourceSpace::Tagged,7);
    fixture.target.resources().configure_resource(1,1,ResourceSpace::Send,3);
    fixture.target.resources().configure_resource(1,1,ResourceSpace::Rma,9);
    fixture.target.post_receive(1,1,fixture.destination.key,16,8,20);
    fixture.post(0,8,{0,UINT64_MAX,{}},21);
    auto operation=fixture.message(0xfeed,0x11); operation.target_generation=7;
    fixture.source.submit(operation); fixture.run(); fixture.source_completion(); fixture.target_completion(21,0xfeed);
    operation.type=OperationType::Send; operation.target_generation=3; operation.payload={0x22};
    fixture.source.submit(operation); fixture.run(); fixture.source_completion();
    Completion completion{}; CHECK(fixture.target.poll_completion(completion) && completion.context==20 && !completion.tag);
    // A tagged posting cannot be consumed by UUD, even if it precedes SEND.
    fixture.post(32,8,{0,UINT64_MAX,{}},22);
    fixture.target.post_receive(1,1,fixture.destination.key,48,8,23);
    operation.type=OperationType::DatagramSend; operation.payload={0x33};
    fixture.source.submit(operation); fixture.run(); fixture.source_completion(CompletionStatus::LocalSuccess,0);
    CHECK(fixture.target.poll_completion(completion) && completion.context==23 && !completion.tag);
    operation=fixture.message(0,0x44); operation.target_generation=7;
    fixture.source.submit(operation); fixture.run(); fixture.source_completion(); fixture.target_completion(22,0);
    operation.type=OperationType::Write; operation.remote_key=fixture.destination.key; operation.remote_offset=64; operation.target_generation=9;
    fixture.source.submit(operation); fixture.run(); fixture.source_completion();
    CHECK(fixture.target.memory().read(1,1,fixture.destination.key,0,1)==std::vector<uint8_t>{0x11});
    CHECK(fixture.target.memory().read(1,1,fixture.destination.key,16,1)==std::vector<uint8_t>{0x22});
    CHECK(fixture.target.memory().read(1,1,fixture.destination.key,48,1)==std::vector<uint8_t>{0x33});
    CHECK(fixture.target.memory().read(1,1,fixture.destination.key,64,1)==std::vector<uint8_t>{0x44});
    fixture.close();
}

void late_posting_and_no_match(pdc_mode mode) {
    TaggedFixture fixture(mode);
    auto first=fixture.message(0xa,0x11,48); first.immediate_data=UINT64_MAX;
    fixture.source.submit(first); fixture.loop.run_until(kMillisecond);
    Completion completion{};
    if (mode==RUD) {
        fixture.source_completion(CompletionStatus::RemoteError,0x05);
        fixture.post(0,64,{0xa,0,{}},30); fixture.run();
        CHECK(!fixture.target.poll_completion(completion)); // No late rescue of the rejected MID.
        fixture.source.submit(first); fixture.run(); fixture.source_completion();
        CHECK(fixture.target_completion(30,0xa).immediate_data==UINT64_MAX);
    } else {
        CHECK(!fixture.source.poll_completion(completion) && fixture.target.unexpected_bytes()==48);
        fixture.source.submit(fixture.message(0xb,0x22,16)); fixture.loop.run_until(2*kMillisecond);
        fixture.post(64,16,{0xb,0,{}},31); // Skip older nonmatching unexpected A.
        fixture.post(0,64,{0,UINT64_MAX,{}},30); fixture.run();
        fixture.target_completion(31,0xb);
        CHECK(fixture.target_completion(30,0xa).immediate_data==UINT64_MAX);
        fixture.source_completion(); fixture.source_completion();
    }
    CHECK(fixture.target.memory().read(1,1,fixture.destination.key,0,48)==first.payload);
    fixture.close();
}

void zero_truncation_and_snapshot(pdc_mode mode) {
    TaggedFixture fixture(mode);
    fixture.post(0,0,{0,0,{}},40); fixture.post(16,8,{0,0,{}},41);
    fixture.source.submit(fixture.message(0,0,0)); fixture.run();
    CHECK(fixture.source_completion().length==0 && fixture.target_completion(40,0).length==0);
    fixture.source.submit(fixture.message(0,0x33)); fixture.run(); fixture.source_completion(); fixture.target_completion(41,0);
    fixture.post(32,2,{1,0,{}},42);
    auto operation=fixture.message(1,0xaa,48); operation.immediate_data=123;
    fixture.source.submit(operation); fixture.run(); fixture.source_completion(CompletionStatus::RemoteError,7);
    const auto truncated=fixture.target_completion(42,1,CompletionStatus::Truncated);
    CHECK(!truncated.length && truncated.original_length==48 && truncated.immediate_data==123);
    CHECK(fixture.target.memory().read(1,1,fixture.destination.key,32,48)==std::vector<uint8_t>(48,0));
    RegionOptions options; options.requested_key=0x1234; options.local_placement_only=true;
    const auto original=fixture.target.memory().register_region(1,1,16,Access::Read|Access::Write,options);
    fixture.target.post_tagged_receive(1,1,original.key,0,16,{2,0,{}},43);
    fixture.target.memory().deregister(original);
    const auto replacement=fixture.target.memory().register_region(1,1,16,Access::Read|Access::Write,options);
    fixture.source.submit(fixture.message(2,0xff)); fixture.run();
    fixture.source_completion(CompletionStatus::RemoteError,0x1c);
    fixture.target_completion(43,2,CompletionStatus::RemoteError);
    std::vector<uint8_t> untouched(16); replacement.storage->read(0,untouched.data(),untouched.size());
    CHECK(untouched==std::vector<uint8_t>(16,0));
    fixture.close();
}

// Observe storage calls, including zero-sized ones. §3.4.2.12 consumes a
// zero-byte tagged posting but forbids even a zero-sized storage write.
class TaggedStorageAudit final : public MemoryStorage {
public:
    uint64_t size() const override { return bytes.size(); }
    size_t allocated_pages() const override { return 1; }
    void read(uint64_t offset,uint8_t* destination,size_t length) const override {
        CHECK(offset<=bytes.size() && length<=bytes.size()-offset);
        if (length) std::copy_n(bytes.data()+offset,length,destination);
    }
    void write(uint64_t offset,const uint8_t* source,size_t length) override {
        CHECK(offset<=bytes.size() && length<=bytes.size()-offset); ++writes;
        if (length) std::copy_n(source,length,bytes.data()+offset);
    }
    std::array<uint8_t,16> bytes{};
    size_t writes=0;
};

void zero_storage_and_resource_recovery() {
    TaggedFixture fixture(ROD,false,16);
    const auto storage=std::make_shared<TaggedStorageAudit>();
    const auto region=fixture.target.memory().register_storage(1,1,storage,7);
    fixture.target.post_tagged_receive(1,1,region.key,16,0,{7,0,{}},60);
    fixture.source.submit(fixture.message(7,0,0)); fixture.run();
    fixture.source_completion(); fixture.target_completion(60,7); CHECK(!storage->writes);
    // Exhaust only the Tagged index, then prove an untagged posting cannot
    // accidentally enable that space or advance its generation.
    auto operation=fixture.message(8,0xaa,32);
    fixture.source.submit(operation); fixture.run(); fixture.source_completion(CompletionStatus::RemoteError,4);
    fixture.target.post_receive(1,1,fixture.destination.key,64,8,61);
    fixture.source.submit(operation); fixture.run(); fixture.source_completion(CompletionStatus::RemoteError,4);
    fixture.post(0,64,{8,0,{}},62);
    fixture.source.submit(operation); fixture.run(); fixture.source_completion(CompletionStatus::RemoteError,2);
    operation.target_generation=1;
    fixture.source.submit(operation); fixture.run(); fixture.source_completion(); fixture.target_completion(62,8);
    operation.type=OperationType::Send; operation.payload={0xbb}; operation.target_generation=0;
    fixture.source.submit(operation); fixture.run(); fixture.source_completion();
    Completion completion{}; CHECK(fixture.target.poll_completion(completion) && completion.context==61 && !completion.tag);
    fixture.close();
}

void absolute_rank_job_scope(pdc_mode mode) {
    TaggedFixture fixture(mode);
    fixture.source.memory().add_job(99); fixture.target.memory().add_job(99);
    RegionOptions options; options.allow_any_job=true;
    const auto shared=fixture.target.memory().register_region(1,1,32,7,options);
    fixture.target.post_tagged_receive(1,1,shared.key,0,8,{17,0,uint32_t{5}},70);
    auto operation=fixture.message(17,0xcc,1,5); operation.job=99; operation.relative_addressing=false;
    fixture.source.submit(operation); fixture.loop.run_until(kMillisecond);
    Completion completion{}; CHECK(!fixture.target.poll_completion(completion));
    if (mode==RUD) fixture.source_completion(CompletionStatus::RemoteError,5);
    else CHECK(!fixture.source.poll_completion(completion));
    fixture.target.post_tagged_receive(99,1,shared.key,16,8,{17,0,uint32_t{5}},71);
    if (mode==RUD) fixture.source.submit(operation);
    fixture.run(); fixture.source_completion(); fixture.target_completion(71,17);
    operation.job=1; operation.payload={0xdd};
    fixture.source.submit(operation); fixture.run(); fixture.source_completion(); fixture.target_completion(70,17);
    CHECK(fixture.target.memory().read(1,1,shared.key,0,1)==std::vector<uint8_t>{0xdd});
    CHECK(fixture.target.memory().read(1,1,shared.key,16,1)==std::vector<uint8_t>{0xcc});
    fixture.close();
}

void faults_and_fragment_identity(pdc_mode mode,bool congestion) {
    TaggedFixture fixture(mode,congestion);
    fixture.post(0,64,{0xface,0,{}},50); fixture.post(64,64,{0xface,0,{}},51);
    fixture.forward.duplicate_first=true; fixture.reverse.drop_result=true;
    if (mode==RUD) fixture.forward.delay_first=true;
    auto operation=fixture.message(0xface,0x77,48); operation.immediate_data=0xbeef;
    fixture.source.submit(operation); fixture.run(); fixture.source_completion();
    CHECK(fixture.target_completion(50,0xface).immediate_data==0xbeef && fixture.reverse.dropped_results==1);
    CHECK(fixture.target.memory().read(1,1,fixture.destination.key,0,48)==operation.payload);
    CHECK(fixture.target.memory().read(1,1,fixture.destination.key,64,48)==std::vector<uint8_t>(48,0));
    // The second posting remains available despite duplicate packets/ACK loss.
    fixture.source.submit(fixture.message(0xface,0x88)); fixture.run(); fixture.source_completion(); fixture.target_completion(51,0xface);
    fixture.post(128,64,{0xface,0,{}},52); fixture.forward.change_fragment_tag=true;
    fixture.source.submit(operation); fixture.run(); fixture.source_completion(CompletionStatus::RemoteError,0x18);
    fixture.target_completion(52,0xface,CompletionStatus::RemoteError);
    CHECK(fixture.target.memory().read(1,1,fixture.destination.key,144,32)==std::vector<uint8_t>(32,0));
    fixture.close();
}

int main() {
    try {
        for (const auto mode:{RUD,ROD}) {
            for (const bool congestion:{false,true}) { fifo_and_source_matching(mode,congestion); faults_and_fragment_identity(mode,congestion); }
            independent_spaces_and_generations(mode); late_posting_and_no_match(mode); zero_truncation_and_snapshot(mode); absolute_rank_job_scope(mode);
        }
        zero_storage_and_resource_recovery();
        std::cout<<"PASS native tagged exact/wildcard FIFO, rank, independent spaces, unexpected, zero/truncation, snapshots and wire faults\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
