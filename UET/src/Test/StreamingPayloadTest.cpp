#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
#include <string>

using namespace UET::Runtime;
using namespace UET::SES;

class StreamFaultPort : public IPacketPort {
public:
    StreamFaultPort(IPacketPort& lower,bool permanent=false):lower_(lower),permanent_(permanent) {}
    SendResult try_send(const Frame& frame) override {
        ++frames;
        if (permanent_ || (drop_second && frames==2)) return SendResult::Accepted;
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
    bool drop_second=false;
    size_t frames=0;
private:
    IPacketPort& lower_; bool permanent_;
};

void streaming_write(uint64_t length,bool drop_packet,bool use_nscc=false) {
    CHECK(length>=4 && length<=UINT32_MAX);
    EventLoop loop; Trace trace(loop,0); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    StreamFaultPort faults(forward); faults.drop_second=drop_packet;
    PdsHost source_host(1,loop,trace,faults),target_host(2,loop,trace,reverse);
    if (use_nscc) {
        auto congestion=UET::CMS::NsccConfig::for_link(12000,12500000000ULL,12500000000ULL,8296);
        congestion.initial_maximum_window=4*8296;
        source_host.enable_nscc(congestion); target_host.enable_nscc(congestion);
    }
    Endpoint source(1,source_host,loop,trace,8192,10000*kMillisecond),target(2,target_host,loop,trace,8192);
    source.memory().add_job(1); target.memory().add_job(1);
    const auto region=target.memory().register_region(1,1,length,7);
    target.memory().write(1,1,region.key,1,{99});
    target.memory().write(1,1,region.key,length-2,{99});
    size_t reads=0,maximum_fragment=0,maximum_queued=0,maximum_intervals=0;
    auto payload=std::make_shared<GeneratedPayload>(length,[&](uint64_t offset,uint8_t* bytes,size_t count) {
        ++reads; maximum_fragment=std::max(maximum_fragment,count);
        maximum_queued=std::max(maximum_queued,source.queued_fragments()+1);
        maximum_intervals=std::max(maximum_intervals,target.receive_intervals());
        std::memset(bytes,0,count);
        const std::pair<uint64_t,uint8_t> markers[]={{0,0x11},{length/2,0x22},{length-1,0x33}};
        for (const auto& marker:markers)
            if (marker.first>=offset && marker.first-offset<count) bytes[marker.first-offset]=marker.second;
    });
    std::weak_ptr<const PayloadSource> lifetime=payload;
    Operation write; write.type=OperationType::Write; write.peer=2; write.remote_key=region.key;
    write.payload_source=std::move(payload);
    source.submit(std::move(write));
    CHECK(reads<=8 && source.queued_fragments()<=8); // Submission cannot eagerly read the message.
    loop.run(100000000);
    Completion completion{};
    CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Success && completion.length==length);
    CHECK(!source.poll_completion(completion));
    CHECK(reads==(length+8191)/8192 && maximum_fragment<=8192 && maximum_queued<=8);
    CHECK(maximum_intervals<=1 && region.storage->allocated_pages()<=3);
    CHECK(target.memory().read(1,1,region.key,0,1)[0]==0x11);
    CHECK(target.memory().read(1,1,region.key,length/2,1)[0]==0x22);
    CHECK(target.memory().read(1,1,region.key,length-1,1)[0]==0x33);
    CHECK(target.memory().read(1,1,region.key,1,1)[0]==0 && target.memory().read(1,1,region.key,length-2,1)[0]==0);
    CHECK(source.queued_fragments()==0 && source.leased_message_ids()==0 && target.retained_receive_messages()==0);
    CHECK(lifetime.expired());
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(loop.pending()==0);
    std::cout<<"PASS streaming bytes="<<length<<" fragments="<<reads<<" peak_queued="<<maximum_queued
        <<" intervals="<<maximum_intervals<<" pages="<<region.storage->allocated_pages()<<" loss="<<drop_packet<<" nscc="<<use_nscc<<'\n';
}

void invalid_size_and_permanent_loss() {
    EventLoop loop; Trace trace(loop,0); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    StreamFaultPort faults(forward,true);
    PdsHost host(1,loop,trace,faults),target_host(2,loop,trace,reverse);
    Endpoint endpoint(1,host,loop,trace,1024,10000*kMillisecond);
    endpoint.memory().add_job(1);
    size_t reads=0;
    Operation write; write.type=OperationType::Write; write.peer=2;
    write.payload_source=std::make_shared<GeneratedPayload>(uint64_t{UINT32_MAX}+1,[&](uint64_t,uint8_t*,size_t) { ++reads; });
    endpoint.submit(write);
    Completion completion{};
    CHECK(endpoint.poll_completion(completion) && completion.status==CompletionStatus::InvalidRequest && reads==0);
    write.payload_source=std::make_shared<GeneratedPayload>(1024*1024,[&](uint64_t,uint8_t* bytes,size_t count) {
        ++reads; std::memset(bytes,0,count);
    });
    endpoint.submit(std::move(write));
    loop.run(100000);
    CHECK(endpoint.poll_completion(completion) && completion.status==CompletionStatus::Timeout);
    CHECK(!endpoint.poll_completion(completion));
    CHECK(reads<=16 && endpoint.queued_fragments()==0 && endpoint.leased_message_ids()==0);
    CHECK(host.manager().getPDSStatus().open_cnt==0 && host.manager().getPDSStatus().pend_cnt==0);
    endpoint.close(); host.close(); target_host.close(); CHECK(loop.pending()==0);
}

int main(int argc,char** argv) {
    try {
        if (argc==3 && std::string(argv[1])=="--bytes") streaming_write(std::stoull(argv[2]),false);
        else if (argc==3 && std::string(argv[1])=="--nscc-bytes") streaming_write(std::stoull(argv[2]),false,true);
        else {
            CHECK(argc==1);
            invalid_size_and_permanent_loss();
            streaming_write(8*1024*1024+3,false);
            streaming_write(1024*1024+3,true);
            streaming_write(8*1024*1024+3,false,true);
            streaming_write(1024*1024+3,true,true);
        }
        return 0;
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
