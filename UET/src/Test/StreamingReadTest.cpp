#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <algorithm>
#include <functional>
#include <iostream>
#include <set>
#include <string>

using namespace UET::Runtime;
using namespace UET::SES;
#ifndef SOFTUE_READ_BUILD_COMMIT
#define SOFTUE_READ_BUILD_COMMIT "unknown"
#define SOFTUE_READ_BUILD_DIRTY 1
#endif

class ObservedSparseStorage final : public MemoryStorage {
public:
    explicit ObservedSparseStorage(uint64_t length,bool verify_result=false):memory_(length),verify_result_(verify_result) {}
    uint64_t size() const override { return memory_.size(); }
    size_t allocated_pages() const override { return memory_.allocated_pages(); }
    void read(uint64_t offset,uint8_t* destination,size_t count) const override {
        memory_.read(offset,destination,count);
        if (recording) { ++reads; maximum_read=std::max(maximum_read,count); if (observe) observe(); }
    }
    void write(uint64_t offset,const uint8_t* bytes,size_t count) override {
        if (recording) {
            if (verify_result_) {
                CHECK(offset<size() && offset%8192==0 && count==std::min<uint64_t>(8192,size()-offset));
                const auto chunk=offset/8192;
                CHECK(chunk>=next_verified_chunk_ && verified_chunks_.insert(chunk).second);
                // Independent bounded checker: ROD can replay an older lost
                // ACK after newer ACK data. Keep at most one transmit window
                // of chunk indices, rather than assuming placement order or
                // sharing the endpoint's interval-coalescing implementation.
                CHECK(verified_chunks_.size()<=8);
                while (verified_chunks_.erase(next_verified_chunk_)) ++next_verified_chunk_;
                // Verify every placed byte without allocating a message-sized
                // expected vector. Only three marker pages need real storage.
                for (size_t index=0;index<count;++index) {
                    const auto position=offset+index;
                    const uint8_t expected=position==0?0x11:position==size()/2?0x22:position==size()-1?0x33:0;
                    CHECK(bytes[index]==expected);
                }
                verified_bytes+=count;
            }
            ++writes; if (observe) observe();
        }
        memory_.write(offset,bytes,count);
    }
    bool recording=false;
    mutable uint64_t reads=0;
    mutable size_t maximum_read=0;
    uint64_t writes=0,verified_bytes=0;
    std::function<void()> observe;
    bool verification_complete() const { return verified_chunks_.empty() && next_verified_chunk_==(size()+8191)/8192; }
private:
    SparseMemory memory_;
    bool verify_result_;
    uint64_t next_verified_chunk_=0;
    std::set<uint64_t> verified_chunks_;
};

void streaming_read(uint64_t length,bool congestion,bool ack_data,size_t buffer_bytes=1024*1024) {
    CHECK(length>=4 && length<=UINT32_MAX);
    EventLoop loop; Trace trace(loop,0); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    LinkConfig link; link.buffer_bytes=buffer_bytes;
    fabric.add_link(1,2,link); fabric.add_link(2,1,link);
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    if (ack_data) { source_host.configure_read_ack_data(8192); target_host.configure_read_ack_data(8192); }
    if (congestion) {
        auto config=UET::CMS::NsccConfig::for_link(12000,12500000000ULL,12500000000ULL,8300);
        config.initial_maximum_window=4*8300;
        source_host.enable_nscc(config); target_host.enable_nscc(config);
    }
    Endpoint source(1,source_host,loop,trace,8192,10000*kMillisecond),target(2,target_host,loop,trace,8192);
    source.memory().add_job(1); target.memory().add_job(1);
    auto destination=std::make_shared<ObservedSparseStorage>(length,true);
    auto remote=std::make_shared<ObservedSparseStorage>(length);
    const auto local_region=source.memory().register_storage(1,1,destination,Access::Read|Access::Write);
    const auto remote_region=target.memory().register_storage(1,1,remote,Access::Read|Access::Write);
    target.memory().write(1,1,remote_region.key,0,{0x11});
    target.memory().write(1,1,remote_region.key,length/2,{0x22});
    target.memory().write(1,1,remote_region.key,length-1,{0x33});
    source.memory().write(1,1,local_region.key,1,{99});
    source.memory().write(1,1,local_region.key,length-2,{99});
    size_t peak_producer=0,peak_results=0,peak_credits=0,source_intervals=0,target_intervals=0;
    const auto observe=[&] {
        peak_producer=std::max(peak_producer,source.queued_fragments());
        peak_results=std::max(peak_results,source.pending_read_results());
        peak_credits=std::max(peak_credits,target.retained_read_packets());
        source_intervals=std::max(source_intervals,source.receive_intervals());
        target_intervals=std::max(target_intervals,target.receive_intervals());
        CHECK(peak_producer<=8 && peak_results<=8 && peak_credits<=8 && target.pending_read_returns()<=8);
        CHECK(source_intervals<=8 && target_intervals<=1);
    };
    destination->observe=remote->observe=observe;
    destination->recording=remote->recording=true;
    Operation read; read.type=OperationType::Read; read.peer=2; read.remote_key=remote_region.key;
    read.read_length=length; read.read_result=ReadResultBuffer{local_region.key,0,static_cast<uint32_t>(length),1,1};
    const auto operation=source.submit(read); observe();
    CHECK(destination->writes==0 && remote->reads==0); // No eager remote work during submission.
    loop.run(100000000); observe();
    destination->recording=remote->recording=false;
    Completion completion{};
    CHECK(source.poll_completion(completion) && completion.operation==operation && completion.status==CompletionStatus::Success);
    CHECK(completion.length==length && !source.poll_completion(completion));
    CHECK(destination->writes==(length+8191)/8192 && destination->verified_bytes==length && destination->verification_complete());
    CHECK(remote->reads>=destination->writes && remote->maximum_read<=8192);
    CHECK(destination->allocated_pages()<=3 && remote->allocated_pages()<=3);
    CHECK(source.memory().read(1,1,local_region.key,0,1)[0]==0x11);
    CHECK(source.memory().read(1,1,local_region.key,length/2,1)[0]==0x22);
    CHECK(source.memory().read(1,1,local_region.key,length-1,1)[0]==0x33);
    CHECK(source.memory().read(1,1,local_region.key,1,1)[0]==0 && source.memory().read(1,1,local_region.key,length-2,1)[0]==0);
    CHECK(source.queued_fragments()==0 && source.pending_read_results()==0 && source.leased_message_ids()==0 &&
        target.retained_read_packets()==0 && target.pending_read_returns()==0 && target.retained_receive_messages()==0);
    const auto drops=fabric.stats(1,2).dropped+fabric.stats(2,1).dropped;
    if (buffer_bytes>=1024*1024) CHECK(drops==0 && source_intervals<=1);
    else CHECK(ack_data && drops>0 && remote->reads>destination->writes);
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(loop.pending()==0);
    std::cout<<"PASS streaming-read bytes="<<length<<" fragments="<<destination->writes<<" reads="<<remote->reads
        <<" verified_bytes="<<destination->verified_bytes<<" peak_queued="<<peak_producer<<" result_window="<<peak_results
        <<" target_credits="<<peak_credits<<" source_intervals="<<source_intervals<<" target_intervals="<<target_intervals
        <<" source_pages="<<destination->allocated_pages()<<" target_pages="<<remote->allocated_pages()
        <<" nscc="<<congestion<<" ack_data="<<ack_data<<" buffer_bytes="<<buffer_bytes<<" drops="<<drops<<'\n';
}

int main(int argc,char** argv) {
    try {
        if (argc==2 && std::string(argv[1])=="--build-info") {
            std::cout<<"{\"source_commit\":\""<<SOFTUE_READ_BUILD_COMMIT<<"\",\"source_dirty\":"
                <<(SOFTUE_READ_BUILD_DIRTY?"true":"false")<<"}\n";
            return 0;
        }
        if (argc==1) {
            for (const bool congestion:{false,true}) for (const bool ack_data:{false,true})
                streaming_read(1024*1024+3,congestion,ack_data);
            streaming_read(1024*1024+3,false,true,65536);
            return 0;
        }
        uint64_t length=0; bool congestion=false,ack_data=false,small_queue=false;
        for (int argument=1;argument<argc;++argument) {
            const std::string option=argv[argument];
            if (option=="--bytes" && argument+1<argc && !length) length=std::stoull(argv[++argument]);
            else if (option=="--nscc" && !congestion) congestion=true;
            else if (option=="--ack-data" && !ack_data) ack_data=true;
            else if (option=="--small-queue" && !small_queue) small_queue=true;
            else throw std::invalid_argument("unknown/duplicate streaming READ argument");
        }
        streaming_read(length,congestion,ack_data,small_queue?65536:1024*1024);
        return 0;
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
