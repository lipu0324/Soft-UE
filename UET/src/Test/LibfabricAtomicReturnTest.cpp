#include "LibfabricTestSupport.hpp"
#include "../SES/Endpoint.hpp"
#include "../Runtime/UdpFramePort.hpp"
#include <rdma/fi_atomic.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <functional>
#include <map>
#include <set>
#include <vector>

using namespace UET::Runtime;
using namespace UET::SES;
using namespace UET::NetworkLayer;

class AtomicReturnPort final : public IPacketPort {
public:
    explicit AtomicReturnPort(UdpFramePort& lower):lower_(lower) {}
    SendResult try_send(const Frame& frame) override {
        const auto packet=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        if (packet.PDS_type==RUOD_ack_header && packet.SESpkt.bth_type==Semantic_Response_Header &&
            packet.SESpkt.bth_header.Semantic_Response_Header.return_code==2) {
            const auto& acknowledgment=packet.PDS_header.RUOD_ack_header;
            generation_error_sequences_.insert(acknowledgment.cack_psn+acknowledgment.ack_psn_off);
            generation_errors=generation_error_sequences_.size(); // Cached replays are not new failed attempts.
        }
        if (packet.PDS_type==RUOD_ack_header && packet.SESpkt.bth_type==Semantic_Response_with_Data_Header &&
            lose_result && !dropped) {
            dropped=true; if (on_drop) on_drop(); return SendResult::Accepted;
        }
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver callback) override { lower_.set_receiver(std::move(callback)); }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
    bool lose_result=false,dropped=false;
    size_t generation_errors=0;
    std::function<void()> on_drop;
private:
    UdpFramePort& lower_;
    std::set<uint32_t> generation_error_sequences_;
};

struct AtomicReturnHarness {
    ProviderFixture provider;
    RealtimeRuntime runtime;
    Trace trace{runtime.events()};
    UdpFramePort network{0};
    AtomicReturnPort observed{network};
    PdsHost host{network.node(),runtime.events(),trace,observed};
    Endpoint target{network.node(),host,runtime.events(),trace,1024,5000*kMillisecond};
    Region remote;
    fi_addr_t peer;
    size_t successes=0,errors=0;
    uintptr_t next_context=0;
    explicit AtomicReturnHarness(bool ordered=false):provider(ordered?FI_ORDER_ATOMIC_RAW|FI_ORDER_ATOMIC_WAR|FI_ORDER_ATOMIC_WAW:0) {
        host.services().rto_ns=20*kMillisecond;
        target.memory().add_job(1); remote=target.memory().register_region(1,1,64,7);
        peer=provider.add_peer(network.local_port());
        network.add_peer(ntohs(provider.address.sin_port),"127.0.0.1",ntohs(provider.address.sin_port));
    }
    void* context() { return reinterpret_cast<void*>(++next_context); }
    void complete(void* context,void* result,size_t bytes,int error_code=0,int protocol_code=0) {
        const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(5);
        bool completed=false;
        while (!completed && std::chrono::steady_clock::now()<deadline) {
            fi_cq_data_entry entry{}; const auto count=fi_cq_read(provider.completions,&entry,1);
            if (count==-FI_EAVAIL) {
                fi_cq_err_entry failure{}; CHECK(fi_cq_readerr(provider.completions,&failure,0)==1);
                CHECK(error_code && failure.op_context==context && failure.buf==result && !failure.len &&
                    failure.flags==(FI_ATOMIC|FI_READ) && failure.err==error_code && failure.prov_errno==protocol_code);
                ++errors; completed=true;
            } else if (count==1) {
                CHECK(!error_code && entry.op_context==context && entry.buf==result && entry.len==bytes && entry.flags==(FI_ATOMIC|FI_READ));
                ++successes; completed=true;
            } else CHECK(count==-FI_EAGAIN);
            network.progress(); runtime.progress(10000);
        }
        CHECK(completed);
    }
    void close() { target.close(); host.close(); network.close(); provider.close(); CHECK(runtime.events().pending()==0); }
};

std::vector<uint8_t> native_scalar(uint64_t value,size_t width) {
    std::vector<uint8_t> bytes(width,0);
    for (size_t byte=0;byte<std::min<size_t>(8,width);++byte) bytes[byte]=static_cast<uint8_t>(value>>(8*byte));
    return bytes;
}

void operation_matrix(bool ordered) {
    AtomicReturnHarness harness(ordered);
    const std::vector<std::pair<fi_op,uint64_t>> fetch_cases{{FI_MIN,2},{FI_MAX,3},{FI_SUM,5},{FI_DIFF,1},
        {FI_PROD,6},{FI_LOR,1},{FI_LAND,1},{FI_BOR,3},{FI_BAND,2},{FI_LXOR,0},{FI_BXOR,1},{FI_ATOMIC_READ,3},{FI_ATOMIC_WRITE,2}};
    const std::array<fi_datatype,10> datatypes{{FI_INT8,FI_UINT8,FI_INT16,FI_UINT16,FI_INT32,FI_UINT32,FI_INT64,FI_UINT64,FI_INT128,FI_UINT128}};
    size_t variant=0;
    for (size_t datatype_index=0;datatype_index<datatypes.size();++datatype_index) {
        const auto datatype=datatypes[datatype_index];
        fi_atomic_attr limits{}; CHECK(fi_query_atomic(harness.provider.domain,datatype,FI_SUM,&limits,FI_FETCH_ATOMIC)==0);
        CHECK(limits.count==1 && limits.size==(size_t{1}<<(datatype_index/2))); const auto width=limits.size;
        for (const auto [operation,expected]:fetch_cases) {
            const auto old=native_scalar(3,width),operand=native_scalar(2,width); std::vector<uint8_t> result(width,0xee);
            harness.target.memory().write(1,1,harness.remote.key,16,old);
            void* context=harness.context();
            fi_ioc input{const_cast<uint8_t*>(operand.data()),1},output{result.data(),1};
            fi_rma_ioc remote{16,1,harness.remote.key}; fi_msg_atomic message{};
            message.msg_iov=&input; message.iov_count=1; message.rma_iov=&remote; message.rma_iov_count=1;
            message.addr=harness.peer; message.datatype=datatype; message.op=operation; message.context=context;
            const auto form=variant++%3;
            if (form==0) CHECK(fi_fetch_atomic(harness.provider.endpoint,operation==FI_ATOMIC_READ?nullptr:operand.data(),1,nullptr,
                result.data(),nullptr,harness.peer,16,harness.remote.key,datatype,operation,context)==0);
            else if (form==1) CHECK(fi_fetch_atomicv(harness.provider.endpoint,operation==FI_ATOMIC_READ?nullptr:&input,nullptr,
                operation==FI_ATOMIC_READ?0:1,&output,nullptr,1,harness.peer,16,harness.remote.key,datatype,operation,context)==0);
            else {
                if (operation==FI_ATOMIC_READ) { message.msg_iov=nullptr; message.iov_count=0; }
                CHECK(fi_fetch_atomicmsg(harness.provider.endpoint,&message,&output,nullptr,1,FI_FENCE|FI_COMPLETION)==0);
            }
            harness.complete(context,result.data(),width);
            CHECK(result==old && harness.target.memory().read(1,1,harness.remote.key,16,width)==native_scalar(expected,width));
        }
        for (const auto operation:{FI_CSWAP,FI_CSWAP_NE,FI_CSWAP_LE,FI_CSWAP_LT,FI_CSWAP_GE,FI_CSWAP_GT,FI_MSWAP}) {
            const auto compare_value=operation==FI_CSWAP_NE?1:operation==FI_CSWAP_LE || operation==FI_CSWAP_LT?2:
                operation==FI_CSWAP_GE || operation==FI_CSWAP_GT?4:3;
            const auto old=native_scalar(3,width),operand=native_scalar(2,width),comparison=native_scalar(compare_value,width);
            std::vector<uint8_t> result(width,0xee); harness.target.memory().write(1,1,harness.remote.key,16,old);
            void* context=harness.context();
            fi_ioc input{const_cast<uint8_t*>(operand.data()),1},compare{const_cast<uint8_t*>(comparison.data()),1},output{result.data(),1};
            fi_rma_ioc remote{16,1,harness.remote.key}; fi_msg_atomic message{};
            message.msg_iov=&input; message.iov_count=1; message.rma_iov=&remote; message.rma_iov_count=1;
            message.addr=harness.peer; message.datatype=datatype; message.op=operation; message.context=context;
            const auto form=variant++%3;
            if (form==0) CHECK(fi_compare_atomic(harness.provider.endpoint,operand.data(),1,nullptr,comparison.data(),nullptr,
                result.data(),nullptr,harness.peer,16,harness.remote.key,datatype,operation,context)==0);
            else if (form==1) CHECK(fi_compare_atomicv(harness.provider.endpoint,&input,nullptr,1,&compare,nullptr,1,&output,nullptr,1,
                harness.peer,16,harness.remote.key,datatype,operation,context)==0);
            else CHECK(fi_compare_atomicmsg(harness.provider.endpoint,&message,&compare,nullptr,1,&output,nullptr,1,FI_FENCE)==0);
            harness.complete(context,result.data(),width);
            // All compare predicates above select replacement. FI_MSWAP also
            // yields2; directly copying the libfabric mask into UE would yield1.
            CHECK(result==old && harness.target.memory().read(1,1,harness.remote.key,16,width)==operand);
        }
    }
    std::vector<uint8_t> old_masked(16,0xf0),mask(16,0x0f),input(16,0x05),result(16,0);
    harness.target.memory().write(1,1,harness.remote.key,16,old_masked); auto* context=harness.context();
    CHECK(fi_compare_atomic(harness.provider.endpoint,input.data(),1,nullptr,mask.data(),nullptr,result.data(),nullptr,
        harness.peer,16,harness.remote.key,FI_UINT128,FI_MSWAP,context)==0);
    harness.complete(context,result.data(),16);
    CHECK(result==old_masked && harness.target.memory().read(1,1,harness.remote.key,16,16)==std::vector<uint8_t>(16,0xf5));
    harness.close();
}

void retry_generation_and_loss() {
    AtomicReturnHarness harness(true); harness.target.resources().configure_resource(1,1,ResourceSpace::Rma,7);
    const uint64_t operand=1; uint64_t first=0,second=0;
    harness.target.memory().write(1,1,harness.remote.key,16,native_scalar(3,8));
    harness.observed.lose_result=true;
    harness.observed.on_drop=[&] { harness.target.memory().write(1,1,harness.remote.key,16,native_scalar(99,8)); };
    auto* first_context=harness.context(); auto* second_context=harness.context();
    CHECK(fi_fetch_atomic(harness.provider.endpoint,&operand,1,nullptr,&first,nullptr,harness.peer,16,harness.remote.key,FI_UINT64,FI_SUM,first_context)==0);
    CHECK(fi_fetch_atomic(harness.provider.endpoint,&operand,1,nullptr,&second,nullptr,harness.peer,16,harness.remote.key,FI_UINT64,FI_SUM,second_context)==0);
    harness.complete(first_context,&first,8); harness.complete(second_context,&second,8);
    CHECK(harness.observed.dropped && harness.observed.generation_errors==1 && first==3 && second==99);
    CHECK(harness.target.memory().read(1,1,harness.remote.key,16,8)==native_scalar(100,8));
    size_t executed=0;
    for (const auto& event:harness.trace.events()) if (event.event=="fetching_atomic_executed") ++executed;
    CHECK(executed==2); harness.close();
}

void validation_and_errors() {
    AtomicReturnHarness harness; size_t count=0; fi_atomic_attr limits{};
    CHECK(fi_fetch_atomicvalid(harness.provider.endpoint,FI_UINT128,FI_SUM,&count)==0 && count==1);
    CHECK(fi_compare_atomicvalid(harness.provider.endpoint,FI_INT128,FI_CSWAP,&count)==0 && count==1);
    CHECK(fi_atomicvalid(harness.provider.endpoint,FI_UINT128,FI_SUM,&count)==-FI_EOPNOTSUPP && count==0);
    CHECK(fi_atomicvalid(harness.provider.endpoint,FI_UINT64,FI_ATOMIC_READ,&count)==-FI_EOPNOTSUPP && count==0);
    CHECK(fi_fetch_atomicvalid(harness.provider.endpoint,FI_FLOAT,FI_SUM,&count)==-FI_EOPNOTSUPP && count==0);
    CHECK(fi_query_atomic(harness.provider.domain,FI_UINT64,FI_SUM,&limits,FI_FETCH_ATOMIC|FI_COMPARE_ATOMIC)==-FI_EOPNOTSUPP && !limits.size && !limits.count);
    const uint64_t operand=1,comparison=0; uint64_t result=0xeeeeeeeeeeeeeeee;
    CHECK(fi_fetch_atomic(harness.provider.endpoint,&operand,2,nullptr,&result,nullptr,harness.peer,0,harness.remote.key,FI_UINT64,FI_SUM,nullptr)==-FI_EINVAL);
    CHECK(fi_compare_atomic(harness.provider.endpoint,&operand,1,nullptr,nullptr,nullptr,&result,nullptr,harness.peer,0,harness.remote.key,FI_UINT64,FI_CSWAP,nullptr)==-FI_EINVAL);
    fi_ioc input{const_cast<uint64_t*>(&operand),1},output{&result,1},compare{const_cast<uint64_t*>(&comparison),1};
    fi_rma_ioc remote{0,1,harness.remote.key}; fi_msg_atomic message{};
    message.msg_iov=&input; message.iov_count=1; message.rma_iov=&remote; message.rma_iov_count=1;
    message.addr=harness.peer; message.datatype=FI_UINT64; message.op=FI_SUM;
    CHECK(fi_fetch_atomicmsg(harness.provider.endpoint,&message,&output,nullptr,1,FI_INJECT)==-FI_EOPNOTSUPP);
    message.op=FI_CSWAP;
    CHECK(fi_compare_atomicmsg(harness.provider.endpoint,&message,&compare,nullptr,1,&output,nullptr,1,FI_REMOTE_CQ_DATA)==-FI_EOPNOTSUPP);
    void* context=harness.context();
    CHECK(fi_fetch_atomic(harness.provider.endpoint,&operand,1,nullptr,&result,nullptr,harness.peer,0,0,FI_UINT64,FI_SUM,context)==0);
    harness.complete(context,&result,0,FI_EACCES,0x1c); CHECK(result==0xeeeeeeeeeeeeeeee);
    context=harness.context();
    CHECK(fi_fetch_atomic(harness.provider.endpoint,nullptr,1,nullptr,&result,nullptr,harness.peer,0,harness.remote.key,FI_UINT64,FI_ATOMIC_READ,context)==0);
    harness.complete(context,&result,8); CHECK(result==0);
    harness.close();
}

int main() {
    try {
        operation_matrix(false); operation_matrix(true); retry_generation_and_loss(); validation_and_errors();
        std::cout<<"PASS public fetching/CAS APIs,128bit queries, mask conversion, cached results, generation retries and CQ ownership\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
