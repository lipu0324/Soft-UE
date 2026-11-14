#include "LibfabricTestSupport.hpp"
#include "../SES/MemoryRegistry.hpp"
#include <rdma/fi_atomic.h>
#include <rdma/fi_tagged.h>
#include <rdma/fi_rma.h>
#include <array>
#include <chrono>
#include <map>

static void* context(uintptr_t value) { return reinterpret_cast<void*>(value); }

struct CompletionStream {
    ProviderFixture& provider;
    std::map<void*,fi_cq_tagged_entry> successes;
    std::map<void*,fi_cq_err_entry> errors;
    void poll() {
        fi_cq_tagged_entry entries[8]{};
        const auto count=fi_cq_read(provider.completions,entries,8);
        if (count==-FI_EAVAIL) {
            fi_cq_err_entry error{}; CHECK(fi_cq_readerr(provider.completions,&error,0)==1);
            CHECK(errors.emplace(error.op_context,error).second);
        } else {
            CHECK(count>=0 || count==-FI_EAGAIN);
            for (ssize_t index=0;index<count;++index) CHECK(successes.emplace(entries[index].op_context,entries[index]).second);
        }
    }
};

template<class Predicate> static void progress_until(CompletionStream& first,CompletionStream& second,Predicate ready) {
    const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(5);
    while (!ready() && std::chrono::steady_clock::now()<deadline) { first.poll(); second.poll(); }
    CHECK(ready());
}

static void public_tagged_atomics(bool ordered) {
    const auto ordering=ordered?FI_ORDER_ATOMIC_RAW|FI_ORDER_ATOMIC_WAR|FI_ORDER_ATOMIC_WAW:0;
    ProviderFixture initiator(ordering,FI_FENCE,false,FI_CQ_FORMAT_TAGGED);
    ProviderFixture target(ordering,FI_FENCE,false,FI_CQ_FORMAT_TAGGED);
    CompletionStream sent{initiator},received{target};
    const auto destination=initiator.add_peer(ntohs(target.address.sin_port));
    target.add_peer(ntohs(initiator.address.sin_port));
    constexpr uint64_t tag=0xfedcba9876543242ULL;
    std::array<uint64_t,2> values{3,5},increments{1,2};
    const auto post=[&](uintptr_t token) {
        CHECK(fi_trecv(target.endpoint,values.data(),sizeof(values),nullptr,FI_ADDR_UNSPEC,
            tag&~uint64_t{0xff},0xff,context(token))==0);
    };
    post(101);
    // The first private posting has a predictable auto key in a fresh domain.
    // Even after granting local tagged atomic rights, key-based remote WRITE
    // must fail before touching that still-posted application buffer.
    const uint64_t intrusive=99;
    CHECK(fi_write(initiator.endpoint,&intrusive,sizeof(intrusive),nullptr,destination,0,
        UET::SES::MemoryRegistry::kProviderSpace|1,context(1))==0);
    progress_until(sent,received,[&] { return sent.errors.count(context(1)); });
    CHECK(sent.errors.at(context(1)).err==FI_EACCES && values[0]==3 && values[1]==5 && received.successes.empty());

    fi_ioc input{increments.data(),increments.size()}; fi_rma_ioc remote{0,increments.size(),tag};
    fi_msg_atomic message{}; message.msg_iov=&input; message.iov_count=1; message.addr=destination;
    message.rma_iov=&remote; message.rma_iov_count=1; message.datatype=FI_UINT64; message.op=FI_SUM; message.context=context(2);
    CHECK(fi_atomicmsg(initiator.endpoint,&message,FI_TAGGED|FI_INJECT|FI_FENCE|FI_COMPLETION)==0);
    increments.fill(99); // Injected operands are owned before the public call returns.
    progress_until(sent,received,[&] { return sent.successes.count(context(2)) && received.successes.count(context(101)); });
    CHECK(values[0]==4 && values[1]==7);
    const auto& write=sent.successes.at(context(2));
    CHECK(write.flags==(FI_ATOMIC|FI_WRITE|FI_TAGGED) && write.tag==tag && write.len==16);
    CHECK(received.successes.at(context(101)).flags==(FI_TAGGED|FI_RECV) &&
        received.successes.at(context(101)).tag==tag && received.successes.at(context(101)).len==16);

    post(102);
    uint64_t operand=3,result=0; input={&operand,1}; remote={0,1,tag}; fi_ioc output{&result,1}; message.context=context(3);
    CHECK(fi_fetch_atomicmsg(initiator.endpoint,&message,&output,nullptr,1,FI_TAGGED|FI_FENCE)==0);
    progress_until(sent,received,[&] { return sent.successes.count(context(3)) && received.successes.count(context(102)); });
    CHECK(result==4 && values[0]==7 && values[1]==7);
    CHECK(sent.successes.at(context(3)).flags==(FI_ATOMIC|FI_READ|FI_TAGGED) && sent.successes.at(context(3)).len==8);

    post(103);
    uint64_t expected=7; operand=9; result=0; fi_ioc compare{&expected,1}; message.op=FI_CSWAP; message.context=context(4);
    CHECK(fi_compare_atomicmsg(initiator.endpoint,&message,&compare,nullptr,1,&output,nullptr,1,FI_TAGGED|FI_COMPLETION)==0);
    progress_until(sent,received,[&] { return sent.successes.count(context(4)) && received.successes.count(context(103)); });
    CHECK(result==7 && values[0]==9 && values[1]==7);
    CHECK(received.successes.at(context(103)).len==8 && sent.successes.at(context(4)).len==8);

    // A tagged buffer is a receive posting: the next ordinary tagged SEND
    // uses the same FIFO and replaces its bytes rather than performing AMO.
    post(104); const uint64_t replacement=11;
    CHECK(fi_tsend(initiator.endpoint,&replacement,8,nullptr,destination,tag,context(5))==0);
    progress_until(sent,received,[&] { return sent.successes.count(context(5)) && received.successes.count(context(104)); });
    CHECK(values[0]==11 && values[1]==7);

    // Tagged query flags describe selection independently from fetch/compare.
    const std::array<fi_datatype,10> datatypes{FI_INT8,FI_UINT8,FI_INT16,FI_UINT16,FI_INT32,FI_UINT32,FI_INT64,FI_UINT64,FI_INT128,FI_UINT128};
    for (size_t index=0;index<datatypes.size();++index) {
        fi_atomic_attr limits{}; const size_t width=size_t{1}<<(index/2);
        CHECK(fi_query_atomic(initiator.domain,datatypes[index],FI_SUM,&limits,FI_TAGGED|FI_FETCH_ATOMIC)==0 && limits.size==width && limits.count==1);
        CHECK(fi_query_atomic(initiator.domain,datatypes[index],FI_CSWAP,&limits,FI_TAGGED|FI_COMPARE_ATOMIC)==0 && limits.size==width && limits.count==1);
        const auto status=fi_query_atomic(initiator.domain,datatypes[index],FI_SUM,&limits,FI_TAGGED);
        CHECK(status==(width<=8?0:-FI_EOPNOTSUPP));
        if (width<=8) CHECK(limits.size==width && limits.count==16*1024*1024/width);
    }
    fi_atomic_attr limits{};
    CHECK(fi_query_atomic(initiator.domain,FI_UINT64,FI_SUM,&limits,FI_TAGGED|FI_FETCH_ATOMIC|FI_COMPARE_ATOMIC)==-FI_EOPNOTSUPP);
    CHECK(!limits.size && !limits.count);
    iovec local_write{const_cast<uint64_t*>(&replacement),8}; fi_rma_iov remote_write{0,8,tag}; fi_msg_rma write_message{};
    write_message.msg_iov=&local_write; write_message.iov_count=1; write_message.addr=destination;
    write_message.rma_iov=&remote_write; write_message.rma_iov_count=1;
    CHECK(fi_writemsg(initiator.endpoint,&write_message,FI_TAGGED)==-FI_EOPNOTSUPP);
    CHECK(sent.errors.size()==1 && received.errors.empty());
    initiator.close(); target.close();
}

int main() {
    try {
        public_tagged_atomics(false); public_tagged_atomics(true);
        std::cout << "PASS public tagged atomic/fetch/CAS/inject, private posting authority, shared tag queue and datatype queries\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
