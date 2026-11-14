#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>

using namespace UET::CMS;
using namespace UET::Runtime;
using namespace UET::SES;
using UET::NetworkLayer::UetWireCodec;

namespace {
enum class SemanticCase { Read, FetchAdd, CompareSwap };

class ResultFaultPort final : public IPacketPort {
public:
    ResultFaultPort(IPacketPort& lower,EventLoop& loop,bool lose_result)
        : lower_(lower),loop_(loop),lose_result_(lose_result) {}
    size_t data_requests=0,data_acks=0,lost=0;
    std::function<void()> after_loss;
    SendResult try_send(const Frame& frame) override {
        const auto packet=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        const bool result=packet.SESpkt.bth_type==Semantic_Response_with_Data_Header ||
            packet.SESpkt.bth_type==Optimized_Response_with_Data_Header;
        if (result) {
            if (packet.PDS_type==RUOD_req_header) {
                ++data_requests;
                CHECK(packet.PDS_header.RUOD_req_header.type==RUD_CC_REQ ||
                    packet.PDS_header.RUOD_req_header.type==ROD_CC_REQ);
            } else { CHECK(packet.PDS_type==RUOD_ack_header); ++data_acks; }
            if (lose_result_) {
                lose_result_=false;
                ++lost;
                if (after_loss) after_loss();
                if (frame.transmission_event) frame.transmission_event(loop_.now(),TransmitOutcome::Started);
                return SendResult::Accepted;
            }
        }
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable writable) override { lower_.set_writable_handler(std::move(writable)); }
private:
    IPacketPort& lower_;
    EventLoop& loop_;
    bool lose_result_;
};

void semantic_case(SemanticCase kind,RequestHeaderFormat format,pdc_mode mode,bool nscc,bool return_direction,bool loss) {
    EventLoop loop;
    Trace trace(loop);
    Fabric fabric(loop,trace,43);
    auto& forward=fabric.add_host(1);
    ResultFaultPort reverse(fabric.add_host(2),loop,loss);
    fabric.add_link(1,2,{});
    fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    source_host.configure_read_ack_data(return_direction ? 0 : 16);
    target_host.configure_read_ack_data(return_direction ? 0 : 16);
    if (nscc) {
        auto congestion=NsccConfig::for_link(12000,12500000000ULL,12500000000ULL,176);
        congestion.initial_maximum_window=352;
        source_host.enable_nscc(congestion);
        target_host.enable_nscc(congestion);
    }
    TfcEngineConfig flow;
    flow.outgoing.payload_mtu_bytes=flow.incoming.payload_mtu_bytes=64;
    flow.receive_context_bytes=1024;
    flow.receive_pool_bytes=4096;
    source_host.enable_tfc(flow);
    target_host.enable_tfc(flow);
    Endpoint source(1,source_host,loop,trace,64),target(2,target_host,loop,trace,64);
    source.memory().add_job(1);
    target.memory().add_job(1);
    target.resources().configure_resource(1,1,ResourceSpace::Rma,7);
    RegionOptions remote_options;
    if (format==RequestHeaderFormat::Small) {
        remote_options.requested_key=MemoryKeyFormat::Optimized|3;
        remote_options.idempotent_safe=nscc;
        target.resources().configure_resource(1,3,ResourceSpace::Rma,7);
    }
    const auto remote=target.memory().register_region(1,1,1024,7,remote_options);
    const auto local=source.memory().register_region(1,1,1024,Access::Read|Access::Write);
    const bool read=kind==SemanticCase::Read;
    const uint32_t length=read && return_direction ? (format==RequestHeaderFormat::Standard ? 512 : 64) : 8;
    const uint64_t offset=read ? 13 : 16;
    std::vector<uint8_t> expected(length);
    if (read) for (size_t byte=0; byte<length; ++byte) expected[byte]=static_cast<uint8_t>(byte*7+0x33);
    else expected[0]=3;
    remote.storage->write(offset,expected.data(),expected.size());
    auto expected_remote=expected;
    if (!read) expected_remote[0]=kind==SemanticCase::FetchAdd ? 5 : 2;
    reverse.after_loss=[&] {
        if (!read) {
            std::vector<uint8_t> applied(length);
            remote.storage->read(offset,applied.data(),applied.size());
            CHECK(applied==expected_remote); // The one original atomic effect happened before the lost result.
        }
        const uint8_t newer=99;
        remote.storage->write(offset,&newer,1);
        expected_remote[0]=newer;
        // ACK-data READ may be re-executed. Reverse PDS data and fetching
        // atomic results must replay their retained old payload instead.
        if (read && !return_direction) expected[0]=newer;
    };
    Operation operation;
    operation.type=read ? OperationType::Read : OperationType::FetchingAtomic;
    operation.peer=2;
    operation.delivery_mode=mode;
    operation.header_format=format;
    operation.target_generation=7;
    operation.remote_key=remote.key;
    operation.remote_offset=offset;
    if (read) {
        operation.read_length=length;
        operation.read_result=ReadResultBuffer{local.key,17,length,1,1};
    } else {
        operation.atomic_operation=kind==SemanticCase::FetchAdd ? IntegerAtomicOperation::Sum : IntegerAtomicOperation::CompareSwapEqual;
        operation.payload.assign(8,0);
        operation.payload[0]=2;
        if (kind==SemanticCase::CompareSwap) { operation.atomic_compare.assign(8,0); operation.atomic_compare[0]=3; }
        operation.atomic_result=AtomicResultBuffer{local.key,17,8,1,1};
    }
    const auto submitted=source.submit(operation);
    Operation noop;
    noop.type=OperationType::Noop;
    noop.peer=2;
    noop.delivery_mode=mode;
    noop.target_generation=7;
    const auto following=source.submit(noop);
    loop.run_until(100*kMillisecond);
    Completion completion{};
    size_t results=0,noops=0;
    while (source.poll_completion(completion)) {
        if (completion.status!=CompletionStatus::Success)
            throw std::runtime_error("TFC semantic failure kind="+std::to_string(int(kind))+" format="+
                std::to_string(int(format))+" mode="+std::to_string(mode)+" nscc="+std::to_string(nscc)+
                " reverse="+std::to_string(return_direction)+" loss="+std::to_string(loss)+
                " status="+std::to_string(int(completion.status)));
        if (completion.operation==submitted) { ++results; CHECK(completion.length==length); }
        else { CHECK(completion.operation==following); ++noops; }
    }
    CHECK(results==1 && noops==1 && !target.poll_completion(completion));
    CHECK(source.memory().read(1,1,local.key,17,length)==expected);
    CHECK(target.memory().read(1,1,remote.key,offset,length)==expected_remote);
    CHECK(reverse.lost==(loss ? 1u : 0u));
    if (read && return_direction) CHECK(reverse.data_requests>0 && !reverse.data_acks);
    else CHECK(reverse.data_acks>0 && !reverse.data_requests);
    CHECK(source_host.tfc()->reserved_receive_bytes()<=flow.receive_pool_bytes);
    CHECK(target_host.tfc()->reserved_receive_bytes()<=flow.receive_pool_bytes);
    source.close();
    target.close();
    source_host.close();
    target_host.close();
    CHECK(source_host.tfc()->source_connection_count()==0 && target_host.tfc()->source_connection_count()==0);
    CHECK(source_host.tfc()->reserved_receive_bytes()==0 && target_host.tfc()->reserved_receive_bytes()==0);
    CHECK(loop.pending()==0);
}
}

int main() {
    try {
        size_t scenarios=0;
        for (const auto format : {RequestHeaderFormat::Standard,RequestHeaderFormat::Small,RequestHeaderFormat::Medium})
            for (const auto mode : {RUD,ROD})
                for (const bool nscc : {false,true})
                    for (const bool loss : {false,true}) {
                        for (const bool reverse : {false,true}) {
                            semantic_case(SemanticCase::Read,format,mode,nscc,reverse,loss);
                            ++scenarios;
                        }
                        for (const auto kind : {SemanticCase::FetchAdd,SemanticCase::CompareSwap}) {
                            semantic_case(kind,format,mode,nscc,true,loss);
                            ++scenarios;
                        }
                    }
        CHECK(scenarios==96);
        std::cout << "96 original SES/PDS TFC bidirectional READ and retained atomic-result cases passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
