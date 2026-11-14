#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

// An independent request producer exercises target ordering without relying on
// the native initiator's choice to transmit its completing atomic last.
struct TargetFixture {
    EventLoop loop; Trace trace{loop}; Fabric fabric{loop,trace,42};
    IPacketPort& forward=fabric.add_host(1); IPacketPort& reverse=fabric.add_host(2);
    PdsHost initiator{1,loop,trace,forward},responder{2,loop,trace,reverse};
    Endpoint target{2,responder,loop,trace,16,20*kMillisecond};
    Region writes,atomic;
    std::map<uint16_t,std::vector<uint8_t>> results;
    pdc_mode mode;
    explicit TargetFixture(pdc_mode delivery):mode(delivery) {
        fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
        initiator.services().pdc_mapping.rud.include_source_pid=true;
        initiator.services().pdc_mapping.rod.include_source_pid=true;
        initiator.configure_semantic_payload_mtu(16);
        target.memory().add_job(1); target.memory().add_job(2);
        RegionOptions options; options.requested_key=0x1111;
        writes=target.memory().register_region(1,1,64,7,options);
        options.requested_key=0x2222; atomic=target.memory().register_region(1,1,8,7,options);
        initiator.set_response_handler([this](const PDC_SES_rsp& response) {
            const auto& semantic=response.pkt.bth_header.Semantic_Response_Header;
            CHECK(response.pkt.bth_type==Semantic_Response_Header && semantic.return_code);
            results[semantic.message_id].push_back(semantic.return_code);
        });
    }
    SES_PDS_req request(uint16_t message,bool completing_atomic,uint16_t count=0,uint16_t source_pid=1) {
        SES_PDS_req request{}; request.src_fep=1; request.dst_fep=2; request.source_pid=source_pid;
        request.mode=mode; request.next_hdr=UET_HDR_REQUEST_STD; request.rod_context=1; request.lock_pdc=true;
        request.tx_pkt_handle=message; request.pkt.bth_type=Standard_Header;
        request.pkt.eth_type=completing_atomic?Synchronized_Atomic_Extension_Headers:Synchronized_Operation_Extension_Header;
        auto& header=request.pkt.bth_header.Standard_Header;
        header.opcode=completing_atomic?0x11:0x10; header.som=header.eom=header.dc=header.rel=1;
        header.msg_id=message; header.job_id=header.PIDonFEP=header.resource_index=1;
        header.initiator=7; header.request_length=completing_atomic?8:4;
        header.match_bits=completing_atomic?atomic.key:writes.key;
        auto& synchronization=completing_atomic?request.pkt.eth_header.Synchronized_Atomic_Extension_Headers.synchronization:
            request.pkt.eth_header.Synchronized_Operation_Extension_Header;
        synchronization.sync_group=42; synchronization.sync_count=count;
        if (completing_atomic) {
            auto& extension=request.pkt.eth_header.Synchronized_Atomic_Extension_Headers.atomic;
            extension.atomic_opcode=static_cast<uint8_t>(IntegerAtomicOperation::Sum);
            extension.atomic_datatype=static_cast<uint8_t>(IntegerAtomicDatatype::Uint64);
            request.pkt.payload={0,0,0,0,0,0,0,5}; // Independent network-order operand.
        } else request.pkt.payload.assign(4,0x33);
        request.pkt_len=static_cast<uint16_t>(44+(completing_atomic?8:4)+request.pkt.payload.size()); return request;
    }
    void send(const SES_PDS_req& packet) { CHECK(initiator.submit(packet)); }
    void check_result(uint16_t message,SemanticReturnCode code=SemanticReturnCode::Ok,size_t count=1) {
        CHECK(results[message]==std::vector<uint8_t>(count,static_cast<uint8_t>(code)));
    }
    void close() {
        target.close(); initiator.close(); responder.close(); CHECK(!loop.pending());
    }
};

void atomic_arrives_before_writes(pdc_mode mode,bool revoke,bool failed_member) {
    TargetFixture fixture(mode);
    fixture.send(fixture.request(1,true,3,2)); fixture.loop.run_until(kMillisecond);
    CHECK(fixture.results[1].empty() && fixture.target.memory().read(1,1,fixture.atomic.key,0,8)==std::vector<uint8_t>(8));
    if (revoke) {
        CHECK(fixture.target.memory().deregister(fixture.atomic));
        RegionOptions options; options.requested_key=0x2222;
        fixture.atomic=fixture.target.memory().register_region(1,1,8,7,options);
    }
    auto first=fixture.request(2,false); if (failed_member) first.pkt.bth_header.Standard_Header.match_bits=UINT64_MAX;
    fixture.send(first); fixture.loop.run_until(2*kMillisecond);
    CHECK(fixture.results[1].empty() && fixture.target.memory().read(1,1,fixture.atomic.key,0,8)==std::vector<uint8_t>(8));
    auto second=fixture.request(3,false); second.pkt.bth_header.Standard_Header.buffer_offset=16; fixture.send(second);
    fixture.loop.run(300000);
    fixture.check_result(1,revoke?SemanticReturnCode::BadMemoryKey:SemanticReturnCode::Ok);
    fixture.check_result(2,failed_member?SemanticReturnCode::BadMemoryKey:SemanticReturnCode::Ok); fixture.check_result(3);
    CHECK(fixture.target.memory().read(1,1,fixture.atomic.key,0,8)==(revoke?std::vector<uint8_t>(8):std::vector<uint8_t>{5,0,0,0,0,0,0,0}));
    CHECK(fixture.target.memory().read(1,1,fixture.writes.key,16,4)==std::vector<uint8_t>(4,0x33));
    CHECK(!fixture.target.retained_synchronized_groups() && !fixture.target.retained_synchronized_members() && !fixture.target.retained_receive_messages());
    Completion completion{}; CHECK(!fixture.target.poll_completion(completion)); fixture.close();
}

void invalid_count_and_job(pdc_mode mode) {
    TargetFixture fixture(mode);
    fixture.send(fixture.request(1,false)); fixture.loop.run_until(kMillisecond);
    auto foreign=fixture.request(2,false,0,2); foreign.pkt.bth_header.Standard_Header.job_id=2; fixture.send(foreign);
    fixture.send(fixture.request(3,false)); fixture.loop.run_until(2*kMillisecond);
    fixture.send(fixture.request(4,true,1,2)); fixture.loop.run(300000);
    fixture.check_result(1); fixture.check_result(2,SemanticReturnCode::PermissionViolation); fixture.check_result(3);
    fixture.check_result(4,SemanticReturnCode::OperationViolation);
    CHECK(fixture.target.memory().read(1,1,fixture.atomic.key,0,8)==std::vector<uint8_t>(8));
    CHECK(!fixture.target.retained_synchronized_groups() && !fixture.target.retained_synchronized_members()); fixture.close();
}

void extra_members_and_completer(pdc_mode mode) {
    TargetFixture fixture(mode);
    fixture.send(fixture.request(1,true,2,2)); fixture.loop.run_until(kMillisecond);
    auto partial=fixture.request(2,false); auto& first=partial.pkt.bth_header.Standard_Header;
    first.eom=0; first.request_length=32; partial.pkt.payload.assign(16,0x33); partial.pkt_len=64;
    fixture.send(partial); fixture.loop.run_until(2*kMillisecond);
    fixture.send(fixture.request(3,true,2,3)); fixture.send(fixture.request(4,false,0,3));
    fixture.loop.run_until(3*kMillisecond);
    CHECK(fixture.results[1].empty());
    auto end=partial; auto& last=end.pkt.bth_header.Standard_Header; last.som=0; last.eom=1;
    last.diff.som_false.message_offset=16; last.diff.som_false.payload_length=16; fixture.send(end);
    fixture.loop.run(300000);
    fixture.check_result(1); fixture.check_result(2,SemanticReturnCode::Ok,2);
    fixture.check_result(3,SemanticReturnCode::OperationViolation); fixture.check_result(4,SemanticReturnCode::OperationViolation);
    CHECK(fixture.target.memory().read(1,1,fixture.atomic.key,0,8)==std::vector<uint8_t>({5,0,0,0,0,0,0,0}));
    CHECK(!fixture.target.retained_synchronized_groups() && !fixture.target.retained_synchronized_members()); fixture.close();
}

void incomplete_group_expires(pdc_mode mode) {
    TargetFixture fixture(mode); fixture.send(fixture.request(1,true,2,2)); fixture.loop.run_until(25*kMillisecond);
    CHECK(!fixture.target.retained_synchronized_groups() && fixture.results[1].empty());
    CHECK(fixture.target.memory().read(1,1,fixture.atomic.key,0,8)==std::vector<uint8_t>(8));
    // An expired local owner must not execute even if the missing message
    // appears later with the same16-bit number and forms a new tracking root.
    fixture.send(fixture.request(2,false)); fixture.loop.run_until(30*kMillisecond);
    CHECK(fixture.results[1].empty() && fixture.target.memory().read(1,1,fixture.atomic.key,0,8)==std::vector<uint8_t>(8));
    fixture.close();
}
int main() {
    try {
        for (auto mode:{RUD,ROD}) {
            for (bool revoke:{false,true}) for (bool failed:{false,true}) atomic_arrives_before_writes(mode,revoke,failed);
            invalid_count_and_job(mode); extra_members_and_completer(mode); incomplete_group_expires(mode);
        }
        std::cout<<"PASS14 independent-PDS target barriers, cross-context members, revoked/reused MR, job/count/errors and expiry\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
