#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

// Drive the real source PDS directly to construct a legal message whose last
// payload byte precedes a separate zero-payload EOM. Source application-level
// completion is outside this target-side regression's scope.
void waits_for_end(OperationType type,pdc_mode mode,bool late_posting=false,uint32_t length=48) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    source_host.configure_semantic_payload_mtu(64);
    Endpoint target(2,target_host,loop,trace,64); target.memory().add_job(1);
    const auto region=target.memory().register_region(1,1,64,7);
    const auto post=[&] {
        if (type==OperationType::Send) target.post_receive(1,1,region.key,0,64,77);
        if (type==OperationType::TaggedSend) target.post_tagged_receive(1,1,region.key,0,64,{0x1234,0,{}},77);
    };
    if (!late_posting) post();
    size_t responses=0; bool clear_requested=false;
    fabric.set_capture([&](Time,const Frame& frame) {
        const auto packet=UET::NetworkLayer::UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        if (frame.source==2 && packet.PDS_type==RUOD_ack_header && packet.SESpkt.bth_type==Semantic_Response_Header &&
            packet.SESpkt.bth_header.Semantic_Response_Header.return_code==1)
            clear_requested|=bool(packet.PDS_header.RUOD_ack_header.flags.req&1);
    });
    source_host.set_response_handler([&](const PDC_SES_rsp& response) {
        CHECK(response.pkt.bth_type==Semantic_Response_Header && response.pkt.bth_header.Semantic_Response_Header.return_code==1);
        // §3.4.4.3/Table3-26: successful results retain one encoding/list.
        // Expected payload uses DEFAULT; tracked unexpected uses OVERFLOW
        // RESPONSE, even when a posting arrives before the final marker.
        const auto& semantic=response.pkt.bth_header.Semantic_Response_Header;
        CHECK(semantic.opcode==(late_posting?1:0) && semantic.list==(late_posting?1:0));
        ++responses;
    });
    SES_PDS_req request{}; request.src_fep=1; request.dst_fep=2; request.source_pid=1;
    request.mode=mode; request.next_hdr=UET_HDR_REQUEST_STD; request.rod_context=1; request.lock_pdc=true;
    request.tx_pkt_handle=9; request.pkt.bth_type=Standard_Header;
    auto& header=request.pkt.bth_header.Standard_Header;
    header.opcode=static_cast<uint8_t>(type); header.som=1; header.eom=0; header.rel=1; header.dc=1;
    header.msg_id=9; header.job_id=1; header.PIDonFEP=1; header.resource_index=1; header.initiator=1;
    header.match_bits=type==OperationType::TaggedSend?0x1234:region.key;
    header.request_length=length; header.hd=1; header.diff.som_true.header_data=42;
    request.pkt.payload.assign(length,0xa5); request.pkt_len=44+length;
    CHECK(source_host.submit(request)); loop.run_until(kMillisecond);
    Completion completion{}; CHECK(!target.poll_completion(completion));
    if (late_posting) {
        CHECK(target.unexpected_bytes()==length); post();
        CHECK(!target.poll_completion(completion) && !target.unexpected_bytes());
    }
    CHECK(target.memory().read(1,1,region.key,0,length)==std::vector<uint8_t>(length,0xa5));
    CHECK(target.retained_receive_messages()==1);
    // The final marker has its own PSN and no payload. Data coverage was
    // already complete; only this marker permits a successful receive CQ.
    header.som=0; header.eom=1; header.diff.som_false.message_offset=length;
    header.diff.som_false.payload_length=0; request.pkt.payload.clear(); request.pkt_len=44;
    CHECK(source_host.submit(request)); loop.run(100000);
    CHECK(target.poll_completion(completion) && completion.receive && completion.status==CompletionStatus::Success &&
        completion.context==(type==OperationType::Write?0:77) && completion.length==length && completion.immediate_data==42);
    CHECK(completion.tag==(type==OperationType::TaggedSend?std::optional<uint64_t>{0x1234}:std::nullopt));
    CHECK(!target.poll_completion(completion) && !target.retained_receive_messages() && responses==2 && clear_requested);
    target.close(); source_host.close(); target_host.close(); CHECK(!loop.pending());
}
int main() {
    try {
        for (const uint32_t length:{48,0}) {
            for (const auto mode:{RUD,ROD}) for (const auto type:{OperationType::Write,OperationType::Send,OperationType::TaggedSend})
                waits_for_end(type,mode,false,length);
            waits_for_end(OperationType::Send,ROD,true,length); waits_for_end(OperationType::TaggedSend,ROD,true,length);
        }
        std::cout<<"PASS receive completion waits for EOM after all bytes, with zero final marker and late ROD posting\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
