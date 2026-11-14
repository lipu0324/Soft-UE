#include "DeferrableTestFixture.hpp"

void restart_token_golden_bytes() {
    PDStoNET_pkt packet{}; packet.PDS_type=RUOD_req_header;
    auto& transport=packet.PDS_header.RUOD_req_header;
    transport.type=RUD_REQ; transport.next_hdr=UET_HDR_REQUEST_STD;
    packet.SESpkt.bth_type=Standard_Header;
    auto& header=packet.SESpkt.bth_header.Standard_Header;
    header.opcode=12; header.dc=1; header.rel=1; header.som=1; header.eom=1;
    header.msg_id=0x1234; header.ri_generation=0x45; header.job_id=0x010203;
    header.PIDonFEP=0x123; header.resource_index=0x456; header.buffer_offset=0x11223344;
    header.initiator=0x89abcdef;
    header.match_bits=0x5566778810203040ULL; header.request_length=0x90abcdef;
    // Figure3-14 layout and the pinned reference local/remote token roles.
    // This literal is independent of encoder/decode round trips: for reverse
    // RTR the original target's token is high; original source's is low.
    const std::vector<uint8_t> expected={
        12,0x2b,0x12,0x34,0x45,1,2,3,1,0x23,4,0x56,
        0,0,0,0,0x11,0x22,0x33,0x44,0x89,0xab,0xcd,0xef,
        0x55,0x66,0x77,0x88,0x10,0x20,0x30,0x40,
        0,0,0,0,0,0,0,0,0x90,0xab,0xcd,0xef};
    for (bool ipv6:{false,true}) for (bool udp:{false,true}) for (bool crc:{false,true}) {
        UET::NetworkLayer::WireOptions network; network.ipv6=ipv6; network.udp=udp; network.crc=crc;
        network.native_ip_protocol=253;
        const auto bytes=UetWireCodec::encode(packet,network);
        const size_t start=14+(ipv6?40:20)+(udp?8:4)+12;
        CHECK(std::vector<uint8_t>(bytes.begin()+start,bytes.begin()+start+44)==expected);
    }
}
void token_exhaustion(bool tagged) {
    DeferrableFixture fixture;
    fixture.source_host.services().next_semantic_restart_token=UINT32_MAX;
    fixture.target_host.services().next_semantic_restart_token=UINT32_MAX;
    const auto last=fixture.source.submit(fixture.operation(tagged,ROD,10));
    fixture.loop.run_until(2*kMillisecond);
    fixture.source.submit(fixture.operation(tagged,ROD,11));
    fixture.complete(fixture.source,CompletionStatus::ResourceExhausted,11);
    CHECK(fixture.source_host.services().next_semantic_restart_token==uint64_t{UINT32_MAX}+1 &&
        fixture.target_host.services().next_semantic_restart_token==uint64_t{UINT32_MAX}+1);
    fixture.post(tagged,20); fixture.loop.run(100000);
    CHECK(fixture.complete(fixture.source,CompletionStatus::Success,10).operation==last);
    fixture.complete(fixture.target,CompletionStatus::Success,20);
    fixture.source.close();
    // Replacing SES cannot reset FEP token authority and revive stale tokens.
    Endpoint replacement(1,fixture.source_host,fixture.loop,fixture.trace,16); replacement.memory().add_job(1);
    replacement.submit(fixture.operation(tagged,ROD,12));
    fixture.complete(replacement,CompletionStatus::ResourceExhausted,12); replacement.close();
    fixture.close();
}
void bounded_source_transactions(bool tagged) {
    DeferrableFixture fixture;
    std::vector<uint64_t> operations;
    for (size_t index=0;index<64;++index) {
        auto operation=fixture.operation(tagged,ROD,100+index); operation.payload.resize(1);
        operations.push_back(fixture.source.submit(operation));
    }
    fixture.loop.run_until(2*kMillisecond);
    CHECK(fixture.source.pending()==64 && fixture.target.captured_deferrable_headers()==64 &&
        !fixture.target.unexpected_bytes());
    fixture.source.submit(fixture.operation(tagged,ROD,999));
    fixture.complete(fixture.source,CompletionStatus::ResourceExhausted,999);
    for (size_t index=0;index<operations.size();++index) {
        CHECK(fixture.source.cancel_deferrable(operations[index]));
        fixture.complete(fixture.source,CompletionStatus::Cancelled,100+index);
        fixture.post(tagged,200+index,1,index);
    }
    fixture.loop.run(1000000);
    for (size_t index=0;index<operations.size();++index)
        fixture.complete(fixture.target,CompletionStatus::RemoteError,200+index);
    fixture.close();
}
void maximum_offset_suffix(bool tagged) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),oracle(2,loop,trace,reverse);
    Endpoint source(1,source_host,loop,trace,16); source.memory().add_job(1);
    oracle.configure_semantic_payload_mtu(16);
    size_t reads=0,bytes_read=0,restart_packets=0,controls=0,invalid_controls=0;
    std::vector<uint8_t> suffix;
    bool restarted=false;
    oracle.set_response_handler([&](const PDC_SES_rsp& response) {
        const auto code=response.pkt.bth_header.Semantic_Response_Header.return_code;
        if (code==1) ++controls;
        else { CHECK(code==static_cast<uint8_t>(SemanticReturnCode::BadAddress)); ++invalid_controls; }
    });
    oracle.set_request_handler([&](const PDC_SES_req& request) {
        const auto& header=request.pkt.bth_header.Standard_Header;
        if (restarted) {
            CHECK(header.request_length==1); ++restart_packets;
            suffix.insert(suffix.end(),request.pkt.payload.begin(),request.pkt.payload.end());
        }
        else CHECK(header.request_length==UINT32_MAX);
        SES_PDS_rsp response{}; response.PDCID=request.PDCID; response.rx_pkt_handle=request.rx_pkt_handle;
        response.rsp_len=12; response.gtd_del=true; response.rsp.bth_type=Semantic_Response_Header;
        auto& semantic=response.rsp.bth_header.Semantic_Response_Header;
        semantic.opcode=restarted?0:1; semantic.list=restarted?0:1;
        semantic.return_code=1; semantic.job_id=1; semantic.message_id=header.msg_id; semantic.modified_length=restarted?1:0;
        CHECK(oracle.manager().pushSESResponse(response)); oracle.wake();
        if (!restarted && header.eom) {
            restarted=true;
            SES_PDS_req control{}; control.src_fep=2; control.dst_fep=1; control.source_pid=1;
            control.mode=RUD; control.next_hdr=UET_HDR_REQUEST_STD; control.rod_context=1; control.lock_pdc=true;
            control.tx_pkt_handle=100; control.pkt.bth_type=Standard_Header; control.pkt_len=44;
            auto& restart=control.pkt.bth_header.Standard_Header;
            restart.opcode=12; restart.dc=1; restart.rel=1; restart.som=1; restart.eom=1;
            restart.msg_id=100; restart.job_id=1; restart.PIDonFEP=1; restart.resource_index=1; restart.initiator=2;
            restart.buffer_offset=UINT32_MAX; restart.request_length=0;
            restart.match_bits=(uint64_t{0x55667788}<<32)|static_cast<uint32_t>(header.buffer_offset>>32);
            CHECK(oracle.submit(control)); // 2^32-1 is explicitly outside §3.4.3.1's RTR range.
            restart.buffer_offset=UINT32_MAX-1u; restart.request_length=1;
            restart.msg_id=101; control.tx_pkt_handle=101;
            CHECK(oracle.submit(control));
        }
    });
    Operation operation; operation.type=tagged?OperationType::DeferrableTaggedSend:OperationType::DeferrableSend;
    operation.peer=2; operation.delivery_mode=ROD;
    operation.payload_source=std::make_shared<GeneratedPayload>(UINT32_MAX,[&](uint64_t offset,uint8_t* output,size_t count) {
        CHECK((offset==0 && count==16) || (offset==UINT32_MAX-1u && count==1));
        ++reads; bytes_read+=count; std::fill(output,output+count,0xa5);
    });
    std::weak_ptr<const PayloadSource> owned=operation.payload_source;
    const auto submitted=source.submit(std::move(operation)); loop.run(100000);
    Completion completion{};
    CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Success &&
        completion.operation==submitted && completion.length==UINT32_MAX && !source.poll_completion(completion));
    CHECK(reads==2 && bytes_read==17 && restart_packets==2 && suffix==std::vector<uint8_t>{0xa5} && controls==1 && invalid_controls==1 && owned.expired());
    CHECK(!source.pending() && !source.leased_message_ids() && !source.retained_receive_messages());
    source.close(); source_host.close(); oracle.close(); CHECK(!loop.pending());
}
void peer_source_token_zero(bool tagged) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost oracle(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    oracle.configure_semantic_payload_mtu(16);
    Endpoint target(2,target_host,loop,trace,16); target.memory().add_job(1); target.enable_deferrable_capture();
    const auto region=target.memory().register_region(1,1,73,7);
    SES_PDS_req original{}; original.src_fep=1; original.dst_fep=2; original.source_pid=1;
    original.mode=ROD; original.next_hdr=UET_HDR_REQUEST_STD; original.rod_context=1; original.lock_pdc=true;
    original.tx_pkt_handle=1; original.pkt.bth_type=Standard_Header;
    auto& header=original.pkt.bth_header.Standard_Header;
    header.opcode=tagged?11:8; header.rel=1; header.dc=1; header.som=1;
    header.msg_id=1; header.job_id=1; header.PIDonFEP=1; header.resource_index=1;
    header.initiator=0; header.request_length=73; header.hd=1; header.diff.som_true.header_data=42;
    header.match_bits=tagged?UINT64_MAX:0; header.buffer_offset=0; // Both initial tokens zero is legal.
    original.pkt.payload.assign(16,0xa5); original.pkt_len=60;
    size_t responses=0,restarts=0;
    oracle.set_response_handler([&](const PDC_SES_rsp& response) {
        const auto& semantic=response.pkt.bth_header.Semantic_Response_Header;
        CHECK(semantic.return_code==1);
        if (semantic.message_id==1) CHECK(semantic.list==1 && !semantic.modified_length);
        ++responses;
    });
    oracle.set_request_handler([&](const PDC_SES_req& request) {
        const auto& restart=request.pkt.bth_header.Standard_Header;
        CHECK(restart.opcode==12 && !static_cast<uint32_t>(restart.match_bits) &&
            static_cast<uint32_t>(restart.match_bits>>32) && restart.request_length==73 && !restart.buffer_offset);
        SES_PDS_rsp response{}; response.PDCID=request.PDCID; response.rx_pkt_handle=request.rx_pkt_handle;
        response.rsp_len=12; response.gtd_del=true; response.rsp=UET::PDS::default_semantic_response(request.pkt);
        CHECK(oracle.manager().pushSESResponse(response)); oracle.wake(); ++restarts;
        for (uint32_t offset=0;offset<73;offset+=16) {
            auto data=original; data.mode=RUD; data.tx_pkt_handle=2;
            auto& restarted=data.pkt.bth_header.Standard_Header;
            restarted.msg_id=2; restarted.som=offset==0; restarted.eom=offset+16>=73;
            restarted.buffer_offset=static_cast<uint32_t>(restart.match_bits>>32); // High source half stays zero.
            const auto count=std::min<uint32_t>(16,73-offset);
            if (!restarted.som) { restarted.diff.som_false.message_offset=offset; restarted.diff.som_false.payload_length=count; }
            data.pkt.payload.assign(count,0xa5); data.pkt_len=44+count;
            CHECK(oracle.submit(data));
        }
    });
    CHECK(oracle.submit(original)); loop.run_until(kMillisecond);
    CHECK(target.captured_deferrable_headers()==1);
    auto end=original; end.pkt.bth_header.Standard_Header.som=0; end.pkt.bth_header.Standard_Header.eom=1;
    end.pkt.bth_header.Standard_Header.diff.som_false.message_offset=16;
    end.pkt.bth_header.Standard_Header.diff.som_false.payload_length=0; end.pkt.payload.clear(); end.pkt_len=44;
    CHECK(oracle.submit(end)); loop.run_until(2*kMillisecond);
    if (tagged) target.post_tagged_receive(1,1,region.key,0,73,{UINT64_MAX,0,uint32_t{0}},77);
    else target.post_receive(1,1,region.key,0,73,77,1,uint32_t{0});
    loop.run(100000);
    Completion completion{};
    CHECK(target.poll_completion(completion) && completion.status==CompletionStatus::Success && completion.context==77 &&
        completion.length==73 && completion.immediate_data==42 && !target.poll_completion(completion));
    CHECK(restarts==1 && responses==7 && !target.captured_deferrable_headers() && !target.retained_receive_messages() &&
        !target.leased_message_ids() && target.memory().read(1,1,region.key,0,73)==std::vector<uint8_t>(73,0xa5));
    target.close(); oracle.close(); target_host.close(); CHECK(!loop.pending());
}
int main() {
    try {
        restart_token_golden_bytes();
        for (bool tagged:{false,true}) { token_exhaustion(tagged); bounded_source_transactions(tagged); maximum_offset_suffix(tagged); peer_source_token_zero(tagged); }
        std::cout<<"PASS RTR golden bytes, exhausted/wrap-safe FEP tokens, bounded transactions and maximum legal RTR offset and rejected UINT32_MAX\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
