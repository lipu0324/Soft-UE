#include "DeferrableTestFixture.hpp"
void packet_fault(unsigned fault,bool tagged,pdc_mode mode,bool congestion) {
    std::cerr<<"fault="<<fault<<" tagged="<<tagged<<" mode="<<mode<<" NSCC="<<congestion<<'\n';
    DeferrableFixture fixture(congestion);
    bool applied=false; size_t capture_responses=0;
    const auto inject=[&](bool reverse,const PDStoNET_pkt& packet) {
        using Action=DeferrableFaultPort::Action;
        if (applied) return Action::Pass;
        if (packet.PDS_type==RUOD_req_header && packet.SESpkt.bth_type==Standard_Header) {
            const auto& header=packet.SESpkt.bth_header.Standard_Header;
            const bool data=header.opcode==8 || header.opcode==11;
            const bool restart=data && static_cast<uint32_t>(header.buffer_offset)!=0;
            if ((fault==1 && !reverse && data && !restart && header.eom) ||
                (fault==2 && reverse && header.opcode==12) ||
                (fault==4 && !reverse && restart && header.som)) {
                applied=true; return Action::Drop;
            }
            if (fault==3 && reverse && header.opcode==12) { applied=true; return Action::Duplicate; }
            if (fault==5 && !reverse && restart && header.som) { applied=true; return Action::Delay; }
        }
        if (packet.PDS_type==RUOD_ack_header && packet.SESpkt.bth_type==Semantic_Response_Header) {
            const auto& response=packet.SESpkt.bth_header.Semantic_Response_Header;
            if (reverse && response.list==1 && response.return_code==1) ++capture_responses;
            if (fault==8 && reverse && capture_responses==2 && response.list==1 && response.return_code==1) {
                applied=true; return Action::Drop;
            }
            if ((fault==0 && reverse && response.list==1 && response.return_code==1) ||
                (fault==6 && reverse && response.list==0 && response.return_code==1)) {
                applied=true; return Action::Drop;
            }
            if (fault==7 && !reverse && response.return_code==1) { applied=true; return Action::Drop; }
        }
        return Action::Pass;
    };
    fixture.forward.inject=[&](const auto& packet) { return inject(false,packet); };
    fixture.reverse.inject=[&](const auto& packet) { return inject(true,packet); };
    const auto submitted=fixture.source.submit(fixture.operation(tagged,mode));
    fixture.loop.after(5*kMillisecond,[&] { fixture.post(tagged); }); fixture.loop.run(100000);
    const auto source=fixture.complete(fixture.source,CompletionStatus::Success,99);
    const auto target=fixture.complete(fixture.target,CompletionStatus::Success,77);
    CHECK(source.operation==submitted && source.length==73 && target.length==73 && target.immediate_data==42);
    CHECK(target.tag==(tagged?std::optional<uint64_t>{UINT64_MAX}:std::nullopt));
    CHECK(applied && fixture.forward.faults+fixture.reverse.faults==1);
    CHECK(fixture.target.memory().read(1,1,fixture.region.key,4,73)==std::vector<uint8_t>(73,0xa5));
    fixture.close();
}
void lifecycle(unsigned scenario,bool tagged) {
    std::cerr<<"lifecycle="<<scenario<<" tagged="<<tagged<<'\n';
    DeferrableFixture fixture;
    const auto submitted=fixture.source.submit(fixture.operation(tagged,ROD));
    fixture.loop.run_until(2*kMillisecond);
    Completion completion{};
    CHECK(fixture.source.pending()==1 && fixture.source.transport_pending(submitted) &&
        fixture.target.captured_deferrable_headers()==1 && !fixture.target.retained_receive_messages() &&
        !fixture.source.poll_completion(completion) && !fixture.target.poll_completion(completion));
    if (scenario==0 || scenario==1) {
        if (scenario==0) CHECK(fixture.source.cancel_deferrable(submitted));
        else fixture.loop.run(100000);
        fixture.complete(fixture.source,scenario==0?CompletionStatus::Cancelled:CompletionStatus::Timeout,99);
        CHECK(!fixture.source.cancel_deferrable(submitted));
        fixture.post(tagged); fixture.loop.run(100000);
        fixture.complete(fixture.target,CompletionStatus::RemoteError,77);
    } else if (scenario==2) {
        fixture.post(tagged);
        CHECK(fixture.target.memory().deregister(fixture.region));
        RegionOptions options; options.requested_key=fixture.region.key;
        fixture.region=fixture.target.memory().register_region(1,1,256,7,options);
        fixture.loop.run(100000);
        fixture.complete(fixture.source,CompletionStatus::RemoteError,99);
        fixture.complete(fixture.target,CompletionStatus::RemoteError,77);
        CHECK(fixture.target.memory().read(1,1,fixture.region.key,0,256)==std::vector<uint8_t>(256));
    } else if (scenario==3) {
        fixture.post(tagged,77,72); fixture.loop.run(100000);
        fixture.complete(fixture.source,CompletionStatus::RemoteError,99);
        const auto truncated=fixture.complete(fixture.target,CompletionStatus::Truncated,77);
        CHECK(truncated.original_length==73);
    } else {
        fixture.source.close(); fixture.complete(fixture.source,CompletionStatus::Cancelled,99);
        fixture.post(tagged); fixture.loop.run(100000);
        const bool completed=fixture.target.poll_completion(completion);
        CHECK(completed && completion.receive && completion.context==77 && completion.status!=CompletionStatus::Success);
    }
    fixture.close();
}
void header_exhaustion_and_fifo(bool tagged) {
    DeferrableFixture fixture(false,1);
    const auto first=fixture.source.submit(fixture.operation(tagged,ROD,10));
    fixture.loop.run_until(2*kMillisecond);
    auto second=fixture.operation(tagged,ROD,11); second.payload.assign(73,0xb6);
    fixture.source.submit(second); fixture.loop.run_until(4*kMillisecond);
    CHECK(fixture.target.captured_deferrable_headers()==1 && fixture.source.pending()==2);
    fixture.post(tagged,20,73,0); fixture.post(tagged,21,73,80); fixture.loop.run(100000);
    fixture.complete(fixture.source,CompletionStatus::Success,10); fixture.complete(fixture.source,CompletionStatus::Success,11);
    fixture.complete(fixture.target,CompletionStatus::Success,20); fixture.complete(fixture.target,CompletionStatus::Success,21);
    CHECK(!fixture.source.transport_pending(first));
    CHECK(fixture.target.memory().read(1,1,fixture.region.key,0,73)==std::vector<uint8_t>(73,0xa5));
    CHECK(fixture.target.memory().read(1,1,fixture.region.key,80,73)==std::vector<uint8_t>(73,0xb6));
    fixture.close();
}
void restarted_reader_failure(bool tagged) {
    DeferrableFixture fixture;
    size_t reads=0;
    auto operation=fixture.operation(tagged,ROD); operation.payload.clear();
    operation.payload_source=std::make_shared<GeneratedPayload>(73,[&](uint64_t,uint8_t* output,size_t count) {
        if (++reads>1) throw std::runtime_error("source revoked after eager packet");
        std::fill(output,output+count,0xa5);
    });
    fixture.source.submit(std::move(operation)); fixture.loop.run_until(2*kMillisecond);
    fixture.post(tagged); fixture.loop.run(100000);
    fixture.complete(fixture.source,CompletionStatus::LocalError,99);
    fixture.complete(fixture.target,CompletionStatus::RemoteError,77);
    CHECK(reads==2 && fixture.target.memory().read(1,1,fixture.region.key,0,256)==std::vector<uint8_t>(256));
    fixture.close();
}
void clean_connection_replacement(bool tagged) {
    DeferrableFixture fixture;
    uint16_t local_pdc=UINT16_MAX;
    fixture.forward.inject=[&](const PDStoNET_pkt& packet) {
        if (packet.PDS_type==RUOD_req_header) local_pdc=packet.PDS_header.RUOD_req_header.spdcid;
        return DeferrableFaultPort::Action::Pass;
    };
    fixture.source.submit(fixture.operation(tagged,ROD)); fixture.loop.run_until(2*kMillisecond);
    CHECK(local_pdc!=UINT16_MAX && fixture.source_host.request_connection_close(local_pdc));
    fixture.loop.run_until(4*kMillisecond);
    CHECK(fixture.source.pending()==1 && fixture.target.captured_deferrable_headers()==1);
    fixture.post(tagged); fixture.loop.run(100000);
    fixture.complete(fixture.source,CompletionStatus::Success,99); fixture.complete(fixture.target,CompletionStatus::Success,77);
    fixture.close();
}
void failed_restarted_connection(bool tagged) {
    DeferrableFixture fixture;
    fixture.source_host.services().maximum_packet_retries=0;
    fixture.target_host.services().maximum_packet_retries=0;
    uint16_t restarted_message=0,target_data_pdc=UINT16_MAX;
    fixture.forward.inject=[&](const PDStoNET_pkt& packet) {
        if (packet.PDS_type==RUOD_req_header && packet.SESpkt.bth_type==Standard_Header) {
            const auto& header=packet.SESpkt.bth_header.Standard_Header;
            if ((header.opcode==8 || header.opcode==11) && static_cast<uint32_t>(header.buffer_offset)) {
                if (header.som) restarted_message=header.msg_id;
                else return DeferrableFaultPort::Action::Drop;
            }
        }
        return DeferrableFaultPort::Action::Pass;
    };
    fixture.reverse.inject=[&](const PDStoNET_pkt& packet) {
        if (packet.PDS_type==RUOD_ack_header && packet.SESpkt.bth_type==Semantic_Response_Header &&
            packet.SESpkt.bth_header.Semantic_Response_Header.message_id==restarted_message)
            target_data_pdc=packet.PDS_header.RUOD_ack_header.spdcid;
        if (packet.PDS_type==RUOD_cp_header && packet.PDS_header.RUOD_cp_header.ctl_type==Close_req)
            return DeferrableFaultPort::Action::Drop;
        return DeferrableFaultPort::Action::Pass;
    };
    fixture.source.submit(fixture.operation(tagged,ROD)); fixture.loop.run_until(2*kMillisecond);
    fixture.post(tagged); fixture.loop.run_until(2*kMillisecond+10000);
    CHECK(target_data_pdc!=UINT16_MAX && fixture.target_host.request_connection_close(target_data_pdc));
    fixture.loop.run(100000);
    Completion source{},target{};
    CHECK(fixture.source.poll_completion(source) && source.status!=CompletionStatus::Success && source.context==99);
    CHECK(fixture.target.poll_completion(target) && target.status!=CompletionStatus::Success && target.context==77 && target.length==16);
    fixture.close();
}
void configured_target_rank(bool tagged) {
    DeferrableFixture fixture;
    fixture.target.enable_deferrable_capture(64,UINT32_MAX);
    auto operation=fixture.operation(tagged,ROD); operation.peer_initiator_id=UINT32_MAX;
    fixture.source.submit(operation); fixture.loop.run_until(2*kMillisecond);
    fixture.post(tagged); fixture.loop.run(100000);
    fixture.complete(fixture.source,CompletionStatus::Success,99); fixture.complete(fixture.target,CompletionStatus::Success,77);
    fixture.close();
}
void shared_unexpected_fifo(bool tagged,bool deferred_first) {
    DeferrableFixture fixture;
    auto deferred=fixture.operation(tagged,ROD,10);
    auto ordinary=fixture.operation(tagged,ROD,11); ordinary.payload.assign(73,0xb6);
    ordinary.type=tagged?OperationType::TaggedSend:OperationType::Send;
    fixture.source.submit(deferred_first?deferred:ordinary);
    fixture.source.submit(deferred_first?ordinary:deferred);
    fixture.loop.run_until(200000);
    CHECK(fixture.target.captured_deferrable_headers()==1 && fixture.target.unexpected_bytes()==73);
    fixture.post(tagged,20,73,4); fixture.post(tagged,21,73,100); fixture.loop.run(100000);
    std::set<uint64_t> source_contexts,target_contexts; Completion completion{};
    while (fixture.source.poll_completion(completion)) {
        CHECK(completion.status==CompletionStatus::Success); source_contexts.insert(completion.context);
    }
    while (fixture.target.poll_completion(completion)) {
        CHECK(completion.status==CompletionStatus::Success); target_contexts.insert(completion.context);
    }
    CHECK(source_contexts==std::set<uint64_t>({10,11}) && target_contexts==std::set<uint64_t>({20,21}));
    CHECK(fixture.target.memory().read(1,1,fixture.region.key,4,73)==std::vector<uint8_t>(73,deferred_first?0xa5:0xb6));
    CHECK(fixture.target.memory().read(1,1,fixture.region.key,100,73)==std::vector<uint8_t>(73,deferred_first?0xb6:0xa5));
    fixture.close();
}
int main() {
    try {
        for (unsigned fault=0;fault<9;++fault) for (bool tagged:{false,true}) for (auto mode:{RUD,ROD})
            for (bool congestion:{false,true}) packet_fault(fault,tagged,mode,congestion);
        for (bool tagged:{false,true}) {
            for (unsigned scenario=0;scenario<5;++scenario) lifecycle(scenario,tagged);
            header_exhaustion_and_fifo(tagged); restarted_reader_failure(tagged); clean_connection_replacement(tagged); failed_restarted_connection(tagged); configured_target_rank(tagged);
            shared_unexpected_fifo(tagged,false); shared_unexpected_fifo(tagged,true);
        }
        std::cout<<"PASS deferrable packet faults, cancellation, deadline, revoked/reused MR, truncation, close, header exhaustion/FIFO\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
