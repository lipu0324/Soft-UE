#include "SynchronizedTestFixture.hpp"

void immediate_reuse_with_lost_clear(pdc_mode mode) {
    SynchronizedFixture fixture;
    fixture.forward.inject=[](const PDStoNET_pkt& packet) {
        return packet.PDS_type==RUOD_cp_header && packet.PDS_header.RUOD_cp_header.ctl_type==Clear_cmd?
            SynchronizedFaultPort::Action::Drop:SynchronizedFaultPort::Action::Pass;
    };
    const auto first=fixture.source.begin_synchronized_group(2,1,1);
    fixture.source.submit(fixture.completing(first,mode,false)); fixture.loop.run_until(kMillisecond);
    Completion result{}; CHECK(fixture.source.poll_completion(result) && result.status==CompletionStatus::Success);
    CHECK(fixture.target.poll_completion(result) && result.status==CompletionStatus::Success);
    const auto second=fixture.source.begin_synchronized_group(2,1,1);
    CHECK(second && second->wire_identifier()==first->wire_identifier());
    fixture.forward.inject={}; // The new request must first drain the lost old Clear through its piggyback field.
    auto operation=fixture.completing(second,mode,false); operation.remote_offset=144;
    fixture.source.submit(operation); fixture.loop.run(300000);
    CHECK(fixture.source.poll_completion(result) && result.status==CompletionStatus::Success && !fixture.source.poll_completion(result));
    CHECK(fixture.target.poll_completion(result) && result.status==CompletionStatus::Success && !fixture.target.poll_completion(result));
    fixture.drained(); fixture.close();
}
void tracking_pressure(pdc_mode mode) {
    SynchronizedFixture fixture; fixture.target.configure_synchronized_tracking(1);
    fixture.source_host.services().pdc_mapping.rud.include_source_pid=true;
    fixture.source_host.services().pdc_mapping.rod.include_source_pid=true;
    size_t resource_nacks=0;
    fixture.fabric.set_capture([&](Time,const Frame& frame) {
        if (frame.source!=2) return;
        const auto packet=UET::NetworkLayer::UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        if (packet.PDS_type==nack_header && packet.PDS_header.nack_header.nack_code==UET_NO_SES_SYNC_AVAIL) ++resource_nacks;
    });
    const auto first=fixture.source.begin_synchronized_group(2,1,2),second=fixture.source.begin_synchronized_group(2,1,1);
    fixture.source.submit(fixture.completing(first,mode,false));
    auto blocked=fixture.completing(second,mode,false); blocked.source_pid=2; blocked.remote_offset=144;
    fixture.source.submit(blocked); fixture.loop.run_until(kMillisecond);
    CHECK(resource_nacks && fixture.target.retained_synchronized_groups()==1 && fixture.source.pending()==1);
    fixture.source.submit(fixture.write(first,mode,0,73)); fixture.loop.run(300000);
    Completion result{}; size_t source_count=0,target_count=0;
    while (fixture.source.poll_completion(result)) { CHECK(result.status==CompletionStatus::Success); ++source_count; }
    while (fixture.target.poll_completion(result)) { CHECK(result.status==CompletionStatus::Success); ++target_count; }
    CHECK(source_count==3 && target_count==2); fixture.drained(); fixture.close();
}
void cancel_waiting_atomic(pdc_mode mode,bool close_endpoint) {
    SynchronizedFixture fixture; const auto group=fixture.source.begin_synchronized_group(2,1,3);
    const auto operation=fixture.source.submit(fixture.completing(group,mode,true));
    fixture.source.submit(fixture.write(group,mode,0,73)); fixture.loop.run_until(kMillisecond);
    if (close_endpoint) fixture.source.close();
    else {
        CHECK(fixture.source.cancel_synchronized(operation) && !fixture.source.cancel_synchronized(operation));
        fixture.source.submit(fixture.write(group,mode,96,17));
    }
    fixture.loop.run(300000);
    Completion result{}; size_t cancelled=0,successful=0;
    while (fixture.source.poll_completion(result)) {
        if (result.operation==operation) { CHECK(result.status==CompletionStatus::Cancelled); ++cancelled; }
        else { CHECK(result.status==CompletionStatus::Success); ++successful; }
    }
    CHECK(cancelled==1 && successful==(close_endpoint?1:2));
    CHECK(!fixture.target.poll_completion(result) && fixture.target.memory().read(1,1,fixture.destination.key,128,8)==std::vector<uint8_t>(8));
    CHECK(!fixture.source.pending() && !fixture.source.active_synchronized_source_groups() && !fixture.target.retained_synchronized_groups());
    fixture.close();
}
void incomplete_write_notification(pdc_mode mode) {
    SynchronizedFixture fixture; const auto group=fixture.source.begin_synchronized_group(2,1,2);
    fixture.source.submit(fixture.completing(group,mode,false)); fixture.loop.run(300000);
    Completion result{}; CHECK(fixture.source.poll_completion(result) && result.status==CompletionStatus::Success && !fixture.source.poll_completion(result));
    CHECK(!fixture.target.poll_completion(result)); fixture.drained(); fixture.close();
}
void identifier_exhaustion_and_endpoint_replacement() {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    source_host.services().next_synchronization_group_id=65535;
    Endpoint target(2,target_host,loop,trace); target.memory().add_job(1);
    const auto destination=target.memory().register_region(1,1,16,7);
    std::shared_ptr<const SynchronizedGroup> old_handle;
    {
        Endpoint source(1,source_host,loop,trace); source.memory().add_job(1);
        old_handle=source.begin_synchronized_group(2,1,1); CHECK(old_handle && old_handle->wire_identifier()==65535);
        Operation write; write.type=OperationType::SynchronizedWrite; write.peer=2; write.remote_key=destination.key;
        write.immediate_data=0; write.payload={1}; write.synchronization=old_handle; source.submit(write); loop.run(300000);
        Completion result{}; CHECK(source.poll_completion(result) && result.status==CompletionStatus::Success && target.poll_completion(result));
        const auto reused=source.begin_synchronized_group(2,1,1); CHECK(reused && reused->wire_identifier()==65535);
        write.synchronization=reused; write.remote_key=UINT64_MAX; source.submit(write); loop.run(300000);
        CHECK(source.poll_completion(result) && result.status==CompletionStatus::RemoteError && target.poll_completion(result));
        CHECK(!source.begin_synchronized_group(2,1,1)); source.close();
    }
    {
        Endpoint replacement(1,source_host,loop,trace); replacement.memory().add_job(1);
        CHECK(!replacement.begin_synchronized_group(2,1,1));
        Operation stale; stale.type=OperationType::SynchronizedWrite; stale.peer=2; stale.synchronization=old_handle; stale.immediate_data=1;
        replacement.submit(stale); Completion result{};
        CHECK(replacement.poll_completion(result) && result.status==CompletionStatus::InvalidRequest && !replacement.pending());
        replacement.close();
    }
    target.close(); source_host.close(); target_host.close(); CHECK(!loop.pending());
}
void source_group_budget() {
    SynchronizedFixture fixture;
    for (unsigned group=0;group<64;++group) CHECK(fixture.source.begin_synchronized_group(2,1,2));
    CHECK(!fixture.source.begin_synchronized_group(2,1,2) && fixture.source.active_synchronized_source_groups()==64);
    fixture.source.close(); CHECK(!fixture.source.active_synchronized_source_groups()); fixture.close();
}
void source_member_budget() {
    SynchronizedFixture fixture; const auto group=fixture.source.begin_synchronized_group(2,1,65535);
    for (unsigned member=0;member<4096;++member) fixture.source.submit(fixture.write(group,RUD,0,1));
    CHECK(fixture.source.pending()==4096);
    const auto rejected=fixture.source.submit(fixture.write(group,RUD,0,1)); Completion result{};
    CHECK(fixture.source.poll_completion(result) && result.operation==rejected && result.status==CompletionStatus::ResourceExhausted);
    CHECK(fixture.source.pending()==4096); fixture.source.close();
    size_t cancelled=0;
    while (fixture.source.poll_completion(result)) { CHECK(result.status==CompletionStatus::Cancelled); ++cancelled; }
    CHECK(cancelled==4096 && !fixture.source.pending()); fixture.close();
}
void fatal_context_during_generation_backoff(pdc_mode mode) {
    SynchronizedFixture fixture; fixture.source_host.configure_retry_limit(0);
    fixture.source_host.configure_retransmission_timeout(100000);
    fixture.target.resources().configure_resource(1,1,ResourceSpace::Rma,9);
    // Keep the logical member in recovery until the old PDC actually fails.
    // An enabled new generation could complete on a replacement PDC before
    // plaintext Close safety expires, which is legal successful recovery.
    fixture.target.resources().disable_for_exhaustion(1,1,ResourceSpace::Rma);
    std::optional<uint16_t> local_context;
    std::set<uint16_t> messages;
    fixture.forward.inject=[&](const PDStoNET_pkt& packet) {
        if (packet.PDS_type==RUOD_req_header) {
            local_context=packet.PDS_header.RUOD_req_header.spdcid;
            messages.insert(packet.SESpkt.bth_header.Standard_Header.msg_id);
        }
        return packet.PDS_type==RUOD_cp_header && packet.PDS_header.RUOD_cp_header.ctl_type==Close_cmd?
            SynchronizedFaultPort::Action::Drop:SynchronizedFaultPort::Action::Pass;
    };
    const auto group=fixture.source.begin_synchronized_group(2,1,2);
    const auto operation=fixture.source.submit(fixture.write(group,mode,0,73)); fixture.loop.run_until(100000);
    CHECK(local_context && fixture.source_host.request_connection_close(*local_context));
    fixture.loop.run(500000);
    Completion result{}; const bool available=fixture.source.poll_completion(result);
    if (!available || result.status!=CompletionStatus::Timeout)
        std::cerr<<"fatal backoff mode="<<mode<<" available="<<available<<" status="<<unsigned(result.status)
            <<" code="<<unsigned(result.remote_code)<<" pending="<<fixture.source.pending()<<" leases="<<fixture.source.leased_message_ids()<<'\n';
    CHECK(available && result.operation==operation && result.status==CompletionStatus::Timeout && !fixture.source.poll_completion(result));
    std::optional<Time> completed_at;
    for (const auto& event:fixture.trace.events()) if (event.node==1 && event.event=="operation_complete" && event.value==operation) {
        CHECK(!completed_at); completed_at=event.time;
    }
    CHECK(completed_at && *completed_at<80*kMillisecond && messages.size()==1 && fixture.forward.faults);
    CHECK(!fixture.target.poll_completion(result)); fixture.drained(); fixture.close();
}
int main() {
    try {
        for (auto mode:{RUD,ROD}) {
            immediate_reuse_with_lost_clear(mode); tracking_pressure(mode);
            for (bool closed:{false,true}) cancel_waiting_atomic(mode,closed);
            incomplete_write_notification(mode);
            fatal_context_during_generation_backoff(mode);
        }
        identifier_exhaustion_and_endpoint_replacement(); source_group_budget(); source_member_budget();
        std::cout<<"PASS15 synchronized lifecycle, lost-Clear reuse, resource bounds, fatal backoff, cancellation, expiry and FEP IDs\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
