#include "RendezvousTestFixture.hpp"

void bidirectional(bool tagged,bool standalone) {
    RendezvousFixture fixture(standalone);
    RegionOptions options; options.requested_key=0x3333;
    const auto reverse_destination=fixture.source.memory().register_region(1,1,256,7,options);
    std::vector<uint8_t> reverse_bytes(73,0x7c); fixture.target_storage->write(104,reverse_bytes.data(),73);
    if (tagged) fixture.source.post_tagged_receive(1,1,reverse_destination.key,4,73,{0x1234,0,uint32_t{2}},88);
    else fixture.source.post_receive(1,1,reverse_destination.key,4,73,88,1,uint32_t{2});
    fixture.post(tagged);
    auto reverse=fixture.operation(tagged,ROD,98); reverse.peer=1; reverse.initiator_id=2; reverse.tag=0x1234;
    reverse.rendezvous_source=RendezvousBuffer{fixture.target_region.key,104,73,1,1,0}; reverse.rendezvous_eager_length=16;
    const auto first=fixture.source.submit(fixture.operation(tagged,ROD,99,4,16));
    const auto second=fixture.target.submit(reverse); fixture.loop.run(1000000);
    size_t source_send=0,source_receive=0,target_send=0,target_receive=0; Completion completion{};
    while (fixture.source.poll_completion(completion)) {
        CHECK(completion.status==CompletionStatus::Success && completion.length==73);
        if (completion.receive) { CHECK(completion.context==88); ++source_receive; }
        else { CHECK(completion.operation==first && completion.context==99); ++source_send; }
    }
    while (fixture.target.poll_completion(completion)) {
        CHECK(completion.status==CompletionStatus::Success && completion.length==73);
        if (completion.receive) { CHECK(completion.context==77); ++target_receive; }
        else { CHECK(completion.operation==second && completion.context==98); ++target_send; }
    }
    CHECK(source_send==1 && source_receive==1 && target_send==1 && target_receive==1);
    CHECK(fixture.source.memory().read(1,1,reverse_destination.key,4,73)==reverse_bytes);
    CHECK(fixture.target.memory().read(1,1,fixture.target_region.key,4,73)==fixture.bytes);
    fixture.close();
}
void absolute_any_job(bool tagged) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    Endpoint source(1,source_host,loop,trace,16),target(2,target_host,loop,trace,16);
    source.memory().add_job(99); target.memory().add_job(1);
    auto storage=std::make_shared<SparseMemory>(81); std::vector<uint8_t> bytes(73,0xa5); storage->write(4,bytes.data(),73);
    RegionOptions options; options.requested_key=0x1234;
    const auto region=source.memory().register_storage(99,1,storage,1,options);
    options.requested_key=0x2222; options.allow_any_job=true;
    const auto destination=target.memory().register_region(1,1,81,7,options);
    if (tagged) target.post_tagged_receive(1,1,destination.key,4,73,{UINT64_MAX,0,{}},77);
    else target.post_receive(1,1,destination.key,4,73,77);
    Operation operation; operation.type=tagged?OperationType::RendezvousTaggedSend:OperationType::RendezvousSend;
    operation.peer=2; operation.job=99; operation.relative_addressing=false; operation.tag=UINT64_MAX;
    operation.rendezvous_source=RendezvousBuffer{region.key,4,73,1,1,0}; operation.rendezvous_eager_length=16;
    operation.context=99; operation.immediate_data=42;
    source.submit(operation); loop.run(1000000);
    Completion completion{};
    CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Success && completion.context==99);
    CHECK(target.poll_completion(completion) && completion.status==CompletionStatus::Success && completion.context==77);
    CHECK(target.memory().read(1,1,destination.key,4,73)==bytes && !target.memory().has_job(99));
    // Authorized reverse READ does not install or grant a new local Job.
    Operation unrelated; unrelated.type=OperationType::Read; unrelated.peer=1; unrelated.job=99;
    target.submit(unrelated); CHECK(target.poll_completion(completion) && completion.status==CompletionStatus::InvalidRequest);
    CHECK(!source.poll_completion(completion) && !target.poll_completion(completion) &&
        !source.pending() && !target.pending() && !source.leased_message_ids() && !target.leased_message_ids() &&
        !source.retained_receive_messages() && !target.retained_receive_messages() && !target.retained_rendezvous_receives());
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(!loop.pending());
}
void alias_isolation(bool tagged,bool standalone) {
    RendezvousFixture fixture(standalone);
    fixture.source.memory().add_job(2); fixture.target.memory().add_job(2);
    uint64_t alias=0;
    fixture.forward.inject=[&](const PDStoNET_pkt& packet) {
        if (packet.PDS_type==RUOD_req_header && packet.SESpkt.eth_type==Rendezvous_Extension_Header)
            alias=packet.SESpkt.eth_header.Rendezvous_Extension_Header.read_mem_key;
        return RendezvousFaultPort::Action::Pass;
    };
    fixture.source.submit(fixture.operation(tagged,ROD)); fixture.loop.run_until(2*kMillisecond);
    CHECK(alias && fixture.source.pending()==1 && fixture.target.retained_rendezvous_receives()==1);
    const auto attack=[&](Endpoint& endpoint,Operation operation,SemanticReturnCode expected) {
        operation.type=OperationType::Read; operation.peer=1; operation.delivery_mode=RUD;
        operation.remote_key=alias; operation.context=101;
        // Zero-byte READ still checks identity and key. It must not supply
        // the legitimate transaction's second completion point.
        endpoint.submit(operation); fixture.loop.run_until(fixture.loop.now()+2*kMillisecond);
        const auto completion=fixture.complete(endpoint,101,CompletionStatus::RemoteError);
        CHECK(completion.remote_code==static_cast<uint8_t>(expected));
        CHECK(fixture.source.pending()==1);
        Completion unexpected{}; CHECK(!fixture.source.poll_completion(unexpected));
    };
    Operation operation; operation.source_pid=2; operation.initiator_id=3;
    attack(fixture.target,operation,SemanticReturnCode::OperationViolation);
    operation.initiator_id=2; operation.job=2;
    attack(fixture.target,operation,SemanticReturnCode::PermissionViolation);

    auto& third_port=fixture.fabric.add_host(3);
    fixture.fabric.add_link(1,3,{}); fixture.fabric.add_link(3,1,{});
    PdsHost third_host(3,fixture.loop,fixture.trace,third_port);
    third_host.configure_read_ack_data(standalone?0:16);
    Endpoint third(3,third_host,fixture.loop,fixture.trace,16); third.memory().add_job(1);
    operation.job=1; // Correct claimed rank cannot substitute for the FEP.
    attack(third,operation,SemanticReturnCode::OperationViolation);
    CHECK(!third.pending() && !third.leased_message_ids()); third.close(); third_host.close();

    // An advertised view is read-only even when the original application MR
    // also grants WRITE. Failed access must leave the legitimate root alive.
    operation.type=OperationType::Write; operation.peer=1; operation.remote_key=alias;
    operation.context=102; operation.payload={0xff};
    fixture.target.submit(operation); fixture.loop.run_until(fixture.loop.now()+2*kMillisecond);
    fixture.complete(fixture.target,102,CompletionStatus::RemoteError);
    CHECK(fixture.source.pending()==1);
    fixture.post(tagged); fixture.loop.run(1000000);
    fixture.complete(fixture.source,99,CompletionStatus::Success);
    fixture.complete(fixture.target,77,CompletionStatus::Success);
    CHECK(fixture.target.memory().read(1,1,fixture.target_region.key,4,73)==fixture.bytes);
    fixture.close();
}
int main() {
    try {
        for (bool tagged:{false,true}) for (bool standalone:{false,true}) bidirectional(tagged,standalone);
        for (bool tagged:{false,true}) absolute_any_job(tagged);
        for (bool tagged:{false,true}) for (bool standalone:{false,true}) alias_isolation(tagged,standalone);
        std::cout<<"PASS bidirectional ownership, absolute AnyJob reverse READ, alias Job/FEP/rank and read-only isolation\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
