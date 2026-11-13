#include "RendezvousTestFixture.hpp"

void rejected_source(unsigned scenario,bool tagged) {
    RendezvousFixture fixture;
    auto operation=fixture.operation(tagged,ROD);
    auto expected=CompletionStatus::InvalidRequest;
    switch (scenario) {
    case 0: operation.rendezvous_source.reset(); break;
    case 1: operation.rendezvous_eager_length=74; break;
    case 2: operation.payload={1}; break;
    case 3: operation.payload_source=std::make_shared<VectorPayload>(std::vector<uint8_t>{1}); break;
    case 4: operation.read_length=1; break;
    case 5: operation.read_result=ReadResultBuffer{}; break;
    case 6: operation.atomic_result=AtomicResultBuffer{}; break;
    case 7: operation.atomic_compare={1}; break;
    case 8: operation.remote_key=1; break;
    case 9: operation.remote_offset=1; break;
    case 10: operation.zero_length_atomic=true; break;
    case 11: operation.peer=0; break;
    case 12: operation.job=2; break;
    case 13: operation.source_pid=4096; break;
    case 14: operation.target_pid=4096; break;
    case 15: operation.target_resource=4096; break;
    case 16: operation.rendezvous_source->pid=4096; break;
    case 17: operation.rendezvous_source->resource_index=4096; break;
    case 18: operation.delivery_mode=UUD; break;
    case 19: operation.rendezvous_source->offset=250; expected=CompletionStatus::LocalError; break;
    case 20: operation.rendezvous_source->offset=UINT64_MAX; expected=CompletionStatus::LocalError; break;
    case 21: operation.rendezvous_source->key=0xffff; expected=CompletionStatus::LocalError; break;
    case 22: case 23: {
        RegionOptions options; options.local_placement_only=scenario==23;
        const auto region=fixture.source.memory().register_region(1,1,256,scenario==22?2:1,options);
        operation.rendezvous_source->key=region.key; expected=CompletionStatus::LocalError; break;
    }
    }
    const auto submitted=fixture.source.submit(operation);
    const auto completion=fixture.complete(fixture.source,99,expected);
    CHECK(completion.operation==submitted && !completion.length && !completion.receive);
    CHECK(!fixture.loop.pending() && !fixture.target.retained_rendezvous_receives());
    fixture.close();
}

void overlapping_coverage() {
    ByteCoverage coverage;
    CHECK(coverage.cover(8,8,32) && coverage.cover(0,12,32));
    CHECK(coverage.bytes()==16 && coverage.intervals()==1);
    CHECK(coverage.cover(24,8,32) && coverage.bytes()==24 && coverage.intervals()==2);
    CHECK(coverage.cover(12,16,32) && coverage.bytes()==32 && coverage.intervals()==1);
    CHECK(coverage.cover(0,32,32) && coverage.bytes()==32 && coverage.intervals()==1);
    CHECK(!coverage.cover(32,1,32) && !coverage.cover(UINT32_MAX,2,32) && coverage.bytes()==32);
    ByteCoverage maximum;
    CHECK(maximum.cover(0,UINT32_MAX-1,UINT32_MAX));
    CHECK(maximum.cover(UINT32_MAX-1,1,UINT32_MAX) && maximum.cover(UINT32_MAX,0,UINT32_MAX));
    CHECK(maximum.bytes()==UINT32_MAX && maximum.intervals()==1);
    CHECK(!maximum.cover(UINT32_MAX,1,UINT32_MAX) && maximum.bytes()==UINT32_MAX);
}

void maximum_logical_message(bool tagged) {
    RendezvousFixture fixture;
    const auto storage=std::make_shared<SparseMemory>(uint64_t{UINT32_MAX}+8);
    const std::vector<uint8_t> first_bytes(16,0xa5); storage->write(4,first_bytes.data(),first_bytes.size());
    const uint8_t last_byte=0x7c; storage->write(uint64_t{UINT32_MAX}+3,&last_byte,1);
    const auto registration=fixture.source.memory().register_storage(1,1,storage,1);
    uint64_t alias=0; size_t eager_bytes=0;
    fixture.forward.inject=[&](const PDStoNET_pkt& packet) {
        if (packet.PDS_type==RUOD_req_header && packet.SESpkt.eth_type==Rendezvous_Extension_Header) {
            CHECK(packet.SESpkt.bth_header.Standard_Header.request_length==UINT32_MAX);
            const auto& extension=packet.SESpkt.eth_header.Rendezvous_Extension_Header;
            CHECK(extension.eager_length==16 && !extension.read_offset);
            alias=extension.read_mem_key; eager_bytes+=packet.SESpkt.payload.size();
        }
        return RendezvousFaultPort::Action::Pass;
    };
    auto operation=fixture.operation(tagged,ROD); operation.rendezvous_eager_length=16;
    operation.rendezvous_source=RendezvousBuffer{registration.key,4,UINT32_MAX,1,1,0};
    const auto submitted=fixture.source.submit(operation); fixture.loop.run_until(2*kMillisecond);
    CHECK(alias && eager_bytes==16 && fixture.source.pending()==1 && storage->allocated_pages()==2);
    CHECK(!fixture.source.memory().authorize(1,1,alias,0,UINT32_MAX,Access::Read,1).storage->allocated_pages());
    Operation last; last.type=OperationType::Read; last.delivery_mode=RUD; last.peer=1;
    last.remote_key=alias; last.remote_offset=UINT32_MAX-1; last.read_length=1; last.context=101;
    last.read_result=ReadResultBuffer{fixture.target_region.key,200,1,1,1};
    fixture.target.submit(last); fixture.loop.run_until(4*kMillisecond);
    CHECK(fixture.complete(fixture.target,101,CompletionStatus::Success).length==1);
    CHECK(fixture.target.memory().read(1,1,fixture.target_region.key,200,1)==std::vector<uint8_t>{last_byte});
    // The last byte's real READ acknowledgement cannot stand in for the
    // remaining 4 GiB. This checks logical bounds, not a full 4 GiB transfer.
    Completion completion{}; CHECK(fixture.source.pending()==1 && !fixture.source.poll_completion(completion));
    CHECK(fixture.source.cancel_rendezvous(submitted)); fixture.complete(fixture.source,99,CompletionStatus::Cancelled);
    bool revoked=false;
    try { fixture.source.memory().authorize(1,1,alias,0,0,Access::Read,1); }
    catch (const MemoryAccessError&) { revoked=true; }
    CHECK(revoked); fixture.target.close(); fixture.loop.run(1000000); fixture.close();
}

void bounded_roots(bool tagged) {
    RendezvousFixture fixture;
    std::vector<uint64_t> submitted;
    for (size_t index=0;index<64;++index) submitted.push_back(fixture.source.submit(fixture.operation(tagged,ROD,100+index)));
    fixture.loop.run_until(2*kMillisecond);
    CHECK(fixture.source.pending()==64 && fixture.target.retained_rendezvous_receives()==64);
    fixture.source.submit(fixture.operation(tagged,ROD,999));
    fixture.complete(fixture.source,999,CompletionStatus::ResourceExhausted);
    CHECK(!fixture.source.cancel_rendezvous(0) && !fixture.source.cancel_read(0) && !fixture.source.transport_pending(0));
    for (size_t index=0;index<submitted.size();++index) {
        CHECK(fixture.source.cancel_rendezvous(submitted[index]));
        fixture.complete(fixture.source,100+index,CompletionStatus::Cancelled);
    }
    fixture.target.close(); fixture.loop.run(1000000); fixture.close();
}

int main() {
    try {
        overlapping_coverage();
        for (bool tagged:{false,true}) {
            for (unsigned scenario=0;scenario<24;++scenario) rejected_source(scenario,tagged);
            maximum_logical_message(tagged); bounded_roots(tagged);
        }
        std::cout<<"PASS rendezvous source validation, overlap/uint32 coverage, 4 GiB logical bounds and bounded roots\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
