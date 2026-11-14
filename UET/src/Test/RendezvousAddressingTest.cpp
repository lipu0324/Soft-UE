#include "RendezvousTestFixture.hpp"

void mapped_source_and_receive(bool tagged,bool standalone,bool relative,bool late) {
    RendezvousFixture fixture(standalone);
    // Distinct wire-relative and node-absolute PIDs make accidental use of a
    // wire PID as a local registration identity observable in both directions.
    fixture.source.resources().map_relative_pid(1,2,4);
    fixture.source.resources().configure_resource(4,3,ResourceSpace::Rma,7);
    fixture.target.resources().map_relative_pid(1,2,5);
    fixture.target.resources().configure_resource(5,4,tagged?ResourceSpace::Tagged:ResourceSpace::Send,9);
    fixture.target.configure_rendezvous(64,UINT32_MAX);
    RegionOptions options; options.resource_index=3; options.requested_key=0x1234;
    const auto source=fixture.source.memory().register_storage(1,4,fixture.source_storage,1,options);
    options.resource_index=4; options.requested_key=0x2222;
    const auto destination=fixture.target.memory().register_storage(1,5,fixture.target_storage,2,options);
    const auto post=[&] {
        if (tagged) fixture.target.post_tagged_receive(1,5,destination.key,4,73,{UINT64_MAX,0,uint32_t{0}},77,4);
        else fixture.target.post_receive(1,5,destination.key,4,73,77,4,uint32_t{0});
    };
    if (late) fixture.loop.after(5*kMillisecond,post); else post();
    auto operation=fixture.operation(tagged,ROD,99,4,16);
    operation.relative_addressing=relative; operation.target_pid=relative?2:5; operation.target_resource=4;
    operation.peer_initiator_id=UINT32_MAX;
    operation.rendezvous_source=RendezvousBuffer{source.key,4,73,static_cast<uint16_t>(relative?2:4),3,7};
    // Initial target generation0 must be rejected, retired through Clear and
    // retried with generation9. Source RMA generation7 is a separate field.
    const auto submitted=fixture.source.submit(operation); fixture.loop.run(1000000);
    const auto completion=fixture.complete(fixture.source,99,CompletionStatus::Success);
    CHECK(completion.operation==submitted && completion.length==73 && completion.remote_generation==9);
    fixture.complete(fixture.target,77,CompletionStatus::Success);
    // The destination deliberately grants only WRITE. Inspect the test-owned
    // storage locally instead of asking the remote READ API for extra rights.
    std::vector<uint8_t> placed(73); fixture.target_storage->read(4,placed.data(),placed.size());
    CHECK(placed==fixture.bytes);
    fixture.close();
}
int main() {
    try {
        for (bool tagged:{false,true}) for (bool standalone:{false,true})
            for (bool relative:{false,true}) for (bool late:{false,true}) mapped_source_and_receive(tagged,standalone,relative,late);
        std::cout<<"PASS relative/absolute source and receive mappings, distinct generations, retry and configured reverse rank\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
