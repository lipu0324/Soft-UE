#include "RendezvousTestFixture.hpp"

template<class Callback> void denied(Callback callback) {
    bool rejected=false;
    try { callback(); } catch (const MemoryAccessError&) { rejected=true; }
    CHECK(rejected);
}
void source_authority() {
    MemoryRegistry registry; registry.add_job(1); registry.add_job(2);
    RegionOptions options; options.rendezvous_source_only=true; options.requested_key=0x1234;
    auto storage=std::make_shared<SparseMemory>(32); const std::vector<uint8_t> bytes={1,2,3,4};
    storage->write(4,bytes.data(),bytes.size());
    const auto source=registry.register_storage(1,1,storage,1,options);
    denied([&] { registry.read(1,1,source.key,4,4,1); });
    denied([&] { registry.authorize_local(1,1,source.key,4,4,Access::Read,1); });
    denied([&] { registry.authorize_registration(source,1,1,4,4,Access::Read,1); });
    RegisteredReadPayload view(registry,source,1,1,1,4,4);
    uint8_t result[4]{}; view.read(0,result,4); CHECK(std::vector<uint8_t>(result,result+4)==bytes);
    denied([&] { registry.authorize(2,1,source.key,4,4,Access::Read,1,true,MemoryAccessOrigin::RendezvousSource); });
    denied([&] { registry.authorize(1,2,source.key,4,4,Access::Read,1,true,MemoryAccessOrigin::RendezvousSource); });
    denied([&] { registry.authorize(1,1,source.key,31,2,Access::Read,1,true,MemoryAccessOrigin::RendezvousSource); });
    CHECK(registry.deregister(source));
    options.requested_key=0x1234;
    const auto replacement=registry.register_region(1,1,32,1,options);
    denied([&] { view.read(0,result,4); });
    MemoryRegistry other; other.add_job(1);
    denied([&] { other.authorize_registration(replacement,1,1,0,0,Access::Read,1,MemoryAccessOrigin::RendezvousSource); });
    options.rendezvous_source_only=false; options.local_placement_only=true;
    const auto placement=registry.register_region(1,2,32,1,options);
    denied([&] { RegisteredReadPayload invalid(registry,placement,1,2,1,0,1); });
    options.rendezvous_source_only=true;
    bool conflicting=false;
    try { registry.register_region(1,3,32,1,options); } catch (const std::invalid_argument&) { conflicting=true; }
    CHECK(conflicting);
}
void private_source_transaction(bool tagged,bool standalone) {
    RendezvousFixture fixture(standalone);
    RegionOptions options; options.rendezvous_source_only=true;
    const auto source=fixture.source.memory().register_storage(1,1,fixture.source_storage,1,options);
    auto operation=fixture.operation(tagged,ROD,99,4,16); operation.rendezvous_source->key=source.key;
    fixture.source.submit(operation); fixture.loop.run_until(2*kMillisecond);
    CHECK(fixture.source.pending()==1 && fixture.target.retained_rendezvous_receives()==1);
    // Even the intended rendezvous peer cannot use the underlying private key
    // as a general remote READ. Only the advertised transaction alias grants it.
    Operation probe; probe.type=OperationType::Read; probe.peer=1; probe.context=101; probe.remote_key=source.key;
    fixture.target.submit(probe); fixture.loop.run_until(4*kMillisecond);
    CHECK(fixture.complete(fixture.target,101,CompletionStatus::RemoteError).remote_code==
        static_cast<uint8_t>(SemanticReturnCode::OperationViolation));
    CHECK(fixture.source.pending()==1);
    fixture.post(tagged); fixture.loop.run(1000000);
    fixture.complete(fixture.source,99,CompletionStatus::Success); fixture.complete(fixture.target,77,CompletionStatus::Success);
    CHECK(fixture.target.memory().read(1,1,fixture.target_region.key,4,73)==fixture.bytes);
    fixture.close();
}
int main() {
    try {
        source_authority();
        for (bool tagged:{false,true}) for (bool standalone:{false,true}) private_source_transaction(tagged,standalone);
        std::cout<<"PASS dedicated rendezvous source authority, direct RMA denial, exact registration and private source transactions\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
