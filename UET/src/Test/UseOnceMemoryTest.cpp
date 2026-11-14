#include "Check.hpp"
#include "../SES/MemoryRegistry.hpp"
#include <iostream>
using namespace UET::SES;

static RmaMessageOwnerToken message_owner() { return std::make_shared<const RmaMessageOwner>(); }

static void exclusive_message_and_retirement() {
    MemoryRegistry memory; memory.add_job(0); memory.add_job(1);
    RegionOptions options; options.use_once=true; options.bind_zero_pid=true;
    const auto region=memory.register_region(0,0,32,7,options);
    const auto first=message_owner(),second=message_owner();
    const auto claim=[&](const RmaMessageOwnerToken& owner,uint64_t offset,uint64_t length) {
        return memory.claim_rma_registration(0,0,region.key,offset,length,Access::Write,{},true,owner);
    };
    // Failed scope, permission or span checks must not consume the grant.
    check_throws<MemoryAccessError>([&] { memory.claim_rma_registration(1,0,region.key,0,8,Access::Write,{},true,first); });
    check_throws<MemoryAccessError>([&] { memory.claim_rma_registration(0,1,region.key,0,8,Access::Write,{},true,first); });
    check_throws<MemoryAccessError>([&] { claim(first,31,2); });
    CHECK(memory.retained_use_once_claims()==0);
    const auto pinned=claim(first,0,16);
    CHECK(memory.retained_use_once_claims()==1);
    CHECK(claim(first,16,16).registration_id==pinned.registration_id);
    check_throws<MemoryAccessError>([&] { claim(second,24,8); });
    check_throws<MemoryAccessError>([&] { claim(second,32,0); });
    check_throws<MemoryAccessError>([&] { memory.write(0,0,region.key,0,{99}); });
    check_throws<MemoryAccessError>([&] { memory.read_registration(pinned,0,0,0,1,{},MemoryAccessOrigin::RemoteRequest,second); });
    memory.write_registration(pinned,0,0,0,{1,2}, {},MemoryAccessOrigin::RemoteRequest,first);
    memory.write_registration(pinned,0,0,2,{3,4}, {},MemoryAccessOrigin::RemoteRequest,first);
    CHECK(memory.read_registration(pinned,0,0,0,4,{},MemoryAccessOrigin::RemoteRequest,first)==std::vector<uint8_t>({1,2,3,4}));
    CHECK(!memory.finish_rma_registration(pinned,second));
    CHECK(memory.finish_rma_registration(pinned,first));
    CHECK(memory.retained_use_once_claims()==0);
    check_throws<MemoryAccessError>([&] { claim(first,0,1); });
    // Consuming remote authorization does not destroy application storage.
    std::array<uint8_t,4> bytes{}; region.storage->read(0,bytes.data(),bytes.size());
    CHECK((bytes==std::array<uint8_t,4>{1,2,3,4}));
}

static void revocation_and_owner_lifetime() {
    MemoryRegistry memory; memory.add_job(1);
    RegionOptions options; options.use_once=true; options.requested_key=42;
    const auto old=memory.register_region(1,7,16,7,options);
    const auto first=message_owner(),second=message_owner();
    memory.claim_rma_registration(1,7,42,0,16,Access::Read,1,true,first);
    CHECK(memory.deregister(old));
    const auto replacement=memory.register_region(1,7,16,7,options);
    memory.claim_rma_registration(1,7,42,0,16,Access::Read,1,true,second);
    CHECK(!memory.finish_rma_registration(old,first));
    check_throws<MemoryAccessError>([&] { memory.read_registration(old,1,7,0,8,1,MemoryAccessOrigin::RemoteRequest,first); });
    CHECK(memory.read_registration(replacement,1,7,0,8,1,MemoryAccessOrigin::RemoteRequest,second).size()==8);
    CHECK(memory.finish_rma_registration(replacement,second));

    auto abandoned=message_owner();
    const auto orphan=memory.register_region(1,7,16,7,options);
    memory.claim_rma_registration(1,7,42,0,16,Access::Read,1,true,abandoned);
    abandoned.reset();
    // Expiry is not permission to recycle a consumed grant. Its weak control
    // block remains distinct even if an allocator reuses an object address.
    check_throws<MemoryAccessError>([&] { memory.claim_rma_registration(1,7,42,0,16,Access::Read,1,true,message_owner()); });
    CHECK(memory.retained_use_once_claims()==1);
    memory.remove_job(1);
    CHECK(memory.retained_use_once_claims()==0);
    CHECK(!memory.deregister(orphan));
}

static void persistent_buffers_and_key_metadata() {
    MemoryRegistry memory; memory.add_job(1);
    const auto persistent=memory.register_region(1,7,16,7);
    const auto first=message_owner(),second=message_owner();
    memory.claim_rma_registration(1,7,persistent.key,0,8,Access::Write,{},true,first);
    memory.claim_rma_registration(1,7,persistent.key,0,8,Access::Write,{},true,second);
    CHECK(!memory.finish_rma_registration(persistent,first));
    memory.write(1,7,persistent.key,0,{8});
    CHECK(memory.read(1,7,persistent.key,0,1)==std::vector<uint8_t>({8}));
    RegionOptions options; options.use_once=true; options.idempotent_safe=true;
    const auto safe=memory.register_region(1,7,16,7,options);
    memory.claim_rma_registration(1,7,safe.key,0,8,Access::Read,{},true,first);
    CHECK(memory.finish_rma_registration(safe,first));
    options.idempotent_safe=false; options.requested_key=42|MemoryRegistry::kIdempotentSafe;
    const auto assigned_safe=memory.register_region(1,7,16,7,options);
    memory.claim_rma_registration(1,7,assigned_safe.key,0,8,Access::Read,1,true,first);
    // IDEMPOTENT_SAFE describes duplicate effects; it does not authorize an
    // ownerless RUDI access or a different logical message to bypass use-once.
    check_throws<MemoryAccessError>([&] { memory.read(1,7,assigned_safe.key,0,8,1); });
    CHECK(memory.finish_rma_registration(assigned_safe,first));
    options.requested_key=42;
    const auto read_only=memory.register_region(1,7,16,1,options);
    check_throws<MemoryAccessError>([&] { memory.claim_rma_registration(1,7,42,0,8,Access::Write,1,true,first); });
    CHECK(memory.retained_use_once_claims()==0);
    memory.claim_rma_registration(1,7,42,0,8,Access::Read,1,true,second);
    CHECK(memory.finish_rma_registration(read_only,second));
    const auto atomic_only=memory.register_region(1,7,16,4,options);
    check_throws<MemoryAccessError>([&] { memory.claim_rma_registration(1,7,42,0,8,Access::Atomic,1,true,first); });
    CHECK(memory.retained_use_once_claims()==0);
    CHECK(memory.deregister(atomic_only));
    CHECK(memory.deregister(persistent));
}

int main() {
    try {
        exclusive_message_and_retirement(); revocation_and_owner_lifetime(); persistent_buffers_and_key_metadata();
        std::cout << "PASS: logical use-once ownership, checked spans, exact revocation, expired owners and persistent buffers\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
