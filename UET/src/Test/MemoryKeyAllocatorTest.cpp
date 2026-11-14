#include "Check.hpp"
#include "../SES/MemoryRegistry.hpp"
#include <iostream>
using namespace UET::SES;

int main() {
    try {
        auto history=std::make_shared<MemoryKeyAllocator>();
        MemoryRegistry first(history),replacement(history),independent;
        for (auto* registry:{&first,&replacement,&independent}) registry->add_job(1);
        const auto old_region=first.register_region(1,1,8,7);
        RegionOptions idempotent; idempotent.idempotent_safe=true;
        const auto new_region=replacement.register_region(1,1,8,7,idempotent);
        CHECK((old_region.key&MemoryKeyFormat::Rkey)==1 && (new_region.key&MemoryKeyFormat::Rkey)==2 &&
            (new_region.key&MemoryKeyFormat::IdempotentSafe));
        CHECK(independent.register_region(1,1,8,7).key==old_region.key); // Separate FEP/domain authority is independent.
        RegionOptions application; application.requested_key=123;
        const auto old_application=first.register_region(1,1,8,7,application);
        const auto new_application=replacement.register_region(1,1,8,7,application);
        CHECK(old_application.key==new_application.key);
        check_throws<MemoryAccessError>([&] {
            replacement.authorize_registration(old_application,1,1,0,1,Access::Write,1);
        }); // Explicit numeric reuse still cannot rebind a pinned local registration.
        CHECK((replacement.register_region(1,1,8,7).key&MemoryKeyFormat::Rkey)==3);
        CHECK(first.deregister(old_region) && (first.register_region(1,1,8,7).key&MemoryKeyFormat::Rkey)==4);
        replacement.remove_job(1); replacement.add_job(1);
        check_throws<MemoryAccessError>([&] { replacement.read(1,1,new_region.key,0,1); });
        CHECK((replacement.register_region(1,1,8,7).key&MemoryKeyFormat::Rkey)==5);

        auto final_key=std::make_shared<MemoryKeyAllocator>(MemoryKeyFormat::Rkey);
        MemoryRegistry boundary(final_key); boundary.add_job(1);
        CHECK((boundary.register_region(1,1,1,7).key&MemoryKeyFormat::Rkey)==MemoryKeyFormat::Rkey);
        check_throws<std::overflow_error>([&] { boundary.register_region(1,1,1,7); });
        CHECK(boundary.register_region(1,1,1,7,application).key==123); // Exhaustion does not disable explicit keys.
        MemoryRegistry after_exhaustion(final_key); after_exhaustion.add_job(1);
        check_throws<std::overflow_error>([&] { after_exhaustion.register_region(1,1,1,7); });
        check_throws<std::invalid_argument>([] { MemoryKeyAllocator invalid(0); });
        check_throws<std::invalid_argument>([] { MemoryKeyAllocator invalid(MemoryKeyFormat::Rkey+2); });
        std::cout<<"PASS shared automatic MR allocation, independent authority, explicit keys and48-bit exhaustion\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
