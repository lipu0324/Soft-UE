#include "Check.hpp"
#include "../SES/MemoryRegistry.hpp"
#include <iostream>
using namespace UET::SES;

int main() {
    try {
        MemoryRegistry registry; registry.add_job(1); registry.add_job(2);
        const auto region = registry.register_region(1,7,(1ULL<<32)-1,7,true);
        CHECK(region.key & MemoryRegistry::kIdempotentSafe);
        CHECK(region.storage->allocated_pages() == 0);
        registry.write(1,7,region.key,4094,{1,2,3,4});
        CHECK(registry.read(1,7,region.key,4093,6) == std::vector<uint8_t>({0,1,2,3,4,0}));
        CHECK(region.storage->allocated_pages() == 2);
        registry.write(1,7,region.key,(1ULL<<32)-2,{99});
        CHECK(registry.read(1,7,region.key,(1ULL<<32)-2,1)[0] == 99);
        const auto before = registry.read(1,7,region.key,4094,4);
        check_throws<MemoryAccessError>([&] { registry.write(2,7,region.key,4094,{9}); });
        check_throws<MemoryAccessError>([&] { registry.write(1,8,region.key,4094,{9}); });
        check_throws<MemoryAccessError>([&] { registry.write(1,7,region.key,UINT64_MAX,{9}); });
        check_throws<MemoryAccessError>([&] { registry.write(1,7,region.key,(1ULL<<32)-2,{9,9}); });
        CHECK(registry.read(1,7,region.key,4094,4) == before);
        CHECK(registry.atomic(1,7,region.key,0,Atomic64::Add,4) == 0);
        CHECK(registry.atomic(1,7,region.key,0,Atomic64::CompareSwap,9,3) == 4);
        CHECK(registry.atomic(1,7,region.key,0,Atomic64::CompareSwap,9,4) == 4);
        CHECK(registry.atomic(1,7,region.key,0,Atomic64::Swap,0) == 9);
        check_throws<MemoryAccessError>([&] { registry.atomic(1,7,region.key,1,Atomic64::Add,1); });
        const auto read_only = registry.register_region(1,0,16,static_cast<uint8_t>(Access::Read));
        CHECK(registry.read(1,99,read_only.key,16,0).empty());
        check_throws<MemoryAccessError>([&] { registry.write(1,7,read_only.key,0,{1}); });
        CHECK(registry.deregister(region.key));
        check_throws<MemoryAccessError>([&] { registry.read(1,7,region.key,0,1); });
        const auto replacement = registry.register_region(1,7,16,7);
        CHECK(replacement.key != region.key);
        auto application_buffer=std::make_shared<std::vector<uint8_t>>(16,0);
        std::weak_ptr<std::vector<uint8_t>> buffer_lifetime=application_buffer;
        auto host_region=registry.register_buffer(1,7,application_buffer->data(),application_buffer->size(),7,{},application_buffer);
        registry.write(1,7,host_region.key,8,{4,5,6});
        CHECK((*application_buffer)[8]==4 && (*application_buffer)[10]==6);
        (*application_buffer)[0]=8;
        CHECK(registry.atomic(1,7,host_region.key,0,Atomic64::Add,2)==8 && (*application_buffer)[0]==10);
        const auto original=*application_buffer;
        check_throws<MemoryAccessError>([&] { registry.write(2,7,host_region.key,8,{99}); });
        check_throws<MemoryAccessError>([&] { registry.write(1,7,host_region.key,15,{99,99}); });
        CHECK(*application_buffer==original);
        application_buffer.reset();
        CHECK(!buffer_lifetime.expired());
        CHECK(registry.deregister(host_region.key));
        check_throws<MemoryAccessError>([&] { registry.write(1,7,host_region.key,0,{99}); });
        host_region.storage.reset(); CHECK(buffer_lifetime.expired());
        registry.remove_job(1);
        check_throws<MemoryAccessError>([&] { registry.read(1,7,replacement.key,0,1); });
        std::cout << "PASS: sparse 4GiB boundary, scoped authorization, no mutation on failure, atomics and revocation\n";
        return 0;
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
