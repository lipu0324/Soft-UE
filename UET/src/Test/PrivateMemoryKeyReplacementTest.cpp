#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

static void stale_auto_key_does_not_select_new_storage(pdc_mode mode,RequestHeaderFormat format,bool congestion,bool idempotent) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& source_port=fabric.add_host(1); auto& target_port=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,source_port),target_host(2,loop,trace,target_port);
    if (congestion) { source_host.enable_nscc({}); target_host.enable_nscc({}); }
    Endpoint source(1,source_host,loop,trace,64),previous(2,target_host,loop,trace,64);
    source.memory().add_job(1); previous.memory().add_job(1);
    RegionOptions options; options.idempotent_safe=idempotent;
    const auto old_region=previous.memory().register_region(1,1,8,7,options);
    const std::vector<uint8_t> old_bytes(8,0x11); old_region.storage->write(0,old_bytes.data(),old_bytes.size());
    previous.close(); Endpoint replacement(2,target_host,loop,trace,64); replacement.memory().add_job(1);
    const auto new_region=replacement.memory().register_region(1,1,8,7,options);
    const std::vector<uint8_t> new_bytes(8,0x22); new_region.storage->write(0,new_bytes.data(),new_bytes.size());
    Operation operation; operation.type=OperationType::Write; operation.delivery_mode=mode;
    operation.header_format=format; operation.peer=2; operation.remote_key=old_region.key; operation.payload.assign(4,0xaa);
    source.submit(operation); loop.run_until(kMillisecond);
    if (replacement.memory().read(1,1,new_region.key,0,8)!=new_bytes)
        throw std::runtime_error("stale automatically assigned key selected a replacement Endpoint's new MR");
    Completion completion{}; CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::RemoteError &&
        completion.remote_code==static_cast<uint8_t>(SemanticReturnCode::BadMemoryKey));
    CHECK(old_region.key!=new_region.key && !source.poll_completion(completion));
    operation.remote_key=new_region.key; operation.payload.assign(4,0xbb);
    source.submit(operation); loop.run_until(2*kMillisecond);
    CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Success && !source.poll_completion(completion));
    CHECK(replacement.memory().read(1,1,new_region.key,0,4)==std::vector<uint8_t>(4,0xbb));
    CHECK(previous.memory().read(1,1,old_region.key,0,8)==old_bytes);
    source.close(); replacement.close(); source_host.close(); target_host.close(); loop.run_until(3*kMillisecond); CHECK(!loop.pending());
}
int main() {
    try {
        for (auto mode:{RUD,ROD}) for (auto format:{RequestHeaderFormat::Standard,RequestHeaderFormat::Medium})
            for (bool congestion:{false,true}) for (bool idempotent:{false,true})
                stale_auto_key_does_not_select_new_storage(mode,format,congestion,idempotent);
        std::cout<<"PASS16 private MR automatic keys remain unique across SES replacement and preserve metadata\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
