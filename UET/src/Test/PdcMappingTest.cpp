#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
#include <map>
#include <set>

using namespace UET::Runtime;
using namespace UET::SES;
using namespace UET::PDS;
using UET::NetworkLayer::UetWireCodec;

PdcMappingFields fields(unsigned selected) {
    PdcMappingFields result;
    result.include_job_id=selected&1; result.include_source_pid=selected&2;
    result.include_target_pid=selected&4; result.include_resource_index=selected&8;
    return result;
}
PdcMappingIdentity identity(unsigned input) {
    return {static_cast<uint16_t>(1+bool(input&2)),static_cast<uint16_t>(1+bool(input&4)),
        static_cast<uint16_t>(1+bool(input&8))};
}
uint32_t job(unsigned input) { return 1+bool(input&1); }

void mapping_and_memory(unsigned selected,pdc_mode mode) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    PdcMappingConfiguration mapping; mapping.rud=mapping.rod=fields(selected);
    source_host.configure_pdc_mapping(mapping);
    source_host.enable_nscc({}); target_host.enable_nscc({});
    Endpoint source(1,source_host,loop,trace,16),target(2,target_host,loop,trace,16);
    using RegionScope=std::tuple<uint32_t,uint16_t,uint16_t>;
    std::map<RegionScope,Region> registrations;
    for (uint32_t job_id:{1,2}) {
        source.memory().add_job(job_id); target.memory().add_job(job_id);
        for (uint16_t pid:{1,2}) for (uint16_t resource:{1,2}) {
            target.resources().map_relative_pid(job_id,pid,pid);
            target.resources().configure_resource(pid,resource,ResourceSpace::Rma);
            RegionOptions options; options.resource_index=resource;
            registrations.emplace(RegionScope{job_id,pid,resource},target.memory().register_region(job_id,pid,2048,7,options));
        }
    }
    std::map<unsigned,uint16_t> buckets;
    std::map<unsigned,uint16_t> expected_contexts;
    for (unsigned input=0;input<16;++input) {
        const auto context=source_host.open_connection(2,job(input),mode,false,identity(input));
        CHECK(context!=UINT16_MAX); expected_contexts.emplace(input,context);
        const auto inserted=buckets.emplace(input&selected,context);
        CHECK(inserted.second || inserted.first->second==context);
    }
    std::set<uint16_t> unique_contexts;
    for (const auto& bucket:buckets) CHECK(unique_contexts.insert(bucket.second).second);
    CHECK(source_host.manager().getPDSStatus().open_cnt==static_cast<int>(buckets.size()));
    CHECK(source_host.nscc()->source_connection_count()==buckets.size());
    CHECK(source_host.nscc()->congestion_context_count()==(mode==RUD?1:buckets.size()));
    loop.run_until(kMillisecond);
    std::map<unsigned,uint16_t> observed_contexts;
    std::map<uint16_t,std::vector<uint16_t>> messages_per_context;
    fabric.set_capture([&](Time,const Frame& frame) {
        if (frame.source!=1) return;
        const auto packet=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        if (packet.PDS_type!=RUOD_req_header) return;
        const auto& semantic=packet.SESpkt.bth_header.Standard_Header;
        const auto context=packet.PDS_header.RUOD_req_header.spdcid;
        CHECK(semantic.initiator==1); // Job rank is deliberately independent of local source PID.
        const bool retransmitted=packet.PDS_header.RUOD_req_header.flags.retx;
        if (!retransmitted) messages_per_context[context].push_back(semantic.msg_id);
        if (semantic.som) {
            CHECK(semantic.buffer_offset%64==0);
            const auto inserted=observed_contexts.emplace(semantic.buffer_offset/64,context);
            if (!inserted.second && (inserted.first->second!=context || !retransmitted))
                throw std::runtime_error("duplicate mapping SOM mask="+std::to_string(selected)+
                    ", mode="+std::to_string(mode)+", offset="+std::to_string(semantic.buffer_offset)+
                    ", old_pdc="+std::to_string(inserted.first->second)+", new_pdc="+std::to_string(context)+
                    ", retx="+std::to_string(retransmitted));
        }
    });
    for (unsigned input=0;input<16;++input) {
        const auto process=identity(input);
        const auto& region=registrations.at({job(input),process.target_pid,process.resource_index});
        Operation write; write.type=OperationType::Write; write.peer=2; write.job=job(input);
        write.source_pid=process.source_pid; write.target_pid=process.target_pid; write.target_resource=process.resource_index;
        write.delivery_mode=mode; write.remote_key=region.key; write.remote_offset=input*64;
        write.context=input+1; write.payload.assign(33,static_cast<uint8_t>(input+11));
        source.submit(write);
    }
    loop.run(1000000);
    Completion completion{}; std::set<uint64_t> completions;
    while (source.poll_completion(completion)) {
        if (completion.status!=CompletionStatus::Success)
            throw std::runtime_error("mapping WRITE mask="+std::to_string(selected)+", mode="+std::to_string(mode)+
                ", context="+std::to_string(completion.context)+", status="+std::to_string(static_cast<int>(completion.status))+
                ", remote_code="+std::to_string(completion.remote_code));
        CHECK(completion.status==CompletionStatus::Success && completion.length==33);
        CHECK(completions.insert(completion.context).second);
    }
    CHECK(completions.size()==16 && observed_contexts==expected_contexts);
    for (unsigned input=0;input<16;++input) {
        const auto process=identity(input);
        const auto& region=registrations.at({job(input),process.target_pid,process.resource_index});
        CHECK(target.memory().read(job(input),process.target_pid,region.key,input*64,33,process.resource_index)==
            std::vector<uint8_t>(33,static_cast<uint8_t>(input+11)));
    }
    // §3.5.8.1 orders original message packets. Recovery may revisit an older
    // message after later originals; it is checked separately by PDS tests.
    for (const auto& context:messages_per_context) {
        std::set<uint16_t> finished; std::optional<uint16_t> previous;
        for (uint16_t message:context.second) {
            if (previous && *previous!=message) finished.insert(*previous);
            CHECK(!finished.count(message)); previous=message;
        }
    }
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(loop.pending()==0);
}

void independent_modes_and_base_fields() {
    EventLoop loop; Services services{loop,loop,[]{}};
    services.pdc_mapping.rud=fields(0); services.pdc_mapping.rod=fields(15);
    PDS_Manager manager(&services); CHECK(manager.initPDSM());
    std::set<int> unordered,ordered;
    for (unsigned input=0;input<16;++input) for (auto mode:{RUD,ROD}) {
        const auto context=manager.muxTx2PDCID(job(input),2,0,mode,1,identity(input));
        CHECK(context>0);
        if (!manager.PDCOpen(context)) CHECK(manager.allocPDC(context,2,1,mode));
        (mode==RUD?unordered:ordered).insert(context);
    }
    CHECK(unordered.size()==1 && ordered.size()==16 && !ordered.count(*unordered.begin()));
    std::set<int> base_contexts=unordered;
    for (const auto& tuple:std::vector<std::tuple<uint32_t,uint32_t,uint8_t>>{{3,2,0},{1,3,0},{1,2,2}}) {
        const auto source_fa=std::get<0>(tuple),target_fa=std::get<1>(tuple);
        const auto context=manager.muxTx2PDCID(1,target_fa,std::get<2>(tuple),RUD,source_fa);
        CHECK(context>0 && base_contexts.insert(context).second);
        CHECK(manager.allocPDC(context,target_fa,source_fa,RUD));
    }
    CHECK(loop.pending()==0);
}

void invalid_identity_and_configuration_lifetime() {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& port=fabric.add_host(1); fabric.add_host(2); fabric.add_link(1,2,{});
    PdsHost host(1,loop,trace,port); Endpoint endpoint(1,host,loop,trace); endpoint.memory().add_job(1);
    for (const auto invalid:std::vector<PdcMappingIdentity>{{4096,1,1},{1,4096,1},{1,1,4096}})
        CHECK(host.open_connection(2,1,ROD,false,invalid)==UINT16_MAX);
    Operation write; write.type=OperationType::Write; write.peer=2; write.source_pid=4096;
    endpoint.submit(write); Completion completion{};
    CHECK(endpoint.poll_completion(completion) && completion.status==CompletionStatus::InvalidRequest);
    CHECK(host.manager().getPDSStatus().open_cnt==0);
    PdcMappingConfiguration complete; complete.rud=complete.rod=fields(15); host.configure_pdc_mapping(complete);
    const auto zero_identity=host.open_connection(2,0,ROD,false,{0,0,0});
    const auto maximum_identity=host.open_connection(2,0xffffff,ROD,false,{4095,4095,4095});
    CHECK(zero_identity!=UINT16_MAX && maximum_identity!=UINT16_MAX && zero_identity!=maximum_identity);
    check_throws<std::logic_error>([&] { host.configure_pdc_mapping({}); });
    endpoint.close(); host.close(); CHECK(loop.pending()==0);
}

int main() {
    try {
        for (unsigned selected=0;selected<16;++selected) for (auto mode:{RUD,ROD}) mapping_and_memory(selected,mode);
        independent_modes_and_base_fields(); invalid_identity_and_configuration_lifetime();
        std::cout<<"PASS: all optional PDC mapping-field combinations, mode/base isolation, fragments and checked memory\n";
        return 0;
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
