#include "RendezvousTestFixture.hpp"

void packet_fault(unsigned fault,bool tagged,pdc_mode mode,bool standalone,bool congestion) {
    RendezvousFixture fixture(standalone,congestion);
    bool applied=false; std::optional<uint32_t> eager_end;
    const auto inject=[&](bool reverse,const PDStoNET_pkt& packet) {
        using Action=RendezvousFaultPort::Action;
        const bool request=packet.PDS_type==RUOD_req_header;
        if (request && packet.SESpkt.bth_type==Standard_Header) {
            const auto& header=packet.SESpkt.bth_header.Standard_Header;
            const bool eager=header.opcode==6 || header.opcode==10;
            if (!reverse && eager && header.eom) eager_end=packet.PDS_header.RUOD_req_header.psn;
            if (!applied) {
                if ((fault==0 && !reverse && eager && header.som) ||
                    (fault==3 && reverse && header.opcode==2 && header.som)) { applied=true; return Action::Drop; }
                if (fault==1 && !reverse && eager && header.som) { applied=true; return Action::Duplicate; }
                if (fault==2 && !reverse && eager && !header.som && !header.eom) { applied=true; return Action::Delay; }
            }
        }
        if (!applied && !reverse && packet.SESpkt.bth_type==Semantic_Response_with_Data_Header &&
            (packet.PDS_type==RUOD_req_header || packet.PDS_type==RUOD_ack_header)) {
            if (fault==4) { applied=true; return Action::Drop; }
            if (fault==5) { applied=true; return Action::Duplicate; }
        }
        if (!applied && reverse && packet.PDS_type==RUOD_ack_header && packet.SESpkt.bth_type==Semantic_Response_Header) {
            const auto& ack=packet.PDS_header.RUOD_ack_header;
            if (ack.dpdcid<MAX_PDC && packet.SESpkt.bth_header.Semantic_Response_Header.return_code==1) {
                const uint32_t acknowledged=ack.cack_psn+static_cast<int32_t>(ack.ack_psn_off);
                if (fault==6 || (fault==7 && eager_end && acknowledged==*eager_end)) { applied=true; return Action::Drop; }
            }
            if (fault==8 && ack.dpdcid>=MAX_PDC) { applied=true; return Action::Drop; }
        }
        if (!applied && fault==8 && reverse && packet.PDS_type==RUOD_cp_header &&
            packet.PDS_header.RUOD_cp_header.ctl_type==Clear_cmd && packet.PDS_header.RUOD_cp_header.dpdcid>=MAX_PDC) {
            applied=true; return Action::Drop;
        }
        return Action::Pass;
    };
    fixture.forward.inject=[&](const auto& packet) { return inject(false,packet); };
    fixture.reverse.inject=[&](const auto& packet) { return inject(true,packet); };
    fixture.post(tagged); const auto submitted=fixture.source.submit(fixture.operation(tagged,mode)); fixture.loop.run(1000000);
    const auto source=fixture.complete(fixture.source,99,CompletionStatus::Success);
    const auto target=fixture.complete(fixture.target,77,CompletionStatus::Success);
    CHECK(source.operation==submitted && source.length==73 && target.length==73 && target.immediate_data==42);
    CHECK(target.tag==(tagged?std::optional<uint64_t>{UINT64_MAX}:std::nullopt));
    CHECK(applied && fixture.forward.faults+fixture.reverse.faults==1);
    CHECK(fixture.target.memory().read(1,1,fixture.target_region.key,4,73)==fixture.bytes);
    fixture.close();
}
void lifecycle(unsigned scenario,bool tagged,bool standalone) {
    RendezvousFixture fixture(standalone);
    const auto submitted=fixture.source.submit(fixture.operation(tagged,ROD)); fixture.loop.run_until(2*kMillisecond);
    CHECK(fixture.source.pending()==1 && fixture.source.transport_pending(submitted) &&
        fixture.target.retained_rendezvous_receives()==1 && !fixture.target.retained_receive_messages());
    Completion completion{}; CHECK(!fixture.source.poll_completion(completion) && !fixture.target.poll_completion(completion));
    if (scenario<=2) {
        if (scenario==0) CHECK(fixture.source.cancel_rendezvous(submitted));
        if (scenario==1) fixture.loop.run(1000000);
        if (scenario==2) fixture.source.close();
        fixture.complete(fixture.source,99,scenario==1?CompletionStatus::Timeout:CompletionStatus::Cancelled);
        fixture.post(tagged); fixture.loop.run(1000000);
        const auto target=fixture.take(fixture.target,77); CHECK(target.status!=CompletionStatus::Success);
    } else if (scenario==3) {
        CHECK(fixture.source.memory().deregister(fixture.source_region));
        RegionOptions options; options.requested_key=0x1234;
        fixture.source_region=fixture.source.memory().register_region(1,1,256,1,options);
        fixture.post(tagged); fixture.loop.run(1000000);
        fixture.complete(fixture.source,99,CompletionStatus::RemoteError);
        fixture.complete(fixture.target,77,CompletionStatus::RemoteError);
        CHECK(fixture.source.memory().read(1,1,fixture.source_region.key,0,256)==std::vector<uint8_t>(256));
    } else if (scenario==4) {
        fixture.post(tagged);
        CHECK(fixture.target.memory().deregister(fixture.target_region));
        RegionOptions options; options.requested_key=0x2222;
        fixture.target_region=fixture.target.memory().register_region(1,1,256,7,options);
        fixture.loop.run(1000000);
        const auto source=fixture.take(fixture.source,99);
        // READ permits DEFAULT on requester-local placement failure. Its
        // responder cannot infer that local MR failure from a valid PDS ACK.
        CHECK(source.status==CompletionStatus::Success || source.status==CompletionStatus::RemoteError || source.status==CompletionStatus::Timeout);
        fixture.complete(fixture.target,77,CompletionStatus::LocalError);
        CHECK(fixture.target.memory().read(1,1,fixture.target_region.key,0,256)==std::vector<uint8_t>(256));
    } else {
        fixture.post(tagged,77,4,72); fixture.loop.run(1000000);
        fixture.complete(fixture.target,77,CompletionStatus::Truncated);
        fixture.complete(fixture.source,99,CompletionStatus::Timeout);
    }
    CHECK(!fixture.source.cancel_rendezvous(submitted)); fixture.close();
}
void header_pressure(bool tagged,pdc_mode mode) {
    RendezvousFixture fixture; fixture.target.configure_rendezvous(1);
    fixture.source.submit(fixture.operation(tagged,mode,10)); fixture.loop.run_until(2*kMillisecond);
    std::vector<uint8_t> second_bytes(73,0xb6); fixture.source_storage->write(104,second_bytes.data(),73);
    fixture.source.submit(fixture.operation(tagged,mode,11,104)); fixture.loop.run_until(4*kMillisecond);
    CHECK(fixture.source.pending()==2 && fixture.target.retained_rendezvous_receives()==1);
    fixture.post(tagged,20,4); fixture.post(tagged,21,104); fixture.loop.run(1000000);
    std::set<uint64_t> source_contexts,target_contexts; Completion completion{};
    while (fixture.source.poll_completion(completion)) { CHECK(completion.status==CompletionStatus::Success && source_contexts.insert(completion.context).second); }
    while (fixture.target.poll_completion(completion)) { CHECK(completion.status==CompletionStatus::Success && target_contexts.insert(completion.context).second); }
    CHECK(source_contexts==std::set<uint64_t>({10,11}) && target_contexts==std::set<uint64_t>({20,21}));
    CHECK(fixture.target.memory().read(1,1,fixture.target_region.key,4,73)==fixture.bytes);
    CHECK(fixture.target.memory().read(1,1,fixture.target_region.key,104,73)==second_bytes);
    fixture.close();
}
int main() {
    try {
        for (unsigned fault=0;fault<9;++fault) for (bool tagged:{false,true}) for (auto mode:{RUD,ROD})
            for (bool standalone:{false,true}) for (bool congestion:{false,true}) packet_fault(fault,tagged,mode,standalone,congestion);
        for (bool tagged:{false,true}) {
            for (unsigned scenario=0;scenario<6;++scenario) for (bool standalone:{false,true}) lifecycle(scenario,tagged,standalone);
            for (auto mode:{RUD,ROD}) header_pressure(tagged,mode);
        }
        std::cout<<"PASS rendezvous packet faults, cancellation/deadline/close, source/result MR reuse, truncation and header pressure/FIFO\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
