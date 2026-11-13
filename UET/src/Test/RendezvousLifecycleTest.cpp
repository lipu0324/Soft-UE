#include "RendezvousTestFixture.hpp"
#include <array>
std::string stage;

void shared_arrival_fifo(bool tagged,pdc_mode mode,std::array<unsigned,3> order) {
    RendezvousFixture fixture;
    fixture.target.enable_deferrable_capture();
    // Independent PDCs expose all three arrivals before application posting.
    // A delivery-complete ordinary ROD EOM may otherwise hold later semantic
    // responses on its PDC until the application places that first message.
    UET::PDS::PdcMappingConfiguration mapping;
    mapping.rud.include_source_pid=mapping.rod.include_source_pid=true;
    fixture.source_host.configure_pdc_mapping(mapping);
    std::vector<std::tuple<uint32_t,uint8_t,uint16_t,bool,bool>> wire;
    fixture.forward.inject=[&](const PDStoNET_pkt& packet) {
        if (packet.PDS_type==RUOD_req_header && packet.SESpkt.bth_type==Standard_Header) {
            const auto& header=packet.SESpkt.bth_header.Standard_Header;
            wire.emplace_back(static_cast<uint32_t>(fixture.loop.now()),header.opcode,header.msg_id,header.som,header.eom);
        }
        return RendezvousFaultPort::Action::Pass;
    };
    const std::array<std::vector<uint8_t>,3> messages={fixture.bytes,std::vector<uint8_t>(73,0xb6),std::vector<uint8_t>(73,0xc7)};
    for (size_t arrival=0;arrival<order.size();++arrival) {
        const auto kind=order[arrival]; auto operation=fixture.operation(tagged,mode,10+kind);
        operation.source_pid=1+kind;
        if (kind) {
            operation.type=kind==1?(tagged?OperationType::DeferrableTaggedSend:OperationType::DeferrableSend):
                (tagged?OperationType::TaggedSend:OperationType::Send);
            operation.rendezvous_source.reset(); operation.rendezvous_eager_length=0; operation.payload=messages[kind];
            // Ordinary RUD SEND returns NO_MATCH; ordinary ROD SEND buffers
            // unexpected payload. Only the latter participates in this FIFO.
            if (kind==2) operation.delivery_mode=ROD;
        }
        fixture.source.submit(operation); fixture.loop.run_until((arrival+1)*2*kMillisecond);
    }
    if (fixture.target.retained_rendezvous_receives()!=1 || fixture.target.captured_deferrable_headers()!=1 ||
        fixture.target.unexpected_bytes()!=73) std::cerr<<"FIFO tagged="<<tagged<<" mode="<<mode<<" order="
        <<order[0]<<order[1]<<order[2]<<" retained="<<fixture.target.retained_rendezvous_receives()<<'/'
        <<fixture.target.captured_deferrable_headers()<<'/'<<fixture.target.unexpected_bytes()<<'\n';
    if (fixture.target.captured_deferrable_headers()!=1) for (const auto& packet:wire)
        std::cerr<<std::get<0>(packet)<<" opcode="<<unsigned(std::get<1>(packet))<<" MID="<<std::get<2>(packet)
            <<" SOM="<<std::get<3>(packet)<<" EOM="<<std::get<4>(packet)<<'\n';
    CHECK(fixture.target.retained_rendezvous_receives()==1 && fixture.target.captured_deferrable_headers()==1 &&
        fixture.target.unexpected_bytes()==73);
    for (size_t arrival=0;arrival<order.size();++arrival) fixture.post(tagged,20+arrival,4+80*arrival);
    fixture.loop.run(1000000);
    std::set<uint64_t> source_contexts,target_contexts; Completion completion{};
    while (fixture.source.poll_completion(completion)) {
        CHECK(completion.status==CompletionStatus::Success && completion.length==73 && source_contexts.insert(completion.context).second);
    }
    while (fixture.target.poll_completion(completion)) {
        CHECK(completion.status==CompletionStatus::Success && completion.length==73 && target_contexts.insert(completion.context).second);
    }
    CHECK(source_contexts==std::set<uint64_t>({10,11,12}) && target_contexts==std::set<uint64_t>({20,21,22}));
    for (size_t arrival=0;arrival<order.size();++arrival)
        CHECK(fixture.target.memory().read(1,1,fixture.target_region.key,4+80*arrival,73)==messages[order[arrival]]);
    fixture.close();
}

void normal_connection_replacement(bool tagged,bool standalone) {
    RendezvousFixture fixture(standalone); uint16_t eager_pdc=UINT16_MAX;
    fixture.forward.inject=[&](const PDStoNET_pkt& packet) {
        if (packet.PDS_type==RUOD_req_header) eager_pdc=packet.PDS_header.RUOD_req_header.spdcid;
        return RendezvousFaultPort::Action::Pass;
    };
    fixture.source.submit(fixture.operation(tagged,ROD)); fixture.loop.run_until(2*kMillisecond);
    CHECK(eager_pdc!=UINT16_MAX && fixture.source_host.request_connection_close(eager_pdc));
    fixture.loop.run_until(4*kMillisecond);
    CHECK(fixture.source.pending()==1 && fixture.target.retained_rendezvous_receives()==1);
    fixture.post(tagged); fixture.loop.run(1000000);
    fixture.complete(fixture.source,99,CompletionStatus::Success); fixture.complete(fixture.target,77,CompletionStatus::Success);
    fixture.close();
}

void failed_connection(bool tagged,bool standalone,bool fail_read) {
    RendezvousFixture fixture(standalone);
    fixture.source_host.configure_retry_limit(0); fixture.target_host.configure_retry_limit(0);
    uint16_t responder_pdc=UINT16_MAX;
    fixture.forward.inject=[&](const PDStoNET_pkt& packet) {
        if (fail_read && packet.SESpkt.bth_type==Semantic_Response_with_Data_Header) {
            if (packet.PDS_type==RUOD_req_header) responder_pdc=packet.PDS_header.RUOD_req_header.spdcid;
            if (packet.PDS_type==RUOD_ack_header) responder_pdc=packet.PDS_header.RUOD_ack_header.spdcid;
        }
        if (fail_read && packet.PDS_type==RUOD_cp_header && packet.PDS_header.RUOD_cp_header.ctl_type==Close_req)
            return RendezvousFaultPort::Action::Drop;
        if (!fail_read && packet.PDS_type==RUOD_req_header && packet.SESpkt.bth_type==Standard_Header &&
            !packet.SESpkt.bth_header.Standard_Header.som) return RendezvousFaultPort::Action::Drop;
        return RendezvousFaultPort::Action::Pass;
    };
    fixture.reverse.inject=[&](const PDStoNET_pkt& packet) {
        if (!fail_read && packet.PDS_type==RUOD_ack_header && packet.PDS_header.RUOD_ack_header.spdcid>=MAX_PDC)
            responder_pdc=packet.PDS_header.RUOD_ack_header.spdcid;
        if (!fail_read && packet.PDS_type==RUOD_cp_header && packet.PDS_header.RUOD_cp_header.ctl_type==Close_req)
            return RendezvousFaultPort::Action::Drop;
        if (fail_read && packet.PDS_type==RUOD_req_header && packet.SESpkt.bth_type==Standard_Header) {
            const auto& header=packet.SESpkt.bth_header.Standard_Header;
            if (header.opcode==2 && !header.som) return RendezvousFaultPort::Action::Drop;
        }
        return RendezvousFaultPort::Action::Pass;
    };
    fixture.post(tagged); fixture.source.submit(fixture.operation(tagged,ROD)); fixture.loop.run_until(10000);
    // Local retry exhaustion does not invent a remote cancellation packet.
    // Explicit management closes the responder's stalled PDC too; losing its
    // Close Requests forces the real responder retry-exhaustion event.
    CHECK(responder_pdc!=UINT16_MAX && (fail_read?fixture.source_host:fixture.target_host).request_connection_close(responder_pdc));
    fixture.loop.run(1000000);
    Completion source{},target{};
    const bool source_ready=fixture.source.poll_completion(source),target_ready=fixture.target.poll_completion(target);
    if (!source_ready || !target_ready) {
        std::cerr<<"ready="<<source_ready<<'/'<<target_ready<<" pending="<<fixture.source.pending()<<'/'<<fixture.target.pending()
            <<" target retained="<<fixture.target.retained_receive_messages()<<'/'<<fixture.target.retained_rendezvous_receives()<<'\n';
        for (const auto& event:fixture.trace.events()) if (event.event.find("close")!=std::string::npos ||
            event.event.find("rendezvous")!=std::string::npos || event.event.find("complete")!=std::string::npos)
            std::cerr<<event.time<<" node="<<event.node<<' '<<event.event<<' '<<event.value<<'\n';
    }
    CHECK(source_ready && target_ready && source.context==99 && target.context==77);
    CHECK(source.status!=CompletionStatus::Success && target.status!=CompletionStatus::Success);
    CHECK((fail_read?fixture.reverse.faults:fixture.forward.faults)>0 && target.length<=73);
    fixture.close();
}

void target_closes_before_read(bool tagged,bool standalone) {
    RendezvousFixture fixture(standalone);
    fixture.reverse.inject=[](const PDStoNET_pkt& packet) {
        if (packet.PDS_type==RUOD_req_header && packet.SESpkt.bth_type==Standard_Header &&
            packet.SESpkt.bth_header.Standard_Header.opcode==2) return RendezvousFaultPort::Action::Delay;
        return RendezvousFaultPort::Action::Pass;
    };
    fixture.post(tagged); fixture.source.submit(fixture.operation(tagged,ROD));
    fixture.loop.run_until(10000); CHECK(fixture.target.retained_rendezvous_receives()==1);
    fixture.target.close(); fixture.complete(fixture.target,77,CompletionStatus::Cancelled);
    fixture.loop.run(1000000);
    // ACK_DATA can drain at PDS after the SES handler is detached. Standalone
    // return data still needs that handler's semantic ACK, so its source times
    // out. Both are separate from this target's Cancelled application CQ.
    fixture.complete(fixture.source,99,standalone?CompletionStatus::Timeout:CompletionStatus::Success);
    CHECK(fixture.target.memory().read(1,1,fixture.target_region.key,4,73)==fixture.bytes);
    fixture.close();
}

int main() {
    try {
        for (bool tagged:{false,true}) {
            for (auto mode:{RUD,ROD}) {
                std::array<unsigned,3> order={0,1,2};
                do {
                    stage="FIFO tagged="+std::to_string(tagged)+" mode="+std::to_string(mode)+" order="+
                        std::to_string(order[0])+std::to_string(order[1])+std::to_string(order[2]);
                    shared_arrival_fifo(tagged,mode,order);
                } while (std::next_permutation(order.begin(),order.end()));
            }
            for (bool standalone:{false,true}) {
                stage="normal close tagged="+std::to_string(tagged)+" standalone="+std::to_string(standalone);
                normal_connection_replacement(tagged,standalone);
                for (bool fail_read:{false,true}) {
                    stage="failed connection tagged="+std::to_string(tagged)+" standalone="+std::to_string(standalone)+
                        " read="+std::to_string(fail_read);
                    failed_connection(tagged,standalone,fail_read);
                }
                stage="target close tagged="+std::to_string(tagged)+" standalone="+std::to_string(standalone);
                target_closes_before_read(tagged,standalone);
            }
        }
        std::cout<<"PASS shared SEND/deferrable/rendezvous FIFO, normal/fatal PDC lifetime and target close\n";
    } catch (const std::exception& error) { std::cerr<<stage<<": "<<error.what()<<'\n'; return 1; }
}
