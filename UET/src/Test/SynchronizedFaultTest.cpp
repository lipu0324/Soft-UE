#include "SynchronizedTestFixture.hpp"

void packet_fault(unsigned fault,pdc_mode mode,bool congestion,bool atomic) {
    SynchronizedFixture fixture(congestion); bool applied=false;
    const auto inject=[&](bool reverse,const PDStoNET_pkt& packet) {
        using Action=SynchronizedFaultPort::Action;
        if (applied) return Action::Pass;
        if (!reverse && packet.PDS_type==RUOD_req_header && packet.SESpkt.bth_type==Standard_Header) {
            const auto& header=packet.SESpkt.bth_header.Standard_Header;
            if (header.opcode==0x10 && !header.hd) {
                if (fault==0 && header.som) { applied=true; return Action::Drop; }
                if (fault==1 && header.som) { applied=true; return Action::Duplicate; }
                if (fault==2 && !header.som && !header.eom) { applied=true; return Action::Delay; }
                if (fault==3 && header.eom) { applied=true; return Action::Drop; }
            }
            if (fault==4 && (header.opcode==0x11 || header.hd) && header.som) { applied=true; return Action::Drop; }
        }
        if (reverse && packet.PDS_type==RUOD_ack_header && !packet.PDS_header.RUOD_ack_header.flags.p &&
            packet.SESpkt.bth_type==Semantic_Response_Header) {
            const auto& semantic=packet.SESpkt.bth_header.Semantic_Response_Header;
            if ((fault==5 && semantic.message_id==3) || (fault==6 && semantic.message_id==1)) {
                applied=true; return Action::Drop;
            }
        }
        if (fault==7 && !reverse && packet.PDS_type==RUOD_cp_header && packet.PDS_header.RUOD_cp_header.ctl_type==Clear_cmd) {
            applied=true; return Action::Drop;
        }
        return Action::Pass;
    };
    fixture.forward.inject=[&](const auto& packet) { return inject(false,packet); };
    fixture.reverse.inject=[&](const auto& packet) { return inject(true,packet); };
    const auto group=fixture.source.begin_synchronized_group(2,1,3);
    fixture.source.submit(fixture.write(group,mode,0,73)); fixture.source.submit(fixture.write(group,mode,96,17));
    fixture.source.submit(fixture.completing(group,mode,atomic)); fixture.loop.run(1000000);
    CHECK(applied && fixture.forward.faults+fixture.reverse.faults==1);
    Completion completion{}; std::set<uint64_t> identifiers;
    while (fixture.source.poll_completion(completion)) {
        CHECK(completion.status==CompletionStatus::Success && identifiers.insert(completion.operation).second && !completion.receive);
    }
    CHECK(identifiers.size()==3);
    if (!atomic) CHECK(fixture.target.poll_completion(completion) && completion.status==CompletionStatus::Success && completion.immediate_data==42);
    CHECK(!fixture.target.poll_completion(completion));
    CHECK(fixture.target.memory().read(1,1,fixture.destination.key,0,73)==std::vector<uint8_t>(73,0x35));
    CHECK(fixture.target.memory().read(1,1,fixture.destination.key,96,17)==std::vector<uint8_t>(17,0x35));
    CHECK(fixture.target.memory().read(1,1,fixture.destination.key,128,atomic?8:3)==
        (atomic?std::vector<uint8_t>{5,0,0,0,0,0,0,0}:std::vector<uint8_t>(3,0x35)));
    fixture.drained(); fixture.close();
}
void generation_recovery(pdc_mode mode,bool disabled,bool atomic) {
    SynchronizedFixture fixture;
    fixture.target.resources().configure_resource(1,1,ResourceSpace::Rma,9);
    if (disabled) {
        fixture.target.resources().disable_for_exhaustion(1,1,ResourceSpace::Rma);
        fixture.loop.at(3*kMillisecond,[&] { CHECK(fixture.target.resources().recover_after_exhaustion(1,1,ResourceSpace::Rma,9)); });
    }
    std::set<uint16_t> messages;
    fixture.fabric.set_capture([&](Time,const Frame& frame) {
        if (frame.source!=1) return;
        const auto packet=UET::NetworkLayer::UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        if (packet.PDS_type==RUOD_req_header && packet.SESpkt.bth_type==Standard_Header && packet.SESpkt.bth_header.Standard_Header.som)
            messages.insert(packet.SESpkt.bth_header.Standard_Header.msg_id);
    });
    const auto group=fixture.source.begin_synchronized_group(2,1,3);
    fixture.source.submit(fixture.completing(group,mode,atomic));
    fixture.source.submit(fixture.write(group,mode,0,73)); fixture.source.submit(fixture.write(group,mode,96,17));
    fixture.loop.run(1000000);
    Completion completion{}; std::set<uint64_t> identifiers;
    while (fixture.source.poll_completion(completion)) {
        CHECK(completion.status==CompletionStatus::Success && completion.remote_generation==(disabled?10:9) &&
            identifiers.insert(completion.operation).second);
    }
    CHECK(identifiers.size()==3 && messages.size()>3);
    if (!atomic) CHECK(fixture.target.poll_completion(completion) && completion.status==CompletionStatus::Success);
    CHECK(!fixture.target.poll_completion(completion)); fixture.drained(); fixture.close();
}
int main() {
    try {
        for (unsigned fault=0;fault<8;++fault) for (auto mode:{RUD,ROD}) for (bool congestion:{false,true})
            for (bool atomic:{false,true}) packet_fault(fault,mode,congestion,atomic);
        for (auto mode:{RUD,ROD}) for (bool disabled:{false,true}) for (bool atomic:{false,true}) {
            try { generation_recovery(mode,disabled,atomic); }
            catch (...) { std::cerr<<"recovery mode="<<mode<<" disabled="<<disabled<<" atomic="<<atomic<<'\n'; throw; }
        }
        std::cout<<"PASS64 synchronized packet faults and8 generation/disabled recovery transactions\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
