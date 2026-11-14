#include "RendezvousTestFixture.hpp"

// Script only SES fields. Production PDS still establishes contexts, assigns
// packet sequence numbers, retransmits responses and performs Clear.
void rejected_target(unsigned scenario,bool tagged,bool continuation) {
    RendezvousFixture fixture;
    SES_PDS_req request{}; request.src_fep=1; request.dst_fep=2; request.source_pid=1;
    request.mode=RUD; request.next_hdr=UET_HDR_REQUEST_STD; request.rod_context=1; request.lock_pdc=true;
    request.tx_pkt_handle=9; request.pkt.bth_type=Standard_Header; request.pkt.eth_type=Rendezvous_Extension_Header;
    auto& header=request.pkt.bth_header.Standard_Header;
    header.opcode=tagged?10:6; header.som=1; header.eom=!continuation;
    header.dc=1; header.rel=1; header.hd=1; header.msg_id=9; header.job_id=1;
    header.PIDonFEP=1; header.resource_index=1; header.initiator=0;
    header.request_length=73; header.match_bits=tagged?UINT64_MAX:0; header.diff.som_true.header_data=42;
    auto& extension=request.pkt.eth_header.Rendezvous_Extension_Header;
    extension.eager_length=32; extension.read_PIDonFEP=1; extension.read_resource_index=1;
    extension.read_offset=4; extension.read_mem_key=fixture.source_region.key;
    request.pkt.payload.assign(fixture.bytes.begin(),fixture.bytes.begin()+16); request.pkt_len=84;
    size_t successes=0,errors=0;
    fixture.source_host.set_response_handler([&](const PDC_SES_rsp& response) {
        CHECK(response.pkt.bth_type==Semantic_Response_Header);
        const auto& semantic=response.pkt.bth_header.Semantic_Response_Header;
        if (semantic.return_code==1) ++successes; else ++errors;
    });
    if (continuation) {
        CHECK(fixture.source_host.submit(request)); fixture.loop.run_until(2*kMillisecond);
        CHECK(successes==1 && !errors && fixture.target.retained_rendezvous_receives()==1);
        header.som=0; header.eom=1; header.diff.som_false.message_offset=16; header.diff.som_false.payload_length=0;
        request.pkt.payload.clear(); request.pkt_len=68;
        switch (scenario) {
        case 0: ++extension.eager_length; break;
        case 1: ++extension.read_PIDonFEP; break;
        case 2: ++extension.read_resource_index; break;
        case 3: ++extension.read_ri_generation; break;
        case 4: ++extension.read_offset; break;
        case 5: ++extension.read_mem_key; break;
        case 6: ++header.request_length; break;
        case 7: ++header.PIDonFEP; break;
        case 8: ++header.resource_index; break;
        case 9: ++header.ri_generation; break;
        case 10: header.rel=0; break;
        case 11: header.opcode=tagged?6:10; break;
        case 12: header.hd=0; break;
        case 13: header.diff.som_false.message_offset=33; break;
        case 14: header.diff.som_false.payload_length=1; break;
        case 15: header.opcode=0xf; request.pkt_len=44; break; // MSG_ERROR has no extension on wire.
        case 16: header.match_bits=0; break; // Tagged-only inconsistent tag.
        }
    } else {
        switch (scenario) {
        case 0: header.version=1; break;
        case 1: header.ie=1; break;
        case 2: extension.eager_length=74; break;
        case 3: extension.read_offset=UINT64_MAX; break;
        case 4: extension.eager_length=8; break;
        }
    }
    CHECK(fixture.source_host.submit(request)); fixture.loop.run(1000000);
    CHECK(errors>=1 && successes==size_t(continuation));
    CHECK(!fixture.target.retained_rendezvous_receives() && !fixture.target.retained_receive_messages());
    CHECK(fixture.target.memory().read(1,1,fixture.target_region.key,0,256)==std::vector<uint8_t>(256));
    fixture.close();
}

void rejected_source_result(unsigned scenario,bool tagged) {
    RendezvousFixture fixture; size_t eager_packets=0;
    fixture.target_host.set_receive_admission([](const PDC_SES_req&) {
        return SemanticAdmission::ExistingMessage;
    },[](const PDC_SES_req&) {});
    fixture.target_host.set_request_handler([&](const PDC_SES_req& request) {
        const auto& header=request.pkt.bth_header.Standard_Header;
        SES_PDS_rsp response{}; response.PDCID=request.PDCID; response.rx_pkt_handle=request.rx_pkt_handle;
        response.rsp_len=12; response.gtd_del=true; response.rsp.bth_type=Semantic_Response_Header;
        auto& semantic=response.rsp.bth_header.Semantic_Response_Header;
        semantic.job_id=header.job_id; semantic.message_id=header.msg_id; semantic.return_code=1;
        if (header.opcode==6 || header.opcode==10) {
            ++eager_packets;
            if (scenario==0 || scenario==1) {
                semantic.opcode=1; semantic.modified_length=UINT32_MAX;
                if (scenario==1) semantic.return_code=static_cast<uint8_t>(SemanticReturnCode::BadAddress);
            } else if (header.eom) { semantic.opcode=1; semantic.list=1; }
        }
        CHECK(fixture.target_host.manager().pushSESResponse(response)); fixture.target_host.wake();
    });
    fixture.source.submit(fixture.operation(tagged,ROD,99,4,16)); fixture.loop.run(1000000);
    const auto completion=fixture.complete(fixture.source,99,CompletionStatus::RemoteError);
    if (completion.remote_code!=static_cast<uint8_t>(SemanticReturnCode::OperationViolation) || completion.length)
        std::cerr<<"source result scenario="<<scenario<<" code="<<unsigned(completion.remote_code)<<" length="<<completion.length<<'\n';
    CHECK(completion.remote_code==static_cast<uint8_t>(SemanticReturnCode::OperationViolation) && !completion.length);
    CHECK(eager_packets>=1); fixture.close();
}

int main() {
    try {
        for (bool tagged:{false,true}) {
            // The wire decoder rejects unsupported versions before SES.
            for (unsigned scenario=1;scenario<5;++scenario) rejected_target(scenario,tagged,false);
            for (unsigned scenario=0;scenario<(tagged?17u:16u);++scenario) rejected_target(scenario,tagged,true);
            for (unsigned scenario=0;scenario<3;++scenario) rejected_source_result(scenario,tagged);
        }
        std::cout<<"PASS malformed rendezvous initial/continuation fields, MSG_ERROR and inconsistent semantic results\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
