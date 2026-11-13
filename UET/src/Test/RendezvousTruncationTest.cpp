#include "RendezvousTestFixture.hpp"

void first_start_truncated(bool tagged) {
    RendezvousFixture fixture; fixture.post(tagged,77,4,72);
    fixture.source.submit(fixture.operation(tagged,ROD)); fixture.loop.run(1000000);
    const auto source=fixture.complete(fixture.source,99,CompletionStatus::RemoteError);
    const auto target=fixture.complete(fixture.target,77,CompletionStatus::Truncated);
    CHECK(source.remote_code==static_cast<uint8_t>(SemanticReturnCode::UnsupportedSize));
    CHECK(!target.length && target.original_length==73 && target.immediate_data==42);
    CHECK(target.tag==(tagged?std::optional<uint64_t>{UINT64_MAX}:std::nullopt));
    CHECK(fixture.target.memory().read(1,1,fixture.target_region.key,0,256)==std::vector<uint8_t>(256));
    fixture.close();
}

void truncated_before_start(bool tagged,bool missing_start=false) {
    RendezvousFixture fixture;
    CHECK(fixture.source_host.open_connection(2,1,RUD)!=UINT16_MAX);
    fixture.loop.run_until(kMillisecond); fixture.post(tagged,77,4,72);
    fixture.forward.inject=[missing_start](const PDStoNET_pkt& packet) {
        if (packet.PDS_type==RUOD_req_header && packet.SESpkt.bth_type==Standard_Header &&
            packet.SESpkt.bth_header.Standard_Header.som)
            return missing_start?RendezvousFaultPort::Action::Drop:RendezvousFaultPort::Action::Delay;
        return RendezvousFaultPort::Action::Pass;
    };
    fixture.source_host.set_response_handler([](const PDC_SES_rsp& response) {
        CHECK(response.pkt.bth_type==Semantic_Response_Header &&
            response.pkt.bth_header.Semantic_Response_Header.return_code==static_cast<uint8_t>(SemanticReturnCode::UnsupportedSize));
    });
    SES_PDS_req request{}; request.src_fep=1; request.dst_fep=2; request.source_pid=1;
    request.mode=RUD; request.next_hdr=UET_HDR_REQUEST_STD; request.rod_context=1; request.lock_pdc=true;
    request.tx_pkt_handle=9; request.pkt.bth_type=Standard_Header; request.pkt.eth_type=Rendezvous_Extension_Header;
    auto& header=request.pkt.bth_header.Standard_Header;
    header.opcode=tagged?10:6; header.som=1; header.dc=1; header.rel=1; header.hd=1;
    header.msg_id=9; header.job_id=1; header.PIDonFEP=1; header.resource_index=1;
    header.initiator=0; header.request_length=73; header.match_bits=tagged?UINT64_MAX:0;
    header.diff.som_true.header_data=42;
    auto& extension=request.pkt.eth_header.Rendezvous_Extension_Header;
    extension.eager_length=32; extension.read_PIDonFEP=1; extension.read_resource_index=1;
    extension.read_mem_key=fixture.source_region.key; extension.read_offset=4;
    request.pkt.payload.assign(16,0xa5); request.pkt_len=84;
    CHECK(fixture.source_host.submit(request));
    header.som=0; header.eom=1; header.diff.som_false.message_offset=16; header.diff.som_false.payload_length=0;
    request.pkt.payload.clear(); request.pkt_len=68; CHECK(fixture.source_host.submit(request));
    fixture.loop.run_until(2*kMillisecond);
    Completion completion{}; CHECK(!fixture.target.poll_completion(completion));
    CHECK(fixture.target.retained_rendezvous_receives()==1);
    if (missing_start) {
        // No header data can be invented when management closes a connection
        // whose SOM never arrived. Keep the original error and publish once.
        fixture.target.close();
        const auto target=fixture.complete(fixture.target,77,CompletionStatus::Truncated);
        CHECK(!target.length && target.original_length==73 && !target.immediate_data);
        fixture.source.close(); fixture.source_host.close(); fixture.target_host.close();
        fixture.loop.run(1000000); fixture.close(); return;
    }
    fixture.loop.run(1000000);
    const auto target=fixture.complete(fixture.target,77,CompletionStatus::Truncated);
    CHECK(!target.length && target.original_length==73 && target.immediate_data==42);
    CHECK(fixture.target.memory().read(1,1,fixture.target_region.key,0,256)==std::vector<uint8_t>(256));
    fixture.close();
}
int main() {
    try {
        for (bool tagged:{false,true}) {
            first_start_truncated(tagged); truncated_before_start(tagged); truncated_before_start(tagged,true);
        }
        std::cout<<"PASS rendezvous truncation retains CQ data with immediate or delayed SOM and never places payload\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
