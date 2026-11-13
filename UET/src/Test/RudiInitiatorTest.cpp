#include "Check.hpp"
#include "../PDS/RudiInitiator.hpp"
#include <iostream>
using namespace UET::Runtime;
using UET::PDS::RudiInitiator;

static SES_PDS_req write_request(uint16_t message=9) {
    SES_PDS_req request{}; request.src_fep=1; request.dst_fep=2; request.mode=RUDI;
    request.next_hdr=UET_HDR_REQUEST_STD; request.tx_pkt_handle=message; request.pkt.bth_type=Standard_Header;
    auto& header=request.pkt.bth_header.Standard_Header;
    header.opcode=1; header.job_id=1; header.msg_id=message; header.som=header.eom=1; header.request_length=3;
    request.pkt.payload={1,2,3}; return request;
}
static PDStoNET_pkt response_for(const PDStoNET_pkt& request) {
    PDStoNET_pkt response{}; response.src_fep=request.dst_fep; response.dst_fep=request.src_fep;
    response.PDS_type=RUDI_header;
    response.PDS_header.RUDI_header={RUDI_RESP,UET_HDR_RESPONSE,{0,0},request.PDS_header.RUDI_header.pkt_id};
    response.SESpkt.bth_type=Semantic_Response_Header;
    auto& result=response.SESpkt.bth_header.Semantic_Response_Header;
    const auto& header=request.SESpkt.bth_header.Standard_Header;
    result.opcode=1; result.return_code=1; result.job_id=header.job_id; result.message_id=header.msg_id;
    result.modified_length=header.request_length; return response;
}
static void first_bit_backpressure_and_matching() {
    EventLoop loop; Services services{loop,loop,[] {}};
    bool writable=false; std::vector<PDStoNET_pkt> emitted; std::vector<RudiInitiator::Result> results;
    RudiInitiator initiator(services,[&](const PDStoNET_pkt& packet) {
        if (!writable) return false; emitted.push_back(packet); return true;
    },[&](auto result) { results.push_back(std::move(result)); });
    const auto packet_id=initiator.submit(write_request()); CHECK(packet_id && *packet_id==0);
    CHECK(!loop.pending() && !initiator.progress()); loop.run_until(10*kMillisecond);
    writable=true; CHECK(initiator.progress() && emitted.size()==1 && !loop.pending());
    loop.run_until(20*kMillisecond); CHECK(emitted.size()==1); // NIC has not departed yet.
    const auto identity=*emitted.back().transmit_identity;
    auto stale=identity; ++stale.attempt; CHECK(!initiator.notify_transmit({stale,loop.now(),TransmitOutcome::Started}));
    CHECK(initiator.notify_transmit({identity,loop.now(),TransmitOutcome::Started}));
    CHECK(!initiator.notify_transmit({identity,loop.now(),TransmitOutcome::Started}));
    auto response=response_for(emitted.back());
    auto wrong=response; wrong.src_fep=3; CHECK(!initiator.receive(wrong));
    wrong=response; ++wrong.SESpkt.bth_header.Semantic_Response_Header.job_id; CHECK(!initiator.receive(wrong));
    wrong=response; ++wrong.SESpkt.bth_header.Semantic_Response_Header.message_id; CHECK(!initiator.receive(wrong));
    CHECK(initiator.outstanding_packets()==1 && results.empty());
    CHECK(initiator.receive(response) && !initiator.receive(response));
    CHECK(results.size()==1 && results.front().packet_id==*packet_id && !results.front().timed_out);
    CHECK(!loop.pending() && !initiator.outstanding_packets());
    CHECK(initiator.submit(write_request(10))==1); initiator.cancel_message(2,1,10);
    CHECK(!initiator.active_attempt(*emitted.back().transmit_identity) && !loop.pending());
}
static void recovery(bool negative,bool trimmed,bool resource_delay) {
    EventLoop loop; Services services{loop,loop,[] {}};
    std::vector<PDStoNET_pkt> emitted; std::vector<RudiInitiator::Result> results;
    RudiInitiator initiator(services,[&](const auto& packet) { emitted.push_back(packet); return true; },
        [&](auto result) { results.push_back(std::move(result)); });
    CHECK(initiator.submit(write_request())==0);
    CHECK(initiator.notify_transmit({*emitted.back().transmit_identity,0,TransmitOutcome::Started}));
    Time delay=services.rto_ns;
    if (negative || trimmed) {
        auto indication=response_for(emitted.back()); indication.trimmed=trimmed;
        if (negative) {
            indication.PDS_type=nack_header; auto& nack=indication.PDS_header.nack_header;
            nack.type=NACK; nack.next_hdr=UET_HDR_NONE; nack.flags.nt=1; nack.nack_pkt_id=0;
            nack.nack_code=resource_delay?UET_NO_RESOURCE:UET_TRIMMED;
        }
        delay=resource_delay?services.nack_retransmission_delays_ns[1]:0;
        CHECK(initiator.receive(indication)); CHECK(!initiator.receive(indication));
    }
    if (delay) { loop.run_until(delay-1); CHECK(!initiator.progress() && emitted.size()==1); }
    loop.run_until(delay); CHECK(initiator.progress() && emitted.size()==2);
    CHECK(emitted.back().PDS_header.RUDI_header.flags.retx && emitted.back().PDS_header.RUDI_header.pkt_id==0);
    const auto second=*emitted.back().transmit_identity; CHECK(second.attempt==2);
    CHECK(!initiator.notify_transmit({*emitted.front().transmit_identity,loop.now(),TransmitOutcome::Started}));
    loop.run_until(delay+5*kMillisecond); CHECK(emitted.size()==2); // No timer before retry's actual departure.
    CHECK(initiator.notify_transmit({second,loop.now(),TransmitOutcome::Started}));
    const auto expected_rto=negative || trimmed?services.rto_ns:2*services.rto_ns;
    const auto deadline=loop.now()+expected_rto;
    loop.run_until(deadline-1); CHECK(!initiator.progress() && emitted.size()==2);
    CHECK(initiator.receive(response_for(emitted.back())) && results.size()==1 && !loop.pending());
}
static void budget_and_identity_boundaries() {
    for (uint8_t limit:{uint8_t{0},uint8_t{2},kInfiniteRetryLimit}) {
        EventLoop loop; Services services{loop,loop,[] {}}; services.maximum_packet_retries=limit;
        services.rto_ns=1; services.rudi_packet_limit=1; services.next_rudi_packet_id=UINT32_MAX;
        std::vector<PDStoNET_pkt> emitted; std::vector<RudiInitiator::Result> results;
        RudiInitiator initiator(services,[&](const auto& packet) { emitted.push_back(packet); return true; },
            [&](auto result) { results.push_back(std::move(result)); });
        CHECK(initiator.submit(write_request())==UINT32_MAX); CHECK(!initiator.submit(write_request(10)));
        const unsigned attempts=limit==kInfiniteRetryLimit?18:limit+1;
        for (unsigned attempt=0;attempt<attempts;++attempt) {
            CHECK(initiator.notify_transmit({*emitted.back().transmit_identity,loop.now(),TransmitOutcome::Started}));
            CHECK(loop.run()==1); CHECK(initiator.progress());
        }
        CHECK(emitted.size()==(limit==kInfiniteRetryLimit?attempts+1:attempts));
        CHECK(results.size()==(limit==kInfiniteRetryLimit?0:1));
        if (!results.empty()) CHECK(results.front().timed_out && results.front().message_id==9);
        initiator.clear(); CHECK(!loop.pending() && !initiator.submit(write_request()));
        // Replacing SES/PDS must not wrap a source-wide allocation cursor.
        RudiInitiator replacement(services,[](const auto&) { return true; },[](auto) {});
        CHECK(!replacement.submit(write_request()));
    }
}
int main() {
    try {
        first_bit_backpressure_and_matching(); recovery(false,false,false); recovery(true,false,false);
        recovery(true,false,true); recovery(false,true,false); budget_and_identity_boundaries();
        std::cout<<"PASS8 RUDI initiator first-bit timers, backpressure, tuple/semantic matching, loss indications, budgets and ID exhaustion\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
