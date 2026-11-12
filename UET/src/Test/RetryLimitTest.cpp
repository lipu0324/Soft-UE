#include "Check.hpp"
#include "../PDS/PDC/IPDC.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

class RetrySubject final : public I_PDC {
public:
    using I_PDC::I_PDC;
    void retry(uint32_t sequence,bool timeout) {
        retryPacket(sequence,timeout?RetryCause::Timeout:RetryCause::NegativeAcknowledgment);
    }
    void probe_timeout() { progressProbe(); }
};
PDS_PDC_req request_packet() {
    PDS_PDC_req request{}; request.next_hdr=UET_HDR_REQUEST_STD; request.delivery_mode=RUD;
    request.som=request.eom=true; request.pkt.bth_type=Standard_Header;
    auto& header=request.pkt.bth_header.Standard_Header;
    header.opcode=0; header.som=header.eom=header.dc=1; header.msg_id=1;
    return request;
}
void common_budget(uint8_t limit) {
    EventLoop loop; Services services{loop,loop,[]{}}; services.maximum_packet_retries=limit;
    RetrySubject sender(&services); CHECK(sender.initPDC(1)); sender.state=ESTABLISHED; sender.DPDCID=MAX_PDC;
    auto request=request_packet(); sender.sesTxReq(&request);
    const uint32_t sequence=sender.tx_pkt_q.back().PDS_header.RUOD_req_header.psn;
    sender.tx_pkt_q.pop();
    for (uint64_t attempt=1;attempt<=limit;++attempt) {
        sender.retry(sequence,attempt%2==0);
        CHECK(!sender.close_error && sender.tx_pkt_map.at(sequence).retry_cnt==attempt);
        CHECK(sender.tx_pkt_map.at(sequence).timeout_retry_count==attempt/2);
        CHECK(sender.tx_pkt_q.size()==1 && sender.tx_pkt_q.front().PDS_header.RUOD_req_header.flags.retx);
        sender.tx_pkt_q.pop();
    }
    sender.retry(sequence,false);
    CHECK(sender.close_error && sender.tx_pkt_q.empty() && sender.tx_pkt_map.at(sequence).retry_cnt==limit);
    sender.freePDC(); CHECK(loop.pending()==0);
}
void infinite_budget_and_wide_attempt_identity() {
    EventLoop loop; Services services{loop,loop,[]{}}; services.rto_ns=128;
    services.maximum_packet_retries=kInfiniteRetryLimit; services.actual_transmit_notifications=true;
    RetrySubject sender(&services); CHECK(sender.initPDC(1)); sender.state=ESTABLISHED; sender.DPDCID=MAX_PDC;
    auto request=request_packet(); sender.sesTxReq(&request);
    const auto original=*sender.tx_pkt_q.front().transmit_identity; sender.tx_pkt_q.pop();
    CHECK(sender.notifyTransmit({original,0,TransmitOutcome::Started}));
    for (uint64_t attempt=1;attempt<=32;++attempt) {
        sender.retry(original.sequence,attempt%2==0);
        const auto current=*sender.tx_pkt_q.front().transmit_identity; sender.tx_pkt_q.pop();
        CHECK(!sender.close_error && current.attempt==attempt);
        CHECK(sender.notifyTransmit({current,0,TransmitOutcome::Started}));
        CHECK(sender.tx_pkt_map.at(original.sequence).timeout_retry_count==attempt/2);
    }
    // Cross the old 16-bit boundary without producing 65K equivalent copies.
    // Real retry admission and the NIC's stale-notification check still run.
    sender.tx_pkt_map.at(original.sequence).retry_cnt=UINT16_MAX;
    sender.retry(original.sequence,false);
    const auto wide=*sender.tx_pkt_q.front().transmit_identity; sender.tx_pkt_q.pop();
    CHECK(wide.attempt==65536 && !sender.notifyTransmit({original,0,TransmitOutcome::Started}));
    CHECK(sender.rto_timer_.getActiveTimerCount()==0);
    CHECK(sender.notifyTransmit({wide,0,TransmitOutcome::Started}));
    CHECK(sender.rto_timer_.getActiveTimerCount()==1);
    sender.tx_pkt_map.at(original.sequence).retry_cnt=UINT64_MAX;
    check_throws<std::overflow_error>([&] { sender.retry(original.sequence,false); });
    sender.freePDC(); CHECK(loop.pending()==0);
    CHECK(retry_permitted(UINT64_MAX,kInfiniteRetryLimit));
    CHECK(retransmission_timeout_ns(128,65536)==UINT64_MAX);
}
void probe_budget(uint8_t limit) {
    EventLoop loop; Services services{loop,loop,[]{}}; services.maximum_packet_retries=limit; services.rto_ns=1;
    RetrySubject sender(&services); CHECK(sender.initPDC(1)); sender.SYN=0; sender.state=ESTABLISHED; sender.DPDCID=MAX_PDC;
    CHECK(sender.requestProbe(1000)); sender.tx_pkt_q.pop();
    const uint64_t attempts=limit==kInfiniteRetryLimit?20:limit;
    for (uint64_t attempt=1;attempt<=attempts;++attempt) {
        loop.run(); sender.probe_timeout();
        CHECK(sender.probePending() && !sender.close_error && sender.tx_pkt_q.size()==1);
        CHECK(sender.tx_pkt_q.front().PDS_header.RUOD_cp_header.flags.retx); sender.tx_pkt_q.pop();
    }
    if (limit!=kInfiniteRetryLimit) {
        loop.run(); sender.probe_timeout(); CHECK(!sender.probePending() && sender.tx_pkt_q.empty());
    }
    sender.freePDC(); CHECK(loop.pending()==0);
}
void public_configuration() {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42); auto& port=fabric.add_host(1);
    PdsHost host(1,loop,trace,port); CHECK(host.services().maximum_packet_retries==5);
    for (uint32_t limit=0;limit<=15;++limit) { host.configure_retry_limit(limit); CHECK(host.services().maximum_packet_retries==limit); }
    for (const auto invalid:{16u,256u,UINT32_MAX})
        check_throws<std::invalid_argument>([&] { host.configure_retry_limit(invalid); });
    host.services().maximum_packet_retries=16;
    RetrySubject invalid(&host.services()); CHECK(!invalid.initPDC(1));
    host.configure_retry_limit(0);
    Endpoint endpoint(1,host,loop,trace); endpoint.memory().add_job(1);
    Operation noop; noop.type=OperationType::Noop; noop.peer=2; endpoint.submit(noop); loop.run_until(0);
    check_throws<std::logic_error>([&] { host.configure_retry_limit(5); });
    endpoint.close(); host.close(); CHECK(loop.pending()==0);
    check_throws<std::logic_error>([&] { host.configure_retry_limit(5); });
}
int main() {
    try {
        for (uint8_t limit=0;limit<kInfiniteRetryLimit;++limit) common_budget(limit);
        infinite_budget_and_wide_attempt_identity();
        for (const uint8_t limit:{0,2,15}) probe_budget(limit);
        public_configuration();
        std::cout<<"PASS common retry limits, infinite setting, wide identities and Probe policy\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
