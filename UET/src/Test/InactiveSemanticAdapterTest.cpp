#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

class BeforeHostDispatchPort final : public IPacketPort {
public:
    explicit BeforeHostDispatchPort(IPacketPort& lower):lower_(lower) {}
    bool provides_transmit_timing() const override { return lower_.provides_transmit_timing(); }
    SendResult try_send(const Frame& frame) override { return lower_.try_send(frame); }
    void set_receiver(Receiver receiver) override {
        if (!receiver) { lower_.set_receiver({}); return; }
        lower_.set_receiver([this,receiver=std::move(receiver)](Frame frame) {
            receiver(std::move(frame));
            if (before_dispatch) { auto callback=std::move(before_dispatch); before_dispatch={}; callback(); }
        });
    }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
    std::function<void()> before_dispatch;
private:
    IPacketPort& lower_;
};

static void accepted_request_survives_owner_close(pdc_mode mode) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& source_port=fabric.add_host(1); BeforeHostDispatchPort target_port(fabric.add_host(2));
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source(1,loop,trace,source_port),target_host(2,loop,trace,target_port);
    source.configure_semantic_payload_mtu(4); source.configure_retransmission_timeout(20*kMillisecond);
    Endpoint target(2,target_host,loop,trace,4); target.memory().add_job(1);
    const auto region=target.memory().register_region(1,1,8,7);
    size_t errors=0;
    source.set_response_handler([&](const PDC_SES_rsp& response) {
        CHECK(response.pkt.bth_type==Semantic_Response_Header);
        const auto& header=response.pkt.bth_header.Semantic_Response_Header;
        CHECK(header.return_code==static_cast<uint8_t>(SemanticReturnCode::Undeliverable) && !header.modified_length); ++errors;
    });
    target_port.before_dispatch=[&] {
        // Drive the same PDS kernel only until admission has accepted the
        // packet. Close SES before Host dispatches its real queued upcall.
        for (size_t step=0;step<1000 && !target_host.manager().getQueueStatus().pdc_to_ses_req_count;++step)
            target_host.manager().progressOne();
        CHECK(target_host.manager().getQueueStatus().pdc_to_ses_req_count==1); target.close();
    };
    SES_PDS_req request{}; request.src_fep=1; request.dst_fep=2; request.source_pid=1;
    request.mode=mode; request.next_hdr=UET_HDR_REQUEST_STD; request.rod_context=1; request.lock_pdc=true;
    request.tx_pkt_handle=9; request.pkt.bth_type=Standard_Header; request.pkt_len=48;
    auto& header=request.pkt.bth_header.Standard_Header;
    header.opcode=1; header.som=header.eom=header.dc=header.rel=1; header.msg_id=9;
    header.job_id=header.PIDonFEP=header.resource_index=1; header.initiator=7;
    header.request_length=4; header.match_bits=region.key; request.pkt.payload.assign(4,0xaa);
    CHECK(source.submit(request)); loop.run_until(kMillisecond);
    if (errors!=1 || target_host.manager().getQueueStatus().pdc_to_ses_req_count)
        throw std::runtime_error("closing SES stranded an already accepted PDS-to-SES request without a replacement");
    CHECK(target.memory().read(1,1,region.key,0,8)==std::vector<uint8_t>(8));
    CHECK(!target_host.services().retired_semantic_receives.size());
    source.close(); target_host.close(); loop.run_until(2*kMillisecond); CHECK(!loop.pending());
}
static SES_PDS_req no_op(pdc_mode mode) {
    SES_PDS_req request{}; request.src_fep=1; request.dst_fep=2; request.source_pid=1;
    request.mode=mode; request.next_hdr=UET_HDR_REQUEST_STD; request.rod_context=1; request.lock_pdc=true;
    request.tx_pkt_handle=9; request.pkt.bth_type=Standard_Header; request.pkt_len=44;
    auto& header=request.pkt.bth_header.Standard_Header;
    header.som=header.eom=header.dc=header.rel=1; header.msg_id=9;
    header.job_id=header.PIDonFEP=header.resource_index=1; header.initiator=7;
    return request;
}
static void undelivered_results_do_not_accumulate(pdc_mode mode) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& source_port=fabric.add_host(1); auto& target_port=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source(1,loop,trace,source_port),target_host(2,loop,trace,target_port);
    Endpoint target(2,target_host,loop,trace); target.memory().add_job(1);
    // A raw source has deliberately removed its SES result consumer. PDS
    // must retire its transport and discard the orphaned local upcall.
    CHECK(source.submit(no_op(mode))); loop.run_until(kMillisecond);
    if (source.manager().getQueueStatus().pdc_to_ses_rsp_count)
        throw std::runtime_error("Host retained a semantic result after its consumer disappeared");
    target.close(); source.close(); target_host.close(); loop.run_until(2*kMillisecond); CHECK(!loop.pending());
}
static void binding_after_a_gap_allows_real_retry(pdc_mode mode,bool congestion) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& source_port=fabric.add_host(1); auto& target_port=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source(1,loop,trace,source_port),target_host(2,loop,trace,target_port);
    if (congestion) { source.enable_nscc({}); target_host.enable_nscc({}); }
    size_t results=0;
    source.set_response_handler([&](const PDC_SES_rsp& response) {
        CHECK(response.pkt.bth_header.Semantic_Response_Header.return_code==static_cast<uint8_t>(SemanticReturnCode::Ok)); ++results;
    });
    CHECK(source.submit(no_op(mode))); loop.run_until(kMillisecond);
    CHECK(!results && !target_host.manager().getQueueStatus().pdc_to_ses_req_count);
    // No request was accepted in the gap. Its later retry must reserve its
    // message with the newly bound SES before it can receive a success ACK.
    Endpoint target(2,target_host,loop,trace); target.memory().add_job(1);
    loop.run_until(10*kMillisecond); CHECK(results==1);
    target.close(); source.close(); target_host.close(); loop.run_until(11*kMillisecond); CHECK(!loop.pending());
}
int main() {
    try {
        for (auto mode:{RUD,ROD}) {
            accepted_request_survives_owner_close(mode); undelivered_results_do_not_accumulate(mode);
            for (bool congestion:{false,true}) binding_after_a_gap_allows_real_retry(mode,congestion);
        }
        std::cout<<"PASS8 absent SES drains accepted handles/results and retries only after new admission\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
