#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../Runtime/PdsHost.hpp"
#include <iostream>
using namespace UET::Runtime;

// An independent SES consumer of the original PDS API. Network progress is
// automatic, but the test intentionally leaves accepted SES upcalls queued.
// It does not implement ACKs, recovery, PSN allocation or context teardown.
class DelayedSemanticPeer {
public:
    DelayedSemanticPeer(EventLoop& loop,IPacketPort& port)
        : loop_(loop),port_(port),services_{loop,loop,[this] { wake(); }},manager_(&services_) {
        services_.target_context_limit=1; services_.maximum_packet_retries=0;
        CHECK(manager_.start());
        port_.set_receiver([this](Frame frame) {
            auto decoded=UET::NetworkLayer::UetWireCodec::decode(frame.bytes.data(),frame.bytes.size());
            network_.source=decoded.network.destination; network_.destination=decoded.network.source;
            auto packet=std::move(decoded.packet); packet.src_fep=frame.source; packet.dst_fep=frame.destination;
            if (packet.PDS_type==RUOD_req_header && !packet.PDS_header.RUOD_req_header.flags.retx)
                sequences.push_back(packet.PDS_header.RUOD_req_header.psn);
            CHECK(manager_.pushNetworkPacket(packet)); wake();
        });
    }
    ~DelayedSemanticPeer() { close(); }
    PDSProcessManager& manager() { return manager_; }
    bool request_close(uint16_t local_pdc) {
        if (!manager_.requestConnectionClose(local_pdc)) return false;
        wake(); return true;
    }
    void reply(const PDC_SES_req& request) {
        SES_PDS_rsp response{}; response.PDCID=request.PDCID; response.rx_pkt_handle=request.rx_pkt_handle;
        response.gtd_del=true; response.rsp_len=12; response.rsp=UET::PDS::default_semantic_response(request.pkt);
        CHECK(manager_.pushSESResponse(response)); wake();
    }
    void close() {
        if (closed_) return;
        closed_=true; if (scheduled_) loop_.cancel(scheduled_); scheduled_=0;
        port_.set_receiver({}); manager_.stop();
    }
    std::vector<uint32_t> sequences;
private:
    void wake() {
        if (closed_ || scheduled_) return;
        scheduled_=loop_.at(loop_.now(),[this] { scheduled_=0; pump(); });
    }
    void pump() {
        for (size_t step=0;step<256;++step) {
            bool worked=manager_.progressOne(); PDStoNET_pkt packet{};
            while (manager_.popNetworkPacket(packet)) {
                Frame frame; frame.source=packet.src_fep; frame.destination=packet.dst_fep;
                frame.bytes=UET::NetworkLayer::UetWireCodec::encode(packet,network_);
                CHECK(port_.try_send(frame)==SendResult::Accepted); worked=true;
            }
            if (!worked) return;
        }
        wake();
    }
    EventLoop& loop_; IPacketPort& port_; Services services_; PDSProcessManager manager_;
    UET::NetworkLayer::WireOptions network_; TimerId scheduled_=0; bool closed_=false;
};
static void stale_queue_does_not_cross_context_reuse(pdc_mode mode) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& source_port=fabric.add_host(1); auto& target_port=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source(1,loop,trace,source_port); source.configure_retry_limit(0);
    source.services().initiator_context_limit=1; DelayedSemanticPeer target(loop,target_port);
    size_t results=0; source.set_response_handler([&](const PDC_SES_rsp&) { ++results; });
    SES_PDS_req request{}; request.src_fep=1; request.dst_fep=2; request.source_pid=1;
    request.mode=mode; request.next_hdr=UET_HDR_REQUEST_STD; request.rod_context=1; request.lock_pdc=true;
    request.tx_pkt_handle=8; request.pkt.bth_type=Standard_Header; request.pkt_len=44;
    auto& header=request.pkt.bth_header.Standard_Header;
    header.som=header.eom=header.dc=header.rel=1; header.msg_id=8;
    header.job_id=header.PIDonFEP=header.resource_index=1; header.initiator=7;
    // Complete the SYN normally before testing retry exhaustion on this
    // established context; lost-SYN safety time is a separate lifecycle.
    CHECK(source.submit(request)); loop.run_until(100000);
    PDC_SES_req accepted{}; CHECK(target.manager().popSESRequest(accepted)); target.reply(accepted);
    loop.run_until(200000); CHECK(results==1);
    header.msg_id=9; request.tx_pkt_handle=9; CHECK(source.submit(request));
    loop.run_until(2*kMillisecond); CHECK(!source.manager().getPDSStatus().open_cnt && results==1);
    CHECK(target.manager().getQueueStatus().pdc_to_ses_req_count==1);
    CHECK(target.request_close(MAX_PDC));
    // The target's first numbered reverse packet is this Close Request.
    // Preserve the plaintext lost-SYN safety interval before reusing its ID.
    const auto retirement_time=80*kMillisecond; loop.run_until(retirement_time);
    CHECK(!target.manager().getPDSStatus().open_cnt);
    CHECK(source.submit(request)); loop.run_until(retirement_time+100000);
    CHECK(target.sequences.size()==3 && target.manager().getQueueStatus().pdc_to_ses_req_count==2);
    CHECK(target.manager().popSESRequest(accepted));
    if (accepted.orig_psn==target.sequences[1])
        throw std::runtime_error("PDS delivered a retired context's queued receive after the same PDC ID was reused");
    CHECK(accepted.PDCID==MAX_PDC && accepted.orig_psn==target.sequences[2]);
    CHECK(!target.manager().getQueueStatus().pdc_to_ses_req_count); target.reply(accepted);
    loop.run_until(retirement_time+kMillisecond); CHECK(results==2);
    source.close(); target.close(); loop.run_until(retirement_time+2*kMillisecond); CHECK(!loop.pending());
}
int main() {
    try {
        for (auto mode:{RUD,ROD}) stale_queue_does_not_cross_context_reuse(mode);
        std::cout<<"PASS2 retired queued SES requests are filtered before delivery after real PDC reuse\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
