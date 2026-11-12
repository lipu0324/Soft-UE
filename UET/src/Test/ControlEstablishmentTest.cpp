#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;
using namespace UET::NetworkLayer;

class OpeningFaultPort : public IPacketPort {
public:
    OpeningFaultPort(IPacketPort& lower,EventLoop& loop,bool source):lower_(lower),loop_(loop),source_(source) {}
    SendResult try_send(const Frame& frame) override {
        const auto packet=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        if (packet.PDS_type==RUOD_cp_header) {
            const auto& header=packet.PDS_header.RUOD_cp_header;
            if (header.ctl_type==Noop || header.ctl_type==Negotiation) {
                CHECK(header.flags.ar && header.flags.pdc_type==(mode==ROD));
                if (!controls++) { CHECK(header.flags.syn && !header.psn_off && !header.flags.retx); first=frame; }
                else CHECK(header.flags.retx && header.psn==1000);
                if (drop_first && controls==1) return SendResult::Accepted;
            } else if (header.ctl_type==Close_cmd) close_times.push_back(loop_.now());
        }
        if (!source_ && packet.PDS_type==RUOD_ack_header && drop_first && !ack_dropped_) {
            ack_dropped_=true; return SendResult::Accepted;
        }
        if (packet.PDS_type==RUOD_req_header) {
            const auto& header=packet.PDS_header.RUOD_req_header;
            CHECK(!header.flags.syn && header.psn==1001 && header.dpdcid>=512);
        }
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
    bool drop_first=false; pdc_mode mode=ROD; size_t controls=0;
    std::optional<Frame> first; std::vector<Time> close_times;
private:
    IPacketPort& lower_; EventLoop& loop_; bool source_,ack_dropped_=false;
};

void control_open(pdc_mode mode,bool negotiation,bool lose_syn,bool lose_ack) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    OpeningFaultPort source_port(forward,loop,true),target_port(reverse,loop,false);
    source_port.mode=target_port.mode=mode; source_port.drop_first=lose_syn; target_port.drop_first=lose_ack;
    PdsHost source_host(1,loop,trace,source_port),target_host(2,loop,trace,target_port);
    Endpoint source(1,source_host,loop,trace),target(2,target_host,loop,trace);
    source.memory().add_job(1); target.memory().add_job(1);
    loop.run_until(10*kMillisecond); // Catch SYN timestamps accidentally left at zero.
    const auto connection=source_host.open_connection(2,1,mode,negotiation);
    CHECK(connection!=UINT16_MAX && source_host.open_connection(2,1,mode,negotiation)==connection);
    loop.run_until(20*kMillisecond);
    CHECK(source_host.manager().hasEstablishedPDC() && target_host.manager().hasEstablishedPDC());
    Completion completion{};
    CHECK(!source.poll_completion(completion) && !target.poll_completion(completion));
    CHECK(target.retained_receive_messages()==0 && source_port.first.has_value());
    const auto& bytes=source_port.first->bytes;
    if (negotiation) {
        // Independently check the fixed 32-byte NO_NEG payload, not just a
        // round trip through the codec. IPv4/native PDS begins at byte 38.
        CHECK(bytes.size()==86);
        CHECK(std::all_of(bytes.begin()+50,bytes.end()-4,[](uint8_t byte) { return byte==0; }));
    } else CHECK(bytes.size()==58);
    const auto region=target.memory().register_region(1,1,8,7);
    Operation write; write.type=OperationType::Write; write.peer=2; write.delivery_mode=mode;
    write.remote_key=region.key; write.payload={1,2,3,4}; source.submit(write);
    loop.run_until(21*kMillisecond);
    CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Success);
    CHECK(target.memory().read(1,1,region.key,0,4)==write.payload);
    CHECK(source_host.request_connection_close(connection)); loop.run(100000);
    CHECK(source_host.manager().getPDSStatus().open_cnt==0 && target_host.manager().getPDSStatus().open_cnt==0);
    CHECK(!source_port.close_times.empty());
    if (lose_syn || lose_ack) CHECK(source_port.close_times.front()>=75*kMillisecond);
    else CHECK(source_port.close_times.front()<22*kMillisecond);
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(loop.pending()==0);
}

struct RawTarget {
    EventLoop loop; Trace trace{loop}; Fabric fabric{loop,trace,42};
    Fabric::Port& source; Fabric::Port& destination; PdsHost host;
    std::vector<PDStoNET_pkt> responses;
    explicit RawTarget():source(fabric.add_host(1)),destination(fabric.add_host(2)),host(2,loop,trace,destination) {
        fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
        source.set_receiver([this](Frame frame) { responses.push_back(UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet); });
    }
    void send(PDStoNET_pkt packet) {
        WireOptions network; network.source.ip[3]=1; network.destination.ip[3]=2;
        network.source.mac[0]=network.destination.mac[0]=2;
        network.source.mac[5]=1; network.destination.mac[5]=2;
        Frame frame; frame.source=1; frame.destination=2; frame.bytes=UetWireCodec::encode(packet,network);
        CHECK(source.try_send(frame)==SendResult::Accepted); loop.run(100000);
    }
    PDStoNET_pkt control(PDS_ctl_type type,uint32_t sequence,uint16_t remote=512,bool syn=false) {
        PDStoNET_pkt packet{}; packet.PDS_type=RUOD_cp_header;
        auto& header=packet.PDS_header.RUOD_cp_header;
        header.type=CP; header.ctl_type=type; header.psn=sequence; header.spdcid=7; header.dpdcid=remote;
        header.flags.syn=syn; header.flags.ar=type!=Clear_cmd && type!=Clear_req;
        return packet;
    }
    void close() { host.close(); CHECK(loop.pending()==0); }
};

void reject_invalid_syn_controls() {
    RawTarget test;
    for (const auto type:{ACK_req,Clear_cmd,Clear_req,Close_cmd,Close_req,Probe,Credit,Credit_req}) {
        test.responses.clear(); test.send(test.control(type,1000,0,true));
        CHECK(test.responses.size()==1 && test.responses[0].PDS_type==nack_header);
        CHECK(test.responses[0].PDS_header.nack_header.nack_code==UET_PDC_HDR_MISMATCH);
        CHECK(test.host.manager().getPDSStatus().open_cnt==0);
    }
    test.close();
}

void acknowledgement_request_states(uint32_t initial_sequence) {
    RawTarget test; size_t delivered=0; std::optional<PDC_SES_req> processing;
    test.host.set_request_handler([&](const PDC_SES_req& request) { ++delivered; processing=request; });
    auto noop=test.control(Noop,initial_sequence,0,true); test.send(noop);
    CHECK(test.responses.size()==1 && test.responses.back().PDS_type==RUOD_ack_header && delivered==0);
    const auto remote=test.responses.back().PDS_header.RUOD_ack_header.spdcid;
    // On-off negotiation is parsed, but unsupported optional features are
    // acknowledged without CP_ACK or any change to the SYN safety owner.
    auto negotiation=test.control(Negotiation,initial_sequence+1,remote);
    negotiation.PDS_header.RUOD_cp_header.payload=0x01020000;
    negotiation.control_extension={0,0,0,1}; test.responses.clear(); test.send(negotiation);
    CHECK(test.responses.size()==1 && test.responses.back().PDS_type==RUOD_ack_header);
    CHECK(test.responses.back().PDS_header.RUOD_ack_header.next_hdr==UET_HDR_NONE);
    PDStoNET_pkt request{}; request.PDS_type=RUOD_req_header;
    auto& transport=request.PDS_header.RUOD_req_header;
    transport.type=RUD_REQ; transport.next_hdr=UET_HDR_REQUEST_STD; transport.psn=initial_sequence+2;
    transport.spdcid=7; transport.dpdcid=remote; transport.clear_psn_off=-1; transport.flags.ar=1;
    request.SESpkt.bth_type=Standard_Header;
    auto& semantic=request.SESpkt.bth_header.Standard_Header;
    semantic.opcode=0; semantic.som=semantic.eom=semantic.dc=semantic.rel=1;
    semantic.msg_id=1; semantic.job_id=1; semantic.PIDonFEP=1; semantic.resource_index=1;
    test.responses.clear(); test.send(request); CHECK(delivered==1 && processing.has_value());
    test.responses.clear(); test.send(test.control(ACK_req,initial_sequence+2,remote));
    CHECK(test.responses.size()==1 && test.responses[0].PDS_header.nack_header.nack_code==UET_RCVD_SES_PROCG);
    test.responses.clear(); test.send(test.control(ACK_req,initial_sequence+3,remote));
    CHECK(test.responses.size()==1 && test.responses[0].PDS_header.nack_header.nack_code==UET_PKT_NOT_RCVD);
    CHECK(test.responses[0].PDS_header.nack_header.payload==initial_sequence+3);
    SES_PDS_rsp response{}; response.PDCID=processing->PDCID; response.rx_pkt_handle=processing->rx_pkt_handle;
    response.rsp_len=12; response.gtd_del=true; response.rsp.bth_type=Semantic_Response_Header;
    auto& header=response.rsp.bth_header.Semantic_Response_Header;
    header.opcode=1; header.return_code=1; header.job_id=1; header.message_id=1;
    CHECK(test.host.manager().pushSESResponse(response)); test.host.wake(); test.loop.run(100000);
    test.responses.clear(); test.send(test.control(ACK_req,initial_sequence+2,remote));
    CHECK(test.responses.size()==1 && test.responses[0].PDS_type==RUOD_ack_header);
    CHECK(test.responses[0].PDS_header.RUOD_ack_header.next_hdr==UET_HDR_RESPONSE);
    // This ACK Request is a new CP, so its replay must reflect RETX=0 even
    // though the response payload comes from the guaranteed-delivery cache.
    CHECK(!test.responses[0].PDS_header.RUOD_ack_header.flags.retx && delivered==1);
    auto retried_query=test.control(ACK_req,initial_sequence+2,remote);
    retried_query.PDS_header.RUOD_cp_header.flags.retx=1;
    test.responses.clear(); test.send(retried_query);
    CHECK(test.responses.size()==1 && test.responses[0].PDS_header.RUOD_ack_header.flags.retx && delivered==1);
    auto clear=test.control(Clear_cmd,0,remote); clear.PDS_header.RUOD_cp_header.payload=initial_sequence+2; test.send(clear);
    test.responses.clear(); test.send(test.control(ACK_req,initial_sequence,remote)); CHECK(test.responses.empty());
    test.close();
}

int main() {
    try {
        for (const auto mode:{ROD,RUD}) for (const bool negotiation:{false,true}) {
            control_open(mode,negotiation,false,false);
            control_open(mode,negotiation,true,true);
        }
        reject_invalid_syn_controls();
        acknowledgement_request_states(1000); acknowledgement_request_states(UINT32_MAX-1);
        std::cout<<"PASS: control-only establishment, fixed NO_NEG layout, SYN loss safety, ACK-request processing/cache/missing/Clear/wrap\n";
        return 0;
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
