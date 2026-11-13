#include "Check.hpp"
#include "../SES/Endpoint.hpp"
#include "../Runtime/Fabric.hpp"
#include <iostream>

using namespace UET::Runtime;
using namespace UET::NetworkLayer;
using namespace UET::SES;

class DelayedReadDataPort final : public IPacketPort {
public:
    DelayedReadDataPort(IPacketPort& lower,EventLoop& loop):lower_(lower),loop_(loop) {}
    SendResult try_send(const Frame& frame) override {
        const auto packet=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        if (packet.PDS_type==RUOD_req_header && packet.SESpkt.bth_type==Semantic_Response_with_Data_Header &&
            (delay_all || !delayed_first)) {
            delayed_first=true;
            loop_.after(200000,[this,frame] { CHECK(lower_.try_send(frame)==SendResult::Accepted); });
            return SendResult::Accepted;
        }
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver callback) override { lower_.set_receiver(std::move(callback)); }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
    bool delay_all=true,delayed_first=false;
private:
    IPacketPort& lower_; EventLoop& loop_;
};

// An independent SES policy allowed by §3.5.20.2.2: accept each forward READ
// before return data has been acknowledged. Both peers still use the actual
// PDS kernel. This fixture does not forge an ACK behind unfinished PDS state.
class EarlyReadTarget {
public:
    explicit EarlyReadTarget(PdsHost& host):host_(host) {
        memory.add_job(1); region=memory.register_region(1,1,65536,Access::Read|Access::Write);
        host_.set_request_handler([this](const PDC_SES_req& request) {
            CHECK(request.pkt.bth_type==Standard_Header);
            const auto& header=request.pkt.bth_header.Standard_Header;
            if (header.opcode==0 || header.opcode==0x0f) { accept(request); return; }
            CHECK(header.opcode==2 && request.pkt.payload.empty());
            ++read_requests;
            const uint32_t offset=header.som?0:header.diff.som_false.message_offset;
            const auto count=std::min<uint32_t>(1024,header.request_length-offset);
            auto bytes=memory.read(header.job_id,1,header.match_bits,header.buffer_offset+offset,count);
            accept(request);
            SEStoPDS_pkt packet{}; packet.bth_type=Semantic_Response_with_Data_Header;
            auto& data=packet.bth_header.Semantic_Response_with_Data_Header;
            data.opcode=2; data.return_code=1; data.job_id=header.job_id;
            data.read_request_msg_id=header.msg_id; data.response_message_id=++next_token_;
            data.payload_length=count; data.modified_length=header.request_length; data.message_offset=offset;
            packet.payload=std::move(bytes);
            CHECK(host_.submit_return_data(request,packet));
        });
        host_.set_response_handler([this](const PDC_SES_rsp& response) {
            CHECK(response.pkt.bth_type==Semantic_Response_Header &&
                response.pkt.bth_header.Semantic_Response_Header.return_code==1);
            ++return_results;
        });
    }
    ~EarlyReadTarget() { host_.set_request_handler({}); host_.set_response_handler({}); }
    MemoryRegistry memory;
    Region region;
    size_t read_requests=0,return_results=0;
private:
    PdsHost& host_;
    uint16_t next_token_=0;
    void accept(const PDC_SES_req& request) {
        SES_PDS_rsp result{}; result.PDCID=request.PDCID; result.rx_pkt_handle=request.rx_pkt_handle;
        result.rsp_len=12; result.rsp=UET::PDS::default_semantic_response(request.pkt);
        CHECK(host_.manager().pushSESResponse(result)); host_.wake();
    }
};

void bounded_source(pdc_mode mode,size_t result_window) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); DelayedReadDataPort reverse(fabric.add_host(2),loop);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    Endpoint source(1,source_host,loop,trace,1024,100*kMillisecond,nullptr,8,4096,256*1024,8,result_window);
    source.memory().add_job(1); const auto destination=source.memory().register_region(1,1,65536,Access::Read|Access::Write);
    EarlyReadTarget target(target_host);
    std::vector<uint8_t> expected(32771); for (size_t index=0;index<expected.size();++index) expected[index]=index*3+9;
    target.memory.write(1,1,target.region.key,0,expected);
    Operation read; read.type=OperationType::Read; read.peer=2; read.delivery_mode=mode;
    read.remote_key=target.region.key; read.read_length=expected.size();
    read.read_result=ReadResultBuffer{destination.key,0,static_cast<uint32_t>(expected.size()),1,1};
    const auto operation=source.submit(read);
    loop.run_until(10000); Completion completion{};
    CHECK(!source.poll_completion(completion));
    CHECK(target.read_requests==result_window && source.pending_read_results()==result_window && source.queued_fragments()==0);
    loop.run(1000000);
    CHECK(source.poll_completion(completion) && completion.operation==operation && completion.status==CompletionStatus::Success);
    CHECK(completion.length==expected.size() && !source.poll_completion(completion));
    CHECK(source.memory().read(1,1,destination.key,0,expected.size())==expected);
    CHECK(source.pending_read_results()==0 && source.leased_message_ids()==0 && target.read_requests==33 && target.return_results==33);
    source.close(); source_host.close(); target_host.close(); CHECK(loop.pending()==0);
}

void cancelled_mid_waits_for_retirement(pdc_mode mode,bool before_transmit,bool source_resources_unavailable) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); DelayedReadDataPort reverse(fabric.add_host(2),loop); reverse.delay_all=false;
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    Endpoint source(1,source_host,loop,trace);
    source.memory().add_job(1); const auto destination=source.memory().register_region(1,1,1024,Access::Read|Access::Write);
    EarlyReadTarget target(target_host);
    const std::vector<uint8_t> expected(17,0x7a); target.memory.write(1,1,target.region.key,0,expected);
    Operation read; read.type=OperationType::Read; read.peer=2; read.delivery_mode=mode;
    read.remote_key=target.region.key; read.read_length=17; read.read_result=ReadResultBuffer{destination.key,0,17,1,1};
    if (source_resources_unavailable) source_host.services().initiator_context_limit=0;
    const auto first=source.submit(read);
    if (!before_transmit) loop.run_until(10000);
    CHECK(source.cancel_read(first)); Completion completion{};
    CHECK(source.poll_completion(completion) && completion.operation==first && completion.status==CompletionStatus::Cancelled);
    CHECK(source.transport_pending(first) && source.leased_message_ids()==1);
    if (!source_resources_unavailable) {
        read.read_result->offset=256;
        const auto next=source.submit(read);
        loop.run_until(100000);
        // §3.5.8.3 makes Close an implicit ACK for the entire return direction.
        // Once that incarnation is retired, this MID can be released even
        // before the delayed old frame reaches the new incarnation.
        CHECK(!source.transport_pending(first));
        loop.run(1000000);
        CHECK(source.poll_completion(completion) && completion.operation==next && completion.status==CompletionStatus::Success);
        CHECK(source.memory().read(1,1,destination.key,256,17)==expected);
    } else loop.run(1000000); // Pending-request rejection uses an unassigned (UINT16_MAX) PDC, not a target PDC.
    CHECK(!source.transport_pending(first) && source.leased_message_ids()==0 && !source.poll_completion(completion));
    CHECK(source.memory().read(1,1,destination.key,0,17)==std::vector<uint8_t>(17));
    source.close(); source_host.close(); target_host.close(); CHECK(loop.pending()==0);
}

int main() {
    try {
        for (const auto mode:{RUD,ROD}) {
            for (const size_t window:{1,2,8}) bounded_source(mode,window);
            cancelled_mid_waits_for_retirement(mode,false,false);
            cancelled_mid_waits_for_retirement(mode,true,false);
            cancelled_mid_waits_for_retirement(mode,true,true);
        }
        std::cout<<"PASS: independent early READ acceptance, bounded source results and cancelled MID retirement\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
