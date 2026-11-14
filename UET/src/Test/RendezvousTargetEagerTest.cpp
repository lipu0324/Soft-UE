#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

// A legal optimistic initiator sends two eager fragments before seeing OK/0.
// Its EOM describes32 constructed bytes, not the advertised64 or accepted0.
// Delay a discarded middle fragment, including its retransmissions, so the
// target must preserve the message's semantic decision until it is processed.
class EagerHolePort final : public IPacketPort {
public:
    EagerHolePort(IPacketPort& lower,EventLoop& loop):lower_(lower),loop_(loop) {}
    SendResult try_send(const Frame& frame) override {
        const auto packet=UET::NetworkLayer::UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        if (packet.PDS_type==RUOD_req_header && packet.SESpkt.bth_type==Standard_Header) {
            const auto& header=packet.SESpkt.bth_header.Standard_Header;
            if ((header.opcode==6 || header.opcode==10) && !header.som && !header.eom &&
                header.diff.som_false.message_offset==16 && loop_.now()<2*kMillisecond) {
                loop_.at(2*kMillisecond,[this,frame] { CHECK(lower_.try_send(frame)==SendResult::Accepted); });
                return SendResult::Accepted;
            }
        }
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
private:
    IPacketPort& lower_; EventLoop& loop_;
};
void optimistic_discarded_hole(bool tagged) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    EagerHolePort forward(fabric.add_host(1),loop); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    source_host.configure_read_ack_data(16); target_host.configure_read_ack_data(16);
    Endpoint source(1,source_host,loop,trace,16),target(2,target_host,loop,trace,16);
    source.memory().add_job(1); target.memory().add_job(1);
    auto storage=std::make_shared<SparseMemory>(81); std::vector<uint8_t> original(73);
    for (uint32_t byte=0;byte<73;++byte) original[byte]=static_cast<uint8_t>(byte*7+3);
    storage->write(4,original.data(),original.size());
    const auto region=source.memory().register_storage(1,1,storage,1);
    const auto destination=target.memory().register_region(1,1,81,7);
    SES_PDS_req packet{}; packet.src_fep=1; packet.dst_fep=2; packet.source_pid=1;
    packet.mode=RUD; packet.next_hdr=UET_HDR_REQUEST_STD; packet.rod_context=1; packet.lock_pdc=true;
    packet.tx_pkt_handle=9; packet.pkt.bth_type=Standard_Header; packet.pkt.eth_type=Rendezvous_Extension_Header;
    auto& header=packet.pkt.bth_header.Standard_Header;
    header.opcode=tagged?10:6; header.som=1; header.dc=1; header.rel=1; header.hd=1;
    header.msg_id=9; header.job_id=1; header.PIDonFEP=1; header.resource_index=1;
    header.initiator=0; header.request_length=73; header.match_bits=tagged?UINT64_MAX:0;
    header.diff.som_true.header_data=42;
    auto& extension=packet.pkt.eth_header.Rendezvous_Extension_Header;
    extension.eager_length=64; extension.read_PIDonFEP=1; extension.read_resource_index=1;
    extension.read_offset=4; extension.read_mem_key=region.key;
    packet.pkt.payload.assign(original.begin(),original.begin()+16); packet.pkt_len=84;
    bool end_sent=false; size_t results=0;
    source_host.set_response_handler([&](const PDC_SES_rsp& response) {
        CHECK(response.pkt.bth_type==Semantic_Response_Header);
        const auto& semantic=response.pkt.bth_header.Semantic_Response_Header;
        CHECK(semantic.return_code==1 && semantic.opcode==1 && semantic.list==1 && !semantic.modified_length);
        ++results;
        if (!end_sent) {
            end_sent=true; auto end=packet;
            auto& final=end.pkt.bth_header.Standard_Header; final.som=0; final.eom=1;
            final.diff.som_false.message_offset=32; final.diff.som_false.payload_length=0;
            end.pkt.payload.clear(); end.pkt_len=68; CHECK(source_host.submit(end));
        }
    });
    CHECK(source_host.submit(packet));
    auto middle=packet; middle.pkt.bth_header.Standard_Header.som=0;
    middle.pkt.bth_header.Standard_Header.diff.som_false.message_offset=16;
    middle.pkt.bth_header.Standard_Header.diff.som_false.payload_length=16;
    middle.pkt.payload.assign(original.begin()+16,original.begin()+32); CHECK(source_host.submit(middle));
    loop.at(kMillisecond,[&] {
        if (tagged) target.post_tagged_receive(1,1,destination.key,4,73,{UINT64_MAX,0,uint32_t{0}},77);
        else target.post_receive(1,1,destination.key,4,73,77,1,uint32_t{0});
    });
    loop.run_until(1500000);
    Completion completion{};
    CHECK(!target.poll_completion(completion)); // Conservative completion waits for the actual wire eager portion.
    loop.run(100000);
    CHECK(target.poll_completion(completion) && completion.context==77 && completion.status==CompletionStatus::Success &&
        completion.length==73 && completion.immediate_data==42 && !target.poll_completion(completion));
    CHECK(results==3 && target.memory().read(1,1,destination.key,4,73)==original);
    CHECK(!target.retained_rendezvous_receives() && !source.retained_receive_messages() && !target.retained_receive_messages());
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(!loop.pending());
}
int main() {
    try { for (bool tagged:{false,true}) optimistic_discarded_hole(tagged);
        std::cout<<"PASS optimistic eager truncation retains its wire length, discarded hole and sticky zero acceptance\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
