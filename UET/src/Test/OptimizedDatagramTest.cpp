#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

class MediumDatagramPort final : public IPacketPort {
public:
    MediumDatagramPort(IPacketPort& lower,EventLoop& loop,UET::NetworkLayer::WireOptions options,bool discard)
        :lower_(lower),loop_(loop),options_(options),discard_(discard) {}
    bool provides_transmit_timing() const override { return lower_.provides_transmit_timing(); }
    SendResult try_send(const Frame& frame) override {
        const auto decoded=UET::NetworkLayer::UetWireCodec::decode(frame.bytes.data(),frame.bytes.size(),options_.crc,253);
        CHECK(decoded.packet.PDS_type==UUD_req_header && decoded.packet.SESpkt.bth_type==Small_Message_RMA_Header);
        const auto& header=decoded.packet.SESpkt.bth_header.Small_Message_RMA_Header;
        CHECK(header.opcode==7 && !header.dc && header.som && header.eom && header.initiator==0x12345678);
        const size_t transport=14+(options_.ipv6?40:20)+(options_.udp?8:4);
        // §3.5.10.14: UUD type6, MEDIUM next_hdr2, no connection/PSN.
        CHECK(std::vector<uint8_t>(frame.bytes.begin()+transport,frame.bytes.begin()+transport+4)==
            std::vector<uint8_t>({0x31,0x00,0x00,0x00}));
        CHECK(frame.bytes[transport+4]==7 && frame.bytes[transport+5]==(header.hd?0x0f:0x0b));
        ++sent;
        if (!discard_) return lower_.try_send(frame);
        if (frame.transmission_event) frame.transmission_event(loop_.now(),TransmitOutcome::Started);
        return SendResult::Accepted;
    }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable handler) override { lower_.set_writable_handler(std::move(handler)); }
    size_t sent=0;
private:
    IPacketPort& lower_; EventLoop& loop_; UET::NetworkLayer::WireOptions options_; bool discard_;
};

static void datagram(bool congestion,bool discard,bool posted,bool header_data,uint32_t length,
                     bool ipv6,bool udp,bool crc) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    UET::NetworkLayer::WireOptions network; network.ipv6=ipv6; network.udp=udp; network.crc=crc; network.native_ip_protocol=253;
    MediumDatagramPort forward(fabric.add_host(1),loop,network,discard);
    auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward,PdsHost::WireFormat::Uet11,network),
        target_host(2,loop,trace,reverse,PdsHost::WireFormat::Uet11,network);
    if (congestion) { source_host.enable_nscc({}); target_host.enable_nscc({}); }
    Endpoint source(1,source_host,loop,trace,64),target(2,target_host,loop,trace,64);
    CHECK(source.capabilities().optimized_medium_datagram_send);
    source.memory().add_job(1); target.memory().add_job(1);
    target.resources().configure_resource(1,1,ResourceSpace::Send,7);
    RegionOptions options; options.local_placement_only=true;
    const auto destination=target.memory().register_region(1,1,64,static_cast<uint8_t>(Access::Write),options);
    if (posted) target.post_receive(1,1,destination.key,0,64,99,1,0x12345678);
    Operation operation; operation.type=OperationType::DatagramSend; operation.header_format=RequestHeaderFormat::Medium;
    operation.peer=2; operation.delivery_mode=UUD; operation.initiator_id=0x12345678; operation.target_generation=7;
    operation.context=77; operation.payload.assign(length,0x71); if (header_data) operation.immediate_data=0;
    const auto identifier=source.submit(operation); loop.run_until(2*kMillisecond);
    Completion completion{};
    if (!source.poll_completion(completion) || completion.status!=CompletionStatus::LocalSuccess)
        throw std::runtime_error("MEDIUM datagram failed local completion: status="+std::to_string(unsigned(completion.status)));
    CHECK(completion.operation==identifier && completion.context==77 && completion.length==length && !source.poll_completion(completion));
    CHECK(forward.sent==1 && !source.pending() && !source.leased_message_ids());
    CHECK(!source_host.manager().getPDSStatus().open_cnt && !target_host.manager().getPDSStatus().open_cnt);
    CHECK(!source.retained_receive_messages() && !target.retained_receive_messages());
    const bool delivered=!discard && posted;
    CHECK(target.poll_completion(completion)==delivered);
    if (delivered) CHECK(completion.receive && completion.context==99 && completion.length==length &&
        completion.immediate_data==(header_data?std::optional<uint64_t>{0}:std::nullopt));
    CHECK(!target.poll_completion(completion));
    std::vector<uint8_t> actual(64); destination.storage->read(0,actual.data(),actual.size());
    std::vector<uint8_t> expected(64); if (delivered) std::fill_n(expected.begin(),length,0x71);
    CHECK(actual==expected && fabric.stats(2,1).packets==0);
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(!loop.pending());
}

int main() {
    try {
        size_t scenarios=0;
        for (bool congestion:{false,true}) for (bool discard:{false,true}) for (bool posted:{false,true})
            for (bool header_data:{false,true}) for (uint32_t length:{0u,1u,64u})
                for (bool ipv6:{false,true}) for (bool udp:{false,true}) for (bool crc:{false,true}) {
                    datagram(congestion,discard,posted,header_data,length,ipv6,udp,crc); ++scenarios;
                }
        CHECK(scenarios==384);
        std::cout << "PASS384 MEDIUM UUD wire/carrier goldens, local completion, no ACK/retry/PDC and checked posting placement\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
