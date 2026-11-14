#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

enum class SynchronizationFault { WriteLost, WriteDuplicated, WriteDelayed, CompletingLost,
                                 CompletingDuplicated, CompletingAcknowledgmentLost, ClearLost };
enum class PacketEffect { Pass, Drop, Duplicate, Delay };

class SynchronizationFaultPort final : public IPacketPort {
public:
    SynchronizationFaultPort(IPacketPort& lower,EventLoop& loop):lower_(lower),loop_(loop) {}
    bool provides_transmit_timing() const override { return lower_.provides_transmit_timing(); }
    SendResult try_send(const Frame& frame) override {
        const auto packet=UET::NetworkLayer::UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        const auto effect=inject?inject(packet):PacketEffect::Pass;
        if (effect==PacketEffect::Pass) return lower_.try_send(frame);
        if (effect==PacketEffect::Duplicate) {
            const auto result=lower_.try_send(frame);
            if (result==SendResult::Accepted) {
                auto duplicate=frame; duplicate.transmission_event={};
                CHECK(lower_.try_send(duplicate)==SendResult::Accepted);
            }
            return result;
        }
        // These network faults occur after the original NIC accepted the
        // packet. Report its departure once; delayed copies have no second
        // transmit callback that could double-charge PDS/CMS accounting.
        if (frame.transmission_event) frame.transmission_event(loop_.now(),TransmitOutcome::Started);
        if (effect==PacketEffect::Delay) {
            auto delayed=frame; delayed.transmission_event={};
            loop_.after(200000,[this,delayed] { CHECK(lower_.try_send(delayed)==SendResult::Accepted); });
        }
        return SendResult::Accepted;
    }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable handler) override { lower_.set_writable_handler(std::move(handler)); }
    std::function<PacketEffect(const PDStoNET_pkt&)> inject;
private:
    IPacketPort& lower_; EventLoop& loop_;
};

static void recover(RequestHeaderFormat format,pdc_mode mode,bool congestion,bool atomic,SynchronizationFault fault) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    SynchronizationFaultPort forward(fabric.add_host(1),loop),reverse(fabric.add_host(2),loop);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    source_host.configure_retransmission_timeout(100000); target_host.configure_retransmission_timeout(100000);
    if (congestion) { source_host.enable_nscc({}); target_host.enable_nscc({}); }
    Endpoint source(1,source_host,loop,trace,64),target(2,target_host,loop,trace,64);
    source.memory().add_job(1); target.memory().add_job(1);
    target.resources().configure_resource(1,3,ResourceSpace::Rma);
    RegionOptions options; options.resource_index=3;
    options.requested_key=format==RequestHeaderFormat::Small?MemoryKeyFormat::Optimized|3:42;
    const auto region=target.memory().register_region(1,1,64,7,options);
    bool applied=false;
    std::optional<std::pair<uint16_t,uint32_t>> completing_packet;
    forward.inject=[&](const PDStoNET_pkt& packet) {
        if (packet.PDS_type==RUOD_cp_header && packet.PDS_header.RUOD_cp_header.ctl_type==Clear_cmd &&
            fault==SynchronizationFault::ClearLost && !applied) { applied=true; return PacketEffect::Drop; }
        if (packet.PDS_type!=RUOD_req_header) return PacketEffect::Pass;
        const auto fields=semantic_request_fields(packet.SESpkt); CHECK(fields);
        const auto& header=fields->header;
        const bool completing=header.opcode==0x11 || (header.opcode==0x10 && header.hd);
        if (completing) completing_packet=std::make_pair(packet.PDS_header.RUOD_req_header.spdcid,packet.PDS_header.RUOD_req_header.psn);
        if (applied) return PacketEffect::Pass;
        if (!completing && header.opcode==0x10) {
            if (fault==SynchronizationFault::WriteLost) { applied=true; return PacketEffect::Drop; }
            if (fault==SynchronizationFault::WriteDuplicated) { applied=true; return PacketEffect::Duplicate; }
            if (fault==SynchronizationFault::WriteDelayed) { applied=true; return PacketEffect::Delay; }
        }
        if (completing) {
            if (fault==SynchronizationFault::CompletingLost) { applied=true; return PacketEffect::Drop; }
            if (fault==SynchronizationFault::CompletingDuplicated) { applied=true; return PacketEffect::Duplicate; }
        }
        return PacketEffect::Pass;
    };
    reverse.inject=[&](const PDStoNET_pkt& packet) {
        if (!applied && fault==SynchronizationFault::CompletingAcknowledgmentLost && completing_packet && packet.PDS_type==RUOD_ack_header) {
            const auto& acknowledgment=packet.PDS_header.RUOD_ack_header;
            const uint32_t sequence=acknowledgment.cack_psn+acknowledgment.ack_psn_off;
            if (!acknowledgment.flags.p && acknowledgment.dpdcid==completing_packet->first && sequence==completing_packet->second) {
                applied=true; return PacketEffect::Drop;
            }
        }
        return PacketEffect::Pass;
    };
    const auto synchronization=source.begin_synchronized_group(2,1,3); CHECK(synchronization);
    Operation write; write.type=OperationType::SynchronizedWrite; write.header_format=format; write.delivery_mode=mode;
    write.peer=2; write.remote_key=region.key; write.target_resource=3; write.remote_offset=16;
    write.payload.assign(8,0x31); write.synchronization=synchronization;
    source.submit(write); write.remote_offset=32; source.submit(write);
    Operation completing=write; completing.remote_offset=0;
    if (atomic) { completing.type=OperationType::SynchronizedAtomic; completing.payload={5,0,0,0,0,0,0,0}; }
    else { completing.payload.assign(8,0x53); completing.immediate_data=42; }
    source.submit(completing); loop.run_until(90*kMillisecond);
    Completion completion{}; std::set<uint64_t> completed;
    while (source.poll_completion(completion)) CHECK(completion.status==CompletionStatus::Success && completed.insert(completion.operation).second);
    CHECK(applied && completed.size()==3);
    CHECK(target.memory().read(1,1,region.key,0,8,3)==completing.payload);
    CHECK(target.memory().read(1,1,region.key,16,8,3)==std::vector<uint8_t>(8,0x31));
    CHECK(target.memory().read(1,1,region.key,32,8,3)==std::vector<uint8_t>(8,0x31));
    if (!atomic) CHECK(target.poll_completion(completion) && completion.status==CompletionStatus::Success && completion.immediate_data==42);
    CHECK(!target.poll_completion(completion));
    CHECK(!source.pending() && !source.active_synchronized_source_groups() && !source.leased_message_ids() &&
        !target.retained_synchronized_groups() && !target.retained_synchronized_members() && !target.retained_synchronized_actions() &&
        !target.retained_receive_messages());
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(!loop.pending());
}

int main() {
    try {
        for (auto format:{RequestHeaderFormat::Small,RequestHeaderFormat::Medium}) for (auto mode:{RUD,ROD})
            for (bool congestion:{false,true}) for (unsigned fault=0;fault<7;++fault) {
                recover(format,mode,congestion,true,static_cast<SynchronizationFault>(fault));
                if (format==RequestHeaderFormat::Medium) recover(format,mode,congestion,false,static_cast<SynchronizationFault>(fault));
            }
        std::cout << "PASS84 optimized synchronization data/completer/ACK/Clear faults and one aggregate action\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
