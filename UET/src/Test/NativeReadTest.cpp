#include "Check.hpp"
#include "../SES/Endpoint.hpp"
#include "../Runtime/Fabric.hpp"
#include <iostream>
#include <fstream>

using namespace UET::Runtime;
using namespace UET::NetworkLayer;
using namespace UET::SES;

enum class ReadFault { None, RequestLoss, DataLoss, ReturnAckLoss, ForwardAckLoss, DataDelay, DataDuplicate,
                       RevokeLocal, RevokeRemote, Cancel, TargetContextPressure, PermanentDataLoss };

class ReadFaultPort final : public IPacketPort {
public:
    ReadFaultPort(IPacketPort& lower,EventLoop& loop,bool source):lower_(lower),loop_(loop),source_(source) {}
    SendResult try_send(const Frame& frame) override {
        const auto packet=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        if (observe) observe();
        if (packet.PDS_type==RUOD_req_header) {
            if (packet.SESpkt.bth_type==Standard_Header && packet.SESpkt.bth_header.Standard_Header.opcode==2) {
                CHECK(packet.SESpkt.payload.empty()); ++requests;
                if (fault==ReadFault::RequestLoss && requests==1) return SendResult::Accepted;
            }
            if (packet.SESpkt.bth_type==Semantic_Response_with_Data_Header) {
                ++data;
                if (fault==ReadFault::PermanentDataLoss) return SendResult::Accepted;
                if (fault==ReadFault::DataLoss && data==1) return SendResult::Accepted;
                if (fault==ReadFault::DataDelay && data==1) {
                    loop_.after(200000,[this,frame] { CHECK(lower_.try_send(frame)==SendResult::Accepted); });
                    return SendResult::Accepted;
                }
                if (fault==ReadFault::DataDuplicate && data==1) CHECK(lower_.try_send(frame)==SendResult::Accepted);
            }
        }
        if (packet.PDS_type==RUOD_ack_header && packet.SESpkt.bth_type==Semantic_Response_Header) {
            const auto& acknowledgment=packet.PDS_header.RUOD_ack_header;
            if (source_ && acknowledgment.spdcid>=MAX_PDC && !held_noop_) {
                // Keep the target's own native MID=1 pending while its target
                // PDC emits response token=1. Numerical token equality must
                // never overwrite a different direction's operation state.
                held_noop_=true;
                loop_.after(200000,[this,frame] { CHECK(lower_.try_send(frame)==SendResult::Accepted); });
                return SendResult::Accepted;
            }
            const bool reverse_result=source_ && acknowledgment.spdcid<MAX_PDC;
            if (reverse_result && !first_reverse_ack_) {
                first_reverse_ack_=true;
                if (on_first_return_ack) on_first_return_ack();
                if (fault==ReadFault::ReturnAckLoss) return SendResult::Accepted;
            }
            if (!source_ && fault==ReadFault::ForwardAckLoss && !dropped_forward_ack_) {
                dropped_forward_ack_=true; return SendResult::Accepted;
            }
        }
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable callback) override { lower_.set_writable_handler(std::move(callback)); }
    ReadFault fault=ReadFault::None;
    std::function<void()> observe,on_first_return_ack;
    size_t requests=0,data=0;
private:
    IPacketPort& lower_; EventLoop& loop_; bool source_;
    bool held_noop_=false,first_reverse_ack_=false,dropped_forward_ack_=false;
};

void native_read(pdc_mode mode,bool congestion,uint32_t length,size_t credits,ReadFault fault) {
    constexpr uint32_t mtu=1024;
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    ReadFaultPort forward(fabric.add_host(1),loop,true),reverse(fabric.add_host(2),loop,false);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    std::ofstream source_debug,target_debug;
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    if (fault==ReadFault::DataLoss && mode==RUD && !congestion) {
        source_debug.open("/tmp/softue-native-read-source-debug.log");
        target_debug.open("/tmp/softue-native-read-target-debug.log");
        source_host.services().diagnostic_output=&source_debug; target_host.services().diagnostic_output=&target_debug;
    }
    if (congestion) {
        const auto config=UET::CMS::NsccConfig::for_link(12000,12500000000ULL,12500000000ULL,1132);
        source_host.enable_nscc(config); target_host.enable_nscc(config);
    }
    Endpoint source(1,source_host,loop,trace,mtu),target(2,target_host,loop,trace,mtu,
        100*kMillisecond,nullptr,8,4096,256*1024,credits);
    source.memory().add_job(1); target.memory().add_job(1);
    const auto destination=source.memory().register_region(1,1,uint64_t{length}+128,Access::Read|Access::Write);
    const auto remote=target.memory().register_region(1,1,uint64_t{length}+128,Access::Read|Access::Write);
    std::vector<uint8_t> expected(length); for (size_t index=0;index<expected.size();++index) expected[index]=index*11+5;
    target.memory().write(1,1,remote.key,9,expected);
    size_t peak_credits=0,peak_returns=0,peak_producer=0,peak_intervals=0;
    const auto observe=[&] {
        peak_credits=std::max(peak_credits,target.retained_read_packets());
        peak_returns=std::max(peak_returns,target.pending_read_returns());
        peak_producer=std::max(peak_producer,source.queued_fragments());
        peak_intervals=std::max(peak_intervals,source.receive_intervals());
        CHECK(peak_credits<=credits && peak_returns<=credits && peak_producer<=8 && peak_intervals<=2);
    };
    forward.observe=reverse.observe=observe;
    forward.fault=reverse.fault=fault;
    Operation noop; noop.type=OperationType::Noop; noop.peer=1; noop.delivery_mode=mode;
    const auto target_operation=target.submit(noop);
    Operation read; read.type=OperationType::Read; read.peer=2; read.delivery_mode=mode;
    read.remote_key=remote.key; read.remote_offset=9; read.read_length=length;
    read.read_result=ReadResultBuffer{destination.key,11,length,1,1}; read.context=99;
    uint64_t operation=0;
    forward.on_first_return_ack=[&] {
        if (fault==ReadFault::RevokeLocal) CHECK(source.memory().deregister(destination.key));
        if (fault==ReadFault::RevokeRemote) CHECK(target.memory().deregister(remote.key));
        if (fault==ReadFault::Cancel) CHECK(source.cancel_read(operation));
    };
    if (fault==ReadFault::TargetContextPressure) {
        target_host.services().target_context_limit=0;
        loop.after(5*kMillisecond,[&] {
            CHECK(target.retained_read_packets()==0 && target.retained_receive_messages()==0);
            target_host.services().target_context_limit=512; target_host.wake();
        });
    }
    operation=source.submit(read); loop.run(1000000);
    Completion completion{};
    CHECK(source.poll_completion(completion) && completion.operation==operation && completion.context==99);
    const auto expected_status=fault==ReadFault::RevokeLocal?CompletionStatus::LocalError:
        fault==ReadFault::RevokeRemote?CompletionStatus::RemoteError:
        fault==ReadFault::Cancel?CompletionStatus::Cancelled:
        fault==ReadFault::PermanentDataLoss?CompletionStatus::Timeout:CompletionStatus::Success;
    if (completion.status!=expected_status) {
        std::cerr<<"native READ mode="<<mode<<" nscc="<<congestion<<" bytes="<<length<<" credits="<<credits
            <<" fault="<<static_cast<int>(fault)<<" status="<<static_cast<int>(completion.status)
            <<" code="<<static_cast<unsigned>(completion.remote_code)<<" returned="<<completion.length<<'\n';
        for (const auto& event:trace.events()) if (event.event=="pds_nack")
            std::cerr<<"NACK node="<<event.node<<" ns="<<event.time<<" code="<<event.value<<'\n';
    }
    CHECK(completion.status==expected_status && !source.poll_completion(completion));
    if (expected_status==CompletionStatus::Success) {
        CHECK(completion.length==length);
        CHECK(source.memory().read(1,1,destination.key,11,length)==expected);
    }
    if (fault==ReadFault::RevokeLocal) CHECK(completion.length==mtu);
    if (fault==ReadFault::RevokeLocal || fault==ReadFault::Cancel) {
        std::vector<uint8_t> untouched(length-mtu);
        destination.storage->read(11+mtu,untouched.data(),untouched.size());
        CHECK(untouched==std::vector<uint8_t>(length-mtu));
    }
    if (fault==ReadFault::RevokeRemote) CHECK(completion.remote_code==static_cast<uint8_t>(SemanticReturnCode::BadMemoryKey));
    CHECK(target.poll_completion(completion) && completion.operation==target_operation && completion.status==CompletionStatus::Success);
    CHECK(!target.poll_completion(completion));
    CHECK(source.leased_message_ids()==0 && target.leased_message_ids()==0 && target.retained_read_packets()==0 &&
        target.pending_read_returns()==0 && target.retained_receive_messages()==0);
    CHECK(peak_returns>0 && peak_credits>0 && peak_producer>0);
    CHECK(!source.cancel_read(operation));
    Operation following; following.type=OperationType::Noop; following.peer=2; following.delivery_mode=mode;
    const auto following_operation=source.submit(following); CHECK(!source.cancel_read(following_operation)); loop.run(100000);
    CHECK(source.poll_completion(completion) && completion.operation==following_operation && completion.status==CompletionStatus::Success);
    CHECK(!source.poll_completion(completion));
    source.close(); target.close(); source_host.close(); target_host.close(); CHECK(loop.pending()==0);
}

int main() {
    try {
        for (const auto mode:{RUD,ROD}) for (const bool congestion:{false,true}) {
            for (const uint32_t length:{17,1024,1025,2051}) native_read(mode,congestion,length,8,ReadFault::None);
            for (const auto fault:{ReadFault::RequestLoss,ReadFault::DataLoss,ReadFault::ReturnAckLoss,
                ReadFault::ForwardAckLoss,ReadFault::DataDelay,ReadFault::DataDuplicate}) native_read(mode,congestion,16387,8,fault);
            for (const size_t credits:{1,2}) native_read(mode,congestion,4099,credits,ReadFault::None);
            for (const auto fault:{ReadFault::RevokeLocal,ReadFault::RevokeRemote,ReadFault::Cancel})
                native_read(mode,congestion,32771,8,fault);
            native_read(mode,congestion,17,1,ReadFault::TargetContextPressure);
            native_read(mode,congestion,32771,8,ReadFault::PermanentDataLoss);
            native_read(mode,congestion,8*1024*1024+1,8,ReadFault::None);
        }
        std::cout<<"PASS: native fragmented READ, bounded return credits, loss/order recovery, MR revocation and token isolation\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
