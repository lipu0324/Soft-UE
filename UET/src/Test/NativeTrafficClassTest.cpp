#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
#include <set>

using namespace UET::CMS;
using namespace UET::Runtime;
using namespace UET::SES;
using UET::NetworkLayer::UetWireCodec;

namespace {
class TrafficClassPort final : public IPacketPort {
public:
    TrafficClassPort(IPacketPort& lower,EventLoop& loop,bool lose_class_zero)
        : lower_(lower),loop_(loop),lose_class_zero_(lose_class_zero) {}
    std::array<size_t,8> requests{};
    std::array<std::set<uint8_t>,8> credit_identifiers;
    size_t ordered_class_three_noops=0,lost=0;
    SendResult try_send(const Frame& frame) override {
        const auto decoded=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size());
        const auto& packet=decoded.packet;
        if (packet.PDS_type==RUOD_req_header) {
            CHECK(frame.traffic_class==0 || frame.traffic_class==3);
            CHECK(decoded.network.dscp==frame.traffic_class);
            ++requests[frame.traffic_class];
            if (packet.PDS_header.RUOD_req_header.type==RUD_CC_REQ || packet.PDS_header.RUOD_req_header.type==ROD_CC_REQ)
                credit_identifiers[frame.traffic_class].insert(packet.credit_request.ccc_id);
            if (!frame.traffic_class && lose_class_zero_) {
                lose_class_zero_=false;
                ++lost;
                if (frame.transmission_event) frame.transmission_event(loop_.now(),TransmitOutcome::Started);
                return SendResult::Accepted;
            }
        }
        if (packet.PDS_type==RUOD_cp_header && packet.PDS_header.RUOD_cp_header.ctl_type==Noop &&
            packet.PDS_header.RUOD_cp_header.flags.pdc_type==1) {
            CHECK(frame.traffic_class==3 && decoded.network.dscp==3);
            ++ordered_class_three_noops;
        }
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable writable) override { lower_.set_writable_handler(std::move(writable)); }
private:
    IPacketPort& lower_;
    EventLoop& loop_;
    bool lose_class_zero_;
};

void enable_policies(PdsHost& host,bool nscc,bool tfc) {
    if (nscc) {
        auto congestion=NsccConfig::for_link(12000,12500000000ULL,12500000000ULL,tfc ? 176 : 172);
        congestion.initial_maximum_window=congestion.nominal_mtu;
        host.enable_nscc(congestion);
    }
    if (tfc) {
        TfcEngineConfig flow;
        flow.outgoing.payload_mtu_bytes=flow.incoming.payload_mtu_bytes=64;
        flow.receive_context_bytes=1024;
        flow.receive_pool_bytes=4096;
        host.enable_tfc(flow);
    }
}

void independent_flows(pdc_mode mode,bool nscc,bool tfc,bool loss) {
    EventLoop loop;
    Trace trace(loop);
    Fabric fabric(loop,trace,61);
    TrafficClassPort forward(fabric.add_host(1),loop,loss);
    auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{});
    fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    source_host.configure_data_traffic_class(3,3);
    enable_policies(source_host,nscc,tfc);
    enable_policies(target_host,nscc,tfc);
    Endpoint source(1,source_host,loop,trace,64),target(2,target_host,loop,trace,64);
    source.memory().add_job(1);
    target.memory().add_job(1);
    const auto region=target.memory().register_region(1,1,1536,7);
    CHECK(source_host.open_connection(2,1,mode,false,{},3)!=UINT16_MAX);
    loop.run_until(10000); // Establish a numbered ROD NOOP on the configured data TC.
    if (mode==ROD) CHECK(forward.ordered_class_three_noops>0);
    Operation write;
    write.type=OperationType::Write;
    write.peer=2;
    write.delivery_mode=mode;
    write.remote_key=region.key;
    write.payload.assign(1024,0x11);
    const auto first=source.submit(write);
    write.traffic_class=3;
    write.remote_offset=1024;
    write.payload.assign(512,0x33);
    const auto other=source.submit(write);
    loop.run_until(10999);
    if (nscc || tfc) CHECK(forward.requests[0]==1 && forward.requests[3]==1);
    loop.run_until(kMillisecond);
    std::set<uint64_t> completed;
    Completion completion{};
    while (source.poll_completion(completion)) {
        CHECK(completion.status==CompletionStatus::Success && completion.length==(completion.operation==first ? 1024u : 512u));
        CHECK(completed.insert(completion.operation).second);
    }
    CHECK(completed.count(other)); // An exhausted/lost TC 0 cannot stop TC 3.
    if (loss) { CHECK(forward.lost==1); if (nscc || tfc) CHECK(!completed.count(first)); }
    loop.run_until(100*kMillisecond);
    while (source.poll_completion(completion)) {
        CHECK(completion.status==CompletionStatus::Success && completion.length==(completion.operation==first ? 1024u : 512u));
        CHECK(completed.insert(completion.operation).second);
    }
    CHECK(completed.size()==2 && completed.count(first) && completed.count(other));
    CHECK(target.memory().read(1,1,region.key,0,1024)==std::vector<uint8_t>(1024,0x11));
    CHECK(target.memory().read(1,1,region.key,1024,512)==std::vector<uint8_t>(512,0x33));
    if (tfc) {
        CHECK(forward.credit_identifiers[0].size()==1 && forward.credit_identifiers[3].size()==1);
        CHECK(*forward.credit_identifiers[0].begin()!=*forward.credit_identifiers[3].begin());
    }
    source.close(); target.close(); source_host.close(); target_host.close();
    CHECK(loop.pending()==0);
}

void reverse_read_handoff(pdc_mode mode,bool nscc) {
    EventLoop loop;
    Trace trace(loop);
    Fabric fabric(loop,trace,61);
    auto& forward=fabric.add_host(1);
    auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    source_host.configure_data_traffic_class(3,3);
    enable_policies(source_host,nscc,true); enable_policies(target_host,nscc,true);
    source_host.configure_read_ack_data(0); target_host.configure_read_ack_data(0);
    Endpoint source(1,source_host,loop,trace,64),target(2,target_host,loop,trace,64);
    source.memory().add_job(1); target.memory().add_job(1);
    const auto remote=target.memory().register_region(1,1,512,7);
    const auto local=source.memory().register_region(1,1,512,7);
    const std::vector<uint8_t> expected(512,0x5a);
    remote.storage->write(0,expected.data(),expected.size());
    size_t outgoing=0,returned=0;
    fabric.set_capture([&](Time,const Frame& frame) {
        const auto decoded=UetWireCodec::decode(frame.bytes.data(),frame.bytes.size());
        if (decoded.packet.PDS_type!=RUOD_req_header) return;
        if (frame.source==1) { CHECK(frame.traffic_class==3 && decoded.network.dscp==3); ++outgoing; }
        else { CHECK(frame.traffic_class==0 && decoded.network.dscp==0); ++returned; }
    });
    Operation read;
    read.type=OperationType::Read; read.peer=2; read.delivery_mode=mode; read.traffic_class=3;
    read.remote_key=remote.key; read.read_length=512; read.read_result=ReadResultBuffer{local.key,0,512,1,1};
    source.submit(read); loop.run_until(100*kMillisecond);
    Completion completion{};
    CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Success && completion.length==512);
    CHECK(!source.poll_completion(completion) && outgoing && returned>=8);
    CHECK(source.memory().read(1,1,local.key,0,512)==expected);
    source.close(); target.close(); source_host.close(); target_host.close();
    CHECK(loop.pending()==0);
}

void rejected_configuration_and_posting() {
    EventLoop loop;
    Trace trace(loop);
    Fabric fabric(loop,trace,61);
    auto& port=fabric.add_host(1);
    PdsHost host(1,loop,trace,port);
    host.configure_data_traffic_class(3,3);
    check_throws<std::invalid_argument>([&] { host.configure_data_traffic_class(8,4); });
    check_throws<std::invalid_argument>([&] { host.configure_data_traffic_class(4,64); });
    check_throws<std::invalid_argument>([&] { host.configure_data_traffic_class(4,48); });
    check_throws<std::invalid_argument>([&] { host.configure_data_traffic_class(4,0); });
    check_throws<std::invalid_argument>([&] { host.configure_data_traffic_class(4,3); });
    check_throws<std::invalid_argument>([&] { host.configure_data_traffic_class(0,3); });
    check_throws<std::logic_error>([&] { host.configure_trimming({}); });
    Endpoint source(1,host,loop,trace,64);
    source.memory().add_job(1);
    Operation bad;
    bad.type=OperationType::Write; bad.peer=2; bad.traffic_class=4;
    source.submit(bad);
    Completion completion{};
    CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Unsupported);
    bad.traffic_class=8; source.submit(bad);
    CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::InvalidRequest);
    bad.traffic_class=3; bad.delivery_mode=RUDI; source.submit(bad);
    CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Unsupported);
    bad.type=OperationType::DatagramSend; source.submit(bad);
    CHECK(source.poll_completion(completion) && completion.status==CompletionStatus::Unsupported);
    CHECK(!source.pending() && !source.leased_message_ids() && !host.manager().getPDSStatus().open_cnt);
    CHECK(host.open_connection(2,1,ROD,false,{},4)==UINT16_MAX);
    CHECK(host.open_connection(2,1,ROD,false,{},3)!=UINT16_MAX);
    check_throws<std::logic_error>([&] { host.configure_data_traffic_class(4,4); });
    source.close(); host.close(); CHECK(loop.pending()==0);
}

void error_cleanup_and_reuse(pdc_mode mode,bool nscc) {
    EventLoop loop;
    Trace trace(loop);
    Fabric fabric(loop,trace,61);
    auto& forward=fabric.add_host(1);
    auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost source_host(1,loop,trace,forward),target_host(2,loop,trace,reverse);
    source_host.configure_data_traffic_class(3,3);
    enable_policies(source_host,nscc,true); enable_policies(target_host,nscc,true);
    Endpoint source(1,source_host,loop,trace,64),target(2,target_host,loop,trace,64);
    source.memory().add_job(1); target.memory().add_job(1);
    const auto region=target.memory().register_region(1,1,1536,7);
    Operation write;
    write.type=OperationType::Write; write.peer=2; write.delivery_mode=mode;
    write.remote_key=region.key+1; // Valid key format, deliberately no registration.
    write.payload.assign(1024,0xee);
    const auto denied=source.submit(write);
    write.remote_key=region.key; write.traffic_class=3; write.remote_offset=1024;
    write.payload.assign(512,0x33);
    const auto other=source.submit(write);
    loop.run_until(20*kMillisecond);
    Completion completion{};
    size_t denied_completions=0,other_completions=0;
    while (source.poll_completion(completion)) {
        if (completion.operation==denied) { CHECK(completion.status==CompletionStatus::RemoteError); ++denied_completions; }
        else { CHECK(completion.operation==other && completion.status==CompletionStatus::Success); ++other_completions; }
    }
    CHECK(denied_completions==1 && other_completions==1);
    CHECK(target.memory().read(1,1,region.key,0,1024)==std::vector<uint8_t>(1024,0));
    CHECK(target.memory().read(1,1,region.key,1024,512)==std::vector<uint8_t>(512,0x33));
    const auto producer_empty=[&] {
        CHECK(!source.pending() && !source.queued_fragments());
        for (uint8_t traffic_class=0; traffic_class<8; ++traffic_class) {
            CHECK(!source.queued_fragments_for_traffic_class(traffic_class));
            CHECK(!source.producer_messages_for_traffic_class(traffic_class));
        }
    };
    producer_empty();
    // Reuse the same Endpoint and both TCs after the rejected message and its
    // MSG_ERROR tail. Counter underflow or stale reservations must not prevent
    // either new operation from producing data.
    write.traffic_class=0; write.remote_offset=0; write.payload.assign(128,0x22);
    const auto again_zero=source.submit(write);
    write.traffic_class=3; write.remote_offset=512; write.payload.assign(128,0x44);
    const auto again_three=source.submit(write);
    loop.run_until(40*kMillisecond);
    std::set<uint64_t> completed;
    while (source.poll_completion(completion)) {
        CHECK(completion.status==CompletionStatus::Success && completion.length==128);
        CHECK(completed.insert(completion.operation).second);
    }
    CHECK(completed.size()==2 && completed.count(again_zero) && completed.count(again_three));
    CHECK(target.memory().read(1,1,region.key,0,128)==std::vector<uint8_t>(128,0x22));
    CHECK(target.memory().read(1,1,region.key,512,128)==std::vector<uint8_t>(128,0x44));
    producer_empty();
    check_throws<std::out_of_range>([&] { source.queued_fragments_for_traffic_class(8); });
    source.close(); target.close(); source_host.close(); target_host.close();
    CHECK(loop.pending()==0);
}
}

int main() {
    try {
        for (const auto mode : {RUD,ROD}) for (const bool nscc : {false,true}) {
            for (const bool tfc : {false,true}) for (const bool loss : {false,true})
                independent_flows(mode,nscc,tfc,loss);
            reverse_read_handoff(mode,nscc);
            error_cleanup_and_reuse(mode,nscc);
        }
        rejected_configuration_and_posting();
        std::cout << "16 independent-TC NIC flows,4 reverse READs,4 error/reuse ledgers and configuration bounds passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
