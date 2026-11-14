#include "Check.hpp"
#include "../CMS/TfcCredit.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>

using namespace UET::CMS;
using namespace UET::Runtime;
using namespace UET::SES;
using UET::NetworkLayer::UetWireCodec;

namespace {
// A test-only CMS observer isolates the original PDS admission bridge. Grants
// are injected explicitly; this fixture is not a TFC destination or wire peer.
class CreditAdmissionObserver final : public ICongestionControl {
public:
    CreditAdmissionObserver() : credit(TfcSourceConfig{64,256,256,256}) {}
    TfcSourceCredit credit;
    size_t new_packets=0, retry_packets=0;
    bool can_send(const Connection&) override { return credit.can_send(); }
    uint32_t transmitted(const Connection&, PDStoNET_pkt&) override {
        throw std::logic_error("PDS did not identify its transmission attempt");
    }
    bool can_send_attempt(const Connection&, bool retransmission) override {
        return credit.can_send(retransmission);
    }
    uint32_t transmitted_attempt(const Connection&, PDStoNET_pkt& packet, bool retransmission) override {
        credit.on_send(packet.SESpkt.payload.size(), retransmission);
        if (retransmission) ++retry_packets;
        else ++new_packets;
        return 1; // Nonzero local accounting identity for PDS's loss path.
    }
    void decorate_control(const Connection&, PDStoNET_pkt&) override {}
    void acknowledged(const Connection&, const PDStoNET_pkt&, std::optional<NsccTransmitSample>) override {}
    void negative_acknowledged(const Connection&, uint32_t, const PDStoNET_pkt&,
                              std::optional<NsccTransmitSample>) override {}
    void inferred_loss(const Connection&, uint32_t) override {}
    void canceled_unsent_retry(const Connection&, uint32_t) override {}
    void received(const Connection&, const PDStoNET_pkt&, bool) override {}
    void decorate_ack(const Connection&, uint32_t, PDStoNET_pkt&) override {}
    void receive_cleared(const Connection&, uint32_t) override {}
    void closed(const Connection&) override {}
};

class AdmissionFaultPort final : public IPacketPort {
public:
    AdmissionFaultPort(IPacketPort& lower, EventLoop& loop, bool lose_data, bool backpressure)
        : lower_(lower), loop_(loop), lose_next_data_(lose_data), blocks_remaining_(backpressure ? 3 : 0) {}
    size_t accepted_data=0, refused_data=0, dropped_data=0;
    SendResult try_send(const Frame& frame) override {
        const auto packet=UetWireCodec::decode(frame.bytes.data(), frame.bytes.size()).packet;
        if (packet.PDS_type==RUOD_req_header) {
            if (blocks_remaining_) {
                --blocks_remaining_;
                ++refused_data;
                loop_.at(add_time(loop_.now(),100), [this] { if (writable_) writable_(); });
                return SendResult::WouldBlock;
            }
            ++accepted_data;
            if (lose_next_data_) {
                lose_next_data_=false;
                ++dropped_data;
                return SendResult::Accepted;
            }
        }
        return lower_.try_send(frame);
    }
    void set_receiver(Receiver receiver) override { lower_.set_receiver(std::move(receiver)); }
    void set_writable_handler(Writable writable) override {
        writable_=writable;
        lower_.set_writable_handler(std::move(writable));
    }
private:
    IPacketPort& lower_;
    EventLoop& loop_;
    bool lose_next_data_;
    unsigned blocks_remaining_;
    Writable writable_;
};

void original_pds_gate(bool ordered, bool lose_data, bool backpressure) {
    EventLoop loop;
    Trace trace(loop);
    Fabric fabric(loop,trace,41);
    auto& source_port=fabric.add_host(1);
    auto& target_port=fabric.add_host(2);
    LinkConfig link;
    link.delay_ns=1000;
    fabric.add_link(1,2,link);
    fabric.add_link(2,1,link);
    AdmissionFaultPort fault_port(source_port,loop,lose_data,backpressure);
    CreditAdmissionObserver observer; // Outlives both PDS hosts and their connections.
    PdsHost source_host(1,loop,trace,fault_port), target_host(2,loop,trace,target_port);
    source_host.services().congestion_control=&observer;
    Endpoint source(1,source_host,loop,trace,64), target(2,target_host,loop,trace,64);
    source.memory().add_job(1);
    target.memory().add_job(1);
    const auto region=target.memory().register_region(1,1,128,7);
    Operation write;
    write.type=OperationType::Write;
    write.peer=2;
    write.remote_key=region.key;
    write.delivery_mode=ordered ? ROD : RUD;
    write.payload.assign(128,0xa5);
    source.submit(write);

    // Cover the 65 ms SYN safety interval as well as the ordinary PDS RTO.
    // No destination credit can arrive: the target has no credit policy.
    loop.run_until(70*kMillisecond);
    CHECK(observer.new_packets==1);
    CHECK(observer.retry_packets==(lose_data ? 1u : 0u));
    CHECK(observer.credit.available_credit_bytes()==-256);
    CHECK(fault_port.refused_data==(backpressure ? 3u : 0u));
    CHECK(fault_port.accepted_data==(lose_data ? 2u : 1u));
    CHECK(fault_port.dropped_data==(lose_data ? 1u : 0u));
    Completion completion{};
    CHECK(!source.poll_completion(completion));
    CHECK(target.memory().read(1,1,region.key,0,64)==std::vector<uint8_t>(64,0xa5));
    CHECK(target.memory().read(1,1,region.key,64,64)==std::vector<uint8_t>(64,0));

    // 512 bytes first repay the -256 debt, leaving positive admission credit.
    observer.credit.on_credit_update(2);
    source_host.wake();
    loop.run_until(75*kMillisecond);
    CHECK(source.poll_completion(completion));
    CHECK(completion.status==CompletionStatus::Success && completion.length==128);
    CHECK(!source.poll_completion(completion));
    CHECK(observer.new_packets==2);
    CHECK(observer.retry_packets==(lose_data ? 1u : 0u));
    CHECK(observer.credit.available_credit_bytes()==-256);
    CHECK(target.memory().read(1,1,region.key,0,128)==write.payload);
    source.close();
    target.close();
    source_host.close();
    target_host.close();
    CHECK(loop.pending()==0);
}
}

int main() {
    try {
        for (const bool ordered : {false,true})
            for (const bool lose_data : {false,true})
                for (const bool backpressure : {false,true})
                    original_pds_gate(ordered,lose_data,backpressure);
        std::cout << "8 original PDS new/retry/backpressure credit admission cases passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
