#include "Check.hpp"
#include "../CMS/NsccEngine.hpp"
#include "../CMS/TfcEngine.hpp"
#include <iostream>

using namespace UET::CMS;
using namespace UET::Runtime;

namespace {
const Connection first_class_zero{2,1,1000,false,0};
const Connection same_class_zero{2,2,2000,false,0};
const Connection other_class_one{2,3,3000,false,1};

void nscc_window_isolation() {
    EventLoop loop;
    NsccConfig config;
    config.initial_maximum_window=1132;
    NsccEngine engine(config,loop,[]{},{});
    for (const auto& connection : {first_class_zero,same_class_zero,other_class_one}) CHECK(engine.can_send(connection));
    CHECK(engine.congestion_context_count()==2);
    CHECK(&engine.state(first_class_zero)==&engine.state(same_class_zero));
    CHECK(&engine.state(first_class_zero)!=&engine.state(other_class_one));
    PDStoNET_pkt data{};
    data.PDS_type=RUOD_req_header;
    data.PDS_header.RUOD_req_header.type=RUD_REQ;
    data.PDS_header.RUOD_req_header.next_hdr=UET_HDR_REQUEST_STD;
    data.SESpkt.bth_type=Standard_Header;
    auto& header=data.SESpkt.bth_header.Standard_Header;
    header.opcode=5;
    header.som=header.eom=1;
    header.request_length=1024;
    data.SESpkt.payload.resize(1024);
    CHECK(engine.transmitted(first_class_zero,data)==1132);
    CHECK(!engine.can_send(first_class_zero) && !engine.can_send(same_class_zero));
    CHECK(engine.can_send(other_class_one));
    CHECK(engine.state(other_class_one).inflight_bytes==0);
    engine.closed(first_class_zero);
    CHECK(engine.can_send(same_class_zero) && engine.congestion_context_count()==2);
    engine.closed(same_class_zero);
    CHECK(engine.can_send(other_class_one) && engine.congestion_context_count()==1);
    engine.closed(other_class_one);
    CHECK(engine.source_connection_count()==0 && engine.congestion_context_count()==0);
}

void tfc_credit_and_feedback_isolation() {
    EventLoop loop;
    TfcEngineConfig config;
    config.outgoing.payload_mtu_bytes=config.incoming.payload_mtu_bytes=64;
    config.receive_context_bytes=config.receive_pool_bytes=1024;
    TfcEngine engine(config,loop,loop,[]{},{});
    for (const auto& connection : {first_class_zero,same_class_zero,other_class_one}) {
        engine.work_posted(connection,0);
        CHECK(engine.can_send(connection));
    }
    CHECK(engine.source_identifier(first_class_zero)==engine.source_identifier(same_class_zero));
    CHECK(engine.source_identifier(first_class_zero)!=engine.source_identifier(other_class_one));
    PDStoNET_pkt packet{};
    packet.PDS_type=RUOD_req_header;
    packet.PDS_header.RUOD_req_header.next_hdr=UET_HDR_NONE; // Isolate CMS's zero-payload debit.
    engine.transmitted_attempt(first_class_zero,packet,false);
    CHECK(engine.source_credit_bytes(first_class_zero)==0);
    CHECK(!engine.can_send(first_class_zero) && !engine.can_send(same_class_zero));
    CHECK(engine.can_send(other_class_one));
    PDStoNET_pkt grant{};
    grant.PDS_type=RUOD_ack_header;
    grant.PDS_header.RUOD_ack_header.type=ACK_CC;
    grant.congestion_ack.type=1;
    grant.congestion_ack.credit_units=2;
    engine.acknowledged(other_class_one,grant,{});
    CHECK(engine.source_credit_bytes(other_class_one)==768);
    CHECK(engine.source_credit_bytes(first_class_zero)==0);
    CHECK(!engine.can_send(first_class_zero));
    engine.acknowledged(same_class_zero,grant,{});
    CHECK(engine.source_credit_bytes(first_class_zero)==512 && engine.can_send(first_class_zero));
    CHECK(engine.source_credit_bytes(same_class_zero)==512);
    CHECK(engine.source_credit_bytes(other_class_one)==768);
    engine.acknowledged(first_class_zero,grant,{});
    CHECK(engine.source_credit_bytes(first_class_zero)==512); // One cumulative grant per shared CCC.
    for (const auto& connection : {first_class_zero,same_class_zero,other_class_one}) engine.closed(connection);
    CHECK(engine.source_connection_count()==0 && loop.pending()==0);
}
}

int main() {
    try {
        nscc_window_isolation();
        tfc_credit_and_feedback_isolation();
        std::cout << "CMS data-TC window, credit, feedback and lifetime isolation passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
