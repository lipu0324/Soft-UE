#include "Check.hpp"
#include "../CMS/TfcEngine.hpp"
#include <iostream>

using namespace UET::CMS;
using namespace UET::Runtime;

namespace {
TfcEngineConfig small_config() {
    TfcEngineConfig config;
    config.outgoing.payload_mtu_bytes=64;
    config.incoming.payload_mtu_bytes=64;
    config.receive_context_bytes=1024;
    config.receive_pool_bytes=1024;
    return config;
}

void sharing_and_last_quiesce() {
    EventLoop loop;
    TfcEngine engine(small_config(),loop,loop,[]{},{});
    const Connection first{2,1,100,false}, second{2,2,200,false}, third{2,3,300,false};
    engine.work_posted(first,64);
    engine.work_posted(second,64);
    CHECK(engine.can_send(first) && engine.can_send(second));
    const auto old_id=engine.source_identifier(first);
    CHECK(engine.source_identifier(second)==old_id);
    engine.update_activity(first,true,false,false,true,1000);
    engine.update_activity(second,true,false,false,false,1000);
    engine.closed(first);
    engine.work_posted(third,64);
    CHECK(engine.can_send(third));
    CHECK(engine.source_identifier(third)==old_id); // The second member is still active.
    engine.update_activity(second,true,false,false,true,1000);
    engine.update_activity(third,true,false,false,true,1000);
    const Connection replacement{2,4,400,false};
    engine.work_posted(replacement,64);
    CHECK(engine.can_send(replacement));
    CHECK(engine.source_identifier(replacement)!=old_id); // Old members have only quiesced, not closed.
    engine.closed(second);
    engine.closed(third);
    engine.closed(replacement);
    CHECK(engine.source_connection_count()==0 && loop.pending()==0);
}

void independent_contexts_and_identifier_pressure() {
    EventLoop loop;
    TfcEngine engine(small_config(),loop,loop,[]{},{});
    for (unsigned index=0; index<256; ++index) {
        const Connection connection{2,static_cast<uint16_t>(index+1),1000+index,true};
        engine.work_posted(connection,64);
        CHECK(engine.can_send(connection));
        CHECK(engine.source_identifier(connection)==index);
    }
    const Connection waiting{2,300,3000,true};
    engine.work_posted(waiting,64);
    CHECK(!engine.can_send(waiting));
    CHECK(engine.source_connection_count()==256);
    const Connection other_peer{3,301,3001,true};
    engine.work_posted(other_peer,64);
    CHECK(engine.can_send(other_peer) && engine.source_identifier(other_peer)==0);
    engine.closed({2,1,1000,true});
    CHECK(engine.can_send(waiting) && engine.source_identifier(waiting)==0);
    engine.closed(waiting);
    engine.closed(other_peer);
    for (unsigned index=1; index<256; ++index)
        engine.closed({2,static_cast<uint16_t>(index+1),1000+index,true});
    CHECK(engine.source_connection_count()==0 && loop.pending()==0);
}

PDStoNET_pkt request(uint8_t context_id=7,size_t payload_bytes=64) {
    PDStoNET_pkt packet{};
    packet.PDS_type=RUOD_req_header;
    packet.PDS_header.RUOD_req_header.type=RUD_CC_REQ;
    packet.PDS_header.RUOD_req_header.psn=100;
    packet.credit_request.ccc_id=context_id;
    packet.credit_request.credit_target_units=4;
    packet.SESpkt.payload.resize(payload_bytes);
    return packet;
}

void destination_pool_and_identity() {
    EventLoop loop;
    TfcEngine engine(small_config(),loop,loop,[]{},{});
    const Connection first{1,512,100,false}, second{1,513,100,false}, denied{1,514,100,false};
    CHECK(engine.admit_receive(first,request(7,65))==UET_NO_PKT_BUFFER);
    CHECK(engine.reserved_receive_bytes()==0); // Malformed MTU must not reserve a CCC.
    CHECK(!engine.admit_receive(first,request()));
    engine.received(first,request());
    CHECK(engine.destination_context_count()==1 && engine.reserved_receive_bytes()==1024);
    CHECK(engine.admit_receive(first,request(8))==UET_PDC_HDR_MISMATCH);
    CHECK(engine.admit_receive(denied,request(8))==UET_NO_CCC_AVAIL);
    CHECK(engine.destination_context_count()==1 && engine.reserved_receive_bytes()==1024);
    engine.handed_to_semantics(first,100);
    engine.handed_to_semantics(first,100); // Duplicate local release is harmless.
    CHECK(!engine.admit_receive(second,request()));
    engine.received(second,request());
    CHECK(engine.destination_context_count()==1 && engine.reserved_receive_bytes()==1024);
    engine.closed(first);
    CHECK(engine.reserved_receive_bytes()==1024);
    engine.closed(second); // Also releases its still-held packet lease.
    CHECK(engine.reserved_receive_bytes()==0 && engine.destination_context_count()==0);
    CHECK(!engine.admit_receive(denied,request(8)));
    CHECK(engine.reserved_receive_bytes()==1024);
    engine.closed(denied);
    CHECK(engine.reserved_receive_bytes()==0 && loop.pending()==0);
}
}

int main() {
    try {
        sharing_and_last_quiesce();
        independent_contexts_and_identifier_pressure();
        destination_pool_and_identity();
        std::cout << "TFC source sharing/quiesce/256-ID pressure and destination pool cases passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
