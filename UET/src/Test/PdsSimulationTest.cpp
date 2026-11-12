#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../Runtime/PdsHost.hpp"
#include "../SES/SES.hpp"
#include <iostream>
#include <sstream>

using namespace UET::Runtime;

SES_PDS_req make_request(uint32_t source, uint32_t destination) {
    SES_PDS_req request{};
    request.src_fep = source; request.dst_fep = destination;
    request.mode = ROD; request.rod_context = 1;
    request.next_hdr = UET_HDR_REQUEST_STD;
    request.tc = 1; request.lock_pdc = true;
    request.tx_pkt_handle = 1;
    auto& header = request.pkt.bth_header.Standard_Header;
    request.pkt.bth_type = Standard_Header;
    header.opcode = SEND; header.version = 2; header.som = 1; header.eom = 1;
    header.msg_id = 1; header.job_id = 0x1234;
    header.PIDonFEP = 1; header.resource_index = 1;
    header.request_length = 257; header.buffer_offset = 1;
    header.initiator = 1; header.match_bits = 1;
    request.pkt.payload.resize(257);
    for (size_t i=0; i<257; ++i) request.pkt.payload[i] = static_cast<uint8_t>(i*29+7);
    request.pkt_len = static_cast<uint16_t>(sizeof(SES_Standard_Header) + 257);
    return request;
}

std::vector<TraceEvent> run_simulation() {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop, trace, 42);
    auto& pa = fabric.add_host(11); auto& pb = fabric.add_host(22);
    LinkConfig link; fabric.add_link(11,22,link); fabric.add_link(22,11,link);
    PdsHost a(11,loop,trace,pa,PdsHost::WireFormat::LegacySup1),
            b(22,loop,trace,pb,PdsHost::WireFormat::LegacySup1);
    SESManager target_ses(b.manager());
    const auto request = make_request(11,22);
    size_t requests = 0, responses = 0;
    b.set_request_handler([&](const PDC_SES_req& received) {
        CHECK(received.pkt.payload == request.pkt.payload);
        ++requests; target_ses.process_recv_req_packet(received);
    });
    a.set_response_handler([&](const PDC_SES_rsp& received) {
        if (received.pkt.bth_type == Semantic_Response_Header) {
            CHECK(received.pkt.bth_header.Semantic_Response_Header.message_id == 1);
            CHECK(received.pkt.bth_header.Semantic_Response_Header.return_code == static_cast<uint8_t>(RSP_RETURN_CODE::RC_OK));
            ++responses;
        }
    });
    CHECK(a.submit(request));
    loop.run_until(100 * kMillisecond, 10000);
    CHECK(requests == 1); CHECK(responses == 1);
    CHECK(a.manager().hasEstablishedPDC()); CHECK(b.manager().hasEstablishedPDC());
    a.close(); b.close(); CHECK(loop.pending() == 0);
    loop.run();
    return trace.events();
}

int main() {
    try {
        const auto first = run_simulation(), second = run_simulation();
        CHECK(first.size() == second.size());
        for (size_t i=0; i<first.size(); ++i) {
            CHECK(first[i].time == second[i].time); CHECK(first[i].node == second[i].node);
            CHECK(first[i].event == second[i].event); CHECK(first[i].value == second[i].value);
        }
        std::cout << "PASS: original SES/PDS/IPDC/TPDC handshake and semantic response under repeatable virtual time\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
