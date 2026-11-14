#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

enum class DatagramViolation { Oversized, WrongOpcode, Incomplete, LengthMismatch, WrongJob, WrongGeneration, SmallFormat };

static void reject_without_consuming_posting(bool medium,DatagramViolation violation) {
    EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,42);
    auto& forward=fabric.add_host(1); auto& reverse=fabric.add_host(2);
    fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
    PdsHost sender(1,loop,trace,forward),responder(2,loop,trace,reverse);
    Endpoint target(2,responder,loop,trace,64); target.memory().add_job(1);
    const auto region=target.memory().register_region(1,1,128,7);
    target.post_receive(1,1,region.key,0,128,99);
    SES_PDS_req request{}; request.src_fep=1; request.dst_fep=2; request.mode=UUD; request.tx_pkt_handle=7;
    request.next_hdr=medium?UET_HDR_REQUEST_MEDIUM:UET_HDR_REQUEST_STD;
    request.pkt.bth_type=medium?Small_Message_RMA_Header:Standard_Header;
    const auto fill=[&](auto& header) {
        header.opcode=violation==DatagramViolation::WrongOpcode?1:7;
        header.som=1; header.eom=violation!=DatagramViolation::Incomplete; header.rel=1;
        header.job_id=violation==DatagramViolation::WrongJob?2:1;
        header.PIDonFEP=header.resource_index=1;
        header.ri_generation=violation==DatagramViolation::WrongGeneration?1:0;
        header.request_length=violation==DatagramViolation::Oversized?65:violation==DatagramViolation::LengthMismatch?7:8;
    };
    if (violation==DatagramViolation::SmallFormat) {
        request.next_hdr=UET_HDR_REQUEST_SMALL; request.pkt.bth_type=Optimized_Header;
        fill(request.pkt.bth_header.Optimized_Header);
    } else if (medium) fill(request.pkt.bth_header.Small_Message_RMA_Header);
    else fill(request.pkt.bth_header.Standard_Header);
    request.pkt.payload.assign(violation==DatagramViolation::Oversized?65:8,0x71);
    const size_t base_header_bytes=violation==DatagramViolation::SmallFormat?20:medium?32:44;
    request.pkt_len=static_cast<uint16_t>(base_header_bytes+request.pkt.payload.size());
    CHECK(sender.submit(request)); loop.run_until(kMillisecond);
    Completion completion{};
    if (target.poll_completion(completion)) throw std::runtime_error("invalid UUD request consumed a posting: medium="+
        std::to_string(medium)+" violation="+std::to_string(unsigned(violation)));
    CHECK(target.memory().read(1,1,region.key,0,128)==std::vector<uint8_t>(128));
    CHECK(fabric.stats(2,1).packets==0 && !responder.manager().getPDSStatus().open_cnt && !target.retained_receive_messages());
    // A valid standard datagram must still find the same posting afterward.
    request.next_hdr=UET_HDR_REQUEST_STD; request.pkt.bth_type=Standard_Header;
    auto& header=request.pkt.bth_header.Standard_Header; header={};
    header.opcode=7; header.som=header.eom=header.rel=1; header.job_id=header.PIDonFEP=header.resource_index=1;
    header.request_length=8; request.pkt.payload.assign(8,0x53); request.pkt_len=52;
    CHECK(sender.submit(request)); loop.run_until(2*kMillisecond);
    CHECK(target.poll_completion(completion) && completion.context==99 && completion.length==8 && !target.poll_completion(completion));
    CHECK(target.memory().read(1,1,region.key,0,8)==std::vector<uint8_t>(8,0x53) && fabric.stats(2,1).packets==0);
    target.close(); sender.close(); responder.close(); CHECK(!loop.pending());
}

int main() {
    try {
        for (bool medium:{false,true}) for (auto violation:{DatagramViolation::Oversized,DatagramViolation::WrongOpcode,
            DatagramViolation::Incomplete,DatagramViolation::LengthMismatch,DatagramViolation::WrongJob,
            DatagramViolation::WrongGeneration,DatagramViolation::SmallFormat}) reject_without_consuming_posting(medium,violation);
        std::cout << "PASS14 malformed UUD drops preserve postings, enforce payload MTU and generate no ACK/context\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
