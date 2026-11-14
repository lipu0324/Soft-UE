#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

// This producer uses the original PDS directly. It intentionally sends the
// completing atomic first on a different PDC; the native source normally
// delays that transmission to avoid filling its own bounded send window.
struct IndependentSynchronizationPeer {
    EventLoop loop; Trace trace{loop}; Fabric fabric{loop,trace,42};
    IPacketPort& forward=fabric.add_host(1); IPacketPort& reverse=fabric.add_host(2);
    PdsHost source{1,loop,trace,forward},responder{2,loop,trace,reverse};
    Endpoint target{2,responder,loop,trace,16,20*kMillisecond};
    Region writes,atomic;
    std::map<uint16_t,std::vector<uint8_t>> results;
    RequestHeaderFormat format;
    pdc_mode mode;
    IndependentSynchronizationPeer(RequestHeaderFormat header_format,pdc_mode delivery,bool congestion):format(header_format),mode(delivery) {
        fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
        source.services().pdc_mapping.rud.include_source_pid=true;
        source.services().pdc_mapping.rod.include_source_pid=true;
        source.configure_semantic_payload_mtu(16);
        if (congestion) { source.enable_nscc({}); responder.enable_nscc({}); }
        target.memory().add_job(1);
        for (uint16_t index:{1,2,3}) target.resources().configure_resource(1,index,ResourceSpace::Rma);
        RegionOptions options; options.resource_index=1;
        options.requested_key=format==RequestHeaderFormat::Small?MemoryKeyFormat::Optimized|1:0x1111;
        writes=target.memory().register_region(1,1,64,7,options);
        options.resource_index=2; options.requested_key=format==RequestHeaderFormat::Small?MemoryKeyFormat::Optimized|2:0x2222;
        atomic=target.memory().register_region(1,1,8,7,options);
        source.set_response_handler([this](const PDC_SES_rsp& response) {
            CHECK(response.pkt.bth_type==Semantic_Response_Header);
            const auto& semantic=response.pkt.bth_header.Semantic_Response_Header;
            CHECK(!semantic.message_id && semantic.return_code);
            // Optimized requests have no wire MID. The original PDS supplies
            // the trusted local submission handle, not an invented peer ID.
            results[response.local_submission_id].push_back(semantic.return_code);
        });
    }
    SES_PDS_req packet(uint16_t local_submission,bool completing,uint64_t offset=0,bool bad_key=false) {
        SES_PDS_req request{}; request.src_fep=1; request.dst_fep=2; request.source_pid=completing?2:1;
        request.mode=mode; request.rod_context=1; request.lock_pdc=true; request.tx_pkt_handle=local_submission;
        const bool small=format==RequestHeaderFormat::Small;
        request.next_hdr=small?UET_HDR_REQUEST_SMALL:UET_HDR_REQUEST_MEDIUM;
        request.pkt.bth_type=small?Optimized_Header:Small_Message_RMA_Header;
        const uint64_t memory_key=bad_key?(small?MemoryKeyFormat::Optimized|3:UINT64_MAX):completing?atomic.key:writes.key;
        const auto fill=[&](auto& header) {
            header.opcode=completing?0x11:0x10; header.som=header.eom=header.dc=header.rel=1;
            header.job_id=header.PIDonFEP=1; header.resource_index=bad_key?3:completing?2:1;
            header.request_length=completing?8:4; header.buffer_offset=offset;
        };
        if (small) fill(request.pkt.bth_header.Optimized_Header);
        else {
            auto& header=request.pkt.bth_header.Small_Message_RMA_Header; fill(header);
            header.initiator=7; header.match_bits=memory_key;
        }
        request.pkt.eth_type=completing?Synchronized_Atomic_Extension_Headers:Synchronized_Operation_Extension_Header;
        auto& synchronization=completing?request.pkt.eth_header.Synchronized_Atomic_Extension_Headers.synchronization:
            request.pkt.eth_header.Synchronized_Operation_Extension_Header;
        synchronization.sync_group=42; synchronization.sync_count=completing?3:0;
        if (completing) {
            auto& atomic_extension=request.pkt.eth_header.Synchronized_Atomic_Extension_Headers.atomic;
            atomic_extension.atomic_opcode=2; atomic_extension.atomic_datatype=7;
            request.pkt.payload={0,0,0,0,0,0,0,5}; // Literal network-order SUM operand.
        } else request.pkt.payload.assign(4,0x33);
        request.pkt_len=static_cast<uint16_t>((small?20:32)+(completing?8:4)+request.pkt.payload.size());
        return request;
    }
    void send(const SES_PDS_req& request) { CHECK(source.submit(request)); }
    void close() { target.close(); source.close(); responder.close(); CHECK(!loop.pending()); }
};

static void barrier(RequestHeaderFormat format,pdc_mode mode,bool congestion,bool revoke,bool failed_member) {
    IndependentSynchronizationPeer peer(format,mode,congestion);
    peer.send(peer.packet(1,true)); peer.loop.run_until(kMillisecond);
    CHECK(peer.results[1].empty() && peer.target.memory().read(1,1,peer.atomic.key,0,8,2)==std::vector<uint8_t>(8));
    if (revoke) {
        CHECK(peer.target.memory().deregister(peer.atomic));
        RegionOptions options; options.requested_key=peer.atomic.key; options.resource_index=2;
        peer.atomic=peer.target.memory().register_region(1,1,8,7,options);
    }
    peer.send(peer.packet(2,false,0,failed_member)); peer.loop.run_until(2*kMillisecond);
    CHECK(peer.results[1].empty() && peer.target.memory().read(1,1,peer.atomic.key,0,8,2)==std::vector<uint8_t>(8));
    peer.send(peer.packet(3,false,16)); peer.loop.run_until(90*kMillisecond);
    CHECK(peer.results[1]==std::vector<uint8_t>{static_cast<uint8_t>(revoke?SemanticReturnCode::BadMemoryKey:SemanticReturnCode::Ok)});
    CHECK(peer.results[2]==std::vector<uint8_t>{static_cast<uint8_t>(failed_member?SemanticReturnCode::BadMemoryKey:SemanticReturnCode::Ok)});
    CHECK(peer.results[3]==std::vector<uint8_t>{1});
    CHECK(peer.target.memory().read(1,1,peer.atomic.key,0,8,2)==
        (revoke?std::vector<uint8_t>(8):std::vector<uint8_t>{5,0,0,0,0,0,0,0}));
    CHECK(peer.target.memory().read(1,1,peer.writes.key,16,4,1)==std::vector<uint8_t>(4,0x33));
    CHECK(!peer.target.retained_synchronized_groups() && !peer.target.retained_synchronized_members() &&
        !peer.target.retained_synchronized_actions() && !peer.target.retained_receive_messages());
    Completion completion{}; CHECK(!peer.target.poll_completion(completion)); peer.close();
}

int main() {
    try {
        for (auto format:{RequestHeaderFormat::Small,RequestHeaderFormat::Medium}) for (auto mode:{RUD,ROD})
            for (bool congestion:{false,true}) for (bool revoke:{false,true}) for (bool failed:{false,true})
                barrier(format,mode,congestion,revoke,failed);
        std::cout << "PASS32 independent optimized cross-PDC barriers, exact MR revocation/key reuse and failed members\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
