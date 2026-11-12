#include "Check.hpp"
#include "../SES/Endpoint.hpp"
#include "../Runtime/Fabric.hpp"
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

int main() {
    try {
        EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,123);
        auto& pa=fabric.add_host(1); auto& pb=fabric.add_host(2);
        fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
        PdsHost a(1,loop,trace,pa), b(2,loop,trace,pb);
        Endpoint source(1,a,loop,trace), target(2,b,loop,trace);
        source.memory().add_job(1); target.memory().add_job(1);
        auto region=target.memory().register_region(1,1,65536,7);
        Operation write; write.type=OperationType::Write; write.peer=2;
        write.remote_key=region.key; write.remote_offset=17; write.context=42;
        write.payload.resize(257); for (size_t i=0; i<write.payload.size(); ++i) write.payload[i]=i*7;
        const auto id=source.submit(write);
        loop.run_until(5*kMillisecond);
        Completion completion{};
        CHECK(source.poll_completion(completion)); CHECK(completion.operation==id);
        CHECK(completion.status==CompletionStatus::Success); CHECK(completion.context==42);
        CHECK(target.memory().read(1,1,region.key,17,257)==write.payload);
        CHECK(!source.poll_completion(completion));

        // A second operation reuses the established real PDC, with a different
        // message ID, and crosses multiple packet boundaries.
        write.remote_offset=4090; write.payload.resize(20000,0xa5);
        source.submit(write); loop.run_until(10*kMillisecond);
        CHECK(source.poll_completion(completion)); CHECK(completion.status==CompletionStatus::Success);
        CHECK(target.memory().read(1,1,region.key,4090,20000)==write.payload);

        target.post_receive(1,1,region.key,8192,1024,99);
        Operation send; send.peer=2; send.payload={1,0,2,0,3};
        source.submit(send); loop.run_until(15*kMillisecond);
        CHECK(source.poll_completion(completion)); CHECK(completion.status==CompletionStatus::Success);
        CHECK(target.poll_completion(completion)); CHECK(completion.receive); CHECK(completion.context==99);
        CHECK(target.memory().read(1,1,region.key,8192,5)==send.payload);

        const auto before=target.memory().read(1,1,region.key,0,16);
        write.remote_key^=0x100000; write.payload={9}; write.remote_offset=0;
        source.submit(write); loop.run_until(20*kMillisecond);
        CHECK(source.poll_completion(completion)); CHECK(completion.status==CompletionStatus::RemoteError);
        CHECK(completion.remote_code==0x1c);
        CHECK(target.memory().read(1,1,region.key,0,16)==before);
        Operation unsupported; unsupported.type=OperationType::Atomic; unsupported.peer=2;
        source.submit(unsupported);
        CHECK(source.poll_completion(completion)); CHECK(completion.status==CompletionStatus::Unsupported);
        CHECK(!source.capabilities().ai_base); CHECK(!source.capabilities().atomic);
        Operation noop; noop.type=OperationType::Noop; noop.peer=2;
        source.submit(noop); loop.run_until(25*kMillisecond);
        CHECK(source.poll_completion(completion)); CHECK(completion.status==CompletionStatus::Success);

        // Unsupported address/header interpretations must be rejected on the
        // receiver, even when a peer bypasses the native submit validator.
        std::vector<uint8_t> codes;
        a.set_response_handler([&](const PDC_SES_rsp& response) {
            if (response.pkt.bth_type==Semantic_Response_Header)
                codes.push_back(response.pkt.bth_header.Semantic_Response_Header.return_code);
        });
        for (size_t variant=0;variant<3;++variant) {
            SES_PDS_req request{};
            request.src_fep=1; request.dst_fep=2; request.mode=ROD;
            request.next_hdr=UET_HDR_REQUEST_STD; request.rod_context=1; request.lock_pdc=true;
            request.tx_pkt_handle=60000+variant; request.pkt_len=45;
            request.pkt.bth_type=Standard_Header;
            auto& h=request.pkt.bth_header.Standard_Header;
            h.opcode=1; h.som=1; h.eom=1; h.dc=1; h.rel=variant!=0;
            h.hd=variant==1; h.ri_generation=variant==2;
            h.msg_id=60000+variant; h.job_id=1; h.PIDonFEP=1; h.resource_index=1;
            h.initiator=1; h.match_bits=region.key; h.request_length=1;
            request.pkt.payload={0x99};
            CHECK(a.submit(request)); loop.run_until((30+variant*5)*kMillisecond);
            CHECK(codes.size()==variant+1); CHECK(codes.back()==(variant==2?0x1a:0x06));
            CHECK(target.memory().read(1,1,region.key,0,16)==before);
        }
        source.close(); target.close(); a.close(); b.close();
        CHECK(loop.pending()==0);
        std::cout << "PASS: native asynchronous WRITE/SEND/NO_OP through original PDC and standard packets, multi-packet memory effects and remote rejection\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
