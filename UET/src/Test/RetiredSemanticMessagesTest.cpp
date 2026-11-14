#include "Check.hpp"
#include "../Runtime/RetiredSemanticMessages.hpp"
#include <iostream>
using namespace UET::Runtime;

int main() {
    try {
        for (uint32_t last:{0u,UINT32_MAX}) {
            RetiredSemanticMessages retired;
            retired.retain(1,{2,0}); // Job0 is a real Job, not an unspecified scope.
            retired.observe({PdcEventKind::RequestTransmitted,512,2,17,last,0,1,PdcFailureReason::None,true},512);
            retired.observe({PdcEventKind::TransmitCleared,1,2,17,last},512);
            CHECK(retired.contains(1)); // A target response token cannot bind a source lease.
            retired.observe({PdcEventKind::RequestTransmitted,1,2,17,last,1,1,PdcFailureReason::None,true},512);
            retired.observe({PdcEventKind::TransmitCleared,1,2,17,last},512);
            CHECK(retired.contains(1)); // Wrong Job must not acquire an unbound lease.
            retired.observe({PdcEventKind::RequestTransmitted,1,2,17,last,0,1,PdcFailureReason::None,true},512);
            retired.observe({PdcEventKind::RequestTransmitted,1,2,17,last-1,0,1},512);
            retired.observe({PdcEventKind::TransmitCleared,1,2,18,last},512);
            retired.observe({PdcEventKind::TransmitCleared,1,3,17,last},512);
            retired.observe({PdcEventKind::TransmitCleared,1,2,17,last-1},512);
            CHECK(retired.contains(1)); // Epoch, FEP and serial-number checks precede reuse.
            retired.observe({PdcEventKind::TransmitCleared,1,2,17,last},512);
            CHECK(!retired.size());

            retired.retain(2,{2,0,1,17,last,false});
            retired.observe({PdcEventKind::TransmitCleared,1,2,17,last},512);
            CHECK(retired.contains(2)); // A partial message has no EOM frontier.
            retired.observe({PdcEventKind::ConnectionClosed,1,2,17,last},512); CHECK(!retired.size());

            retired.retain(3,{2,0,1,17,last,true,false,true});
            size_t closes=0;
            retired.request_read_retirement([&](uint16_t context) { CHECK(context==1); ++closes; return true; });
            retired.request_read_retirement([&](uint16_t) { ++closes; return true; });
            CHECK(closes==1);
            retired.observe({PdcEventKind::TransmitCleared,1,2,17,last},512); CHECK(retired.contains(3));
            retired.observe({PdcEventKind::ConnectionClosed,1,2,17,last},512); CHECK(!retired.size());
        }
        RetiredSemanticMessages retired;
        retired.retain(4,{2,0});
        retired.observe({PdcEventKind::RequestRejected,UINT16_MAX,3,0,0,0,4},512); CHECK(retired.contains(4));
        retired.observe({PdcEventKind::RequestRejected,UINT16_MAX,2,0,0,0,4},512); CHECK(!retired.size());
        retired.retain(5,{2,0,UINT16_MAX,0,0,false,true});
        retired.observe({PdcEventKind::RequestRejected,UINT16_MAX,2,0,0,0,5},512); CHECK(retired.contains(5));
        retired.datagram_completed(6); CHECK(retired.contains(5));
        retired.datagram_completed(5); CHECK(!retired.size());
        std::cout<<"PASS retired message leases, binding, wrap, Clear/Close, READ and datagram boundaries\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
