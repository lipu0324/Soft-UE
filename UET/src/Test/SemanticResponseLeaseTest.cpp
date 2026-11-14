#include "Check.hpp"
#include "../Runtime/RetiredSemanticMessages.hpp"
#include <iostream>
using namespace UET::Runtime;

int main() {
    try {
        for (uint32_t sequence:{0u,UINT32_MAX}) {
            RetiredSemanticMessages sources,responses;
            sources.retain(7,{1,0,1,17,sequence,true});
            responses.retain(7,{1,0,512,17,0,false});
            const PdcEvent transmitted{PdcEventKind::RequestTransmitted,512,1,17,sequence,0,7,PdcFailureReason::None,true};
            sources.observe(transmitted,512); responses.observe(transmitted,1024,512);
            const PdcEvent source_clear{PdcEventKind::TransmitCleared,1,1,17,sequence};
            sources.observe(source_clear,512); responses.observe(source_clear,1024,512);
            CHECK(!sources.size() && responses.contains(7)); // Same number, independent source/target namespaces.
            responses.observe({PdcEventKind::RequestRejected,UINT16_MAX,1,0,0,0,7},1024,512);
            responses.observe({PdcEventKind::TransmitCleared,512,1,18,sequence},1024,512);
            responses.observe({PdcEventKind::TransmitCleared,512,2,17,sequence},1024,512);
            responses.observe({PdcEventKind::TransmitCleared,512,1,17,sequence-1},1024,512);
            CHECK(responses.contains(7));
            responses.observe({PdcEventKind::TransmitCleared,512,1,17,sequence},1024,512); CHECK(!responses.size());
            responses.retain(8,{1,0,512,17,0,false});
            responses.observe({PdcEventKind::TransmitCleared,512,1,17,sequence},1024,512); CHECK(responses.contains(8));
            responses.observe({PdcEventKind::ConnectionClosed,512,1,17,sequence},1024,512); CHECK(!responses.size());
        }
        std::cout<<"PASS source/target response lease role isolation, Job0, queued TX, epoch and PSN wrap\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
