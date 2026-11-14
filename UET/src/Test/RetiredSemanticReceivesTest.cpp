#include "Check.hpp"
#include "../Runtime/RetiredSemanticReceives.hpp"
#include <iostream>
using namespace UET::Runtime;

int main() {
    try {
        RetiredSemanticReceives retired;
        const RetiredSemanticReceives::Key key{2,512,0,7,9,100};
        retired.retain(key,{4,0,false,false,0x1f,3,1});
        const auto clear=[&](uint32_t sequence,uint32_t peer=2,uint16_t pdc=512,uint32_t epoch=100) {
            retired.observe({PdcEventKind::ReceiveCleared,pdc,peer,epoch,sequence});
        };
        clear(10); CHECK(retired.size()==1); // A cleared prefix has no EOM.
        const auto first=retired.answer(key,UINT32_MAX,true);
        CHECK(first && first->guaranteed && first->modified_length==4 && first->return_code==0x1f &&
            first->generation==3 && first->response_list==1);
        const auto repeat=retired.answer(key,UINT32_MAX-1,false);
        CHECK(repeat && !repeat->guaranteed);
        clear(UINT32_MAX-1); clear(0,3); clear(0,2,513); clear(0,2,512,101); CHECK(retired.size()==1);
        clear(0); CHECK(!retired.size()); // Real Clear can wrap across EOM.
        retired.retain(key,{0,0,false,false,0x1f});
        retired.observe({PdcEventKind::TransmitCleared,512,2,100,10}); CHECK(retired.size()==1);
        retired.observe({PdcEventKind::ConnectionClosed,512,2,101,0}); CHECK(retired.size()==1);
        retired.observe({PdcEventKind::ConnectionClosed,512,2,100,0}); CHECK(!retired.size());
        auto optimized=key; std::get<4>(optimized)=RetiredSemanticReceives::packet_identity|9;
        retired.retain(key,{0,0,false,false,0x1f}); retired.retain(optimized,{0,0,false,false,0x1f});
        CHECK(retired.size()==2); retired.clear(); CHECK(!retired.size());
        std::cout<<"PASS retired receive prefix/EOM/role/peer/epoch/wrap and optimized identity boundaries\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
