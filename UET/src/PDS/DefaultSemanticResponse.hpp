#pragma once
#include "../Transport_Layer.hpp"

namespace UET::PDS {
// UE 1.1 §3.5.13, Table 3-69: reconstruct only the default result. A
// guaranteed result must be replayed from the receiver's response cache.
inline SEStoPDS_pkt default_semantic_response(const SEStoPDS_pkt& original_request) {
    SEStoPDS_pkt response{};
    response.bth_type=Semantic_Response_Header;
    const auto& request=original_request.bth_header.Standard_Header;
    auto& semantic=response.bth_header.Semantic_Response_Header;
    semantic.opcode=0; semantic.return_code=1;
    semantic.message_id=request.msg_id; semantic.job_id=request.job_id;
    semantic.ri_generation=request.ri_generation; semantic.modified_length=request.request_length;
    return response;
}
}
