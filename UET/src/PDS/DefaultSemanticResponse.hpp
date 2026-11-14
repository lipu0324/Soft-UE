#pragma once
#include "../Transport_Layer.hpp"
#include "../SES/SemanticRequestFields.hpp"

namespace UET::PDS {
// UE 1.1 §3.5.13, Table 3-69: reconstruct only the default result. A
// guaranteed result must be replayed from the receiver's response cache.
inline SEStoPDS_pkt default_semantic_response(const SEStoPDS_pkt& original_request) {
    SEStoPDS_pkt response{};
    response.bth_type=Semantic_Response_Header;
    auto& semantic=response.bth_header.Semantic_Response_Header;
    semantic.opcode=0; semantic.return_code=1;
    if (original_request.bth_type==Semantic_Response_with_Data_Header) {
        // §3.5.20.2.2: the ACK for return data echoes the target's response
        // message ID, not the original initiator READ message ID.
        const auto& request=original_request.bth_header.Semantic_Response_with_Data_Header;
        semantic.message_id=request.response_message_id; semantic.job_id=request.job_id;
        semantic.modified_length=request.modified_length;
    } else {
        const auto fields=UET::SES::semantic_request_fields(original_request);
        if (!fields) return response; // Not an SES request with reconstructible DEFAULT fields.
        const auto& request=fields->header;
        semantic.message_id=request.msg_id; semantic.job_id=request.job_id;
        semantic.ri_generation=request.ri_generation; semantic.modified_length=request.request_length;
    }
    return response;
}
}
