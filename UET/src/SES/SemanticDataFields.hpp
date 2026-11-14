#pragma once
#include "../Transport_Layer.hpp"
#include <stdexcept>

namespace UET::SES {
// Table3-18: a DATA_SMALL single-packet result omits both MIDs, its offset,
// and a separate modified length. These are local projections, never bytes
// added to the wire. Fetching dual-operand results need the exact request's
// length instead of payload_length; the PDS ACK validation supplies it.
inline SES_Semantic_Response_with_Data_Header small_data_fields(const SES_Optimized_Response_with_Data_Header& compact) {
    SES_Semantic_Response_with_Data_Header full{};
    full.opcode=compact.opcode; full.version=compact.version; full.return_code=compact.return_code;
    full.list=compact.list; full.job_id=compact.job_id; full.payload_length=compact.payload_length;
    full.modified_length=compact.payload_length;
    return full;
}
inline void compact_data_response(SEStoPDS_pkt& response,uint32_t original_request_psn) {
    if (response.bth_type!=Semantic_Response_with_Data_Header)
        throw std::logic_error("only a full local data result can be compacted");
    const auto full=response.bth_header.Semantic_Response_with_Data_Header;
    response.bth_type=Optimized_Response_with_Data_Header;
    auto& compact=response.bth_header.Optimized_Response_with_Data_Header;
    compact={}; compact.opcode=full.opcode; compact.version=full.version; compact.return_code=full.return_code;
    compact.list=full.list; compact.job_id=full.job_id; compact.payload_length=full.payload_length;
    compact.original_request_psn=original_request_psn;
}
} // namespace UET::SES
