#pragma once
#include "../Transport_Layer.hpp"
#include "MemoryKey.hpp"
#include <optional>

namespace UET::SES {
// An internal field view, never a second wire format. The legacy SES/PDS
// engine can share address/operation validation without reading a different
// active union member as Standard_Header. Preserve the original format so
// a missing MID is correlated by PSN rather than invented on the wire.
struct SemanticRequestFields {
    SES_Standard_Header header{};
    SES_BTH_header_type wire_format=Standard_Header;
    bool has_message_id=true;
};
inline std::optional<SemanticRequestFields> semantic_request_fields(const SEStoPDS_pkt& semantic) {
    SemanticRequestFields result; result.wire_format=semantic.bth_type;
    if (semantic.bth_type==Standard_Header) { result.header=semantic.bth_header.Standard_Header; return result; }
    if (semantic.bth_type!=Optimized_Header && semantic.bth_type!=Small_Message_RMA_Header) return {};
    result.has_message_id=false;
    const auto copy_common=[&](const auto& source) {
        auto& header=result.header;
        header.opcode=source.opcode; header.version=source.version; header.dc=source.dc; header.ie=source.ie;
        header.rel=source.rel; header.hd=source.hd; header.som=source.som; header.eom=source.eom;
        header.request_length=source.request_length; header.ri_generation=source.ri_generation;
        header.job_id=source.job_id; header.PIDonFEP=source.PIDonFEP; header.resource_index=source.resource_index;
        header.buffer_offset=source.buffer_offset;
        // §3.4.4.3: responses to requests without MID carry MID0. A local
        // submission handle is separate metadata and must never replace it.
        header.msg_id=0;
    };
    if (semantic.bth_type==Optimized_Header) {
        copy_common(semantic.bth_header.Optimized_Header);
        // These historical internal enum names map to SMALL20B and MEDIUM32B
        // respectively; neither denotes the M8 Unified Local formats.
        result.header.hd=0;
        // Table2-14: RKEY/INDEX is carried in resource_index. This placeholder
        // is not authorization; target SES must resolve its live MR scope.
        result.header.match_bits=MemoryKeyFormat::Optimized|result.header.resource_index;
    } else {
        const auto& source=semantic.bth_header.Small_Message_RMA_Header; copy_common(source);
        result.header.initiator=source.initiator; result.header.match_bits=source.match_bits;
        if (source.hd) {
            result.header.buffer_offset=0;
            result.header.diff.som_true.header_data=source.header_data;
        }
    }
    return result;
}
inline uint16_t local_submission_message(const SES_PDS_req& request) {
    const auto fields=semantic_request_fields(request.pkt);
    return fields && fields->has_message_id?fields->header.msg_id:request.tx_pkt_handle;
}
} // namespace UET::SES
