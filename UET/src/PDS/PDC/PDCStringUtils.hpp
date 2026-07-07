#ifndef PDC_STRING_UTILS_HPP
#define PDC_STRING_UTILS_HPP

#include "../../Transport_Layer.hpp"

#include <string>

inline std::string pdcStateToString(pdc_state state)
{
    switch (state) {
        case CLOSED: return "CLOSED";
        case CREATING: return "CREATING";
        case ESTABLISHED: return "ESTABLISHED";
        case QUIESCE: return "QUIESCE";
        case ACK_WAIT: return "ACK_WAIT";
        case CLOSE_ACK_WAIT: return "CLOSE_ACK_WAIT";
        case PENDING: return "PENDING";
        default: return "UNKNOWN_STATE(" + std::to_string(static_cast<int>(state)) + ")";
    }
}

inline std::string pdcModeToString(pdc_mode mode)
{
    switch (mode) {
        case RUD: return "RUD";
        case ROD: return "ROD";
        case RUDI: return "RUDI";
        case UUD: return "UUD";
        default: return "UNKNOWN_MODE(" + std::to_string(static_cast<int>(mode)) + ")";
    }
}

inline std::string cmTypeToString(cm_type type)
{
    switch (type) {
        case NOOP: return "NOOP";
        case ACK_REQ: return "ACK_REQ";
        case CLR_CMD: return "CLEAR_CMD";
        case CLR_REQ: return "CLEAR_REQ";
        case CLOSE_CMD: return "CLOSE_CMD";
        case CLOSE_REQ: return "CLOSE_REQ";
        case PROBE: return "PROBE";
        case CREDIT: return "CREDIT";
        case CREDIT_REQ: return "CREDIT_REQ";
        case SACK_CTRL: return "SACK_CTRL";
        case NEGOTIATION: return "NEGOTIATION";
        case NONE: return "NONE";
        default: return "UNKNOWN_CM_TYPE(" + std::to_string(static_cast<int>(type)) + ")";
    }
}

inline std::string errorTypeToString(error_type type)
{
    switch (type) {
        case OPEN: return "OPEN";
        case ACK_ERROR: return "ACK_ERROR";
        case OOO: return "OOO";
        case OOO_ACCEPT: return "OOO_ACCEPT";
        case DROP: return "DROP";
        case INV_SYN: return "INV_SYN";
        case INV_DPDCID: return "INV_DPDCID";
        default: return "UNKNOWN_ERROR_TYPE(" + std::to_string(static_cast<int>(type)) + ")";
    }
}

inline std::string pdsTypeToString(PDS_type type)
{
    switch (type) {
        case Reserved: return "Reserved";
        case TSS: return "TSS";
        case RUD_REQ: return "RUD_REQ";
        case ROD_REQ: return "ROD_REQ";
        case RUDI_REQ: return "RUDI_REQ";
        case RUDI_RESP: return "RUDI_RESP";
        case UUD_REQ: return "UUD_REQ";
        case ACK: return "ACK";
        case ACK_CC: return "ACK_CC";
        case ACK_CCX: return "ACK_CCX";
        case NACK: return "NACK";
        case CP: return "CP";
        case NACK_CCX: return "NACK_CCX";
        case RUD_CC_REQ: return "RUD_CC_REQ";
        case ROD_CC_REQ: return "ROD_CC_REQ";
        default: return "UNKNOWN_PDS_TYPE(" + std::to_string(static_cast<int>(type)) + ")";
    }
}

inline std::string pdsHeaderTypeToString(PDS_header_type type)
{
    switch (type) {
        case entropy_header: return "entropy_header";
        case RUOD_req_header: return "RUOD_req_header";
        case RUOD_ack_header: return "RUOD_ack_header";
        case RUOD_cp_header: return "RUOD_cp_header";
        case nack_header: return "nack_header";
        default: return "UNKNOWN_HEADER_TYPE(" + std::to_string(static_cast<int>(type)) + ")";
    }
}

inline std::string pdsNextHdrToString(PDS_next_hdr type)
{
    switch (type) {
        case UET_HDR_REQUEST_SMALL: return "UET_HDR_REQUEST_SMALL";
        case UET_HDR_REQUEST_MEDIUM: return "UET_HDR_REQUEST_MEDIUM";
        case UET_HDR_REQUEST_STD: return "UET_HDR_REQUEST_STD";
        case UET_HDR_RESPONSE: return "UET_HDR_RESPONSE";
        case UET_HDR_RESPONSE_DATA: return "UET_HDR_RESPONSE_DATA";
        case UET_HDR_RESPONSE_DATA_SMALL: return "UET_HDR_RESPONSE_DATA_SMALL";
        case UET_HDR_NONE: return "UET_HDR_NONE";
        default: return "UNKNOWN_NEXT_HDR(" + std::to_string(static_cast<int>(type)) + ")";
    }
}

inline std::string pdsCtlTypeToString(PDS_ctl_type type)
{
    switch (type) {
        case Noop: return "Noop";
        case ACK_req: return "ACK_req";
        case Clear_cmd: return "Clear_cmd";
        case Clear_req: return "Clear_req";
        case Close_cmd: return "Close_cmd";
        case Close_req: return "Close_req";
        case Probe: return "Probe";
        case Credit: return "Credit";
        case Credit_req: return "Credit_req";
        case SACK: return "SACK";
        case Negotiation: return "Negotiation";
        default: return "UNKNOWN_CTL_TYPE(" + std::to_string(static_cast<int>(type)) + ")";
    }
}

inline std::string nackCodeToString(PDS_Nack_Codes code)
{
    switch (code) {
        case UET_TRIMMED: return "UET_TRIMMED";
        case UET_TRIMMED_LASTHOP: return "UET_TRIMMED_LASTHOP";
        case UET_TRIMMED_ACK: return "UET_TRIMMED_ACK";
        case UET_NO_PDC_AVAIL: return "UET_NO_PDC_AVAIL";
        case UET_NO_CCC_AVAIL: return "UET_NO_CCC_AVAIL";
        case UET_NO_BITMAP: return "UET_NO_BITMAP";
        case UET_NO_PKT_BUFFER: return "UET_NO_PKT_BUFFER";
        case UET_NO_GTD_DEL_AVAIL: return "UET_NO_GTD_DEL_AVAIL";
        case UET_NO_SES_MSG_AVAIL: return "UET_NO_SES_MSG_AVAIL";
        case UET_NO_RESOURCE: return "UET_NO_RESOURCE";
        case UET_PSN_OOR_WINDOW: return "UET_PSN_OOR_WINDOW";
        case reserved: return "reserved";
        case UET_ROD_OOO: return "UET_ROD_OOO";
        case UET_INV_DPDCID: return "UET_INV_DPDCID";
        case UET_PDC_HDR_MISMATCH: return "UET_PDC_HDR_MISMATCH";
        case UET_CLOSING: return "UET_CLOSING";
        case UET_CLOSING_IN_ERR: return "UET_CLOSING_IN_ERR";
        case UET_PKT_NOT_RCVD: return "UET_PKT_NOT_RCVD";
        case UET_GTD_RESP_UNAVAIL: return "UET_GTD_RESP_UNAVAIL";
        case UET_ACK_WITH_DATA: return "UET_ACK_WITH_DATA";
        case UET_INVALID_SYN: return "UET_INVALID_SYN";
        case UET_PDC_MODE_MISMATCH: return "UET_PDC_MODE_MISMATCH";
        case UET_NEW_START_PSN: return "UET_NEW_START_PSN";
        case UET_RCVD_SES_PROCG: return "UET_RCVD_SES_PROCG";
        case UET_UNEXP_EVENT: return "UET_UNEXP_EVENT";
        case UET_RCVR_INFER_LOSS: return "UET_RCVR_INFER_LOSS";
        default: return "UNKNOWN_NACK_CODE(0x" + std::to_string(static_cast<int>(code)) + ")";
    }
}

#endif
