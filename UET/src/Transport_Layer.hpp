/*******************************************************************************
 * Copyright 2025 Soft UE Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ******************************************************************************/

/**
 * @file             Transport_Layer.hpp
 * @brief            Transport_Layer.hpp
 * @author           softuegroup@gmail.com
 * @version          1.0.0
 * @date             2025-10-29
 * @copyright        Apache License Version 2.0
 *
 * @details
 * Transport_Layer.hpp
 */



#ifndef TRANSPORT_LAYER_HPP
#define TRANSPORT_LAYER_HPP

#include <cstdint>
#include <string>

//=============================================================================
// Cross-platform structure packing macro definitions
//=============================================================================

// GCC/Clang compiler
#if defined(__GNUC__) || defined(__clang__)
    #define PACKED __attribute__((packed))
// MSVC compiler
#elif defined(_MSC_VER)
    #define PACKED
    #pragma pack(push, 1)
// Other compilers
#else
    #define PACKED
    #pragma message("Warning: Using default packing - may not be portable")
#endif

// MSVC requires special ending marker
#if defined(_MSC_VER)
    #define PACKED_END #pragma pack(pop)
#else
    #define PACKED_END
#endif
//#include "SES/SES.hpp" 



//=============================================================================
// PDS layer configuration parameter definitions
//=============================================================================

#define MAX_PDC             512                     // Maximum number of PDCs per type
#define Base_RTO            100                    // Base retransmission timeout (milliseconds)
#define Pend_Timeout        100                    // Pending timeout (milliseconds)
#define Close_Thresh        4                      // Connection close threshold

// UET protocol operation mode configuration
#define UET_Over_UDP        1                      // Determines if UET runs over UDP (1=yes, 0=no)
#define UDP_Dest_Port       2887                   // When UET runs over UDP, this port number indicates subsequent protocol is UET
#define IP_Proto_Nxt_Hdr    0                      // Protocol number when UET runs directly over IP, can use experimental numbers (253-254) before official protocol number assignment
#define UET_Data_Protect    0                      // Global data protection configuration: 0=no CRC and TSS, 1=enable CRC, 2=enable TSS, 3=reserved
#define Limit_PSN_Range     1                      // When set, PDC closes when PSN reaches Start_PSN + 2^31 (optional security feature)
#define Default_MPR         8                      // Default MPR value assumed when creating PDC, 0 is invalid, if set to 0 then use 1

// ACK related configuration parameters
#define Max_ACK_Data_Size   16 * 8                 // Maximum return data that can be carried in PDS ACK (bytes)
#define Trimmable_ACK_Size  10 * 8 * 1024          // When ACK packets carrying read response data exceed this size, use trimmable DSCP
#define ACK_On_ECN          1                      // TRUE: ECN marked packet reception triggers ACK generation; FALSE: ACK generation not based on ECN marking
#define Enb_ACK_Per_Pkt     1                      // FALSE: use aggregated ACK; TRUE: one ACK per packet, source sets pds.flags.ar field in each PDS request
#define ACK_Gen_Trigger     16 * 8 * 1024          // Generate ACK when ACK_GEN_COUNT reaches this threshold (bytes)
#define ACK_Gen_Min_Pkt_Add 1 * 8 * 1024           // Minimum bytes added to ACK_GEN_COUNT when PDC receives packet

// Retransmission related configuration parameters
#define RTO_Init_Time       4                      // Initial retransmission timeout, retransmit packet if no ACK or NACK received within this time
#define Max_RTO_Retx_Cnt    5                      // Maximum retransmission count for a single packet before declaring failure, maximum value indicates infinite retry
#define NACK_Retx_Time      4                      // NACK packet retransmission delay configuration
#define Max_NACK_Retx_Cnt   5                      // Optional: separate threshold for NACK-based retransmission, may be higher than RTO retransmission threshold

// PDC management related configuration parameters
#define New_PDC_Timeout_Thresh 1024                // Threshold for reporting potential DoS attack errors, used with NEW_PDC_TIMEOUT_CNT
#define New_PDC_Time        50                     // Allowed time for PDC initiator to establish PDC when TSS is enabled
#define PDS_Clear_Time      500                    // Optional: configuration time to trigger Clear Command CP generation
#define Close_REQ_Time      50                     // Optional: time limit for initiator to respond to close request
#define Tail_Loss_Time      0                      // Optional: tail loss handling time
#define Max_Tail_Loss_Retx  0                      // Optional: maximum tail loss retransmission count

//=============================================================================
// PDS layer enumeration type definitions
//=============================================================================

/**
 * @brief PDS header type enumeration
 * @details Defines different header types supported by PDS layer, currently mainly implements ROD related functionality
 */
enum PDS_header_type{
    entropy_header,     // Entropy header, used for path selection
    RUOD_req_header,    // RUOD request header
    RUOD_ack_header,    // RUOD acknowledgment header
    RUOD_cp_header,     // RUOD control packet header
    nack_header         // Negative acknowledgment header
};

/**
 * @brief PDS packet type enumeration
 * @details Defines all packet types supported by PDS layer, including requests, responses, acknowledgments, control packets, etc.
 */
enum PDS_type {
    Reserved,       // Reserved type
    TSS,            // UET encryption header
    RUD_REQ,        // RUD request (Reliable Unordered Delivery)
    ROD_REQ,        // ROD request (Reliable Ordered Delivery)
    RUDI_REQ,       // RUDI request (Reliable Unordered Delivery with Immediate response)
    RUDI_RESP,      // RUDI response
    UUD_REQ,        // UUD request (Unreliable Unordered Delivery)
    ACK,            // Acknowledgment packet
    ACK_CC,         // Congestion control acknowledgment packet
    ACK_CCX,        // Extended congestion control acknowledgment packet
    NACK,           // Negative acknowledgment packet
    CP,             // Control packet (subtype encoded in CTL_TYPE field)
    NACK_CCX,       // Extended congestion control negative acknowledgment packet
    RUD_CC_REQ,     // Congestion control RUD request
    ROD_CC_REQ      // Congestion control ROD request
};

/**
 * @brief PDS next header type enumeration
 * @details Identifies encoding of UET semantic types
 */
enum PDS_next_hdr{
    UET_HDR_REQUEST_SMALL,      // Small request header
    UET_HDR_REQUEST_MEDIUM,     // Medium request header
    UET_HDR_REQUEST_STD,        // Standard request header
    UET_HDR_RESPONSE,           // Response header
    UET_HDR_RESPONSE_DATA,      // Response header with data
    UET_HDR_RESPONSE_DATA_SMALL,// Response header with small data
    UET_HDR_NONE                // No header
};

/**
 * @brief PDS control type enumeration
 * @details Defines various subtypes of control packets (CP)
 */
enum PDS_ctl_type{
    Noop,           // No operation
    ACK_req,        // Source requests ACK for specific PSN
    Clear_cmd,      // Initiator to target: clear target's guaranteed delivery PDS ACK status
    Clear_req,      // Target requests source to send clear command
    Close_cmd,      // Initiator indicates PDC is closing
    Close_req,      // Target requests initiator to close PDC
    Probe,          // Source to target: probe packet requesting PDS ACK
    Credit,         // Target to source: carries congestion control credit
    Credit_req,     // Source to target: request credit
    Negotiation     // Negotiation packet
};

/**
 * @brief PDS Negative Acknowledgment (NACK) code enumeration
 * @details Defines error types, source actions and description information corresponding to different NACK codes
 *          Error types: NORMAL (normal error), PDC_FATAL (PDC fatal error), PDC_ERR (PDC error)
 *          Source actions: RETX (retransmit), RETRY (retry), Close PDC, etc.
 */
enum PDS_Nack_Codes{
    UET_TRIMMED =           0x01,   // NORMAL    - RETX - Packet was trimmed
    UET_TRIMMED_LASTHOP =   0x02,   // NORMAL    - RETX - Packet was trimmed at last hop switch
    UET_TRIMMED_ACK =       0x03,   // NORMAL    - RETX original read request - ACK carrying read response data was trimmed
    UET_NO_PDC_AVAIL=       0x04,   // NORMAL    - Retry (PDC not created) - No available PDC resources, set pds.spdcid=0
    UET_NO_CCC_AVAIL=       0x05,   // NORMAL    - Retry (PDC not created) - No available CCC resources, set pds.spdcid=0
    UET_NO_BITMAP   =       0x06,   // NORMAL    - Retry (PDC not created) - No bitmap or PSN tracking resources, set pds.spdcid=0
    UET_NO_PKT_BUFFER=      0x07,   // NORMAL    - RETX - No packet buffer resources
    UET_NO_GTD_DEL_AVAIL=   0x08,   // NORMAL    - RETX - No SES guaranteed delivery response resources
    UET_NO_SES_MSG_AVAIL=   0x09,   // NORMAL    - RETX - No message tracking state resources
    UET_NO_RESOURCE=        0x0A,   // NORMAL    - RETX - General resource unavailable, set pds.spdcid=0 if no associated PDC
    UET_PSN_OOR_WINDOW=     0x0B,   // NORMAL    - RETX (if PSN>CACK then RETX) - PSN out of tracking window
    reserved=               0x0C,   // Reserved
    UET_ROD_OOO=            0x0D,   // NORMAL    - RETX - ROD PDC received out-of-order PSN
    UET_INV_DPDCID=         0x0E,   // PDC_FATAL - Close PDC (retry) - Unrecognized pds.dpdcid and pds.flags.syn not set, set pds.spdcid=0
    UET_PDC_HDR_MISMATCH=   0x0F,   // PDC_FATAL - Close PDC (retry) - Packet has no pds.flags.syn but doesn't match connection state, set pds.spdcid=0
    UET_CLOSING=            0x10,   // PDC_FATAL - Report error (retry) - Target PDCID in closing state or process, received new PDS request advancing PSN
    UET_CLOSING_IN_ERR=     0x11,   // PDC_FATAL - Close PDC (no retransmission) - Target timeout during closing process, e.g., no close request CP response
    UET_PKT_NOT_RCVD=       0x12,   // PDC_ERR   - RETX - Received ACK request CP but did not receive packet for requested PSN
    UET_GTD_RESP_UNAVAIL=   0x13,   // PDC_FATAL - Close PDC (failure, no retransmission) - Received duplicate PSN, state shows guaranteed delivery SES response exists but not found, and PSN not cleared
    UET_ACK_WITH_DATA=      0x14,   // PDC_ERR   - RETX (retransmit original packet) - Sent ACK request CP for PSN carrying read response data
    UET_INVALID_SYN=        0x15,   // PDC_FATAL - Close PDC (retry) - Received packet with pds.flags.syn set but pds.psn not in expected range
    UET_PDC_MODE_MISMATCH=  0x16,   // PDC_FATAL - Close PDC (retry) - Received packet's transmission mode doesn't match
    UET_NEW_START_PSN=      0x17,   // NORMAL    - RETX - Retransmit all packets using new Start_PSN
    UET_RCVD_SES_PROCG=     0x18,   // NORMAL    - RETX (ACK may arrive before RETX) - May occur when delayed packet and retransmitted packet arrive at target around same time
    UET_UNEXP_EVENT=        0x19,   // PDC_FATAL - Close PDC (retry) - Unexpected event, processing requires unsupported functionality, PDC cannot recover
    UET_RCVR_INFER_LOSS=    0x1A    // NORMAL    - RETX - Receiver infers PSN loss and requests retransmission, application specific
};

//=============================================================================
// PDS layer header structure definitions
//=============================================================================

/**
 * @brief UET entropy header
 * @details This header carries entropy value for network devices (e.g., switches) to use for path selection
 */
struct UET_entropy_header
{
    uint16_t entropy;               // Entropy value, generally used for path selection
} PACKED;

/**
 * @brief PDS RUOD request header structure
 * @details PDS header used for ROD/RUD requests, containing packet sequence number, connection ID, flags and other information
 */
struct PDS_RUOD_req_header
{
    PDS_type type : 5;              // 5 bits, packet type, e.g., ROD request or RUD request
    PDS_next_hdr next_hdr : 4;      // 4 bits, identifies UET semantic type encoding
    struct                          // 7 bits, pds.flags[6:0] = [rsvd, retx, ar, syn, rsvd]
    {
        uint8_t rsvd : 2;           // Reserved bits
        uint8_t retx : 1;           // Retransmission flag: 1 indicates this is a retransmitted packet
        uint8_t ar   : 1;           // ACK request flag: 1 indicates request to send ACK
        uint8_t syn  : 1;           // PDC establishment request flag: 1 indicates PDC establishment request
        uint8_t rsvd1: 2;           // Reserved bits
    } PACKED flags;
    uint16_t clear_psn_off;         // 16 bits, CLEAR_PSN offset encoding relative to PSN
    uint32_t psn;                   // 32 bits, packet sequence number assigned to PDS request
    uint16_t spdcid;                // 16 bits, source PDCID, allocated by packet source
    uint16_t dpdcid;                // 16 bits, destination PDCID, allocated by packet destination
    uint8_t pdc_info : 4;           // 4 bits, PDC information: Bit0=whether to use reserved PDC pool, Bit3:1 reserved
    uint16_t psn_off : 12;          // 12 bits, numerical difference between this packet's PSN and PDC's Start_PSN
}PACKED;

/**
 * @brief PDS RUOD acknowledgment header structure
 * @details Header used for PDS ACK packets, containing cumulative acknowledgment information and various flags
 */
struct PDS_RUOD_ack_header
{
    PDS_type type : 5;              // 5 bits, packet type = PDS ACK
    PDS_next_hdr next_hdr : 4;      // 4 bits, UET semantic type encoding
    struct                          // 7 bits, pds.flags[6:0] = [rsvd, m, retx, p, req, rsvd]
    {
        uint8_t rsvd : 1;           // Reserved bit
        uint8_t m    : 1;           // ECN mark: 1 indicates associated request packet was ECN marked
        uint8_t retx : 1;           // Retransmission ACK: 1 indicates this is ACK for retransmitted packet
        uint8_t p    : 1;           // Probe ACK: 1 indicates this is ACK for Probe CP, ignore ack_psn_offset and cack_psn
        uint8_t req  : 2;           // Request flag: request clear or close
        uint8_t rsvd1: 1;           // Reserved bit
    } PACKED flags;
    union{
        int16_t ack_psn_off;           // 16 bits, signed offset representation from CACK_PSN to ACK_PSN
        uint16_t probe_opaque;          // 16 bits, used by Probe CP, copied from Probe CP to ACK
    };
    uint32_t cack_psn;              // 32 bits, cumulative acknowledgment packet sequence number, all PDS requests with PSN ≤ this value are acknowledged
    uint16_t spdcid;                // 16 bits, source PDCID
    uint16_t dpdcid;                // 16 bits, destination PDCID
}PACKED;

/**
 * @brief PDS RUOD control packet (CP) header structure
 * @details Header used for various control packets, such as clear, close, probe and other commands
 */
struct PDS_RUOD_cp_header
{
    PDS_type type : 5;              // 5 bits, packet type = CP
    uint8_t ctl_type : 4;           // 4 bits, identifies CP type
    struct                          // pds.flags[6:0] = [rsvd, rsvd/isrod, retx, ar, syn, rsvd]
    {
        uint8_t rsvd  : 1;          // Reserved bit
        uint8_t isrod : 1;          // PDC type: 1=ROD PDC, 0=RUD PDC, only valid in NOOP and Negotiation
        uint8_t retx  : 1;          // Retransmission flag: 1 indicates this CP is a retransmission
        uint8_t ar    : 1;          // ACK request flag
        uint8_t syn   : 1;          // PDC establishment request flag
        uint8_t rsvd1 : 2;          // Reserved bits
    } PACKED flags;
    uint16_t probe_opaque;          // 16 bits, used by Probe CP, copied to ACK
    uint32_t psn;                   // 32 bits, packet sequence number assigned to PDS CP
    uint16_t spdcid;                // 16 bits, source PDCID
    uint16_t dpdcid;                // 16 bits, destination PDCID
    uint8_t pdc_info : 4;           // 4 bits, PDC information bits
    uint16_t psn_off : 12;          // 12 bits, numerical difference between this packet's PSN and PDC's Start_PSN
    uint32_t payload;               // 32 bits, payload data
}PACKED;

/**
 * @brief PDS NACK header structure
 * @details Header used for negative acknowledgment packets, containing error codes and related information
 */
struct PDS_nack_header
{
    PDS_type type : 5;              // 5 bits, packet type = PDS NACK
    PDS_next_hdr next_hdr : 4;      // 4 bits, UET semantic type encoding, NACK always set to UET_HDR_NONE
    struct                          // 7 bits, pds.flags[6:0] = [rsvd, m, retx, nt, rsvd]
    {
        uint8_t rsvd : 1;           // Reserved bit
        uint8_t m    : 1;           // ECN mark: 1 indicates associated request packet was ECN marked
        uint8_t retx : 1;           // Retransmission flag: 1 indicates NACKed packet is a retransmitted packet
        uint8_t nt   : 1;           // NACK type: 0=RUD/ROD, 1=RUDI
        uint8_t rsvd1: 3;           // Reserved bits
    } PACKED flags;
    PDS_Nack_Codes nack_code : 8;   // 8 bits, field indicating reason for sending NACK
    uint8_t vendor_code;            // 8 bits, vendor-specific field, no processing or interoperability requirements, used for vendor statistics event types, etc.
    union{
        uint32_t nack_psn;              // 32 bits, packet sequence number of received packet that triggered NACK generation
        uint32_t nack_pkt_id;           // 32 bits, if pds.flags.nt set, this field is pds.nack_pkt_id, NACKed packet is RUDI packet
    };
    uint16_t spdcid;                // 16 bits, source PDCID
    uint16_t dpdcid;                // 16 bits, destination PDCID
    uint32_t payload;               // 32 bits, specific payload related to pds.nack_code
}PACKED;

enum SES_BTH_header_type{
    Standard_Header,
    Optimized_Header,
    Small_Message_RMA_Header,
    Semantic_Response_Header,
    Semantic_Response_with_Data_Header,
    Optimized_Response_with_Data_Header
};

enum SES_EXH_header_type{
    Rendezvous_Extension_Header,
    Atomic_Operation_Extension_Header
};

//header

struct SES_Standard_Header
{
    uint8_t     rsvd            : 2;        //The operation being performed for this packet.
    uint8_t     opcode          : 6;        //Semantic protocol version – set to 0 in the initial version.
    uint8_t     version         : 2;        //Defer the semantic response for this until the packet has been made globally observable
    uint8_t     ie              : 1;        //Indicates this packet encountered an error at the initiator. Initiator Error prevents the packet from being written at the target.
    uint8_t     rel             : 1;        //This packet uses relative addressing.
    uint8_t     dc              : 1;        //Indicates this packet is a data packet.
    uint8_t     hd              : 1;        //Header data was provided for this message.
    uint8_t     eom             : 1;        //Indicates the last packet of the message. ses.eom MUST be set on the last packet of a message.
    uint8_t     som             : 1;        //Indicates this is the first packet of a message. Impacts the interpretation of header data.
    uint16_t    msg_id          : 16;       //Message identifier – assists in associating different packets to one message at the target.
    uint8_t     ri_generation   : 8;        //Resource Index Generation
    uint32_t    job_id          : 24;       //JobID used for relative addressing and for buffer access authorization.
    uint8_t     rsvd1           : 4; 
    uint16_t    PIDonFEP        : 12;       // The PIDonFEP value to be used at the target.   
    uint8_t     rsvd0           : 4;   
    uint16_t    resource_index  : 12;       //Resource Index field.
    uint64_t    buffer_offset   : 64;       //Offset within the target buffer used for 0 based addressing.
    uint32_t    initiator       : 32;       //Initiator ID used as part of matching criteria.
    uint64_t    match_bits      : 64;       //Used for tagged matching or as a memory key, depending on the opcode being used.
    union 
    {
        struct  //when ses.som = 1
        {
            uint64_t header_data    : 64;   //This is the completion data to deliver at the target when this operation completes when ses.som=1.
        }som_true;
        struct // when ses.som = 0
        {
            uint32_t rsvd2          : 18;   
            uint16_t payload_length : 14;   //Length (in bytes) of the payload portion of this packet.
            uint32_t message_offset : 32;   //32-bit offset (in bytes) from the start of the message.
        }som_false;
        //Can be delayed transmission, ignore for now
    }diff PACKED;
    uint32_t    request_length  : 32;       //Length of the payload to be transferred (in bytes). 0 is a legal transfer size (0 byte write/read).
}PACKED;

struct SES_Optimized_Header
{
    uint8_t     rsvd            : 2;        //The operation being performed for this packet.
    uint8_t     opcode          : 6;        //Semantic protocol version – set to 0 in the initial version.
    uint8_t     version         : 2;        //Defer the semantic response for this until the packet has been made globally observable
    uint8_t     ie              : 1;        //Indicates this packet encountered an error at the initiator. Initiator Error prevents the packet from being written at the target.
    uint8_t     rel             : 1;        //This packet uses relative addressing.
    uint8_t     hd              : 1;        //Header data was provided for this message.
    uint8_t     eom             : 1;        //Indicates the last packet of the message. ses.eom MUST be set on the last packet of a message.
    uint8_t     som             : 1;        //Indicates this is the first packet of a message. Impacts the interpretation of header data.
    uint16_t    msg_id          : 16;       //Message identifier – assists in associating different packets to one message at the target.
    uint8_t     ri_generation   : 8;        //Resource Index Generation
    uint32_t    jod_id          : 24;       //JobID used for relative addressing and for buffer access authorization.
    uint8_t     rsvd1           : 4; 
    uint16_t    PIDonFEP        : 12;       // The PIDonFEP value to be used at the target.   
    uint8_t     rsvd0           : 4;   
    uint16_t    resource_index  : 12;       //Resource Index field.    
    uint64_t    buffer_offset   : 64;       //Offset within the target buffer used for 0 based addressing.
}PACKED;

struct SES_Small_Message_RMA_Header
{
    uint8_t     rsvd            : 2;        //The operation being performed for this packet.
    uint8_t     opcode          : 6;        //Semantic protocol version – set to 0 in the initial version.
    uint8_t     version         : 2;        //Defer the semantic response for this until the packet has been made globally observable
    uint8_t     ie              : 1;        //Indicates this packet encountered an error at the initiator. Initiator Error prevents the packet from being written at the target.
    uint8_t     rel             : 1;        //This packet uses relative addressing.
    uint8_t     hd              : 1;        //Header data was provided for this message.
    uint8_t     eom             : 1;        //Indicates the last packet of the message. ses.eom MUST be set on the last packet of a message.
    uint8_t     som             : 1;        //Indicates this is the first packet of a message. Impacts the interpretation of header data.
    uint16_t    msg_id          : 16;       //Message identifier – assists in associating different packets to one message at the target.
    uint8_t     ri_generation   : 8;        //Resource Index Generation
    uint32_t    jod_id          : 24;       //JobID used for relative addressing and for buffer access authorization.
    uint8_t     rsvd1           : 4; 
    uint16_t    PIDonFEP        : 12;       // The PIDonFEP value to be used at the target.   
    uint8_t     rsvd0           : 4;   
    uint16_t    resource_index  : 12;       //Resource Index field.    
    uint64_t    buffer_offset   : 64;       //Offset within the target buffer used for 0 based addressing.
    uint32_t    initiator       : 32;       //Initiator ID used as part of matching criteria.
    uint64_t    match_bits      : 64;       //Used for tagged matching or as a memory key, depending on the opcode being used.
}PACKED;

struct SES_Rendezvous_Extension_Header
{
    uint32_t    eager_length        : 32;
    uint8_t     read_ri_generation  : 8;
    uint16_t    read_PIDonFEP       : 12;
    uint16_t    read_resource_index : 12;
    uint64_t    read_offset         : 64;
    uint64_t    read_mem_key        : 64;
}PACKED;

struct SES_Atomic_Operation_Extension_Header
{
    uint8_t     atomic_opcode       : 8;
    uint8_t     atomic_datatype     : 8;
    uint8_t     semantic_contol     : 8;
    uint8_t     rsvd                : 8;
}PACKED;

struct SES_Semantic_Response_Header
{
    uint8_t     list                : 2;    //Indicates if the payload was delivered to the expected or unexpected list.
    uint8_t     opcode              : 6;    //Indicates type of response (e.g., default response, response with payload, etc.).
    uint8_t     version             : 2;    //Semantic protocol version – set to 0 in the initial version.
    uint8_t     return_code         : 6;    //Indicates success conditions and some types of error conditions detected at the semantic sublayer.
    uint16_t    message_id          : 16;   //Message ID of the original request
    uint8_t     ri_generation       : 8;    //Contains the new index generation on a generation mismatch response.
    uint32_t    job_id              : 24;   //JobID of the original request
    uint32_t    modified_length     : 32;   //Indicates the number of bytes of the target buffer that will be modified by this transaction.
}PACKED;


struct SES_Semantic_Response_with_Data_Header
{
    uint8_t     list                : 2;    //Indicates if the payload was delivered to the expected or unexpected list.
    uint8_t     opcode              : 6;    //Indicates type of response (e.g., default response, response with payload, etc.).
    uint8_t     version             : 2;    //Semantic protocol version – set to 0 in the initial version.
    uint8_t     return_code         : 6;    //Indicates success conditions and some types of error conditions detected at the semantic sublayer.
    uint16_t    response_message_id : 16;   //Message ID of the original request
    uint8_t     rsvd                : 8;    
    uint32_t    job_id              : 24;   //JobID of the original request
    uint16_t    read_request_msg_id : 16;   // Message ID used in the original read request (or of the original fetching atomic operation request).
    uint8_t     rsvd1               : 2;
    uint16_t    payload_length      : 14;   // Length of the payload in this specific packet for a response with data.
    uint32_t    modified_length     : 32;   //Indicates the number of bytes of the target buffer that will be modified by this transaction.   
    uint32_t    message_offset      : 32;   // Indicates the relative position in the message that this payload corresponds to. 
}PACKED;

struct SES_Optimized_Response_with_Data_Header
{
    uint8_t     list                : 2;    //Indicates if the payload was delivered to the expected or unexpected list.
    uint8_t     opcode              : 6;    //Indicates type of response (e.g., default response, response with payload, etc.).
    uint8_t     version             : 2;    //Semantic protocol version – set to 0 in the initial version.
    uint8_t     return_code         : 6;    //Indicates success conditions and some types of error conditions detected at the semantic sublayer.
    uint8_t     rsvd                : 2;
    uint16_t    payload_length      : 14;   //Length of the payload for a response with data.
    uint8_t     rsvd1               : 8;
    uint32_t    job_id              : 24;   //JobID of the original request
    uint32_t    original_request_psn: 32;   //The PSN of the original request (either fetching atomic or read) that yielded this return data.                
}PACKED;


struct SEStoPDS_pkt //Add any additional SES outputs here
{
    SES_BTH_header_type bth_type;
    SES_EXH_header_type eth_type;

    union
    {
        SES_Standard_Header Standard_Header;
        SES_Optimized_Header Optimized_Header;
        SES_Small_Message_RMA_Header Small_Message_RMA_Header;
        SES_Semantic_Response_Header Semantic_Response_Header;
        SES_Semantic_Response_with_Data_Header Semantic_Response_with_Data_Header;
        SES_Optimized_Response_with_Data_Header Optimized_Response_with_Data_Header;
    }bth_header;
    
    union
    {
        SES_Atomic_Operation_Extension_Header Atomic_Operation_Extension_Header;
        SES_Rendezvous_Extension_Header Rendezvous_Extension_Header;
    }eth_header;
    

    std::string DMA_command;//Temporarily use DMA command as payload
};

//=============================================================================
// PDS packet structures sent to network layer
//=============================================================================

/**
 * @brief Packet structure sent by PDS to external network
 * @details Contains PDS header type identifier, specific PDS header union and SES layer data packet
 *          This is the complete packet structure output by PDS layer to network layer
 */
struct PDStoNET_pkt
{   
    // Used by network layer, temporarily placed here
    uint32_t src_fep;       // Source FEP
    uint32_t dst_fep;       // Destination FEP

    PDS_header_type PDS_type;    // PDS header type identifier
    union                               // PDS header union, select specific structure based on header type
    {
        PDS_RUOD_req_header RUOD_req_header;    // RUOD request header
        PDS_RUOD_ack_header RUOD_ack_header;    // RUOD acknowledgment header
        PDS_RUOD_cp_header RUOD_cp_header;      // RUOD control packet header
        PDS_nack_header nack_header;            // NACK header
    } PDS_header;
    SEStoPDS_pkt SESpkt;          // SES layer to PDS layer data packet
};


// PDC PDS SES interaction variable declarations
// Using include guard
#pragma once
enum class NackCode : uint8_t {
    SEQ_GAP        = 0x01,  // NACK_CODE_SEQ_GAP
    RESOURCE       = 0x02,  // NACK_CODE_RESOURCE
    ACCESS_DENIED  = 0x03,  // NACK_CODE_ACCESS_DENIED
    INVALID_OPCODE = 0x04,  // NACK_CODE_INVALID_OPCODE
    CHECKSUM       = 0x05,  // NACK_CODE_CHECKSUM
    TTL_EXCEEDED   = 0x06,  // NACK_CODE_TTL_EXCEEDED
    PROTOCOL       = 0x07,   // NACK_CODE_PROTOCOL
};

#pragma once
// Specification Table 3-47: NACK payload structure
struct NackPayload {
    uint8_t nack_code;      // NACK type enumeration value
    uint64_t expected_psn;   // Expected PSN (for SEQ_GAP) (optional)
    uint32_t current_window;// Current receive window size (resource related) (optional)
};

// #pragma once
// // SES request structure for calling PDS to send NACK
// struct PdsNackRequest {
//     uint32_t pdc_id;         // Packet delivery context ID (Specification 3.5.5.8)
//     NackPayload payload;     // NACK payload
// };

/**
 * @struct PDC_SES_req
 * @brief Request structure from PDC to SES layer
 *
 * Contains information of request packets received from network layer, used for forwarding to SES layer for processing
 */
struct PDC_SES_req
{
    uint16_t PDCID;          /**< SPDC identifier */
    uint16_t rx_pkt_handle;  /**< Receive packet handle, used to identify request */
    SEStoPDS_pkt pkt;        /**< Actual SES to PDS packet data */
    uint16_t pkt_len;        /**< Packet length */
    PDS_next_hdr next_hdr;        /**< Next header type */
    uint16_t orig_pdcid;     /**< DPDCID */
    uint32_t orig_psn;       /**< Original packet sequence number */
};
/**
 * @struct PDC_SES_rsp
 * @brief Response structure from PDC to SES layer
 *
 * Contains information of response packets received from network layer, used for forwarding to SES layer for processing
 */
struct PDC_SES_rsp
{
    uint16_t PDCID;          /**< SPDC identifier */
    uint16_t rx_pkt_handle;  /**< Receive packet handle, used to identify request corresponding to response */
    SEStoPDS_pkt pkt;        /**< Actual SES to PDS packet data */
    uint16_t pkt_len;        /**< Packet length */
};

/**
 * @struct SES_PDC_rsp
 * @brief Response structure from SES layer to PDC
 *
 * Contains response information from SES layer for requests, used by PDC to send responses to network layer
 */
// 
struct SES_PDC_rsp
{
    uint16_t rx_pkt_handle; /**< Receive packet handle, corresponding to original request */
    bool gtd_del;           /**< Guaranteed delivery flag */
    bool ses_nack;          /**< SES layer NACK flag */
    NackPayload nack_payload; /**< NACK information payload */
    SEStoPDS_pkt pkt;       /**< Response packet data */
    uint16_t rep_len;       /**< Response length */
};

/**
 * @struct PDS_PDC_req
 * @brief Request structure from PDS layer to PDC
 *
 * Contains request information received from PDS layer, used by PDC to send requests to network layer
 */
struct PDS_PDC_req
{
    PDS_next_hdr next_hdr;  /**< Next header type */
    uint16_t tx_pkt_handle; /**< Transmit packet handle */
    SEStoPDS_pkt pkt;       /**< Request packet data */
    uint16_t pkt_len;       /**< Packet length */
    bool som;               /**< Start of message flag */
    bool eom;               /**< End of message flag */
};
 
/**
 * @struct SES_PDS_Standard_Header_rsp
 * @brief Request structure from SES layer to PDC
 *
 * Contains request information received from PDS layer, used by PDC to send requests to network layer
 */
enum class RSP_RETURN_CODE : uint8_t {
    //Basic operation codes (0x00-0x0F)
    RC_OK = 0x00,   // Normal
    RC_PARTIAL_WRITE = 0x01,  // Partial data write (insufficient buffer)
    RC_NO_MATCH = 0x02,  // Tagged Send no matching buffer
    RC_INVALID_OP =0x03, // Invalid operation code (e.g., atomic operation not implemented)

    //Memory management error codes (0x10-0x1F)
    RC_NO_BUFFER = 0x10, // No available receive buffer
    RC_INVALID_KEY =0x11, // RMA memory key invalid/expired
    RC_ACCESS_DENIED =0x12, // JobID no access permission
    RC_ADDR_UNREACHABLE = 0x13, // Target address unreachable (PIDonFEP invalid)

    //Security protocol error codes (0x20-0x2F)
    RC_SECURITY_DOMAIN_MISMATCH = 0x20, // Security domain (SDI) verification failed, trigger key rotation (Figure 3-107)
    RC_INTEGRITY_CHECK_FAIL = 0x21, // Packet integrity check failed (TSS authentication tag invalid), discard packet and generate security alert
    RC_REPLAY_DETECTED = 0x22, // Replay attack detected (sequence number duplicate), block source address (Section 3.7.9)

    //System-level error codes (0x30-0x3F)
    RC_INTERNAL_ERROR = 0x30,// SES internal state abnormal, reset PDC context (Figure 3-43)
    RC_RESOURCE_EXHAUST = 0x31,// System resource exhausted (e.g., PDC table full), downgrade to lightweight mode
    RC_PROTOCOL_ERROR = 0x32,// Protocol violation (e.g., out-of-order packet), terminate connection and log
};

enum class RSP_OP_CODE : uint8_t {
    //Basic responses (0x00-0x0F)
    UET_RESPONSE = 0X00,//(General response)
    UET_DEFAULT_RESPONSE=0x01,//(Default success response)
    UET_RESPONSE_W_DATA=0x02,//(Response with data)
    UET_NO_RESPONSE=0x03,//(Empty response)
    UET_NACK =0x04,//Error response
};
/*
struct SES_PDS_Header_rsp {
    uint8_t version;        // Protocol version (0x10)
    RETURN_CODE type;           // 0x1A (ACK response type)
    uint16_t opcode;        // Original request operation code (echo)
    uint32_t job_id;        // Original JobID (echo)
    uint64_t orig_message_id; // Original message ID (echo)
    uint32_t ack_seq;       // Highest acknowledged PSN
    uint16_t rx_pkt_handle; // Receive packet handle
    uint8_t  status;        // Processing status (0=success)
    uint8_t  flags;         // Flag bits
    uint16_t reserved;      // Reserved field

    //Default initialization
    SES_PDS_Header_rsp() : version(2), status(0){}
};
*/

/**
 * @struct SES_PDS_req
 * @brief Request structure from SES layer to PDC
 *
 * Contains request information received from SES layer, used by PDC to send requests to network layer;
 * Parameters to be used but contained within pkt header (not placed outside for now):
 *  eom
 *  som
 *  msg_id
 *  job_id
 */
struct SES_PDS_req {
    uint32_t src_fep;       // Source FEP
    uint32_t dst_fep;       // Destination FEP
    uint8_t mode;           // Transmission mode {RUD, ROD, RUDI, UUD}
    uint16_t rod_context;   // ROD context, identifies a ROD send queue, used to reserve packets from same PDC send queue
    PDS_next_hdr next_hdr;       // Encapsulated UET payload header type
    uint8_t tc;             // Traffic control category
    bool lock_pdc;          // TRUE => do not close this PDC until SES indicates
    uint16_t tx_pkt_handle; // Data packet handle allocated by source SES
    SEStoPDS_pkt pkt;       // Actual SES to PDS packet data
    uint16_t pkt_len;       // Packet length, in bytes
    uint32_t tss_context;   // TSS context, used to limit packets on same PDC to same public SDI
    uint16_t rsv_pdc_context; // Used to reserve packets in same reserved PDC
    uint16_t rsv_ccc_context; // Used to reserve packets in same reserved CCC
};

/**
 * @struct SES_PDS_rsp
 * @brief Response structure from SES layer to PDS
 *
 * Contains response information from SES layer for requests, used by PDS to send responses to network layer
 */
struct SES_PDS_rsp
{
    uint16_t PDCID;         /**< SPDC identifier */
    uint32_t src_fep;       // Source FEP
    uint32_t dst_fep;       // Destination FEP
    uint16_t rx_pkt_handle; /**< Receive packet handle, corresponding to original request */
    bool gtd_del;           /**< Guaranteed delivery flag */
    bool ses_nack;          /**< SES layer NACK flag */
    SEStoPDS_pkt rsp;       /**< Response packet data */
    uint16_t rsp_len;       /**< Response length */
};

/**
 * @struct SES_PDS_eager
 * @brief Eager parameter structure from SES layer to PDS
 *
 * Contains request parameters for SES layer's eager size estimation
 */
struct SES_PDS_eager {
    uint32_t src_fep;       // Source FEP
    uint32_t dst_fep;       // Destination FEP
    uint8_t mode;           // Transmission mode {RUD, ROD, RUDI, UUD}
    uint8_t tc;             // Traffic control category
    uint16_t eager_id;      // Eager ID
};

/**
 * @struct PDS_SES_eager
 * @brief Eager parameter structure returned from PDS layer to SES
 *
 * Contains response parameters for PDS layer's eager size estimation
 */
struct PDS_SES_eager{
    uint16_t eager_id;      // Eager ID
    uint32_t eager_size;    // Eager data size
};

/**
 * @struct PDS_SES_pause
 * @brief Pause parameter structure returned from PDS layer to SES
 *
 * Contains response parameters for PDS layer's pause
 */
struct PDS_SES_pause{
    bool pdc_pause;         // PDC packet pause flag
    bool rudi_pause;        // RUDI packet pause flag
};

/**
 * @enum PDS_SES_Error_Type
 * @brief Error type enumeration values returned from PDS layer to SES
 *
 * Contains error type enumeration values for PDS layer errors
 */
enum PDS_SES_Error_Type{
    PDS_SES_Error_Unknown = 0x00,  // Unknown error
};

/**
 * @struct PDS_SES_error
 * @brief Unrecoverable error structure returned from PDS layer to SES
 *
 * Contains unrecoverable error type and error packet handle for PDS layer errors
 */
struct PDS_SES_error{
    PDS_SES_Error_Type pds_error;  // Error type
    uint16_t pkt_handle;             // Error packet handle
};

// MSVC needs to restore default packing settings at end of file
#if defined(_MSC_VER)
    #pragma pack(pop)
#endif

#endif // TRANSPORT_LAYER_HPP