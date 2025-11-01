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
 * @file             PDS_test.cpp
 * @brief            PDS_test.cpp
 * @author           softuegroup@gmail.com
 * @version          1.0.0
 * @date             2025-10-29
 * @copyright        Apache License Version 2.0
 *
 * @details
 * PDS_test.cpp
 */

//#include "../PDS/PDS_Manager/PDSManager.hpp"
#include "../PDS/PDS_Manager/process/PDSProcessManager.hpp"
#include "../logger/Logger.hpp"
/*Various structure definitions
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

struct SES_Standard_Header
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
    }diff __attribute__((packed));
    uint32_t    request_length  : 32;       //Length of the payload to be transferred (in bytes). 0 is a legal transfer size (0 byte write/read).
}__attribute__((packed));

*/
//Generate req test data
void req_gen(SES_PDS_req& req){
    req.src_fep = 0x12345678;
    req.dst_fep = 0x87654321;
    req.mode = RUD;
    req.rod_context = 0x0001;
    req.next_hdr = PDS_next_hdr::UET_HDR_REQUEST_STD;
    req.tc = 0x01;
    req.lock_pdc = true;
    req.tx_pkt_handle = 0x0001;
    req.pkt_len = 100;
    req.tss_context = 0x0001;
    req.rsv_pdc_context = 0x0001;
    req.rsv_ccc_context = 0x0001;
    req.pkt.bth_type = SES_BTH_header_type::Standard_Header;
    req.pkt.bth_header.Standard_Header.rsvd = 0;
    req.pkt.bth_header.Standard_Header.opcode = 0;
    req.pkt.bth_header.Standard_Header.version = 0;
    req.pkt.bth_header.Standard_Header.ie = 0;
    req.pkt.bth_header.Standard_Header.rel = 0;
    req.pkt.bth_header.Standard_Header.hd = 0;
    req.pkt.bth_header.Standard_Header.eom = 0;
    req.pkt.bth_header.Standard_Header.som = 1;
    req.pkt.bth_header.Standard_Header.msg_id = 0x0001;
    req.pkt.bth_header.Standard_Header.ri_generation = 0x00;
    req.pkt.bth_header.Standard_Header.job_id = 0x00000001;
    req.pkt.bth_header.Standard_Header.PIDonFEP = 0x0001;
    req.pkt.bth_header.Standard_Header.rsvd0 = 0x00;
    req.pkt.bth_header.Standard_Header.resource_index = 0x0001;
    req.pkt.bth_header.Standard_Header.buffer_offset = 0x0000000000000001;
    req.pkt.bth_header.Standard_Header.initiator = 0x00000001;
    req.pkt.bth_header.Standard_Header.match_bits = 0x0000000000000001;
}


//Generate network layer test data - connection establishment packet
void net_pkt_gen(PDStoNET_pkt& pkt,SES_PDS_req &req){
    pkt.src_fep = 0x12345678;
    pkt.dst_fep = 0x87654321;
    pkt.PDS_type = PDS_header_type::RUOD_req_header;
    
    // Set PDS RUOD request header - connection establishment packet
    pkt.PDS_header.RUOD_req_header.type = ROD_REQ;
    pkt.PDS_header.RUOD_req_header.next_hdr = UET_HDR_REQUEST_STD;

    // Set flags - Key: set SYN flag to 1 to indicate connection establishment request
    pkt.PDS_header.RUOD_req_header.flags.rsvd = 0;     // Reserved bits
    pkt.PDS_header.RUOD_req_header.flags.retx = 0;     // Not retransmitted packet
    pkt.PDS_header.RUOD_req_header.flags.ar = 0;       // Do not request ACK
    pkt.PDS_header.RUOD_req_header.flags.syn = 1;      // Connection establishment request flag
    pkt.PDS_header.RUOD_req_header.flags.rsvd1 = 0;    // Reserved bits

    pkt.PDS_header.RUOD_req_header.clear_psn_off = 0;   // CLEAR_PSN offset
    pkt.PDS_header.RUOD_req_header.psn = 1001;         // Packet sequence number
    pkt.PDS_header.RUOD_req_header.spdcid = 5;         // Source PDCID
    pkt.PDS_header.RUOD_req_header.dpdcid = 0;         // Destination PDCID (set to 0 during connection establishment)
    pkt.PDS_header.RUOD_req_header.pdc_info = 0;        // PDC information
    pkt.PDS_header.RUOD_req_header.psn_off = 0;        // PSN offset

    // Set SES layer data packet
    pkt.SESpkt = req.pkt;
}
//Generate network layer

int main()
{
    Logger::initialize("PDS_test.log", LogLevel::DEBUG, 1, 1);
    
    PDSProcessManager pds_processmanager;
    
    // Directly start PDS process manager, queues will be automatically initialized
    if (!pds_processmanager.start()) {
        LOG_ERROR(__FUNCTION__, "PDS process manager startup failed");
        return -1;
    }

    LOG_INFO(__FUNCTION__, "PDS initialization successful");

    // Check PDS process status
    auto state = pds_processmanager.getProcessState();
    LOG_INFO(__FUNCTION__, "PDS process status: " + std::to_string(static_cast<int>(state)));

    // Generate test request data
    SES_PDS_req test_req;
    req_gen(test_req);
    
    // Use log to indicate sending SES request to PDS
    if(!pds_processmanager.pushSESRequest(test_req))
    {
        LOG_ERROR(__FUNCTION__, "PDS pushSESRequest failed");
        LOG_ERROR(__FUNCTION__, "PDS process status: " + std::to_string(static_cast<int>(pds_processmanager.getProcessState())));
        return -1;
    }
    LOG_INFO(__FUNCTION__, "SES request has been sent to PDS");

    // Get queue status
    auto queue_status = pds_processmanager.getQueueStatus();
    LOG_INFO(__FUNCTION__, "Queue status - SES requests: " + std::to_string(queue_status.ses_req_count) +
                          ", SES responses: " + std::to_string(queue_status.ses_rsp_count) +
                          ", network packets: " + std::to_string(queue_status.net_pkt_count));

    // Wait longer for PDS process to process
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    LOG_INFO(__FUNCTION__, "Waited 50ms completed");

    // Try to get processed packet
    PDStoNET_pkt this_pkt;
    bool packet_received = false;
    
    // Get data packet
    for(int i = 0;i<10;i++)
    {
        if (pds_processmanager.popNetworkPacket(this_pkt)) {
            packet_received = true;
            LOG_INFO(__FUNCTION__, "Successfully obtained network layer packet processed by PDS");
            pds_processmanager.pushNetworkPacket(this_pkt);
        } else {
            LOG_ERROR(__FUNCTION__, "Failed to obtain network layer packet processed by PDS");
        }
        // Wait longer for PDS process to process
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        LOG_INFO(__FUNCTION__, "Waited 5ms completed");
    }
    return 0;
}