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
 * @file             SES.hpp
 * @brief            SES.hpp
 * @author           softuegroup@gmail.com
 * @version          1.0.0
 * @date             2025-10-29
 * @copyright        Apache License Version 2.0
 *
 * @details
 * SES.hpp
 */




using namespace std;
#ifndef SES_HPP
#define SES_HPP
#define MAX_MTU 4096 
#define MAX_QUEUE_SIZE 512

#include <cstdint>
#include <string>
#include "../Transport_Layer.hpp"
#include "../PDS/PDS_Manager/process/PDSProcessManager.hpp"
#include "../logger/Logger.hpp"

//PDS-SES Logical Interface

// struct uet_ep {
//     //Content unknown yet
//     uint32_t epid;
// };

// uet_ep src_fep;                     // ptr to struct with source address, etc.
// uet_ep dst_fep;                     // ptr to struct with dest address, etc.

// uint32_t jobid;                     // SES passed through JobID
// uint32_t tss_context;               // Transport Security Sublayer context (e.g., SDI),used to limit pkts on PDC to a common SDI

// enum delivery_mode {RUD, ROD, RUDI, UUD};
// delivery_mode mode;                 // 8 , delivery mode = {RUD, ROD, RUDI, UUD}
// uint16_t rod_context;               // identifies a ROD send queue, used to keep packets from a send queue on same PDC

// bool rsv_pdc;                       // 1 = use reserved PDC, 0 = do not use resv’d PDC
// uint16_t rsv_pdc_context;           // used to keep pkts in same reserved PDC
// uint16_t rsv_ccc_context;           // used to keep pkts in same reserved CCC 
// uint16_t tx_pkt_handle;             // SES assigned packet handle at source 
// uint16_t msg_id;                    // SES assigned message identifier at source 
// void *pkt;                          // ptr to packet 
// uint16_t pkt_len;                   // packet length in bytes 
// void *rsp;                          // ptr to response 
// uint16_t rsp_len;                   // response length in bytes 
// uint8_t tc;                         // traffic 
// uint8_t next_hdr;                   // controlled by SES, used to determine the type of header in the encapsulated UET payload 

// bool som;                           // TRUE => start of message 
// bool eom;                           // TRUE => end of message 
// bool lock_pdc;                      // TRUE => do not close this PDC until SES indicates the lock can be lifted (separate function) 
// bool return_data;                   // TRUE => packet must use PDC in orig_pdcid, set for read responses
// uint16_t orig_pdcid;                // PDCID from Read request in fwd direction local ID identifying a specific PDC

// bool orig_psn_val;                  // TRUE => include orig PSN field in PDS Request hdr 
// uint32_t orig_psn;                  // PSN from Read req or Def Send in fwd direction 
// bool gtd_del;                       // TRUE => SES Response needs guaranteed delivery 
// bool ses_nack;                      // SES indication to send a PDS NACK 
// uint16_t eager_id;                  // SES identifier for eager estimate request 
// uint32_t eager_size;                // size in bytes of eager data 
// uint16_t rx_pkt_handle;             // PDS assigned packet handle at destination 
// bool pdc_pause;                     // TRUE => SES stops sending RUD/ROD packets to PDS 
// bool rudi_pause;                    // TRUE => SES stops sending RUDI packets to PDS 
// enum pds_error;                     // enum of reasons for PDC reset

#pragma once





//SES as sender, structure for getting information from libfabric interface

 // Operation type
enum OpType {
    SEND = 1,       // Standard send operation
    READ = 2,       // RMA read operation
    WRITE= 3,      // RMA write operation
    DEFERRABLE = 4 // Deferred send (AI Full exclusive)
} op_type;

struct OperationMetadata {
    // Operation type
    OpType op_type;
    
    /*/* Can be reused, no classification needed
    // Destination endpoint address
    struct{
        uint32_t pid_on_fep;     // Target endpoint process ID
        uint32_t initiator_id;   // Target ID
    } destnation;
    
    // Source endpoint information
    struct {
        uint32_t pid_on_fep;     // Local endpoint process ID
        uint32_t initiator_id;   // Initiator ID
    } source;
    */
   
    // Memory region information
    struct {
        uint64_t rkey;           // Registered memory key
        bool idempotent_safe;    // Idempotent operation safety flag
    } memory;
    
    // Data payload
    struct {
        uint64_t start_addr;      // Data start address
        size_t length;           // Data length
        uint64_t imm_data;       // Immediate data (optional)
    } payload;
    uint32_t s_pid_on_fep;      // Source endpoint process ID
    uint32_t t_pid_on_fep;     // Target endpoint process ID
    uint32_t job_id;         // Job identifier
    uint16_t res_index; 
    uint32_t messages_id;    // Message identifier
    // Operation flag bits
    bool relative;              // Whether it is relative addressing
    bool use_optimized_header;   // Whether to use optimized header
    bool has_imm_data;           // Whether to carry immediate data
    
    // Constructor default initialization, uint types default to 0, memory also defaults
    OperationMetadata() : op_type(SEND), memory({0, false}), payload({0, 0, 0}), s_pid_on_fep(0), job_id(0), res_index(0), relative(false), use_optimized_header(false), has_imm_data(false) {}

    // Destructor
    ~OperationMetadata() {}

};

struct UETAddress {
    uint8_t version;        // Address format version
    uint16_t flags;          // Valid field flag bits
    
    // Capability identifiers (Figure 1-5)
    struct {
        bool ai_base : 1;   // AI basic profile support
        bool ai_full : 1;   // AI full profile support
        bool hpc : 1;       // HPC profile support
    } capabilities;
    
    uint16_t pid_on_fep;     // Process ID on endpoint
    // 128-bit integer address - represented by two 64-bit integers for cross-platform compatibility
    struct {
        uint64_t low;   // Low 64 bits
        uint64_t high;  // High 64 bits
    } fabric_addr;    
    uint16_t start_res_index; // Starting resource index
    uint16_t num_res_indices; // Number of resource indices
    uint32_t initiator_id;   // Initiator ID
};

struct MemoryRegion {  
    uint64_t start_addr;   // Memory region start address  
    size_t   length;  // Memory region length  
};  

struct MemoryKey {
    // Control flag bits
    union {
        struct {
            uint64_t idempotent_safe : 1;  // Idempotent operation safety flag
            uint64_t optimized : 1;         // Optimized header support flag
            uint64_t reserved : 6;          // Reserved bits
            uint64_t vendor_specific : 8;   // Vendor-specific field
        } flags;
        
        // Key structure in different modes
        struct {
            uint64_t : 48;         // Unused bits
            uint64_t rkey : 16;     // Standard mode memory key
        } standard;
        
        struct {
            uint64_t : 36;         // Unused bits
            uint64_t index : 12;    // Optimized mode resource index
        } optimized;
    };
};

// SES receiver needs to maintain an MSN table for received packets to confirm message order, ack and NACK
struct MSNEntry {
    uint64_t last_psn;     // Last received packet sequence number
    uint64_t expected_len; // Message expected total length
    uint32_t pdc_id;       // Associated PDC (Packet Delivery Context)
};

class SESManager {
    public:
        // Constructor/Destructor
        SESManager();
        ~SESManager();
        PDSProcessManager pds_process_manager;
        // Add receiving task queue above
        std::queue<OperationMetadata> lfbric_ses_q;
        // Initialize SES manager
        void initialize();

        // Process requests from above to generate standard SES header
        void process_send_packet(const OperationMetadata& metadata);
        // Simulate generated SES header to be passed down to PDS
        void send_packet_to_pds(const SES_Standard_Header& header, const SES_PDS_req& sent_pkt ,...);

        // Process received req packets
        void process_recv_req_packet(const PDC_SES_req& req);
        // Process received rsp packets
        void process_recv_rsp_packet(const PDC_SES_rsp& rsp);
        // rsp returned to PDS
        void send_rsp_to_pds(const SES_PDS_rsp& rsp);


        // Unified centralized processing of received req from PDC, needs queue buffering
        void process_pdc_2_ses();
        void mainChk();

        
    private:
        // Default header initialization function
        SES_Standard_Header initialize_header(const OperationMetadata& metadata);
        // Simple message_id generator
        uint16_t get_message_id(const OperationMetadata& metadata, void* pdc_manager);
        // Calculate buffer_offset based on rkey and start_addr
        uint64_t calculate_buffer_offset(uint64_t rkey, uint64_t start_addr);
        // Parse pdc_2_ses_req and return metadata format
        OperationMetadata parse_pdc_2_ses_req(const PDC_SES_req& req );
        // Verify if version is valid
        bool validate_version(uint8_t version);
        // Verify packet header type
        bool validate_header_type(SES_BTH_header_type type);
        // Verify pid on fep based on absolute or relative addressing
        bool validate_pid_on_fep(uint32_t pid_on_fep, uint32_t job_id ,bool relative);
        // Verify opcode
        bool validate_opcode(OpType opcode);
        // Verify if job_id is allowed
        bool validate_job_id(uint64_t job_id);
        // Check if packet data length equals actual length
        bool validate_data_length(size_t data_length, size_t payload_length);
        // PDC status verification
        bool validate_pdc_status(uint16_t pdcid, uint32_t psn);
        // send write read operations need to verify if rkey is valid
        bool validate_rkey(uint64_t rkey,uint32_t messages_id);
        // MSN table check, involves MSN creation and update
        bool validate_msn(uint32_t job_id, uint64_t psn, uint64_t requires_length,uint32_t pcd_id, bool is_first_packet,bool is_last_packet);
        // Determine if ack needs to be returned
        bool validate_need_ack(uint32_t messages_id,bool FI_DELIVERY_COMPLETE); // bool Enable dynamic ack configuration, then confirm whether to return based on msg

        //


        // Parse based on rkey, then call look_mr_by_key to return memory region
        MemoryRegion decode_rkey_to_mr(uint64_t key);
        // Generate NACK response based on error code type
        //NackPayload generate_nack_packet(const OperationMetadata& recv_header, NackCode nack_code);

        MemoryRegion lookup_mr_by_key(uint64_t key);

        // Queue to store received pdc_to_ses_req
        std::queue<PDC_SES_req> pdc_to_ses_req_queue;
        // Initialize MSN table, a hash table supporting O(1) query, insert, delete, and jobid has uniqueness, jobid as key is reasonable
        std::unordered_map<uint64_t, MSNEntry> msn_table;



        // Temporarily not locked std::mutex msn_mutex_; // Mutex to protect msn_table_

};

SESManager::SESManager() {
    pds_process_manager.start();
}
SESManager::~SESManager() {}

void SESManager::mainChk(){
    LOG_ERROR(__FUNCTION__, "SES - message check");
    
    if(!lfbric_ses_q.empty()){
        OperationMetadata metadata ;
        metadata = lfbric_ses_q.front();
        lfbric_ses_q.pop();
        process_send_packet(metadata);
    }
    else if(pds_process_manager.getQueueStatus().pdc_to_ses_req_count != 0 || pds_process_manager.getQueueStatus().pdc_to_ses_rsp_count != 0){
        process_pdc_2_ses();
    }
    
}
// Below are various bool validations for receiver header permissions, etc.

bool SESManager::validate_pid_on_fep(uint32_t pid_on_fep,uint32_t job_id, bool relative) {
    // For absolute addressing, only check if target pid_on_fep is local
    if (!relative) {
        // Simulate normal query if pid_on_fep == locationfep, default true  
        if (pid_on_fep == 0) {
            return false;
        }
        return true;
    }
    
    // For relative addressing, check if corresponding pid in jobid is valid in local jobid
    else{
        // Simulate normal query if job_id == locationjobid and pid_on_fep == locationfep, should be a function to compare with upper interface, default true
        if (job_id == 0 && pid_on_fep == 0) {
            return false;
        }
        return true;
    }


}

//
bool SESManager::validate_header_type(SES_BTH_header_type type) {
    // Simulate verification
    // Should verify
    LOG_DEBUG(__FUNCTION__, "check_validate_header_type" + std::to_string(static_cast<uint8_t>(type)));
    return true;
}

bool SESManager::validate_need_ack(uint32_t messages_id, bool FI_DELIVERY_COMPLETE) {
    // Simulate verification
    // Should confirm whether to return ack based on msg   
    LOG_DEBUG(__FUNCTION__, "check_validate_need_ack");
    if (messages_id == 1 && FI_DELIVERY_COMPLETE == true) {
        return true;    
    }
    return false;
}
bool SESManager::validate_version(uint8_t version) {
    return version == 2;
}

bool SESManager::validate_job_id(uint64_t job_id) {
    // Simulate verification
    // Should query NIC hardware below to check if in permission database
    /*
    Hardware-level policy cache
    JobID authorization policy is preloaded to NIC hardware during session establishment
    // Policy preload interface (Linux implementation see section 2.2.11)
    uet_ctrl_job_id_map_req(job_id, sec_bindings);


    Real-time verification process
    SES completes verification through register access (no real-time cross-layer queries)：
    bool ValidateJobID(uint32_t job_id) {
    return (hw_policy_registry[job_id] & POLICY_VALID_BIT); 
    }
    */   
    LOG_DEBUG(__FUNCTION__, "validate_job_id: " + std::to_string(job_id));
    return true;
}

bool SESManager::validate_opcode(OpType opcode) {
    // Simulate verification, should theoretically verify permissions based on AI base, should have an interface to connect upward to check if corresponding opcode permission exists
    constexpr uint8_t valid_ops[] = {SEND, READ, WRITE, DEFERRABLE};
    if (std::none_of(valid_ops, valid_ops+4, [&](auto op){
        return op == opcode;
    })) {    
    return false;
    }
    return true;
}

bool SESManager::validate_data_length(size_t data_length, size_t payload_length){
    // Simulate verification
    // Need NOC cooperation, default return true
    LOG_DEBUG(__FUNCTION__, "check_validate_data_length" + std::to_string(data_length) + " payload_len :  " + std::to_string(payload_length));
    return true;
    // Theoretically data length equals payload length
    //return data_length == payload_length;
}

bool SESManager::validate_pdc_status(uint16_t pdcid, uint32_t psn) {
    // Simulate verification
    // Should jointly verify with PDC interface
    LOG_DEBUG(__FUNCTION__, "validate_pdc_status: pdcid " + std::to_string(pdcid) + " psn " + std::to_string(psn));
    return true;
}
bool SESManager::validate_msn(uint32_t job_id, uint64_t psn, uint64_t requires_length, uint32_t pcd_id,bool is_first_packet, bool is_last_packet ) {
    // MSN table check
    // If it is the first packet, create new table entry
    LOG_DEBUG(__FUNCTION__, "validate_msn: job_id " + std::to_string(job_id) + " psn " + std::to_string(psn) + " requires_length " + std::to_string(requires_length) + " pcd_id " + std::to_string(pcd_id) + " is_first_packet " + std::to_string(is_first_packet) + " is_last_packet " + std::to_string(is_last_packet));
    if(is_first_packet){
        // Build new table entry
        //msn_table[req.pkt.bth_header.Standard_Header.msg_id] = req.pkt.bth_header.Standard_Header.ri_generation;
        // Considering uniqueness, still use job_id as key
        MSNEntry msn;
        msn.expected_len = requires_length;
        msn.last_psn = psn;
        msn.pdc_id = pcd_id ;
        // Add to MSN hash table with job_id as key
        msn_table[job_id] = msn;
        LOG_INFO(__FUNCTION__, "add new msn_table item");
    }       
    // If it is not the first packet, table entry already established, check if valid
    else{
        // Check if job_id can be found in hashmap
        if(msn_table.find(job_id) == msn_table.end()){
            // job_id not in hashmap, discard
            LOG_WARN(__FUNCTION__, "job_id not in msn_table");
            return false;
        }
        // Check if pdc_id is consistent
        if(pcd_id != msn_table[job_id].pdc_id){
            // pdc_id inconsistent, discard    
            LOG_WARN(__FUNCTION__, "msn_pdc_id not match, except_pcd_id: " + std::to_string(msn_table[job_id].pdc_id) + " but recv_pcd_id: " + std::to_string(pcd_id));
            return false;    
        }
        // Check if psn is last_psn + 1 for ordered reception
        if(psn != msn_table[job_id].last_psn + 1){
            // psn not consecutive, discard
            LOG_WARN(__FUNCTION__, "psn not continuous");
            OperationMetadata metadata;
            return false;
        }
        // Normal, update last_psn
        msn_table[job_id].last_psn =psn;
    }    
    return true;
}

// Check if key is valid
bool SESManager::validate_rkey(uint64_t rkey, uint32_t messages_id) {
    // Simulate verification
    // Should jointly verify with PDC interface
    // Should query NIC hardware below to check if in permission database
    /*
    // Verify memory region permissions
    if (！mr_mgr_.ValidateRKey(header.rkey)) {
        return false
    }
    */
    LOG_DEBUG(__FUNCTION__, "validate_rkey: " + std::to_string(rkey) + " for msg_id: " + std::to_string(messages_id));
    return true;
}   
// bool check end bit


// Check if there are requests below to process
void SESManager::process_pdc_2_ses() {
    if (pds_process_manager.getQueueStatus().pdc_to_ses_req_count != 0){
        // req not empty, take it
        LOG_DEBUG(__FUNCTION__, "Processing __pds_req");
        PDC_SES_req req;
        pds_process_manager.popSESRequest(req);
        process_recv_req_packet(req);
    }
    else if (pds_process_manager.getQueueStatus().pdc_to_ses_rsp_count != 0){
        // rsp not empty, take it
        LOG_DEBUG(__FUNCTION__, "Processing __pds_rsp");
        PDC_SES_rsp rsp;
        pds_process_manager.popSESResponse(rsp);
        process_recv_rsp_packet(rsp);
    }
    else{
        LOG_DEBUG(__FUNCTION__, "No messages");
    }
    return;
}


 
//
OperationMetadata SESManager::parse_pdc_2_ses_req(const PDC_SES_req& req){
    // Parse pdc_2_ses_req
    // Get job_id, pid, resource_index, buffer_type, data_length, data, buffer_offset, imm_data etc. from req to generate metadata
    // First declare metadata
    OperationMetadata metadata;

    switch(req.pkt.bth_type) {
        // Parse based on bth_header type
        case Standard_Header:
            // Parse standard header
            MemoryRegion mr;
            metadata.op_type = static_cast<OpType>(req.pkt.bth_header.Standard_Header.opcode);
            metadata.messages_id = req.pkt.bth_header.Standard_Header.msg_id;
            metadata.job_id = req.pkt.bth_header.Standard_Header.job_id;
            metadata.relative = req.pkt.bth_header.Standard_Header.rel;
            metadata.res_index = req.pkt.bth_header.Standard_Header.resource_index;//re_idx
            metadata.t_pid_on_fep = req.pkt.bth_header.Standard_Header.PIDonFEP;// PID of received packet is the sender locating receiver PID
            metadata.s_pid_on_fep = 0;
            metadata.res_index = req.pkt.bth_header.Standard_Header.resource_index;
            metadata.memory.rkey = req.pkt.bth_header.Standard_Header.match_bits;
            mr = decode_rkey_to_mr(req.pkt.bth_header.Standard_Header.match_bits);

            // Determine if it is a single packet based on som and eom
            if (req.pkt.bth_header.Standard_Header.som == 1 && req.pkt.bth_header.Standard_Header.eom == 1){
                metadata.payload.length = req.pkt.bth_header.Standard_Header.request_length;
                // Start address is buffer_offset + rkey obtained buffer.addr
                metadata.payload.start_addr = mr.start_addr + req.pkt.bth_header.Standard_Header.buffer_offset;

                // Check if there is imm_data
                if (req.pkt.bth_header.Standard_Header.hd == 1){
                    metadata.has_imm_data = true;
                    metadata.payload.imm_data = req.pkt.bth_header.Standard_Header.diff.som_true.header_data;
                }
                // No imm_data
                else{
                    metadata.has_imm_data = false;
                    metadata.payload.imm_data = 0;
                }
            }
            // Slice/segment
            else{
                metadata.payload.length = req.pkt.bth_header.Standard_Header.diff.som_false.payload_length;
                metadata.has_imm_data = false;
                metadata.payload.imm_data = 0;
                // Start address is buffer_offset + rkey obtained buffer.addr + payload message_offset
                metadata.payload.start_addr = mr.start_addr + req.pkt.bth_header.Standard_Header.buffer_offset + req.pkt.bth_header.Standard_Header.diff.som_false.message_offset;

            }
            break;  // Add break to avoid fall-through
        default:
            LOG_WARN(__FUNCTION__, "Unknown bth_header type");
            break;
    }
    return metadata;
}



// Generate corresponding NACK based on error code
// NackPayload SESManager::generate_nack_packet(const OperationMetadata& recv_header, NackCode nack_code)
// {
//     NackPayload nack;
//     nack.nack_code = static_cast<uint8_t>(nack_code);
// Generate different nack content based on different error codes
//     switch (nack_code) {
//         case NackCode::SEQ_GAP:
// nack.expected_psn = 0; // Assume expected PSN is 0
// nack.current_window = 0; // Assume current window size is 0
//             break;
//         case NackCode::RESOURCE:
// nack.expected_psn = 0; // Assume expected PSN is 0
// nack.current_window = 0; // Assume current window size is 0
//             break;
//         case NackCode::ACCESS_DENIED:
// No additional information needed
//             break;
//         case NackCode::INVALID_OPCODE:
// No additional information needed
//             break;
//         case NackCode::CHECKSUM:
// No additional information needed
//             break;
//         case NackCode::TTL_EXCEEDED:
// No additional information needed
//             break;
//         case NackCode::PROTOCOL:
// No additional information needed
//             break;
//         default:
// Unknown error code, set to invalid operation
//             nack.nack_code = static_cast<uint8_t>(NackCode::PROTOCOL);
//             break;
//     }
//     return nack;
// }

uint16_t SESManager::get_message_id(const OperationMetadata& metadata, void* pdc_manager )
{
    // Should properly update and reuse message_id based on PDC management interaction
    LOG_DEBUG(__FUNCTION__, "generate_message_id for job_id: " + std::to_string(metadata.job_id));
    static uint16_t message_id = 0;
    message_id++;
    return message_id;
}

// Header initialization
SES_Standard_Header SESManager::initialize_header(const OperationMetadata& metadata) {
    SES_Standard_Header header;
    header.opcode = metadata.op_type;
    header.version = 2;
    header.buffer_offset = calculate_buffer_offset(metadata.memory.rkey, metadata.payload.start_addr);// Calculate offset
    header.ie = (header.buffer_offset == UINT64_MAX) ? 1 : 0;// Out of bounds indicates error packet
    //cout<<header.ie<<endl;
    header.rel = 0;// Default absolute addressing int1 0 output default empty
    header.hd = 0;
    header.eom = 1; // Default last packet
    header.som = 1; // Default first packet
    header.dc = 1;// Unknown, default
    
    
    // Assigning the same message_id to the same message is important
    header.msg_id = get_message_id(metadata, nullptr);
    
    
    header.ri_generation = 0;
    header.job_id = metadata.job_id;
    header.rsvd1 = 0;
    header.PIDonFEP = metadata.t_pid_on_fep;
    header.rsvd0 = 0;
    header.resource_index = metadata.res_index;
    
    header.initiator = 0;
    header.match_bits = metadata.memory.rkey; // Assume match_bits is used to store rkey
    header.diff.som_true.header_data = 0;// Because default som
    header.request_length = 0;    
    return header;
}

// Make into function for easy repeated calls
MemoryRegion SESManager::decode_rkey_to_mr(uint64_t rkey)
{
    if(rkey == 0) {
        // rkey 0 means invalid
        LOG_WARN(__FUNCTION__, "rkey is 0, invalid rkey");
        MemoryRegion mr;
        mr.start_addr = 0;
        mr.length = 0;
        return mr;
    }
    else{        
        // Parse rkey to get memory region
        MemoryRegion mr;
        if (rkey & (1ULL << 62)) {  
            // Optimized format: Extract 12-bit INDEX  
            uint16_t index = rkey & 0xFFF; // Bits 0-11
            mr = lookup_mr_by_key(index);  
        } else {  
            // General format: Extract 48-bit RKEY  
            uint64_t extracted_rkey = rkey & 0xFFFFFFFFFFFF; // Bits 0-47
            mr = lookup_mr_by_key(extracted_rkey);
        }  
        return mr;
    }
}

MemoryRegion SESManager::lookup_mr_by_key(uint64_t key)
{
    LOG_DEBUG(__FUNCTION__, "lookup_mr_by_key for key: " + std::to_string(key));
    // Simulate query
    MemoryRegion mr;
    mr.start_addr = 0x000000; // Assume start address
    mr.length = 0x10000; // Assume length
    return mr;
}


uint64_t SESManager:: calculate_buffer_offset(uint64_t rkey, uint64_t start_addr)
{
    /*
    buffer_offset calculation essence is:
    Convert target virtual address provided by application layer → Convert to relative offset within target memory region (MR)
    This process depends on RKEY deconstruction and memory region query, formula as follows:

    buffer_offset=target_addr−mr_start_addr
    */
    // Should get mr start_addr based on key

    // Parse mr based on rkey below and make into function for later reuse
    // Parse rkey to get addr
    MemoryRegion mr = decode_rkey_to_mr(rkey);

    //cout<<"mr start_addr: "<<mr.start_addr<<" mr length: "<<mr.length<<endl;
    // Check if out of bounds
    if (start_addr < mr.start_addr || start_addr >= mr.start_addr + mr.length) {
        // Out of bounds
        return UINT64_MAX; // Return maximum value to indicate error
    }
    return start_addr - mr.start_addr;
    
}

void SESManager::send_packet_to_pds(const SES_Standard_Header& header, const SES_PDS_req& sent_pkt,...) {
    // Simulate send
    LOG_INFO(__FUNCTION__, "send packet to pds manager");
    LOG_INFO_PARAM(__FUNCTION__, "msg_id: " + std::to_string(header.msg_id) + 
                   ", opcode: " + std::to_string(header.opcode) + 
                   ", buffer_offset: " + std::to_string(header.buffer_offset) + 
                   ", ie: " + std::to_string(int(header.ie)) + 
                   ", rel: " + std::to_string(int(header.rel)) + 
                   ", hd: " + std::to_string(int(header.hd)) + 
                   ", eom: " + std::to_string(int(header.eom)) + 
                   ", som: " + std::to_string(int(header.som)) + 
                   ", ri_generation: " + std::to_string(header.ri_generation) + 
                   ", PIDonFEP: " + std::to_string(header.PIDonFEP) + 
                   ", resource_index: " + std::to_string(header.resource_index) + 
                   ", initiator: " + std::to_string(header.initiator) + 
                   ", match_bits: " + std::to_string(header.match_bits) + 
                   ", job_id: " + std::to_string(header.job_id) + 
                   ", request_length: " + std::to_string(header.request_length));
    
    // Actually construct packet
    //SES_PDS_req send_pkt;
    //send_pkt.
    pds_process_manager.pushSESRequest(sent_pkt);
    
}

// rsp returned to PDS
void SESManager::send_rsp_to_pds(const SES_PDS_rsp& rsp) {
    // Simulate direct output here
    LOG_INFO(__FUNCTION__, "send rsp to pds manager:");
    LOG_INFO_PARAM(__FUNCTION__, "ack_type: " + std::to_string(int(rsp.rsp.bth_header.Semantic_Response_Header.return_code)) +
                                 ", msg_id: " + std::to_string(rsp.rsp.bth_header.Semantic_Response_Header.message_id) +
                                 ", opcode: " + std::to_string(int(rsp.rsp.bth_header.Semantic_Response_Header.opcode)) +
                                 ", job_id: " + std::to_string(rsp.rsp.bth_header.Semantic_Response_Header.job_id) +
                                 ", rx_pkt_handle: " + std::to_string(rsp.rx_pkt_handle));
    
    // Push to manager
    pds_process_manager.pushSESResponse(rsp);
}


void SESManager::process_send_packet(const OperationMetadata& metadata){

    // First parse metadata information to generate standard header
    SES_Standard_Header header = initialize_header(metadata);
    SES_PDS_req send_pkt = {};
    //初始化共同部分
    send_pkt.dst_fep = metadata.t_pid_on_fep;
    send_pkt.src_fep = metadata.s_pid_on_fep;
    send_pkt.lock_pdc = false;
    send_pkt.mode = ROD;
    send_pkt.next_hdr = UET_HDR_NONE;// Not sure?
    send_pkt.rod_context = 0;// Request, not same context?
    send_pkt.tc = 0;
    send_pkt.tss_context = 0; //?
    send_pkt.rsv_ccc_context =0;//?
    send_pkt.rsv_pdc_context = 0;//?
    send_pkt.pkt_len = 0;
    send_pkt.pkt = {};
    send_pkt.next_hdr = UET_HDR_NONE;//默认NONE，用于避免未初始化值的引用
    
    if (header.ie){
        // Error packet, send directly
        send_pkt.pkt.bth_type =Standard_Header;
        send_pkt.pkt.bth_header.Standard_Header = header;
        send_pkt.pkt_len =  44;// 44 is standard header length 44 bytes, because error packet has no data 
        send_packet_to_pds(header,send_pkt);
        return;
    }
    // Check if need to slice
    else if (metadata.payload.length > MAX_MTU - sizeof(SES_Standard_Header)){
        // Start som=1 eom=0, middle packets som=0 eom=0, end packet som=0 eom=1
        int n = metadata.payload.length / (MAX_MTU - sizeof(SES_Standard_Header));// Calculate number of fragments
        if(metadata.payload.length % (MAX_MTU - sizeof(SES_Standard_Header))) n++;
        LOG_INFO(__FUNCTION__, "Data payload too long, slicing into " + std::to_string(n) + " packets to send to PDS");
        for(int i = 0; i < n; i++){
            if(i == 0){
                // First packet needs additional check for imm_data
                header.som = 1;
                header.eom = 0;
                header.hd = metadata.has_imm_data ? 1 : 0;
                header.diff.som_true.header_data = metadata.has_imm_data ? metadata.payload.imm_data : 0;
                header.request_length = metadata.payload.length;
                LOG_INFO(__FUNCTION__, "First packet data payload length is " + std::to_string(header.request_length));
            }
            else if (i == n - 1){
                // Last packet
                header.som = 0;
                header.eom = 1;
                header.hd = 0;// Middle and last packets will not have header_data
                header.diff.som_false.message_offset = i * (MAX_MTU - sizeof(SES_Standard_Header));
                header.diff.som_false.payload_length = metadata.payload.length - i * (MAX_MTU - sizeof(SES_Standard_Header));
                header.request_length = metadata.payload.length;// Multi-packet total data length
                LOG_INFO(__FUNCTION__, "Last packet data payload length is " + std::to_string(header.request_length));
            }
            else{
                // Middle packet
                header.som = 0;
                header.eom = 0;
                header.hd = 0;
                header.diff.som_false.message_offset = i * (MAX_MTU - sizeof(SES_Standard_Header));
                header.diff.som_false.payload_length = MAX_MTU - sizeof(SES_Standard_Header);
                header.request_length = metadata.payload.length;// Multi-packet total data length
                LOG_INFO(__FUNCTION__, "Middle packet number " + std::to_string(i + 1) + " data payload length is " + std::to_string(header.request_length));
            }
            // Send packet
            send_pkt.pkt.bth_type =Standard_Header;
            send_pkt.pkt.bth_header.Standard_Header = header;
            send_pkt.pkt_len = header.diff.som_false.payload_length/8 + 44;// 44 is standard header length 44 bytes
            send_packet_to_pds(header,send_pkt);        
        }
    }
    else {
        // Single packet send
        header.hd = metadata.has_imm_data ? 1 : 0;
        header.diff.som_true.header_data = metadata.has_imm_data ? metadata.payload.imm_data : 0;
        header.buffer_offset = 0;
        header.request_length = metadata.payload.length;// Single packet total data length

        send_pkt.pkt.bth_type =Standard_Header;
        send_pkt.pkt.bth_header.Standard_Header = header;
        send_pkt.pkt_len = header.request_length/8 + 44;// 44 is standard header length 44 bytes
        // Send packet
        send_packet_to_pds(header,send_pkt);
    }
}


// Implement SESManager::process_recv__req_packet to process received packets
void SESManager::process_recv_req_packet(const PDC_SES_req& req) {
    OperationMetadata metadata;   
    // Parse header // First parse req information
    metadata=parse_pdc_2_ses_req(req);
    SES_Semantic_Response_Header semantic_rsp;
    SES_PDS_rsp ses_pds_rsp;
    // Generate rsp, first initialize some defaults
    semantic_rsp.list = 1;//excpected
    semantic_rsp.version = 2;
    semantic_rsp.job_id = metadata.job_id;
    semantic_rsp.message_id = metadata.messages_id;
    semantic_rsp.modified_length = metadata.payload.length;
    semantic_rsp.ri_generation = req.pkt.bth_header.Standard_Header.ri_generation;
    ses_pds_rsp.rsp.bth_type = Semantic_Response_Header;
    ses_pds_rsp.dst_fep = metadata.t_pid_on_fep;
    ses_pds_rsp.src_fep = metadata.s_pid_on_fep;
    ses_pds_rsp.gtd_del =false;
    ses_pds_rsp.ses_nack =false;
    ses_pds_rsp.PDCID = req.PDCID;
    ses_pds_rsp.rx_pkt_handle =req.rx_pkt_handle;
    ses_pds_rsp.rsp_len =  12;// 12-byte fixed length

    // First check version compatibility, function check version position is fixed, is req.pkt.standerheader 8-9 bits, starting from 0

    // PDC status verification
    if (!validate_pdc_status(req.orig_pdcid, req.orig_psn)) {
        LOG_ERROR(__FUNCTION__, "pdc status error");
        // PDC status error, discard, terminate connection
        // Need to return NACK
        // NackPayload nack = generate_nack_packet( metadata, NackCode::PROTOCOL);
        // // Package into SES_PDC_rsp
        // SES_PDC_rsp nack_rsp = {req.rx_pkt_handle,0,1,nack};// No data, no length
        semantic_rsp.opcode = static_cast<uint8_t>(RSP_OP_CODE::UET_NACK);
        semantic_rsp.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_PROTOCOL_ERROR);
        send_rsp_to_pds(ses_pds_rsp);
        return;
    }
    // Check version
    if(!validate_version(req.pkt.bth_header.Standard_Header.version)){
        // Version mismatch, generate error, discard, seems no return
        LOG_ERROR(__FUNCTION__, "version not match");
        /*
        NackPayload nack = generate_nack_packet(metadata, NackCode::PROTOCOL);// Version mismatch directly aborts connection operation
        SES_PDC_rsp nack_rsp = {req.rx_pkt_handle,0,1,nack};// No data, no length
        */
        semantic_rsp.opcode = static_cast<uint8_t>(RSP_OP_CODE::UET_NACK);
        semantic_rsp.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_PROTOCOL_ERROR);
        send_rsp_to_pds(ses_pds_rsp);
        return;
    }
    
    // Check if packet header type is valid
    if(!validate_header_type(req.pkt.bth_type)){

        LOG_ERROR(__FUNCTION__, "header type illgeal");
        // Generate NACK, discard
        semantic_rsp.opcode = static_cast<uint8_t>(RSP_OP_CODE::UET_NACK);
        semantic_rsp.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_PROTOCOL_ERROR);
        send_rsp_to_pds(ses_pds_rsp);
        return;
    }

    // Check if job_id is allowed
    
    if (!validate_job_id(metadata.job_id)) {
        // Not allowed, discard directly
        LOG_ERROR_PARAM(__FUNCTION__, "Job ID %d not authorized. Packet discarded.", metadata.job_id);
        // Generate NACK
        // Call PDC interface to send to PDC
        // fwdRsp2SES(nack_rsp); // PDC interface not connected yet, no downward output for now
        LOG_INFO(__FUNCTION__, "process_recv_packet end");
        semantic_rsp.opcode = static_cast<uint8_t>(RSP_OP_CODE::UET_NACK);
        semantic_rsp.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_ACCESS_DENIED);
        send_rsp_to_pds(ses_pds_rsp);
        return;
    }

    // Check if pid_on_id based on absolute and relative addressing
    if(!validate_pid_on_fep(metadata.t_pid_on_fep, metadata.job_id,metadata.relative)){
        LOG_ERROR(__FUNCTION__, "pid_on_fep not match");
        // Generate NACK, discard
        semantic_rsp.opcode = static_cast<uint8_t>(RSP_OP_CODE::UET_NACK);
        semantic_rsp.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_ADDR_UNREACHABLE);
        send_rsp_to_pds(ses_pds_rsp);
        return;
    }
    
    // Verify if opcode is valid
    if (!validate_opcode(metadata.op_type)) {
        LOG_ERROR(__FUNCTION__, "opcode not match");
        semantic_rsp.opcode = static_cast<uint8_t>(RSP_OP_CODE::UET_NACK);
        semantic_rsp.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_INVALID_OP);
        send_rsp_to_pds(ses_pds_rsp);
        return;
    }

    // Packet needs to check if packet length equals actual received length
    if(!validate_data_length(req.pkt_len,metadata.payload.length)){
        LOG_ERROR(__FUNCTION__, "data length not match");
        LOG_ERROR_PARAM(__FUNCTION__,"req.pkt_len: " + std::to_string(req.pkt_len) + "metadata.payload.length:" + std::to_string(metadata.payload.length));
        // If eom=1 last packet, generate NACK, other middle packets silently discard
        if(req.pkt.bth_header.Standard_Header.eom == 1){
            // Generate NACK, discard
            semantic_rsp.opcode = static_cast<uint8_t>(RSP_OP_CODE::UET_NACK);
            semantic_rsp.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_INTEGRITY_CHECK_FAIL);
            send_rsp_to_pds(ses_pds_rsp);          
        }
        return;
    }

    // If it is send write read etc., need to check permissions, buffer detection
    if (metadata.op_type == SEND || metadata.op_type == WRITE || metadata.op_type == READ) {
        // Check permissions
        if (!validate_rkey(metadata.memory.rkey,req.pkt.bth_header.Standard_Header.msg_id)) {

            // Permission mismatch, discard
            LOG_ERROR(__FUNCTION__, "RKEY error. Packet discarded.");
            semantic_rsp.opcode = static_cast<uint8_t>(RSP_OP_CODE::UET_NACK);
            semantic_rsp.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_INVALID_KEY);
            send_rsp_to_pds(ses_pds_rsp);  
            return;
        }
        LOG_INFO(__FUNCTION__, "access key ok");
    }

    // Check MSN table
    if (!validate_msn(metadata.job_id, req.orig_psn,req.pkt.bth_header.Standard_Header.request_length,req.orig_pdcid,req.pkt.bth_header.Standard_Header.som, req.pkt.bth_header.Standard_Header.eom)) {
        // MSN table error, discard
        LOG_ERROR(__FUNCTION__, "MSN table error. Packet discarded.");
        // Generate NACK, discard
        LOG_ERROR(__FUNCTION__, "RKEY error. Packet discarded.");
        semantic_rsp.opcode = static_cast<uint8_t>(RSP_OP_CODE::UET_NACK);
        semantic_rsp.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_NO_MATCH);
        send_rsp_to_pds(ses_pds_rsp);
        return;
    }
    semantic_rsp.opcode = static_cast<uint8_t>(RSP_OP_CODE::UET_NO_RESPONSE);
    // If it is the last MSN packet and eom=1, then update MSN table
    if (req.pkt.bth_header.Standard_Header.eom == 1 ) {

        // Update MSN table, release MSN corresponding to job_id
        msn_table.erase(metadata.job_id);
        semantic_rsp.opcode = static_cast<uint8_t>(RSP_OP_CODE::UET_DEFAULT_RESPONSE);// Last update bit default return packet
        LOG_INFO_PARAM(__FUNCTION__, "erase msn , job_id:"+std::to_string(metadata.job_id));
    }
    // Everything normal, for send can choose to return ack, for write can also choose default none, can be configured by application layer to enable ack return, read must return
    // If it is send or write type, check if ack needs to be returned
    if (metadata.op_type == SEND || metadata.op_type == WRITE) {
        // Check if ack needs to be returned
        if(!validate_need_ack(metadata.messages_id,true)){
            LOG_INFO_PARAM(__FUNCTION__, "no need ack! msg_id: %d", metadata.messages_id);
            return;// No return, cold processing
        }

       
        semantic_rsp.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_OK);
        // Simulate return through function
        ses_pds_rsp.rsp.bth_header.Semantic_Response_Header  = semantic_rsp;
        send_rsp_to_pds(ses_pds_rsp);
        return;
    }
    // If it is read, must return
    if(metadata.op_type == READ){
        semantic_rsp.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_OK);
        // Simulate return through function
        ses_pds_rsp.rsp.bth_header.Semantic_Response_Header  = semantic_rsp;
        send_rsp_to_pds(ses_pds_rsp);
        return; 
    }
    return;
}
void SESManager::process_recv_rsp_packet(const PDC_SES_rsp& rsp){
    // First pure output
    LOG_ERROR(__FUNCTION__, "SES received rsp");
    LOG_ERROR(__FUNCTION__, "SPDCID: "+to_string(rsp.PDCID)+"msg_id: "+to_string(rsp.pkt.bth_header.Semantic_Response_Header.message_id)+"job_id: "
            +to_string(rsp.pkt.bth_header.Semantic_Response_Header.job_id)+"op_code: "+to_string(rsp.pkt.bth_header.Semantic_Response_Header.opcode)
            +"return_code: "+to_string(rsp.pkt.bth_header.Semantic_Response_Header.return_code));
}
#endif