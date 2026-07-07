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

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
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
};

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
        uint64_t local_addr;     // Local buffer address (READ response destination)
    } payload;
    uint32_t s_pid_on_fep;      // Source endpoint process ID
    uint32_t t_pid_on_fep;     // Target endpoint process ID
    uint32_t job_id;         // Job identifier
    uint16_t res_index; 
    uint32_t messages_id;    // Message identifier
    uint8_t delivery_mode;   // Delivery mode {RUD, ROD, RUDI, UUD}
    // Operation flag bits
    bool relative;              // Whether it is relative addressing
    bool use_optimized_header;   // Whether to use optimized header
    bool has_imm_data;           // Whether to carry immediate data
    bool is_retry;               // Whether this metadata is being replayed by SES retry logic
    
    // Constructor default initialization, uint types default to 0, memory also defaults
    OperationMetadata() : op_type(SEND), memory({0, false}), payload({0, 0, 0, 0}), s_pid_on_fep(0), job_id(0), res_index(0), messages_id(0), delivery_mode(1), relative(false), use_optimized_header(false), has_imm_data(false), is_retry(false) {}

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

struct WriteTrackKey {
    uint32_t job_id;
    uint16_t msg_id;
    uint16_t pdc_id;
    uint16_t res_index;
    uint32_t src_fep;

    bool operator==(const WriteTrackKey& other) const
    {
        return job_id == other.job_id &&
               msg_id == other.msg_id &&
               pdc_id == other.pdc_id &&
               res_index == other.res_index &&
               src_fep == other.src_fep;
    }
};

struct WriteTrackKeyHash {
    size_t operator()(const WriteTrackKey& k) const noexcept
    {
        const size_t a = static_cast<size_t>(k.job_id);
        const size_t b = static_cast<size_t>(k.msg_id);
        const size_t c = static_cast<size_t>(k.pdc_id);
        const size_t d = static_cast<size_t>(k.res_index);
        const size_t e = static_cast<size_t>(k.src_fep);
        return (a << 32) ^ (b << 16) ^ (c << 1) ^ d ^ (e << 3);
    }
};

struct WriteTrackState {
    uint32_t total_len{0};
    uint32_t chunk_size{0};
    uint32_t chunks_done{0};
    bool saw_eom{false};
    std::vector<uint8_t> chunk_received;
};

struct ReadTrackKey {
    uint32_t job_id;
    uint16_t msg_id;
    uint32_t src_fep;

    bool operator==(const ReadTrackKey& other) const
    {
        return job_id == other.job_id &&
               msg_id == other.msg_id &&
               src_fep == other.src_fep;
    }
};

struct ReadTrackKeyHash {
    size_t operator()(const ReadTrackKey& k) const noexcept
    {
        const size_t a = static_cast<size_t>(k.job_id);
        const size_t b = static_cast<size_t>(k.msg_id);
        const size_t c = static_cast<size_t>(k.src_fep);
        return (a << 32) ^ (b << 16) ^ (c << 1);
    }
};

struct ReadTrackState {
    uint64_t dst_addr{0};              // READ 结果写入的本地地址（若为 0 则写入 buffer）
    uint32_t total_len{0};             // READ 总长度
    uint32_t chunk_size{0};            // 分片大小
    uint32_t chunks_done{0};           // 已收齐分片数量
    std::vector<uint8_t> chunk_received; // 分片 bitmap
    std::vector<uint8_t> buffer;       // 本地地址为空时的临时重组区
};

struct ReadResponseProbe
{
    bool track_present{false};
    bool terminalized{false};
    ReadResponseTerminalReason reason{ReadResponseTerminalReason::CLOSE_RESET};
};

struct RequestTerminalProbe
{
    bool retry_present{false};
    bool terminalized{false};
    SenderTerminalReason reason{SenderTerminalReason::CLOSE_RESET};
    int64_t terminalized_at_ms{0};
    RequestCloseCause close_cause{RequestCloseCause::UNKNOWN};
    uint8_t close_state_at_terminalize{0};
    uint32_t tx_pending_count_at_terminalize{0};
    uint32_t unack_cnt_at_terminalize{0};
    bool all_ack_at_terminalize{false};
    bool retry_present_at_terminalize{false};
    bool read_track_present_at_terminalize{false};
};

struct SendTrackKey {
    uint32_t job_id;
    uint16_t msg_id;
    uint16_t pdc_id;
    uint32_t src_fep;

    bool operator==(const SendTrackKey& other) const
    {
        return job_id == other.job_id &&
               msg_id == other.msg_id &&
               pdc_id == other.pdc_id &&
               src_fep == other.src_fep;
    }
};

struct SendTrackKeyHash {
    size_t operator()(const SendTrackKey& k) const noexcept
    {
        const size_t a = static_cast<size_t>(k.job_id);
        const size_t b = static_cast<size_t>(k.msg_id);
        const size_t c = static_cast<size_t>(k.pdc_id);
        const size_t d = static_cast<size_t>(k.src_fep);
        return (a << 32) ^ (b << 16) ^ c ^ (d << 3);
    }
};

struct SendTrackState {
    uint32_t total_len{0};
    uint32_t chunk_size{0};
    uint32_t chunks_done{0};
    bool saw_eom{false};
    std::vector<uint8_t> chunk_received;
    std::vector<uint8_t> buffer;
};

struct PostedRecvKey {
    uint64_t job_id{0};
    uint16_t pdc_id{0};
    uint32_t src_fep{0};

    bool operator==(const PostedRecvKey& other) const noexcept
    {
        return job_id == other.job_id &&
               pdc_id == other.pdc_id &&
               src_fep == other.src_fep;
    }
};

struct PostedRecvKeyHash {
    size_t operator()(const PostedRecvKey& k) const noexcept
    {
        const size_t a = static_cast<size_t>(k.job_id);
        const size_t b = static_cast<size_t>(k.pdc_id);
        const size_t c = static_cast<size_t>(k.src_fep);
        return (a << 32) ^ (b << 4) ^ (c << 1);
    }
};

struct PostedRecvEntry {
    uint64_t completion_key{0};
    uint64_t base_addr{0};
    uint32_t buffer_len{0};
    uint64_t job_id{0};
    uint16_t pdc_id{0};
    uint32_t src_fep{0};
};

struct SendRetryKey {
    uint64_t job_id{0};
    uint16_t msg_id{0};
    uint32_t dst_fep{0};

    bool operator==(const SendRetryKey& other) const noexcept
    {
        return job_id == other.job_id &&
               msg_id == other.msg_id &&
               dst_fep == other.dst_fep;
    }
};

struct SendRetryKeyHash {
    size_t operator()(const SendRetryKey& key) const noexcept
    {
        const size_t a = static_cast<size_t>(key.job_id);
        const size_t b = static_cast<size_t>(key.msg_id);
        const size_t c = static_cast<size_t>(key.dst_fep);
        return (a << 24) ^ (b << 8) ^ c;
    }
};

struct SendRetryState {
    OperationMetadata metadata{};
    uint16_t retry_count{0};
    int64_t next_retry_ms{0};
    bool waiting_response{false};
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
        void register_mr(uint64_t key, uint64_t start_addr, size_t length); // 注册 MR（供 READ/WRITE 查表）
        void unregister_mr(uint64_t key);

        // Process requests from above to generate standard SES header
        void process_send_packet(const OperationMetadata& metadata, bool is_retry = false);
        // Simulate generated SES header to be passed down to PDS
        void send_packet_to_pds(const SES_Standard_Header& header, const SES_PDS_req& sent_pkt ,...);

        // Process received req packets
        void process_recv_req_packet(const PDC_SES_req& req);
        // Process received rsp packets
        void process_recv_rsp_packet(const PDC_SES_rsp& rsp);
        // rsp returned to PDS
        void send_rsp_to_pds(const SES_PDS_rsp& rsp);
        void postRecv(const PostedRecvEntry& entry);
        uint16_t postedRecvCredits(uint64_t job_id, uint16_t pdc_id, uint32_t src_fep);
        RxPlacementDescriptor resolveRxPlacement(const PDC_SES_req& req);
        RxPlacementDescriptor resolveRxPlacement(const PDC_SES_rsp& rsp);
        void completeRxOperation(const PDC_RX_completion& completion);
        void completeSenderTerminal(const SenderTerminalCompletion& completion);
        void completeRequestTerminal(const RequestTerminalCompletion& completion);
        void completeReadResponseTerminal(const ReadResponseTerminalCompletion& completion);
        RequestTerminalProbe queryRequestTerminalProbe(uint64_t job_id, uint16_t msg_id, uint32_t dst_fep);
        SendRetryProbe querySendRetryProbe(uint64_t job_id, uint16_t msg_id, uint32_t dst_fep);
        RequestTxProbe queryRequestTxProbe(uint64_t job_id, uint16_t msg_id, uint32_t dst_fep);
        ReadResponseProbe queryReadResponseProbe(uint64_t job_id, uint16_t msg_id, uint32_t src_fep);
        UnexpectedSendProbe queryUnexpectedSendProbe(uint64_t job_id, uint16_t msg_id, uint32_t src_fep);


        // Unified centralized processing of received req from PDC, needs queue buffering
        void process_pdc_2_ses();
        void mainChk();

        
    private:
        friend struct SESValidationProbe;
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
        bool validate_msn(uint32_t job_id, uint64_t psn, uint64_t requires_length,uint32_t pcd_id, bool is_first_packet,bool is_last_packet, uint8_t delivery_mode);
        // Determine if ack needs to be returned
        bool validate_need_ack(uint32_t messages_id, bool delivery_complete); // bool Enable dynamic ack configuration, then confirm whether to return based on msg

        //


        // Parse based on rkey, then call look_mr_by_key to return memory region
        MemoryRegion decode_rkey_to_mr(uint64_t key);
        // Generate NACK response based on error code type
        //NackPayload generate_nack_packet(const OperationMetadata& recv_header, NackCode nack_code);

        MemoryRegion lookup_mr_by_key(uint64_t key);
        bool tryPopPostedRecv(const PostedRecvKey& key, PostedRecvEntry& entry);
        SES_PDS_rsp buildSemanticResponse(const PDC_RX_completion& completion) const;
        SES_PDS_rsp buildPdsNackResponse(const PDC_RX_completion& completion) const;
        void trackSendRetry(const OperationMetadata& metadata, bool is_retry);
        void processDueSendRetries();
        void clearSendRetryState(uint64_t job_id, uint16_t msg_id, uint32_t dst_fep);
        bool clearSendRetryStateIfPresent(uint64_t job_id, uint16_t msg_id, uint32_t dst_fep);
        bool clearReadTrackIfPresent(const ReadTrackKey& key);
        int64_t currentTimeMs() const;
        int64_t retryDelayMs(uint16_t retry_count) const;

        // Queue to store received pdc_to_ses_req
        std::queue<PDC_SES_req> pdc_to_ses_req_queue;
        // Initialize MSN table, a hash table supporting O(1) query, insert, delete, and jobid has uniqueness, jobid as key is reasonable
        std::unordered_map<uint64_t, MSNEntry> msn_table;
        std::unordered_map<WriteTrackKey, WriteTrackState, WriteTrackKeyHash> write_track_;
        std::mutex write_track_mu_;
        std::unordered_map<ReadTrackKey, ReadTrackState, ReadTrackKeyHash> read_track_;
        std::unordered_map<ReadTrackKey, ReadResponseTerminalReason, ReadTrackKeyHash> retired_read_response_;
        std::mutex read_track_mu_;
        std::unordered_map<SendTrackKey, SendTrackState, SendTrackKeyHash> send_track_;
        std::mutex send_track_mu_;
        std::unordered_map<SendRetryKey, SendRetryState, SendRetryKeyHash> send_retry_;
        std::unordered_set<SendRetryKey, SendRetryKeyHash> retired_send_retry_;
        std::unordered_map<SendRetryKey, RequestTerminalCompletion, SendRetryKeyHash> retired_request_terminal_;
        std::mutex send_retry_mu_;
        std::unordered_map<PostedRecvKey, std::deque<PostedRecvEntry>, PostedRecvKeyHash> posted_recv_q_;
        std::mutex posted_recv_mu_;
        std::unordered_map<uint64_t, MemoryRegion> mr_table_; // MR 注册表（rkey -> {addr,len}）
        std::mutex mr_mu_;



        // Temporarily not locked std::mutex msn_mutex_; // Mutex to protect msn_table_

};
inline OperationMetadata SESManager::parse_pdc_2_ses_req(const PDC_SES_req& req){
    // Parse pdc_2_ses_req
    // Get job_id, pid, resource_index, buffer_type, data_length, data, buffer_offset, imm_data etc. from req to generate metadata
    // First declare metadata
    OperationMetadata metadata;

    switch(req.pkt.bth_type) {
        // Parse based on bth_header type
        case Standard_Header: {
            // Parse standard header
            MemoryRegion mr{};
            metadata.op_type = static_cast<OpType>(req.pkt.bth_header.Standard_Header.opcode);
            metadata.messages_id = req.pkt.bth_header.Standard_Header.msg_id;
            metadata.job_id = req.pkt.bth_header.Standard_Header.job_id;
            metadata.relative = req.pkt.bth_header.Standard_Header.rel;
            metadata.res_index = req.pkt.bth_header.Standard_Header.resource_index;//re_idx
            metadata.t_pid_on_fep = req.pkt.bth_header.Standard_Header.PIDonFEP;// PID of received packet is the sender locating receiver PID
            metadata.s_pid_on_fep = 0;
            metadata.res_index = req.pkt.bth_header.Standard_Header.resource_index;
            metadata.memory.rkey = req.pkt.bth_header.Standard_Header.match_bits;
            metadata.delivery_mode = req.mode;
            if (metadata.op_type != SEND) {
                mr = decode_rkey_to_mr(req.pkt.bth_header.Standard_Header.match_bits);
            }
            // Note about FI_MSG / SEND:
            // For SEND, the "payload" is carried inline in req.pkt.payload and should be delivered to the application.
            // There is no remote MR to address, so buffer_offset/start_addr derived from rkey is not meaningful here.

            // Determine if it is a single packet based on som and eom
            if (req.pkt.bth_header.Standard_Header.som == 1 && req.pkt.bth_header.Standard_Header.eom == 1){
                metadata.payload.length = req.pkt.bth_header.Standard_Header.request_length;
                // Start address is buffer_offset + rkey obtained buffer.addr
                if (metadata.op_type != SEND) {
                    metadata.payload.start_addr = mr.start_addr + req.pkt.bth_header.Standard_Header.buffer_offset;
                } else {
                    metadata.payload.start_addr = 0;
                }

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
                if (req.pkt.bth_header.Standard_Header.som == 1) {
                    metadata.payload.length = req.pkt.payload.size();
                } else {
                    metadata.payload.length = req.pkt.bth_header.Standard_Header.diff.som_false.payload_length;
                }
                metadata.has_imm_data = false;
                metadata.payload.imm_data = 0;
                // Start address is buffer_offset + rkey obtained buffer.addr + payload message_offset
                if (metadata.op_type != SEND) {
                    const uint32_t msg_off = req.pkt.bth_header.Standard_Header.som ? 0 : req.pkt.bth_header.Standard_Header.diff.som_false.message_offset;
                    metadata.payload.start_addr = mr.start_addr + req.pkt.bth_header.Standard_Header.buffer_offset + msg_off;
                } else {
                    metadata.payload.start_addr = 0;
                }

            }
            break;  // Add break to avoid fall-through
        }
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

inline uint16_t SESManager::get_message_id(const OperationMetadata& metadata, void* pdc_manager )
{
    // Should properly update and reuse message_id based on PDC management interaction
    LOG_DEBUG(__FUNCTION__, "generate_message_id for job_id: " + std::to_string(metadata.job_id));
    // For phase-1 libfabric mapping, preserve the message_id provided by the upper layer
    // so that completions/reassembly can correlate correctly across layers.
    if (metadata.messages_id != 0) {
        return static_cast<uint16_t>(metadata.messages_id);
    }
    static uint16_t message_id = 0;
    message_id++;
    return message_id;
}

// Header initialization
inline SES_Standard_Header SESManager::initialize_header(const OperationMetadata& metadata) {
    SES_Standard_Header header;
    header.opcode = metadata.op_type;
    header.version = 2;
    if (metadata.op_type == SEND) {
        // FI_MSG / SEND carries inline payload bytes.
        // In this prototype, metadata.payload.start_addr points to a local user buffer, and SES will copy those
        // bytes into SEStoPDS_pkt::payload for UDP serialization. Therefore buffer_offset must not be derived
        // from MR/rkey addressing here (no "remote memory target" semantics in phase 1).
        header.buffer_offset = 0;
        header.ie = 0;
    } else {
        header.buffer_offset = calculate_buffer_offset(metadata.memory.rkey, metadata.payload.start_addr);// Calculate offset
        header.ie = (header.buffer_offset == UINT64_MAX) ? 1 : 0;// Out of bounds indicates error packet
    }
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
inline MemoryRegion SESManager::decode_rkey_to_mr(uint64_t rkey)
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

inline MemoryRegion SESManager::lookup_mr_by_key(uint64_t key)
{
    LOG_DEBUG(__FUNCTION__, "lookup_mr_by_key for key: " + std::to_string(key));
    // Simulate query
    MemoryRegion mr;
    {
        std::lock_guard<std::mutex> lock(mr_mu_);
        auto it = mr_table_.find(key);
        if (it != mr_table_.end()) {
            return it->second;
        }
    }
    mr.start_addr = 0x000000; // Assume start address
    mr.length = 0x10000; // Assume length
    return mr;
}


inline uint64_t SESManager:: calculate_buffer_offset(uint64_t rkey, uint64_t start_addr)
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

inline void SESManager::send_packet_to_pds(const SES_Standard_Header& header, const SES_PDS_req& sent_pkt,...) {
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
    const bool queued = pds_process_manager.pushSESRequest(sent_pkt);
    std::cout << "[uet-ses] send_packet_to_pds msg_id=" << header.msg_id
              << " job_id=" << header.job_id
              << " dst_fep=" << sent_pkt.dst_fep
              << " queued=" << (queued ? 1 : 0)
              << std::endl;
    
}

// rsp returned to PDS
inline void SESManager::send_rsp_to_pds(const SES_PDS_rsp& rsp) {
    // Simulate direct output here
    LOG_INFO(__FUNCTION__, "send rsp to pds manager:");
    if (rsp.ses_nack) {
        LOG_INFO_PARAM(__FUNCTION__,
                       "ses_nack: true, nack_code: " + std::to_string(int(rsp.nack_payload.nack_code)) +
                           ", rx_pkt_handle: " + std::to_string(rsp.rx_pkt_handle));
    } else {
        LOG_INFO_PARAM(__FUNCTION__, "ack_type: " + std::to_string(int(rsp.rsp.bth_header.Semantic_Response_Header.return_code)) +
                                     ", msg_id: " + std::to_string(rsp.rsp.bth_header.Semantic_Response_Header.message_id) +
                                     ", opcode: " + std::to_string(int(rsp.rsp.bth_header.Semantic_Response_Header.opcode)) +
                                     ", job_id: " + std::to_string(rsp.rsp.bth_header.Semantic_Response_Header.job_id) +
                                     ", rx_pkt_handle: " + std::to_string(rsp.rx_pkt_handle));
    }
    
    // Push to manager
    pds_process_manager.pushSESResponse(rsp);
}


inline void SESManager::process_send_packet(const OperationMetadata& metadata, bool is_retry){
    {
        const SendRetryKey key{
            metadata.job_id,
            static_cast<uint16_t>(metadata.messages_id),
            metadata.t_pid_on_fep,
        };
        std::lock_guard<std::mutex> lock(send_retry_mu_);
        retired_request_terminal_.erase(key);
    }
    trackSendRetry(metadata, is_retry);

    // SEND path (phase 1 FI_MSG):
    // - Input: OperationMetadata contains a pointer+length to the user's payload buffer.
    // - Output: SES_PDS_req packets where pkt.payload holds the raw bytes.
    // - If payload > MTU, we slice into multiple packets:
    //     * first packet: som=1, eom=0, optional imm_data in header_data
    //     * middle packets: som=0, eom=0, use message_offset/payload_length
    //     * last packet: som=0, eom=1
    // These packets are then forwarded to PDS, which hands them to the UDP shim for on-wire transmission.

    // First parse metadata information to generate standard header
    SES_Standard_Header header = initialize_header(metadata);
    SES_PDS_req send_pkt = {};
    //初始化共同部分
    send_pkt.dst_fep = metadata.t_pid_on_fep;
    send_pkt.src_fep = metadata.s_pid_on_fep;
    send_pkt.lock_pdc = false;
    send_pkt.is_retry = is_retry;
    send_pkt.mode = metadata.delivery_mode;
    send_pkt.next_hdr = UET_HDR_NONE;// Not sure?
    send_pkt.rod_context = 0;// Request, not same context?
    send_pkt.tc = 0;
    send_pkt.tss_context = 0; //?
    send_pkt.rsv_ccc_context =0;//?
    send_pkt.rsv_pdc_context = 0;//?
    send_pkt.pkt_len = 0;
    send_pkt.pkt = {};
    send_pkt.next_hdr = UET_HDR_NONE;//默认NONE，用于避免未初始化值的引用

    if (metadata.op_type == READ) {
        const ReadTrackKey key{
            metadata.job_id,
            header.msg_id,
            metadata.t_pid_on_fep,
        };
        // 记录 READ 事务的本地接收缓冲区，等待 response-with-data 分片回填
        ReadTrackState st;
        st.dst_addr = (metadata.payload.local_addr != 0) ? metadata.payload.local_addr : metadata.payload.start_addr;
        st.total_len = static_cast<uint32_t>(metadata.payload.length);
        st.chunk_size = static_cast<uint32_t>(MAX_MTU - sizeof(SES_Semantic_Response_with_Data_Header));
        const size_t chunks = (st.chunk_size == 0 || st.total_len == 0)
                                  ? 0
                                  : (static_cast<size_t>(st.total_len) + st.chunk_size - 1) / st.chunk_size;
        st.chunk_received.assign(chunks, 0);
        if (st.dst_addr == 0 && st.total_len > 0) {
            st.buffer.resize(st.total_len);
        }
        std::lock_guard<std::mutex> lock(read_track_mu_);
        retired_read_response_.erase(key);
        read_track_[key] = std::move(st);
        setRudActiveReadResponseStates(read_track_.size());
    }

    if (metadata.op_type == READ) {
        // READ 请求不携带 payload，只发送 header，request_length 表示读取长度
        header.hd = 0;
        header.request_length = metadata.payload.length;
        send_pkt.pkt.bth_type = Standard_Header;
        send_pkt.pkt.bth_header.Standard_Header = header;
        send_pkt.pkt.payload.clear();
        send_pkt.pkt_len = static_cast<uint16_t>(sizeof(SES_Standard_Header));
        send_packet_to_pds(header, send_pkt);
        return;
    }

    const uint8_t* src_buf = reinterpret_cast<const uint8_t*>(
        (metadata.op_type == WRITE && metadata.payload.local_addr != 0)
            ? metadata.payload.local_addr
            : metadata.payload.start_addr);
    
    if (header.ie){
        // Error packet, send directly
        send_pkt.pkt.bth_type =Standard_Header;
        send_pkt.pkt.bth_header.Standard_Header = header;
        send_pkt.pkt.payload.clear();
        send_pkt.pkt_len = static_cast<uint16_t>(sizeof(SES_Standard_Header));
        send_packet_to_pds(header,send_pkt);
        return;
    }

    if (metadata.payload.length > 0) {
        const bool invalid_send = (metadata.op_type == SEND) &&
                                  (metadata.payload.start_addr == 0 || src_buf == nullptr);
        const bool invalid_write = (metadata.op_type == WRITE) &&
                                   (metadata.payload.local_addr == 0 || src_buf == nullptr);
        if (invalid_send || invalid_write) {
            LOG_ERROR(__FUNCTION__, "Invalid payload buffer for non-empty payload");
            header.ie = 1;
            send_pkt.pkt.bth_type =Standard_Header;
            send_pkt.pkt.bth_header.Standard_Header = header;
            send_pkt.pkt.payload.clear();
            send_pkt.pkt_len = static_cast<uint16_t>(sizeof(SES_Standard_Header));
            send_packet_to_pds(header,send_pkt);
            return;
        }
    }

    // Check if need to slice
    if (metadata.payload.length > MAX_MTU - sizeof(SES_Standard_Header)){
        // Start som=1 eom=0, middle packets som=0 eom=0, end packet som=0 eom=1
        const size_t max_payload = MAX_MTU - sizeof(SES_Standard_Header);
        int n = static_cast<int>(metadata.payload.length / max_payload);// Calculate number of fragments
        if(metadata.payload.length % max_payload) n++;
        LOG_INFO(__FUNCTION__, "Data payload too long, slicing into " + std::to_string(n) + " packets to send to PDS");
        for(int i = 0; i < n; i++){
            const size_t offset = static_cast<size_t>(i) * max_payload;
            const size_t frag_len = std::min(max_payload, static_cast<size_t>(metadata.payload.length) - offset);
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
                header.diff.som_false.message_offset = static_cast<uint32_t>(offset);
                header.diff.som_false.payload_length = static_cast<uint16_t>(frag_len);
                header.request_length = metadata.payload.length;// Multi-packet total data length
                LOG_INFO(__FUNCTION__, "Last packet data payload length is " + std::to_string(header.request_length));
            }
            else{
                // Middle packet
                header.som = 0;
                header.eom = 0;
                header.hd = 0;
                header.diff.som_false.message_offset = static_cast<uint32_t>(offset);
                header.diff.som_false.payload_length = static_cast<uint16_t>(frag_len);
                header.request_length = metadata.payload.length;// Multi-packet total data length
                LOG_INFO(__FUNCTION__, "Middle packet number " + std::to_string(i + 1) + " data payload length is " + std::to_string(header.request_length));
            }
            if (metadata.op_type == WRITE) {
                const uint32_t msg_off = header.som ? 0 : header.diff.som_false.message_offset;
                const uint64_t abs_off = static_cast<uint64_t>(header.buffer_offset) + msg_off;
                const uint64_t abs_end = abs_off + static_cast<uint64_t>(frag_len);
                LOG_INFO(__FUNCTION__,
                         "WRITE tx frag: msg_id=" + std::to_string(header.msg_id) +
                         " job_id=" + std::to_string(header.job_id) +
                         " ri=" + std::to_string(header.resource_index) +
                         " rkey=" + std::to_string(header.match_bits) +
                         " buf_off=" + std::to_string(header.buffer_offset) +
                         " msg_off=" + std::to_string(msg_off) +
                         " abs_off=" + std::to_string(abs_off) +
                         " abs_end=" + std::to_string(abs_end) +
                         " frag_len=" + std::to_string(frag_len) +
                         " som=" + std::to_string(header.som) +
                         " eom=" + std::to_string(header.eom));
            }
            // Send packet
            send_pkt.pkt.bth_type =Standard_Header;
            send_pkt.pkt.bth_header.Standard_Header = header;
            send_pkt.pkt.payload.allocate(frag_len);
            if (frag_len) {
                uint8_t* dst = send_pkt.pkt.payload.data();
                if (!dst) {
                    LOG_ERROR(__FUNCTION__, "Payload pool exhausted while slicing send");
                    header.ie = 1;
                    send_pkt.pkt.bth_header.Standard_Header = header;
                    send_pkt.pkt.payload.clear();
                    send_pkt.pkt_len = static_cast<uint16_t>(sizeof(SES_Standard_Header));
                    send_packet_to_pds(header, send_pkt);
                    return;
                }
                std::memcpy(dst, src_buf + offset, frag_len);
            }
            send_pkt.pkt_len = static_cast<uint16_t>(sizeof(SES_Standard_Header) + frag_len);
            send_packet_to_pds(header,send_pkt);
        }
    }
    else {
        // Single packet send
        header.hd = metadata.has_imm_data ? 1 : 0;
        header.diff.som_true.header_data = metadata.has_imm_data ? metadata.payload.imm_data : 0;
        if (metadata.op_type == SEND) {
            header.buffer_offset = 0;
        }
        header.request_length = metadata.payload.length;// Single packet total data length

        send_pkt.pkt.bth_type =Standard_Header;
        send_pkt.pkt.bth_header.Standard_Header = header;
        send_pkt.pkt.payload.allocate(static_cast<size_t>(metadata.payload.length));
        if (metadata.op_type == WRITE) {
            const uint64_t abs_off = static_cast<uint64_t>(header.buffer_offset);
            const uint64_t abs_end = abs_off + static_cast<uint64_t>(metadata.payload.length);
            LOG_INFO(__FUNCTION__,
                     "WRITE tx single: msg_id=" + std::to_string(header.msg_id) +
                     " job_id=" + std::to_string(header.job_id) +
                     " ri=" + std::to_string(header.resource_index) +
                     " rkey=" + std::to_string(header.match_bits) +
                     " buf_off=" + std::to_string(header.buffer_offset) +
                     " abs_off=" + std::to_string(abs_off) +
                     " abs_end=" + std::to_string(abs_end) +
                     " msg_off=0" +
                     " frag_len=" + std::to_string(metadata.payload.length) +
                     " som=1 eom=1");
        }
        if (metadata.payload.length > 0) {
            uint8_t* dst = send_pkt.pkt.payload.data();
            if (!dst) {
                LOG_ERROR(__FUNCTION__, "Payload pool exhausted while sending");
                header.ie = 1;
                send_pkt.pkt.bth_header.Standard_Header = header;
                send_pkt.pkt.payload.clear();
                send_pkt.pkt_len = static_cast<uint16_t>(sizeof(SES_Standard_Header));
                send_packet_to_pds(header, send_pkt);
                return;
            }
            std::memcpy(dst, src_buf, static_cast<size_t>(metadata.payload.length));
        }
        send_pkt.pkt_len = static_cast<uint16_t>(sizeof(SES_Standard_Header) + static_cast<size_t>(metadata.payload.length));
        // Send packet
        send_packet_to_pds(header,send_pkt);
    }
}


// Implement SESManager::process_recv__req_packet to process received packets
inline void SESManager::process_recv_req_packet(const PDC_SES_req& req) {
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
    // Response should go back to initiator (src_fep), from target (dst_fep).
    ses_pds_rsp.dst_fep = metadata.s_pid_on_fep;
    ses_pds_rsp.src_fep = metadata.t_pid_on_fep;
    ses_pds_rsp.gtd_del =false;
    ses_pds_rsp.ses_nack =false;
    ses_pds_rsp.PDCID = req.PDCID;
    ses_pds_rsp.rx_pkt_handle =req.rx_pkt_handle;
    ses_pds_rsp.rsp_len =  12;// 12-byte fixed length
    bool send_complete = false;
    bool write_complete = false;
    uint32_t write_total_len = 0;

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

    // READ requests carry no request payload; request_length is the remote byte
    // count to read, not bytes present in this packet.
    const size_t expected_payload_len =
        (metadata.op_type == READ) ? 0 : metadata.payload.length;
    if(!validate_data_length(req.pkt_len, expected_payload_len)){
        LOG_ERROR(__FUNCTION__, "data length not match");
        LOG_ERROR_PARAM(__FUNCTION__,"req.pkt_len: " + std::to_string(req.pkt_len) + "expected_payload_len:" + std::to_string(expected_payload_len));
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
    if (!validate_msn(metadata.job_id, req.orig_psn,req.pkt.bth_header.Standard_Header.request_length,req.orig_pdcid,req.pkt.bth_header.Standard_Header.som, req.pkt.bth_header.Standard_Header.eom, req.mode)) {
        // MSN table error, discard
        LOG_ERROR(__FUNCTION__, "MSN table error. Packet discarded.");
        // Generate NACK, discard
        LOG_ERROR(__FUNCTION__, "RKEY error. Packet discarded.");
        semantic_rsp.opcode = static_cast<uint8_t>(RSP_OP_CODE::UET_NACK);
        semantic_rsp.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_NO_MATCH);
        send_rsp_to_pds(ses_pds_rsp);
        return;
    }

    if (metadata.op_type == SEND && req.mode != RUD) {
        const auto& hdr = req.pkt.bth_header.Standard_Header;
        const uint32_t msg_off = hdr.som ? 0 : hdr.diff.som_false.message_offset;
        const uint32_t payload_len = static_cast<uint32_t>(req.pkt.payload.size());
        const uint32_t total_len = hdr.request_length;
        const uint32_t chunk_size = static_cast<uint32_t>(MAX_MTU - sizeof(SES_Standard_Header));
        const SendTrackKey key{
            metadata.job_id,
            static_cast<uint16_t>(hdr.msg_id),
            req.PDCID,
            req.src_fep,
        };

        {
            std::lock_guard<std::mutex> lock(send_track_mu_);
            auto it = send_track_.find(key);
            if (it == send_track_.end()) {
                SendTrackState st;
                st.total_len = total_len;
                st.chunk_size = chunk_size;
                const size_t chunks = (chunk_size == 0 || total_len == 0)
                                          ? 0
                                          : (static_cast<size_t>(total_len) + chunk_size - 1) / chunk_size;
                st.chunk_received.assign(chunks, 0);
                st.buffer.resize(total_len);
                it = send_track_.emplace(key, std::move(st)).first;
            } else if (it->second.total_len != total_len) {
                semantic_rsp.opcode = static_cast<uint8_t>(RSP_OP_CODE::UET_NACK);
                semantic_rsp.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_PROTOCOL_ERROR);
                send_track_.erase(it);
                send_rsp_to_pds(ses_pds_rsp);
                return;
            }

            auto& st = it->second;
            if (msg_off + payload_len > st.total_len) {
                semantic_rsp.opcode = static_cast<uint8_t>(RSP_OP_CODE::UET_NACK);
                semantic_rsp.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_PROTOCOL_ERROR);
                send_track_.erase(it);
                send_rsp_to_pds(ses_pds_rsp);
                return;
            }

            if (payload_len > 0 && req.pkt.payload.data() && !st.buffer.empty()) {
                std::memcpy(st.buffer.data() + msg_off, req.pkt.payload.data(), payload_len);
            }

            if (total_len > 0) {
                const size_t chunk_idx = chunk_size ? (msg_off / chunk_size) : 0;
                if (chunk_idx >= st.chunk_received.size()) {
                    semantic_rsp.opcode = static_cast<uint8_t>(RSP_OP_CODE::UET_NACK);
                    semantic_rsp.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_PROTOCOL_ERROR);
                    send_track_.erase(it);
                    send_rsp_to_pds(ses_pds_rsp);
                    return;
                }
                if (st.chunk_received[chunk_idx] == 0) {
                    st.chunk_received[chunk_idx] = 1;
                    st.chunks_done++;
                }
            }

            if (hdr.eom) {
                st.saw_eom = true;
            }

            if ((st.total_len == 0 && st.saw_eom) ||
                (st.saw_eom && st.chunks_done == st.chunk_received.size())) {
                send_complete = true;
                send_track_.erase(it);
            }
        }
    }

    if (metadata.op_type == WRITE) {
        const auto& hdr = req.pkt.bth_header.Standard_Header;
        const uint32_t msg_off = hdr.som ? 0 : hdr.diff.som_false.message_offset;
        const uint32_t payload_len = static_cast<uint32_t>(req.pkt.payload.size());
        const uint32_t total_len = hdr.request_length;
        write_total_len = total_len;

        const MemoryRegion mr = decode_rkey_to_mr(hdr.match_bits);
        // WRITE：校验 rkey 对应 MR 是否有效
        if (mr.start_addr == 0 || mr.length == 0) {
            semantic_rsp.opcode = static_cast<uint8_t>(RSP_OP_CODE::UET_NACK);
            semantic_rsp.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_INVALID_KEY);
            send_rsp_to_pds(ses_pds_rsp);
            return;
        }

        const uint64_t end_off = static_cast<uint64_t>(hdr.buffer_offset) +
                                 static_cast<uint64_t>(msg_off) +
                                 static_cast<uint64_t>(payload_len);
        // WRITE 越界检查
        if (end_off > mr.length) {
            semantic_rsp.opcode = static_cast<uint8_t>(RSP_OP_CODE::UET_NACK);
            semantic_rsp.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_PARTIAL_WRITE);
            send_rsp_to_pds(ses_pds_rsp);
            return;
        }

        if (payload_len > 0) {
            const uint8_t* src = req.pkt.payload.data();
            uint8_t* dst = reinterpret_cast<uint8_t*>(metadata.payload.start_addr);
            const uint64_t abs_off = static_cast<uint64_t>(hdr.buffer_offset) + msg_off;
            const uint64_t abs_end = abs_off + payload_len;
            LOG_INFO(__FUNCTION__,
                     "WRITE rx frag: msg_id=" + std::to_string(hdr.msg_id) +
                     " job_id=" + std::to_string(hdr.job_id) +
                     " ri=" + std::to_string(hdr.resource_index) +
                     " rkey=" + std::to_string(hdr.match_bits) +
                     " buf_off=" + std::to_string(hdr.buffer_offset) +
                     " msg_off=" + std::to_string(msg_off) +
                     " abs_off=" + std::to_string(abs_off) +
                     " abs_end=" + std::to_string(abs_end) +
                     " payload_len=" + std::to_string(payload_len) +
                     " dst_addr=" + std::to_string(metadata.payload.start_addr));
            // WRITE 真实落地（按分片直接 memcpy）
            if (!src || !dst) {
                semantic_rsp.opcode = static_cast<uint8_t>(RSP_OP_CODE::UET_NACK);
                semantic_rsp.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_PROTOCOL_ERROR);
                send_rsp_to_pds(ses_pds_rsp);
                return;
            }
            std::memcpy(dst, src, payload_len);
        }

        const uint32_t chunk_size = static_cast<uint32_t>(MAX_MTU - sizeof(SES_Standard_Header));
        const WriteTrackKey key{
            metadata.job_id,
            static_cast<uint16_t>(hdr.msg_id),
            req.orig_pdcid,
            static_cast<uint16_t>(metadata.res_index),
            req.src_fep,
        };

        {
            std::lock_guard<std::mutex> lock(write_track_mu_);
            // WRITE 分片跟踪：按 chunk bitmap 判断是否收齐
            auto it = write_track_.find(key);
            if (it == write_track_.end()) {
                WriteTrackState st;
                st.total_len = total_len;
                st.chunk_size = chunk_size;
                const size_t chunks = (chunk_size == 0 || total_len == 0)
                                          ? 0
                                          : (static_cast<size_t>(total_len) + chunk_size - 1) / chunk_size;
                st.chunk_received.assign(chunks, 0);
                it = write_track_.emplace(key, std::move(st)).first;
            } else if (it->second.total_len != total_len) {
                semantic_rsp.opcode = static_cast<uint8_t>(RSP_OP_CODE::UET_NACK);
                semantic_rsp.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_PROTOCOL_ERROR);
                write_track_.erase(it);
                send_rsp_to_pds(ses_pds_rsp);
                return;
            }

            auto& st = it->second;
            st.chunk_size = chunk_size;

            if (total_len > 0) {
                const size_t chunk_idx = chunk_size ? (msg_off / chunk_size) : 0;
                if (chunk_idx >= st.chunk_received.size()) {
                    semantic_rsp.opcode = static_cast<uint8_t>(RSP_OP_CODE::UET_NACK);
                    semantic_rsp.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_PROTOCOL_ERROR);
                    write_track_.erase(it);
                    send_rsp_to_pds(ses_pds_rsp);
                    return;
                }
                if (st.chunk_received[chunk_idx] == 0) {
                    st.chunk_received[chunk_idx] = 1;
                    st.chunks_done++;
                }
            }

            if (hdr.eom) {
                st.saw_eom = true;
            }

            if (st.saw_eom && st.chunks_done == st.chunk_received.size()) {
                write_complete = true;
                write_track_.erase(it);
            }
        }
    }

    semantic_rsp.opcode = static_cast<uint8_t>(RSP_OP_CODE::UET_NO_RESPONSE);
    const bool req_complete =
        (metadata.op_type == SEND && send_complete) ||
        (metadata.op_type == WRITE && write_complete) ||
        (metadata.op_type == READ && req.pkt.bth_header.Standard_Header.eom == 1);
    // If it is the last MSN packet and eom=1, then update MSN table
    if (req_complete && req.mode != RUD) {

        // Update MSN table, release MSN corresponding to job_id
        msn_table.erase(metadata.job_id);
        semantic_rsp.opcode = static_cast<uint8_t>(RSP_OP_CODE::UET_DEFAULT_RESPONSE);// Last update bit default return packet
        LOG_INFO_PARAM(__FUNCTION__, "erase msn , job_id:"+std::to_string(metadata.job_id));
    }
    if (metadata.op_type == READ) {
        const auto& hdr = req.pkt.bth_header.Standard_Header;
        const MemoryRegion mr = decode_rkey_to_mr(hdr.match_bits);
        // READ：从 MR 读出数据，按 response-with-data 分片回包
        if (mr.start_addr == 0 || mr.length == 0) {
            semantic_rsp.opcode = static_cast<uint8_t>(RSP_OP_CODE::UET_NACK);
            semantic_rsp.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_INVALID_KEY);
            send_rsp_to_pds(ses_pds_rsp);
            return;
        }

        const uint32_t total_len = hdr.request_length;
        const uint64_t end_off = static_cast<uint64_t>(hdr.buffer_offset) + static_cast<uint64_t>(total_len);
        if (end_off > mr.length) {
            semantic_rsp.opcode = static_cast<uint8_t>(RSP_OP_CODE::UET_NACK);
            semantic_rsp.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_PARTIAL_WRITE);
            send_rsp_to_pds(ses_pds_rsp);
            return;
        }

        const uint8_t* src = reinterpret_cast<const uint8_t*>(metadata.payload.start_addr);
        const size_t max_payload = MAX_MTU - sizeof(SES_Semantic_Response_with_Data_Header);
        if (total_len > 0 && (!src || max_payload == 0)) {
            semantic_rsp.opcode = static_cast<uint8_t>(RSP_OP_CODE::UET_NACK);
            semantic_rsp.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_PROTOCOL_ERROR);
            send_rsp_to_pds(ses_pds_rsp);
            return;
        }

        const size_t total = static_cast<size_t>(total_len);
        const size_t chunk = max_payload == 0 ? total : max_payload;
        for (size_t offset = 0; offset < total || (total == 0 && offset == 0); offset += chunk) {
            const size_t frag_len = (total == 0) ? 0 : std::min(chunk, total - offset);
            SES_PDS_rsp rsp_pkt = ses_pds_rsp;
            rsp_pkt.rsp.bth_type = Semantic_Response_with_Data_Header;
            rsp_pkt.gtd_del = false;

            SES_Semantic_Response_with_Data_Header rsp_hdr{};
            rsp_hdr.list = 1;
            rsp_hdr.opcode = static_cast<uint8_t>(RSP_OP_CODE::UET_RESPONSE_W_DATA);
            rsp_hdr.version = 2;
            rsp_hdr.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_OK);
            rsp_hdr.response_message_id = hdr.msg_id;
            rsp_hdr.job_id = metadata.job_id;
            rsp_hdr.read_request_msg_id = hdr.msg_id;
            rsp_hdr.payload_length = static_cast<uint16_t>(frag_len);
            rsp_hdr.modified_length = total_len;
            rsp_hdr.message_offset = static_cast<uint32_t>(offset);
            rsp_pkt.rsp.bth_header.Semantic_Response_with_Data_Header = rsp_hdr;

            rsp_pkt.rsp.payload.clear();
            if (frag_len > 0) {
                rsp_pkt.rsp.payload.allocate(frag_len);
                uint8_t* dst = rsp_pkt.rsp.payload.data();
                if (!dst) {
                    // 池耗尽：返回资源耗尽错误
                    semantic_rsp.opcode = static_cast<uint8_t>(RSP_OP_CODE::UET_NACK);
                    semantic_rsp.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_RESOURCE_EXHAUST);
                    send_rsp_to_pds(ses_pds_rsp);
                    return;
                }
                std::memcpy(dst, src + offset, frag_len);
            }
            rsp_pkt.rsp_len = static_cast<uint16_t>(sizeof(SES_Semantic_Response_with_Data_Header) + frag_len);
            send_rsp_to_pds(rsp_pkt);

            if (total == 0) break;
        }
        return;
    }

    // Everything normal: SEND can be configured to return ack; WRITE should return on completion.
    // READ always returns in the response-with-data path above.
    if (metadata.op_type == SEND || metadata.op_type == WRITE) {
        if (metadata.op_type == SEND && !send_complete) {
            return;
        }
        if (metadata.op_type == WRITE && !write_complete) {
            return;
        }
        if (metadata.op_type == SEND) {
            // Check if ack needs to be returned for SEND
            if(!validate_need_ack(metadata.messages_id,true)){
                LOG_INFO_PARAM(__FUNCTION__, "no need ack! msg_id: %d", metadata.messages_id);
                return;// No return, cold processing
            }
        }
        if (metadata.op_type == WRITE && write_total_len != 0) {
            semantic_rsp.modified_length = write_total_len;
        }
        semantic_rsp.opcode = static_cast<uint8_t>(RSP_OP_CODE::UET_DEFAULT_RESPONSE);
       
        semantic_rsp.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_OK);
        // Simulate return through function
        ses_pds_rsp.rsp.bth_header.Semantic_Response_Header  = semantic_rsp;
        send_rsp_to_pds(ses_pds_rsp);
        return;
    }
    return;
}
inline void SESManager::process_recv_rsp_packet(const PDC_SES_rsp& rsp){
    if (rsp.pkt.bth_type == Semantic_Response_with_Data_Header) {
        const auto& hdr = rsp.pkt.bth_header.Semantic_Response_with_Data_Header;
        const ReadTrackKey key{hdr.job_id, hdr.read_request_msg_id, rsp.src_fep};
        LOG_DEBUG(__FUNCTION__,
                  "READ rsp: job_id=" + to_string(hdr.job_id) +
                  " req_msg_id=" + to_string(hdr.read_request_msg_id) +
                  " src_fep=" + to_string(rsp.src_fep) +
                  " msg_off=" + to_string(hdr.message_offset) +
                  " payload_len=" + to_string(hdr.payload_length) +
                  " modified_len=" + to_string(hdr.modified_length) +
                  " payload_size=" + to_string(rsp.pkt.payload.size()));

        std::lock_guard<std::mutex> lock(read_track_mu_);
        auto it = read_track_.find(key);
        if (it == read_track_.end()) {
            LOG_WARN(__FUNCTION__,
                     "Unexpected READ response, drop: job_id=" + to_string(hdr.job_id) +
                     " req_msg_id=" + to_string(hdr.read_request_msg_id) +
                     " src_fep=" + to_string(rsp.src_fep) +
                     " tracked=" + to_string(read_track_.size()));
            return;
        }
        auto& st = it->second;
        const uint32_t total_len = hdr.modified_length;
        if (st.total_len == 0) {
            st.total_len = total_len;
        } else if (st.total_len != total_len) {
            LOG_ERROR(__FUNCTION__, "READ response length mismatch");
            read_track_.erase(it);
            setRudActiveReadResponseStates(read_track_.size());
            return;
        }

        if (st.chunk_size == 0) {
            st.chunk_size = static_cast<uint32_t>(MAX_MTU - sizeof(SES_Semantic_Response_with_Data_Header));
        }
        if (st.chunk_received.empty() && st.chunk_size > 0 && st.total_len > 0) {
            const size_t chunks = (static_cast<size_t>(st.total_len) + st.chunk_size - 1) / st.chunk_size;
            st.chunk_received.assign(chunks, 0);
        }

        const size_t frag_len = std::min<size_t>(rsp.pkt.payload.size(), hdr.payload_length);
        const size_t frag_off = hdr.message_offset;
        if (frag_off + frag_len > st.total_len) {
            LOG_ERROR(__FUNCTION__,
                      "READ response out of bounds: off=" + to_string(frag_off) +
                      " len=" + to_string(frag_len) +
                      " total=" + to_string(st.total_len));
            read_track_.erase(it);
            setRudActiveReadResponseStates(read_track_.size());
            return;
        }

        if (frag_len > 0) {
            const uint8_t* src = rsp.pkt.payload.data();
            uint8_t* dst = nullptr;
            if (st.dst_addr != 0) {
                dst = reinterpret_cast<uint8_t*>(st.dst_addr);
            } else if (!st.buffer.empty()) {
                dst = st.buffer.data();
            }
            if (!dst) {
                LOG_WARN(__FUNCTION__, "READ response has no dst buffer");
            }
            // 按 message_offset 回填到本地缓冲区
            if (dst && src) {
                std::memcpy(dst + frag_off, src, frag_len);
            }
        }

        if (st.chunk_size > 0 && st.total_len > 0) {
            const size_t chunk_idx = frag_off / st.chunk_size;
            if (chunk_idx < st.chunk_received.size() && st.chunk_received[chunk_idx] == 0) {
                st.chunk_received[chunk_idx] = 1;
                st.chunks_done++;
            }
        }

        if (st.total_len == 0 || st.chunks_done == st.chunk_received.size()) {
            // READ 分片全部收齐
            LOG_INFO(__FUNCTION__, "READ response complete");
            read_track_.erase(it);
            setRudActiveReadResponseStates(read_track_.size());
        }
        return;
    }

    if (rsp.mode == RUD &&
        rsp.pkt.bth_type == Semantic_Response_Header &&
        rsp.pkt.bth_header.Semantic_Response_Header.opcode == static_cast<uint8_t>(RSP_OP_CODE::UET_DEFAULT_RESPONSE) &&
        rsp.pkt.bth_header.Semantic_Response_Header.return_code == static_cast<uint8_t>(RSP_RETURN_CODE::RC_OK)) {
        clearSendRetryState(rsp.pkt.bth_header.Semantic_Response_Header.job_id,
                            rsp.pkt.bth_header.Semantic_Response_Header.message_id,
                            rsp.src_fep);
        LOG_DEBUG(__FUNCTION__,
                  "RUD default response observed: job_id=" +
                      to_string(rsp.pkt.bth_header.Semantic_Response_Header.job_id) +
                      " msg_id=" + to_string(rsp.pkt.bth_header.Semantic_Response_Header.message_id));
        return;
    }

    if (rsp.mode == RUD && rsp.pkt.bth_type == Semantic_Response_Header) {
        const auto& hdr = rsp.pkt.bth_header.Semantic_Response_Header;
        const SendRetryKey key{hdr.job_id, hdr.message_id, rsp.src_fep};
        if (hdr.opcode == static_cast<uint8_t>(RSP_OP_CODE::UET_NACK) &&
            hdr.return_code == static_cast<uint8_t>(RSP_RETURN_CODE::RC_NO_MATCH)) {
            bool exhausted = false;
            {
                std::lock_guard<std::mutex> lock(send_retry_mu_);
                auto it = send_retry_.find(key);
                if (it != send_retry_.end()) {
                    if (it->second.retry_count < Max_RTO_Retx_Cnt) {
                        it->second.next_retry_ms = currentTimeMs() + retryDelayMs(it->second.retry_count);
                        it->second.waiting_response = false;
                        ++it->second.retry_count;
                        noteRudRetryScheduled();
                        noteRudRcNoMatchRetryScheduled();
                    } else {
                        exhausted = true;
                        send_retry_.erase(it);
                        noteRudRetryGiveup();
                    }
                    setRudActiveRetryStates(send_retry_.size());
                }
            }
            if (!exhausted) {
                LOG_INFO(__FUNCTION__,
                         "RUD SEND RC_NO_MATCH scheduled retry: job_id=" + to_string(hdr.job_id) +
                             " msg_id=" + to_string(hdr.message_id));
                return;
            }
        } else {
            clearSendRetryState(hdr.job_id, hdr.message_id, rsp.src_fep);
        }
    }

    // Default response logging
    LOG_ERROR(__FUNCTION__, "SES received rsp");
    LOG_ERROR(__FUNCTION__, "SPDCID: "+to_string(rsp.PDCID)+"msg_id: "+to_string(rsp.pkt.bth_header.Semantic_Response_Header.message_id)+"job_id: "
            +to_string(rsp.pkt.bth_header.Semantic_Response_Header.job_id)+"op_code: "+to_string(rsp.pkt.bth_header.Semantic_Response_Header.opcode)
            +"return_code: "+to_string(rsp.pkt.bth_header.Semantic_Response_Header.return_code));
}
#endif
