#pragma once
#include "MemoryRegistry.hpp"
#include "SemanticReturnCode.hpp"
#include "ResourceDirectory.hpp"
#include "PayloadSource.hpp"
#include "ReadCoverage.hpp"
#include "../PDS/DefaultSemanticResponse.hpp"
#include "../Runtime/PdsHost.hpp"
#include <deque>
#include <tuple>
#include <optional>

namespace UET::SES {

enum class OperationType : uint8_t { Noop=0, Write=1, Read=2, Atomic=3, Send=5, DatagramSend=7 };
enum class CompletionStatus { Success, LocalSuccess, LocalError, Unsupported, InvalidRequest, RemoteError, Timeout, Cancelled, ResourceExhausted, Truncated };
// A local registered destination for READ results. This descriptor never goes
// on the wire; the peer supplies only checked data, never a local host pointer.
struct ReadResultBuffer {
    uint64_t key=0,offset=0;
    uint32_t capacity=0;
    uint16_t pid=1,resource_index=1;
};
struct Operation {
    OperationType type = OperationType::Send;
    pdc_mode delivery_mode = ROD; // Reliable ordered by default; RUD permits packet reordering.
    uint32_t peer = 0;
    uint32_t job = 1;
    uint16_t source_pid = 1; // Local process for optional PDC mapping; not ses.initiator's rank.
    uint16_t target_pid = 1;
    uint16_t target_resource = 1;
    uint64_t remote_key = 0;
    uint64_t remote_offset = 0;
    uint64_t context = 0;
    std::vector<uint8_t> payload;
    IntegerAtomicOperation atomic_operation = IntegerAtomicOperation::Sum;
    IntegerAtomicDatatype atomic_datatype = IntegerAtomicDatatype::Uint64;
    std::optional<uint64_t> immediate_data; // Remote CQ data: WRITE, SEND or DATAGRAM_SEND.
    bool relative_addressing=true;
    uint8_t target_generation=0;
    std::shared_ptr<const PayloadSource> payload_source; // Optional lazy bytes; cannot accompany a nonempty payload vector.
    uint32_t read_length=0;
    std::optional<ReadResultBuffer> read_result;
};
struct Completion {
    uint64_t operation;
    uint64_t context;
    CompletionStatus status;
    uint32_t length;
    uint8_t remote_code;
    bool receive;
    std::optional<uint64_t> immediate_data;
    uint8_t remote_generation=0;
    uint32_t original_length=0; // Before receive truncation; never a placed-byte count.
};
struct EndpointCapabilities {
    bool noop=true, send=true, write=true;
    bool datagram_send=true;
    bool relative_addressing=true, absolute_addressing=true;
    bool read=true, atomic=true, libfabric=false, write_immediate=true;
    uint32_t max_read_length=16; // Endpoint construction derives the fabric/MTU limit.
    bool send_immediate=true, datagram_immediate=true, deferrable_send_as_send=true;
    std::vector<IntegerAtomicDatatype> atomic_datatypes={IntegerAtomicDatatype::Int8,IntegerAtomicDatatype::Uint8,
        IntegerAtomicDatatype::Int16,IntegerAtomicDatatype::Uint16,IntegerAtomicDatatype::Int32,
        IntegerAtomicDatatype::Uint32,IntegerAtomicDatatype::Int64,IntegerAtomicDatatype::Uint64};
    // A feature test is not a complete profile-conformance declaration.
    bool ai_base=false, ai_full=false, hpc=false, unified_local=false;
};

// The first native asynchronous SES adapter. It uses the existing PDS/PDC
// state machines, explicit UE wire fields, and checked registered storage.
// Unsupported operations fail before any request is sent.
class Endpoint {
public:
    Endpoint(uint32_t node, Runtime::PdsHost& host, Runtime::EventLoop& loop,
             Runtime::Trace& trace, size_t payload_mtu=1024,
             Runtime::Time timeout=100*Runtime::kMillisecond,MemoryRegistry* domain_memory=nullptr,size_t submission_window=8,
             size_t receive_message_limit=4096,size_t unexpected_buffer_bytes=256*1024,size_t read_response_limit=8)
        : node_(node), host_(host), loop_(loop), trace_(trace), mtu_(payload_mtu), timeout_(timeout),
          memory_(domain_memory?*domain_memory:private_memory_),submission_window_(submission_window),receive_message_limit_(receive_message_limit),
          unexpected_limit_(unexpected_buffer_bytes),read_response_limit_(read_response_limit) {
        if (!mtu_ || mtu_>8192 || !timeout_ || !submission_window_ || !receive_message_limit_ || !read_response_limit_ || read_response_limit_>UINT16_MAX)
            throw std::invalid_argument("invalid SES configuration");
        // §3.5.12.1: a threshold at/above MTU selects a single-MTU READ
        // fabric. Otherwise large messages use reverse PDS requests.
        capabilities_.max_read_length=host_.services().max_ack_data_size>=mtu_?static_cast<uint32_t>(mtu_):UINT32_MAX;
        host_.set_receive_admission(
            [this](const PDC_SES_req& request) { return reserve_receive_message(request); },
            [this](const PDC_SES_req& request) { cancel_receive_reservation(request); });
        host_.set_request_handler([this](const PDC_SES_req& request) { receive(request); });
        host_.set_response_handler([this](const PDC_SES_rsp& response) { respond(response); });
        host_.set_context_event_handler([this](const Runtime::PdcEvent& event) { context_event(event); });
        host_.set_datagram_transmit_handler([this](uint16_t message,Runtime::SendResult result) {
            const auto pending=pending_.find(message);
            if (pending==pending_.end()) return;
            fragment_transmitted(message);
            // UUD completion establishes only local transmit acceptance. A
            // dropped datagram still completes locally; no remote ACK exists.
            finish(message,result==Runtime::SendResult::Accepted ? CompletionStatus::LocalSuccess
                   : CompletionStatus::LocalError,pending->second.length,0);
        });
    }
    ~Endpoint() { close(); }
    Endpoint(const Endpoint&) = delete;
    Endpoint& operator=(const Endpoint&) = delete;
    MemoryRegistry& memory() { return memory_; }
    ResourceDirectory& resources() { return resources_; }
    const EndpointCapabilities& capabilities() const { return capabilities_; }

    uint64_t submit(Operation operation) {
        if (closed_) throw std::logic_error("endpoint closed");
        if (next_operation_==UINT64_MAX) throw std::overflow_error("operation ids exhausted");
        const auto id=++next_operation_;
        const auto complete_local=[&](CompletionStatus status) {
            completions_.push_back({id,operation.context,status,0,0,false});
        };
        if (pending_.size() >= 4096) { complete_local(CompletionStatus::ResourceExhausted); return id; }
        const bool is_datagram=operation.type==OperationType::DatagramSend;
        const bool is_atomic=operation.type==OperationType::Atomic;
        const bool is_read=operation.type==OperationType::Read;
        if (!is_datagram && operation.delivery_mode!=ROD && operation.delivery_mode!=RUD) {
            complete_local(CompletionStatus::Unsupported); return id;
        }
        if (operation.type!=OperationType::Noop && operation.type!=OperationType::Send &&
            operation.type!=OperationType::Write && !is_atomic && !is_datagram && !is_read) {
            complete_local(CompletionStatus::Unsupported); return id;
        }
        const uint64_t payload_length=operation.payload_source?operation.payload_source->size():operation.payload.size();
        if ((!is_read && (operation.read_length || operation.read_result)) ||
            (is_read && (payload_length || operation.payload_source || operation.immediate_data))) {
            complete_local(CompletionStatus::InvalidRequest); return id;
        }
        if (is_read && host_.services().max_ack_data_size>=mtu_ && operation.read_length>mtu_) {
            complete_local(CompletionStatus::Unsupported); return id;
        }
        if (operation.payload_source && !operation.payload.empty()) {
            complete_local(CompletionStatus::InvalidRequest); return id;
        }
        std::optional<Region> read_registration;
        if (is_read && (operation.read_length || operation.read_result)) {
            if (!operation.read_result || operation.read_result->capacity<operation.read_length ||
                operation.read_result->pid>0xfff || operation.read_result->resource_index>0xfff) {
                complete_local(CompletionStatus::InvalidRequest); return id;
            }
            const auto& destination=*operation.read_result;
            try {
                read_registration=memory_.authorize(operation.job,destination.pid,destination.key,
                    destination.offset,operation.read_length,Access::Write,destination.resource_index);
            } catch (const MemoryAccessError&) { complete_local(CompletionStatus::LocalError); return id; }
        }
        size_t atomic_width=1;
        if (is_atomic) {
            if (static_cast<uint8_t>(operation.atomic_datatype)>7 ||
                static_cast<uint8_t>(operation.atomic_operation)>12 ||
                operation.atomic_operation==IntegerAtomicOperation::Read) {
                complete_local(CompletionStatus::Unsupported); return id;
            }
            atomic_width=integer_atomic_width(operation.atomic_datatype);
            if (!payload_length || payload_length%atomic_width ||
                operation.remote_offset%atomic_width || mtu_<atomic_width) {
                complete_local(CompletionStatus::InvalidRequest); return id;
            }
        }
        if (!operation.peer || !memory_.has_job(operation.job) || operation.source_pid>0xfff || operation.target_pid>0xfff || operation.target_resource>0xfff ||
            payload_length>UINT32_MAX || (is_datagram && payload_length>mtu_) ||
            (operation.immediate_data && operation.type!=OperationType::Write && operation.type!=OperationType::Send && !is_datagram) ||
            (operation.type==OperationType::Noop && payload_length)) {
            complete_local(CompletionStatus::InvalidRequest); return id;
        }
        uint16_t message=0;
        for (size_t i=0; i<UINT16_MAX; ++i) {
            if (++next_message_==0) ++next_message_;
            if (!pending_.count(next_message_) && !message_leases_.count(next_message_)) { message=next_message_; break; }
        }
        if (!message) { complete_local(CompletionStatus::ResourceExhausted); return id; }
        const uint32_t transfer_length=is_read?operation.read_length:static_cast<uint32_t>(payload_length);
        Pending pending{id,operation.context,transfer_length,0,operation.peer,operation.job};
        pending.is_datagram=is_datagram;
        pending.is_read=is_read; pending.read_result=operation.read_result;
        pending.read_registration=std::move(read_registration);
        pending_.emplace(message,pending);
        try {
            auto source=operation.payload_source;
            if (!source) source=std::make_shared<VectorPayload>(std::move(operation.payload));
            operation.payload_source.reset();
            sources_.emplace(message,SourceMessage{std::move(operation),std::move(source),
                transfer_length,0,0,false});
            submission_order_.push_back(message);
            std::weak_ptr<int> life=lifetime_;
            pending_.at(message).timer=loop_.after(timeout_,[this,life,message] {
                if (life.expired()) return;
                finish(message,CompletionStatus::Timeout,0,0);
            });
            feed_submissions();
        } catch (...) {
            finish(message,CompletionStatus::ResourceExhausted,0,0);
            throw;
        }
        return id;
    }
    void post_receive(uint32_t job, uint16_t pid, uint64_t key, uint64_t offset,
                       uint32_t capacity, uint64_t context=0,uint16_t resource_index=1) {
        if (closed_) throw std::logic_error("endpoint closed");
        const auto registration=memory_.authorize(job,pid,key,offset,capacity,Access::Write,resource_index);
        if (posted_.size()>=4096) throw std::runtime_error("receive queue full");
        posted_.push_back({job,pid,key,offset,capacity,context,resource_index,registration});
        match_unexpected();
        if (const auto disabled=disabled_generations_.find({pid,resource_index});disabled!=disabled_generations_.end()) {
            resources_.recover_after_exhaustion(pid,resource_index,ResourceSpace::Send,disabled->second);
            disabled_generations_.erase(disabled);
        }
    }
    bool poll_completion(Completion& completion) {
        if (completions_.empty()) return false;
        completion=completions_.front(); completions_.pop_front(); return true;
    }
    size_t pending() const { return pending_.size(); }
    bool cancel_read(uint64_t operation) {
        for (const auto& pending:pending_) if (pending.second.id==operation && pending.second.is_read) {
            // Local cancellation stops further placement, not packets already
            // on the fabric. Their reverse DEFAULTs still drain PDS state.
            finish(pending.first,CompletionStatus::Cancelled,static_cast<uint32_t>(pending.second.read_results.bytes()),0);
            return true;
        }
        return false;
    }
    bool transport_pending(uint64_t operation) const {
        for (const auto& pending:pending_) if (pending.second.id==operation) return true;
        for (const auto& lease:message_leases_) if (lease.second.operation==operation) return true;
        return false;
    }
    uint64_t unexpected_bytes() const { return unexpected_bytes_; }
    size_t queued_fragments() const { return queued_fragments_; }
    size_t receive_intervals() const {
        size_t count=0;
        for (const auto& message:incoming_) count+=message.second.segments.size()+message.second.read_requests.intervals();
        for (const auto& operation:pending_) count+=operation.second.read_results.intervals();
        return count;
    }
    size_t retained_read_packets() const { return read_packet_reservations_.size(); }
    size_t pending_read_returns() const { return read_returns_.size(); }
    size_t retained_receive_messages() const { return incoming_.size(); }
    size_t leased_message_ids() const { return message_leases_.size(); }
    void close() {
        if (closed_) return;
        closed_=true; lifetime_.reset();
        host_.set_receive_admission({},{});
        host_.set_request_handler({}); host_.set_response_handler({});
        host_.set_datagram_transmit_handler({});
        host_.set_context_event_handler({});
        sources_.clear(); submission_order_.clear(); queued_fragments_=0;
        while (!pending_.empty()) finish(pending_.begin()->first,CompletionStatus::Cancelled,0,0);
        incoming_.clear(); unexpected_order_.clear(); unexpected_bytes_=0; disabled_generations_.clear();
        posted_.clear(); message_leases_.clear(); transmit_clear_frontiers_.clear();
        read_returns_.clear(); read_packet_reservations_.clear();
    }
private:
    struct SourceMessage {
        Operation operation;
        std::shared_ptr<const PayloadSource> source;
        uint32_t length;
        uint64_t offset;
        size_t queued;
        bool all_submitted;
        bool aborting=false;
    };
    struct Pending {
        uint64_t id,context; uint32_t length; Runtime::TimerId timer; uint32_t peer,job;
        uint16_t local_pdc=UINT16_MAX;
        uint32_t connection_start_psn=0,last_transmitted_psn=0;
        bool is_datagram=false;
        bool is_read=false;
        std::optional<ReadResultBuffer> read_result;
        std::optional<Region> read_registration;
        ReadCoverage read_results;
        bool end_of_message_transmitted=false;
        // Only outstanding PSNs are retained, so a multi-gigabyte stream
        // consumes the PDS window's space rather than one entry per fragment.
        std::set<uint32_t> awaiting_semantic_responses;
        uint32_t completed_length=0;
        uint8_t returned_generation=0;
    };
    using ConnectionKey=std::tuple<uint32_t,uint16_t,uint32_t>;
    struct MessageLease { ConnectionKey connection; uint32_t last_psn; bool end_of_message_transmitted; uint64_t operation; };
    struct Posted { uint32_t job; uint16_t pid; uint64_t key,offset; uint32_t capacity; uint64_t context; uint16_t resource_index; Region registration; };
    struct Incoming {
        uint8_t opcode;
        uint32_t total;
        uint64_t key,base;
        uint16_t pid;
        uint64_t context;
        bool completed=false;
        std::map<uint32_t,uint32_t> segments;
        uint64_t received=0;
        uint8_t atomic_operation=0, atomic_datatype=0;
        bool has_immediate=false;
        std::optional<uint64_t> immediate_data;
        uint32_t completion_psn=0;
        uint16_t resource_index=1,wire_pid=1;
        bool relative_addressing=true;
        bool initialized=false,matched_receive=false,completion_reported=false,end_seen=false;
        std::optional<SemanticReturnCode> first_error;
        // §3.4.4.3: only the first error response for a message owns a
        // guaranteed-delivery slot. Later packets repeat the sticky error
        // explicitly, without creating additional guaranteed responses.
        bool error_response_generated=false;
        uint8_t error_generation=0;
        CompletionStatus target_error=CompletionStatus::RemoteError;
        std::shared_ptr<SparseMemory> unexpected;
        uint64_t receive_order=0;
        std::optional<PDC_SES_req> deferred_response;
        std::optional<Region> receive_registration;
        ReadCoverage read_requests;
        size_t read_returns_pending=0;
    };
    using MessageKey=std::tuple<uint32_t,uint16_t,uint32_t,uint32_t,uint16_t,uint32_t>;
    uint32_t node_;
    Runtime::PdsHost& host_;
    Runtime::EventLoop& loop_;
    Runtime::Trace& trace_;
    size_t mtu_;
    Runtime::Time timeout_;
    MemoryRegistry private_memory_;
    MemoryRegistry& memory_; // A provider domain may share its MR authority with its endpoint.
    ResourceDirectory resources_;
    EndpointCapabilities capabilities_;
    std::shared_ptr<int> lifetime_=std::make_shared<int>(0);
    bool closed_=false;
    uint64_t next_operation_=0;
    uint16_t next_message_=0;
    std::map<uint16_t,Pending> pending_;
    std::map<uint16_t,MessageLease> message_leases_;
    std::map<ConnectionKey,uint32_t> transmit_clear_frontiers_;
    std::deque<Posted> posted_;
    std::map<MessageKey,Incoming> incoming_;
    std::deque<Completion> completions_;
    size_t submission_window_,queued_fragments_=0;
    size_t receive_message_limit_;
    uint64_t unexpected_limit_,unexpected_bytes_=0,next_receive_order_=0;
    std::map<uint64_t,MessageKey> unexpected_order_;
    std::map<std::pair<uint16_t,uint16_t>,uint8_t> disabled_generations_;
    std::map<uint16_t,SourceMessage> sources_;
    std::deque<uint16_t> submission_order_;
    // A bounded target packet budget is independent of whole-message slots.
    // Holding each original READ ACK until its return packet completes keeps
    // PDS payload storage and response tokens bounded (§3.5.20.2.2).
    size_t read_response_limit_;
    uint16_t next_read_response_=0;
    struct ReadReservation { MessageKey message; bool processed=false; };
    std::map<ReadPacketIdentity,ReadReservation> read_packet_reservations_;
    struct ReadReturn {
        PDC_SES_req original;
        std::optional<uint32_t> sequence;
    };
    std::map<uint16_t,ReadReturn> read_returns_;

    // This is a producer queue bound, not a second PDS window. The real PDC
    // still owns PSNs, outstanding packets, congestion/recovery and retransmits.
    // FIFO submission keeps all fragments of an ordered message ahead of the
    // next message. At most submission_window_ fragments wait to enter PDS TX.
    void feed_submissions() {
        while (!closed_ && queued_fragments_<submission_window_ && !submission_order_.empty()) {
            const auto message=submission_order_.front();
            auto found=sources_.find(message);
            if (found==sources_.end()) { submission_order_.pop_front(); continue; }
            auto& transfer=found->second;
            const auto& operation=transfer.operation;
            const bool datagram=operation.type==OperationType::DatagramSend;
            const bool atomic=operation.type==OperationType::Atomic;
            const bool read=operation.type==OperationType::Read && !transfer.aborting;
            const auto atomic_width=atomic?integer_atomic_width(operation.atomic_datatype):1;
            const auto fragment_capacity=mtu_-(mtu_%atomic_width);
            auto count=transfer.aborting?size_t{0}:static_cast<size_t>(std::min<uint64_t>(fragment_capacity,transfer.length-transfer.offset));
            SES_PDS_req request{};
            request.src_fep=node_; request.dst_fep=operation.peer;
            request.source_pid=operation.source_pid;
            request.mode=datagram?UUD:operation.delivery_mode;
            request.next_hdr=UET_HDR_REQUEST_STD; request.rod_context=1; request.lock_pdc=true;
            request.tx_pkt_handle=message; request.pkt.bth_type=Standard_Header;
            auto& header=request.pkt.bth_header.Standard_Header;
            header.opcode=transfer.aborting?0x0f:static_cast<uint8_t>(operation.type); header.version=0;
            header.som=transfer.offset==0; header.eom=transfer.aborting || transfer.offset+count==transfer.length;
            header.dc=!datagram; header.rel=operation.relative_addressing; header.ri_generation=operation.target_generation;
            header.msg_id=datagram?0:message; header.job_id=operation.job; header.PIDonFEP=operation.target_pid;
            header.resource_index=operation.target_resource; header.buffer_offset=operation.remote_offset;
            header.initiator=node_; header.match_bits=operation.remote_key; header.request_length=transfer.length;
            if (operation.immediate_data) {
                header.hd=1;
                if (!transfer.offset) header.diff.som_true.header_data=*operation.immediate_data;
            }
            if (atomic && !transfer.aborting) {
                request.pkt.eth_type=Atomic_Operation_Extension_Header;
                auto& extension=request.pkt.eth_header.Atomic_Operation_Extension_Header;
                extension.atomic_opcode=static_cast<uint8_t>(operation.atomic_operation);
                extension.atomic_datatype=static_cast<uint8_t>(operation.atomic_datatype);
            }
            if (transfer.offset) {
                header.diff.som_false.payload_length=read?0:count;
                header.diff.som_false.message_offset=static_cast<uint32_t>(transfer.offset);
            }
            request.pkt.payload.resize(read?0:count);
            bool read_failed=false;
            try {
                if (count && !read) transfer.source->read(transfer.offset,request.pkt.payload.data(),count);
            } catch (...) {
                // A local reader failure is an initiator error, not a corrupt
                // partial payload. Preserve the header and terminate reliably
                // using MSG_ERROR (§3.4.6.4.1), without exposing these bytes.
                read_failed=true; transfer.aborting=true; transfer.source.reset();
                count=0; request.pkt.payload.clear(); header.opcode=0x0f; header.eom=1;
                if (!header.som) header.diff.som_false.payload_length=0;
            }
            if (atomic && !transfer.aborting) convert_integer_atomic_byte_order(request.pkt.payload,operation.atomic_datatype);
            request.pkt_len=static_cast<uint16_t>(44+((atomic && !transfer.aborting)?4:0)+request.pkt.payload.size());
            if (!host_.submit(request)) throw std::runtime_error("PDS rejected operation fragment");
            ++queued_fragments_; ++transfer.queued; transfer.offset+=count;
            if (header.eom) { transfer.all_submitted=true; submission_order_.pop_front(); }
            if (read_failed) finish(message,CompletionStatus::LocalError,0,static_cast<uint8_t>(SemanticReturnCode::InitiatorError));
        }
    }
    void fragment_transmitted(uint16_t message) {
        const auto found=sources_.find(message);
        if (found==sources_.end() || !found->second.queued) return;
        --found->second.queued; --queued_fragments_;
        if (found->second.all_submitted && !found->second.queued) sources_.erase(found);
        feed_submissions();
    }
    void discard_source(uint16_t message) {
        if (auto found=sources_.find(message);found!=sources_.end()) {
            host_.cancel_queued_message(found->second.operation.peer,found->second.operation.job,message);
            queued_fragments_-=found->second.queued; sources_.erase(found);
        }
        submission_order_.erase(std::remove(submission_order_.begin(),submission_order_.end(),message),submission_order_.end());
    }


    void finish(uint16_t message, CompletionStatus status, uint32_t length, uint8_t code,uint8_t remote_generation=0) {
        const auto it=pending_.find(message);
        if (it==pending_.end()) return;
        loop_.cancel(it->second.timer);
        if (status!=CompletionStatus::Success && status!=CompletionStatus::LocalSuccess) {
            if (auto source=sources_.find(message);source!=sources_.end()) {
                // §3.4.6.4.1: already queued fragments own byte copies. Stop
                // reading the application before exposing its error completion;
                // replace the unsent tail by one reliable EOM MSG_ERROR packet.
                source->second.source.reset();
                source->second.aborting=!source->second.all_submitted;
            }
        }
        completions_.push_back({it->second.id,it->second.context,status,length,code,false,{},remote_generation});
        trace_.record(node_,"operation_complete",it->second.id);
        if (!it->second.is_datagram && !closed_) {
            const ConnectionKey connection{it->second.peer,it->second.local_pdc,it->second.connection_start_psn};
            const auto cleared=transmit_clear_frontiers_.find(connection);
            if (it->second.local_pdc==UINT16_MAX || !it->second.end_of_message_transmitted || cleared==transmit_clear_frontiers_.end() ||
                cleared->second-it->second.last_transmitted_psn>=0x80000000u)
                message_leases_[message]={connection,it->second.last_transmitted_psn,it->second.end_of_message_transmitted,it->second.id};
        }
        const bool finish_read_tail=it->second.is_read && status!=CompletionStatus::Success && status!=CompletionStatus::LocalSuccess;
        pending_.erase(it);
        if (finish_read_tail) feed_submissions();
    }

    void context_event(const Runtime::PdcEvent& event) {
        if (event.kind==Runtime::PdcEventKind::ReceiveCleared || event.kind==Runtime::PdcEventKind::ConnectionClosed) {
            for (auto credit=read_packet_reservations_.begin();credit!=read_packet_reservations_.end();) {
                const auto& packet=credit->first;
                const bool context=packet.peer==event.peer && packet.local_pdc==event.local_pdc &&
                    packet.connection_start_psn==event.connection_start_psn;
                if (context && (event.kind==Runtime::PdcEventKind::ConnectionClosed || event.sequence-packet.sequence<0x80000000u))
                    credit=read_packet_reservations_.erase(credit);
                else ++credit;
            }
            if (event.kind==Runtime::PdcEventKind::ConnectionClosed) {
                for (auto response=read_returns_.begin();response!=read_returns_.end();) {
                    const auto& original=response->second.original;
                    if (original.source_fep==event.peer && original.PDCID==event.local_pdc &&
                        original.connection_start_psn==event.connection_start_psn) response=read_returns_.erase(response);
                    else ++response;
                }
            }
        }
        if (event.local_pdc>=MAX_PDC) {
            if (event.kind==Runtime::PdcEventKind::RequestTransmitted || event.kind==Runtime::PdcEventKind::RequestRejected) {
                const auto found=read_returns_.find(event.message_id);
                if (found!=read_returns_.end()) {
                    const auto& original=found->second.original;
                    if (original.PDCID==event.local_pdc && original.source_fep==event.peer &&
                        original.connection_start_psn==event.connection_start_psn) {
                        if (event.kind==Runtime::PdcEventKind::RequestTransmitted) found->second.sequence=event.sequence;
                        else {
                            read_packet_reservations_.erase(ReadPacketIdentity::from(original));
                            read_returns_.erase(found);
                        }
                    }
                }
                // Target-assigned response tokens may numerically equal this
                // endpoint's own native operation MID. They are distinct
                // directions and must never mutate pending_ or its producer.
                return;
            }
            if (event.kind==Runtime::PdcEventKind::TransmitCleared || event.kind==Runtime::PdcEventKind::PeerCumulativeAcknowledged)
                return;
        }
        if (event.kind==Runtime::PdcEventKind::RequestRejected) {
            discard_source(event.message_id);
            const auto pending=pending_.find(event.message_id);
            if (pending!=pending_.end() && pending->second.peer==event.peer && pending->second.job==event.job)
                finish(event.message_id,event.failure==Runtime::PdcFailureReason::RetryExhausted?CompletionStatus::Timeout:
                    (event.failure==Runtime::PdcFailureReason::None || event.failure==Runtime::PdcFailureReason::ResourcesUnavailable)?
                    CompletionStatus::ResourceExhausted:CompletionStatus::RemoteError,0,0);
            // Rejection either precedes transmission or follows context teardown.
            // PDS has removed all queued fragments and retired the incarnation.
            message_leases_.erase(event.message_id);
            feed_submissions();
            return;
        }
        const ConnectionKey connection{event.peer,event.local_pdc,event.connection_start_psn};
        if (event.kind==Runtime::PdcEventKind::RequestTransmitted) {
            if (auto operation=pending_.find(event.message_id);operation!=pending_.end() &&
                operation->second.peer==event.peer && operation->second.job==event.job) {
                operation->second.local_pdc=event.local_pdc;
                operation->second.connection_start_psn=event.connection_start_psn;
                operation->second.last_transmitted_psn=event.sequence;
                operation->second.end_of_message_transmitted|=event.end_of_message;
                if (!operation->second.is_datagram)
                    operation->second.awaiting_semantic_responses.insert(event.sequence);
            } else if (auto lease=message_leases_.find(event.message_id);lease!=message_leases_.end()) {
                lease->second={connection,event.sequence,lease->second.end_of_message_transmitted || event.end_of_message,lease->second.operation};
            }
            fragment_transmitted(event.message_id);
        } else if (event.kind==Runtime::PdcEventKind::TransmitCleared) {
            auto previous=transmit_clear_frontiers_.find(connection);
            if (previous!=transmit_clear_frontiers_.end() && event.sequence-previous->second>=0x80000000u) return;
            transmit_clear_frontiers_[connection]=event.sequence;
            for (auto lease=message_leases_.begin();lease!=message_leases_.end();) {
                if (lease->second.connection==connection && lease->second.end_of_message_transmitted &&
                    event.sequence-lease->second.last_psn<0x80000000u)
                    lease=message_leases_.erase(lease);
                else ++lease;
            }
        } else if (event.kind==Runtime::PdcEventKind::PeerCumulativeAcknowledged) {
            // Peer delivery progress is separate from our completed semantic
            // frontier. It cannot release a message ID on its own.
            return;
        } else {
            for (auto message=incoming_.begin();message!=incoming_.end();) {
                const auto& key=message->first;
                const bool same_context=std::get<0>(key)==event.peer && std::get<1>(key)==event.local_pdc &&
                    std::get<5>(key)==event.connection_start_psn;
                const bool retired=event.kind==Runtime::PdcEventKind::ConnectionClosed ||
                    (message->second.completed && event.sequence-message->second.completion_psn<0x80000000u);
                if (same_context && retired) {
                    if (event.kind==Runtime::PdcEventKind::ConnectionClosed && !message->second.completed) {
                        // §3.4.6.2: a PDC failure also terminates a matched
                        // target transaction. Report placed bytes once; a
                        // receiver must not wait forever for a missing EOM.
                        auto& unfinished=message->second;
                        if (!unfinished.first_error) unfinished.first_error=SemanticReturnCode::Undeliverable;
                        unfinished.target_error=event.failure==Runtime::PdcFailureReason::RetryExhausted?
                            CompletionStatus::Timeout:CompletionStatus::RemoteError;
                        report_receive_error(unfinished);
                    }
                    release_unexpected(message->second);
                    message=incoming_.erase(message);
                } else ++message;
            }
            if (event.kind==Runtime::PdcEventKind::ConnectionClosed) {
                std::vector<uint16_t> failed_messages;
                for (const auto& operation:pending_)
                    if (ConnectionKey{operation.second.peer,operation.second.local_pdc,operation.second.connection_start_psn}==connection)
                        failed_messages.push_back(operation.first);
                for (const auto message:failed_messages) {
                    discard_source(message);
                    finish(message,event.failure==Runtime::PdcFailureReason::RetryExhausted?CompletionStatus::Timeout:
                        CompletionStatus::RemoteError,0,0);
                }
                for (auto lease=message_leases_.begin();lease!=message_leases_.end();)
                    if (lease->second.connection==connection) {
                        discard_source(lease->first); lease=message_leases_.erase(lease);
                    } else ++lease;
                transmit_clear_frontiers_.erase(connection);
                feed_submissions();
            }
        }
    }
    void complete_read_return(const PDC_SES_rsp& response) {
        if (response.pkt.bth_type!=Semantic_Response_Header) return;
        const auto& header=response.pkt.bth_header.Semantic_Response_Header;
        const auto found=read_returns_.find(header.message_id);
        if (found==read_returns_.end()) return;
        const auto original=found->second.original;
        if (response.PDCID!=original.PDCID || response.source_fep!=original.source_fep ||
            response.connection_start_psn!=original.connection_start_psn || !found->second.sequence ||
            response.original_sequence!=*found->second.sequence || header.job_id!=original.pkt.bth_header.Standard_Header.job_id)
            return;
        read_returns_.erase(found);
        read_packet_reservations_.erase(ReadPacketIdentity::from(original));
        const auto incoming=incoming_.find(receive_message_key(original));
        if (incoming==incoming_.end()) return;
        auto& message=incoming->second;
        if (!message.read_returns_pending) throw std::logic_error("READ return counter underflow");
        --message.read_returns_pending;
        if (header.return_code!=1 && !message.first_error) message.first_error=SemanticReturnCode::Undeliverable;
        if (message.first_error) reply_error(original,message);
        else {
            // This is a READ acceptance DEFAULT, including EOM. The generic
            // fragmented SEND/WRITE helper intentionally uses NO_RESPONSE
            // for an incomplete EOM and must not be used for this contract.
            SES_PDS_rsp accepted{}; accepted.PDCID=original.PDCID; accepted.rx_pkt_handle=original.rx_pkt_handle;
            accepted.rsp_len=12; accepted.rsp=UET::PDS::default_semantic_response(original.pkt);
            if (!host_.manager().pushSESResponse(accepted)) throw std::runtime_error("PDS rejected READ acceptance");
            host_.wake();
        }
        message.completed=message.end_seen && !message.read_returns_pending &&
            (message.first_error || message.read_requests.bytes()==message.total);
    }
    void maybe_complete_read(uint16_t message) {
        const auto found=pending_.find(message);
        if (found==pending_.end()) return;
        const auto& operation=found->second;
        if (operation.is_read && operation.read_results.bytes()==operation.length &&
            operation.end_of_message_transmitted && operation.awaiting_semantic_responses.empty())
            finish(message,CompletionStatus::Success,operation.length,static_cast<uint8_t>(SemanticReturnCode::Ok),operation.returned_generation);
    }
    void place_read_result(uint16_t message,const SEStoPDS_pkt& packet) {
        const auto found=pending_.find(message);
        if (found==pending_.end()) return;
        auto& operation=found->second;
        const auto& header=packet.bth_header.Semantic_Response_with_Data_Header;
        const auto previous_bytes=static_cast<uint32_t>(operation.read_results.bytes());
        const uint32_t offset=header.message_offset;
        const bool in_bounds=offset<=operation.length && packet.payload.size()<=operation.length-offset;
        if (header.opcode!=2 || header.version || header.return_code!=1 || header.modified_length!=operation.length ||
            header.payload_length!=packet.payload.size() || !in_bounds || offset%mtu_ ||
            packet.payload.size()!=std::min<uint64_t>(mtu_,uint64_t{operation.length}-offset)) {
            finish(message,CompletionStatus::LocalError,previous_bytes,0); return;
        }
        const auto addition=operation.read_results.add(offset,packet.payload.size(),operation.length);
        if (addition==ReadCoverage::Addition::Invalid) {
            finish(message,CompletionStatus::LocalError,previous_bytes,0); return;
        }
        try {
            if (addition==ReadCoverage::Addition::Added && operation.read_registration) {
                const auto& destination=*operation.read_result;
                // Recheck the exact registration for each fragment, including
                // revocation and bounds. A peer never supplies this descriptor.
                memory_.write_registration(*operation.read_registration,operation.job,destination.pid,
                    Runtime::add_time(destination.offset,offset),packet.payload,destination.resource_index);
            }
        } catch (const MemoryAccessError&) {
            finish(message,CompletionStatus::LocalError,previous_bytes,0); return;
        }
        trace_.record(node_,"read_result_placed",operation.read_results.bytes());
        maybe_complete_read(message);
    }
    void receive_return_data(const PDC_SES_req& request) {
        const auto& header=request.pkt.bth_header.Semantic_Response_with_Data_Header;
        const auto found=pending_.find(header.read_request_msg_id);
        if (found!=pending_.end() && found->second.is_read && request.source_fep==found->second.peer &&
            request.PDCID==found->second.local_pdc && request.connection_start_psn==found->second.connection_start_psn &&
            header.job_id==found->second.job)
            place_read_result(header.read_request_msg_id,request.pkt);
        // §3.4.5.2 permits DEFAULT even on local placement failure. Discard
        // late/cancelled data but keep draining the peer's reliable direction.
        SES_PDS_rsp response{}; response.PDCID=request.PDCID; response.rx_pkt_handle=request.rx_pkt_handle;
        response.rsp_len=12; response.rsp=UET::PDS::default_semantic_response(request.pkt);
        if (!host_.manager().pushSESResponse(response)) throw std::runtime_error("PDS rejected return-data result");
        host_.wake();
    }
    void respond(const PDC_SES_rsp& response) {
        if (response.PDCID>=MAX_PDC) { complete_read_return(response); return; }
        if (response.pkt.bth_type==Semantic_Response_with_Data_Header) {
            const auto& header=response.pkt.bth_header.Semantic_Response_with_Data_Header;
            const auto pending=pending_.find(header.read_request_msg_id);
            if (pending==pending_.end() || !pending->second.is_read) return;
            auto& operation=pending->second;
            if (response.source_fep!=operation.peer || header.job_id!=operation.job ||
                response.PDCID!=operation.local_pdc || response.connection_start_psn!=operation.connection_start_psn ||
                !operation.awaiting_semantic_responses.erase(response.original_sequence)) return;
            place_read_result(header.read_request_msg_id,response.pkt);
            return;
        }
        if (response.pkt.bth_type!=Semantic_Response_Header) return;
        const auto& semantic_header=response.pkt.bth_header.Semantic_Response_Header;
        const auto it=pending_.find(semantic_header.message_id);
        if (it==pending_.end()) return;
        if (response.source_fep!=it->second.peer || semantic_header.job_id!=it->second.job || semantic_header.version) return;
        if (response.PDCID!=it->second.local_pdc || response.connection_start_psn!=it->second.connection_start_psn) return;
        if (semantic_header.opcode>1) return;
        if (!it->second.awaiting_semantic_responses.erase(response.original_sequence)) return;
        if (semantic_header.return_code!=1) {
            finish(semantic_header.message_id,CompletionStatus::RemoteError,
                it->second.is_read?static_cast<uint32_t>(it->second.read_results.bytes()):semantic_header.modified_length,
                semantic_header.return_code,semantic_header.ri_generation);
            return;
        }
        // A positive forward READ result accepts the request; success still
        // requires all returned data to be placed (§3.5.20.2.2).
        if (it->second.is_read) { maybe_complete_read(semantic_header.message_id); return; }
        // §3.4.4.3 / §3.5.13: every transmitted packet needs a positive
        // semantic result. An EOM DEFAULT cannot hide an earlier missing
        // packet. PDS supplies inferred defaults only for strictly-later CACK.
        // A RUD gap-filling packet can carry the final explicit response.
        it->second.completed_length=std::max(it->second.completed_length,
            semantic_header.opcode==0 && !semantic_header.modified_length?it->second.length:semantic_header.modified_length);
        it->second.returned_generation=semantic_header.ri_generation;
        if (it->second.end_of_message_transmitted && it->second.awaiting_semantic_responses.empty())
            finish(semantic_header.message_id,CompletionStatus::Success,it->second.completed_length,
                semantic_header.return_code,it->second.returned_generation);
    }
    enum class ResponseDelivery { Guaranteed, BestEffort };
    void reply(const PDC_SES_req& request, uint8_t code, uint32_t length, bool explicit_response=true,
                std::optional<uint8_t> returned_generation={},ResponseDelivery delivery=ResponseDelivery::Guaranteed) {
        SES_PDS_rsp response{}; response.PDCID=request.PDCID;
        response.rx_pkt_handle=request.rx_pkt_handle; response.rsp_len=12;
        response.gtd_del=explicit_response && delivery==ResponseDelivery::Guaranteed;
        response.rsp.bth_type=Semantic_Response_Header;
        auto& semantic_header=response.rsp.bth_header.Semantic_Response_Header;
        // A fully processed intermediate packet can return DEFAULT immediately
        // (§3.5.13). If EOM arrives before a RUD hole is filled, keep its result
        // as NO_RESPONSE (Table 3-24, RC_NULL); it cannot finish the message.
        // Deferrable-as-SEND instead signals acceptance with OK/full length
        // (§3.4.4.6.1); the source still needs results for every data packet.
        const bool incomplete_end=!explicit_response && request.pkt.bth_header.Standard_Header.eom &&
            request.pkt.bth_header.Standard_Header.opcode!=0x08;
        semantic_header.opcode=explicit_response?1:(incomplete_end?3:0);
        semantic_header.version=0; semantic_header.return_code=incomplete_end?0:code;
        semantic_header.job_id=request.pkt.bth_header.Standard_Header.job_id;
        semantic_header.message_id=request.pkt.bth_header.Standard_Header.msg_id;
        semantic_header.modified_length=!explicit_response && !incomplete_end?
            request.pkt.bth_header.Standard_Header.request_length:length;
        semantic_header.ri_generation=returned_generation.value_or(request.pkt.bth_header.Standard_Header.ri_generation);
        if (!host_.manager().pushSESResponse(response)) throw std::runtime_error("PDS rejected semantic response");
        host_.wake();
    }
    void reply(const PDC_SES_req& request,SemanticReturnCode code,uint32_t length,bool explicit_response=true,
                std::optional<uint8_t> returned_generation={},ResponseDelivery delivery=ResponseDelivery::Guaranteed) {
        reply(request,static_cast<uint8_t>(code),length,explicit_response,returned_generation,delivery);
    }
    void reply_error(const PDC_SES_req& request,Incoming& message) {
        const auto delivery=message.error_response_generated?ResponseDelivery::BestEffort:ResponseDelivery::Guaranteed;
        // An error remains UET_RESPONSE even when it is not guaranteed. Using
        // DEFAULT/NO_RESPONSE here would discard its code or imply success.
        reply(request,*message.first_error,static_cast<uint32_t>(message.received),true,message.error_generation,delivery);
        message.error_response_generated=true;
    }
    static SemanticReturnCode memory_code(MemoryError error) {
        switch(error) {
        // The JobID/PID was already found before the MR lookup. A scope
        // mismatch therefore means authorization failed, not that it is absent.
        case MemoryError::WrongJob: return SemanticReturnCode::PermissionViolation;
        case MemoryError::WrongEndpoint: return SemanticReturnCode::PermissionViolation;
        case MemoryError::InvalidKey: return SemanticReturnCode::BadMemoryKey;
        case MemoryError::Permission: return SemanticReturnCode::OperationViolation;
        case MemoryError::Bounds: return SemanticReturnCode::BadAddress;
        case MemoryError::Alignment: return SemanticReturnCode::AtomicUnaligned;
        }
        return SemanticReturnCode::Uncorrectable;
    }
    void release_unexpected(Incoming& message) {
        if (!message.unexpected) return;
        unexpected_bytes_-=message.total;
        unexpected_order_.erase(message.receive_order);
        message.unexpected.reset();
    }
    void match_unexpected() {
        // §3.4.4.7.2.2: ROD unexpected messages preserve acceptance order.
        // Buffering is internal SES storage; placement into an application MR
        // still requires a posting and the ordinary JobID/key/bounds checks.
        for (auto order=unexpected_order_.begin();order!=unexpected_order_.end();) {
            const auto key=order->second;
            auto found=incoming_.find(key);
            if (found==incoming_.end() || !found->second.unexpected) { order=unexpected_order_.erase(order); continue; }
            auto& message=found->second;
            auto posted=std::find_if(posted_.begin(),posted_.end(),[&](const Posted& receive) {
                return (!message.relative_addressing || receive.job==std::get<2>(key)) && receive.pid==message.pid &&
                    receive.resource_index==message.resource_index;
            });
            if (posted==posted_.end()) { ++order; continue; }
            const auto receive=*posted; posted_.erase(posted);
            message.key=receive.key; message.base=receive.offset; message.context=receive.context;
            message.receive_registration=receive.registration;
            message.matched_receive=true;
            auto buffered=message.unexpected;
            ++order; release_unexpected(message); // Erases the old order entry, not the next iterator.
            const auto fail=[&](SemanticReturnCode code,CompletionStatus status=CompletionStatus::RemoteError) {
                message.first_error=code; message.target_error=status; message.received=0; message.segments.clear();
                message.completed=message.end_seen;
                report_receive_error(message);
                if (message.deferred_response) {
                    reply_error(*message.deferred_response,message);
                    message.deferred_response.reset();
                }
            };
            if (receive.capacity<message.total) { fail(SemanticReturnCode::UnsupportedSize,CompletionStatus::Truncated); continue; }
            try {
                memory_.authorize_registration(*message.receive_registration,std::get<2>(key),message.pid,message.base,message.total,
                    Access::Write,message.resource_index);
                for (const auto& interval:message.segments) {
                    std::vector<uint8_t> bytes(interval.second);
                    buffered->read(interval.first,bytes.data(),bytes.size());
                    memory_.write_registration(*message.receive_registration,std::get<2>(key),message.pid,message.base+interval.first,bytes,message.resource_index);
                }
                if (message.received==message.total) {
                    message.completed=true; message.completion_reported=true;
                    completions_.push_back({0,message.context,CompletionStatus::Success,message.total,1,true,message.immediate_data});
                    if (message.deferred_response) {
                        message.completion_psn=message.deferred_response->orig_psn;
                        reply(*message.deferred_response,SemanticReturnCode::Ok,message.total);
                        message.deferred_response.reset();
                    }
                }
            } catch (const MemoryAccessError& error) { fail(memory_code(error.code)); }
        }
    }

    // First-error state belongs to a whole message, not to its first packet.
    // §3.4.6.1: arrival order chooses the first error, including in RUD.
    // Retain it through EOM + PDS Clear so a later posting cannot rescue a
    // rejected message or receive any of its remaining bytes.
    void report_receive_error(Incoming& message) {
        if (!message.first_error || message.completion_reported) return;
        // SEND still needs a matched receive to identify its completion. Its
        // header data must not create a separate unsolicited RMA notification.
        const bool has_header_data=message.has_immediate && message.immediate_data.has_value();
        const bool unsolicited_completion=message.opcode!=static_cast<uint8_t>(OperationType::Send) && has_header_data;
        if (!message.matched_receive && !unsolicited_completion) return;
        Completion completion{0,message.context,message.target_error,static_cast<uint32_t>(message.received),
            static_cast<uint8_t>(*message.first_error),true,
            has_header_data?message.immediate_data:std::optional<uint64_t>{},message.error_generation};
        completion.original_length=message.total;
        completions_.push_back(completion); message.completion_reported=true;
    }
    void reject_message(const PDC_SES_req& request,Incoming& message,SemanticReturnCode code,
                        std::optional<uint8_t> generation={}) {
        if (!message.first_error) {
            message.first_error=code;
            message.error_generation=generation.value_or(request.pkt.bth_header.Standard_Header.ri_generation);
        }
        if (message.unexpected) {
            release_unexpected(message); message.received=0; message.segments.clear();
        }
        message.completed=message.end_seen && (message.opcode!=2 || !message.read_returns_pending);
        report_receive_error(message);
        // The packet that exposed the error gets the first guarantee. A
        // previously held EOM may also need an explicit result, but it must
        // not steal that guarantee merely because its handle was deferred.
        reply_error(request,message);
        if (message.deferred_response) {
            if (message.deferred_response->orig_psn!=request.orig_psn)
                reply_error(*message.deferred_response,message);
            message.deferred_response.reset();
        }
    }
    static MessageKey receive_message_key(const PDC_SES_req& request) {
        const auto& header=request.pkt.bth_header.Standard_Header;
        return {request.source_fep,request.PDCID,header.job_id,header.initiator,header.msg_id,request.connection_start_psn};
    }
    Runtime::SemanticAdmission reserve_receive_message(const PDC_SES_req& request) {
        if (request.delivery_mode==UUD || request.pkt.bth_type!=Standard_Header)
            return Runtime::SemanticAdmission::ExistingMessage;
        const auto key=receive_message_key(request);
        const auto& header=request.pkt.bth_header.Standard_Header;
        const bool read=header.opcode==2;
        const auto packet=ReadPacketIdentity::from(request);
        if (read) {
            const auto reserved=read_packet_reservations_.find(packet);
            if (reserved!=read_packet_reservations_.end())
                return reserved->second.message==key?Runtime::SemanticAdmission::ExistingMessage:Runtime::SemanticAdmission::Rejected;
        }
        if (read && read_packet_reservations_.size()>=read_response_limit_) {
            trace_.record(node_,"read_packet_admission_blocked",request.orig_psn);
            return Runtime::SemanticAdmission::Rejected;
        }
        const bool existing=incoming_.count(key);
        if (!existing && incoming_.size()>=receive_message_limit_) {
            trace_.record(node_,"ses_admission_blocked",request.orig_psn);
            return Runtime::SemanticAdmission::Rejected;
        }
        if (!existing) {
            const uint8_t opcode=header.opcode==0x08?static_cast<uint8_t>(OperationType::Send):header.opcode;
            Incoming message{opcode,static_cast<uint32_t>(header.request_length),header.match_bits,header.buffer_offset,0,0};
            message.has_immediate=header.hd; message.error_generation=header.ri_generation;
            incoming_.emplace(key,std::move(message));
        }
        // Reserve before PDS accepts a PSN. Even another packet of an existing
        // large READ needs a target return-data credit; message slots alone
        // cannot bound the reverse payload queue.
        if (read) {
            read_packet_reservations_.emplace(packet,ReadReservation{key,false});
            return Runtime::SemanticAdmission::ReservedPacket;
        }
        if (existing) return Runtime::SemanticAdmission::ExistingMessage;
        return Runtime::SemanticAdmission::ReservedMessage;
    }
    void cancel_receive_reservation(const PDC_SES_req& request) {
        const bool read=request.pkt.bth_type==Standard_Header && request.pkt.bth_header.Standard_Header.opcode==2;
        if (read) read_packet_reservations_.erase(ReadPacketIdentity::from(request));
        const auto found=incoming_.find(receive_message_key(request));
        if (found==incoming_.end()) return;
        if (read && found->second.initialized) return; // Only this newly reserved packet is rolled back.
        if (read && std::any_of(read_packet_reservations_.begin(),read_packet_reservations_.end(),
            [&](const auto& credit) { return credit.second.message==found->first; })) return;
        if (found->second.initialized || found->second.first_error || found->second.received)
            throw std::logic_error("cannot roll back a processed SES message");
        incoming_.erase(found);
    }
    void receive_read(const PDC_SES_req& request) {
        const auto& header=request.pkt.bth_header.Standard_Header;
        auto& message=incoming_.at(receive_message_key(request));
        if (header.eom) { message.end_seen=true; message.completion_psn=request.orig_psn; }
        const auto reject=[&](SemanticReturnCode code,std::optional<uint8_t> generation={}) {
            reject_message(request,message,code,generation);
        };
        if (message.first_error) { reject(*message.first_error); return; }
        if (header.rel && !memory_.has_job(header.job_id)) { reject(SemanticReturnCode::BadJob); return; }
        ResourceSelection selected{};
        try {
            selected=message.initialized?ResourceSelection{message.pid,message.resource_index,message.error_generation}:
                resources_.resolve(header.job_id,header.rel,header.PIDonFEP,header.resource_index,ResourceSpace::Rma,header.ri_generation);
        } catch (const AddressingError& error) { reject(error.code,error.generation); return; }
        if (header.version || header.hd) { reject(SemanticReturnCode::UnsupportedOperation); return; }
        const uint32_t offset=header.som?0:header.diff.som_false.message_offset;
        if (!request.pkt.payload.empty() || offset>header.request_length ||
            (!header.som && header.diff.som_false.payload_length) || offset%mtu_ ||
            (host_.services().max_ack_data_size>=mtu_ && header.request_length>mtu_)) {
            reject(SemanticReturnCode::UnsupportedSize); return;
        }
        // §3.4.5.2: each empty READ request asks for one Payload MTU, except
        // the final fragment. The request's payload_length remains zero.
        const uint32_t count=std::min<uint64_t>(mtu_,uint64_t{header.request_length}-offset);
        if (bool(header.som)!=(offset==0) || bool(header.eom)!=(uint64_t{offset}+count==header.request_length)) {
            reject(SemanticReturnCode::UnsupportedSize); return;
        }
        if (header.ie) { reject(SemanticReturnCode::InitiatorError); return; }
        if (message.initialized && (message.opcode!=2 || message.total!=header.request_length ||
            message.key!=header.match_bits || message.base!=header.buffer_offset ||
            message.wire_pid!=header.PIDonFEP || message.resource_index!=selected.resource_index ||
            message.relative_addressing!=bool(header.rel) || message.error_generation!=header.ri_generation)) {
            reject(SemanticReturnCode::OperationViolation); return;
        }
        try {
            if (!message.initialized) {
                memory_.authorize(header.job_id,selected.absolute_pid,header.match_bits,header.buffer_offset,
                    header.request_length,Access::Read,selected.resource_index,header.rel);
                message.pid=selected.absolute_pid; message.resource_index=selected.resource_index;
                message.wire_pid=header.PIDonFEP; message.relative_addressing=header.rel; message.initialized=true;
            }
            const auto packet=ReadPacketIdentity::from(request);
            auto& processed=read_packet_reservations_.at(packet).processed;
            if (!processed) {
                if (message.read_requests.add(offset,count,message.total)!=ReadCoverage::Addition::Added) {
                    reject(SemanticReturnCode::OperationViolation); return;
                }
                processed=true; message.received=message.read_requests.bytes();
            }
            // Always reauthorize the actual access. An ACK-data READ may be
            // re-executed after loss and is allowed to observe newer memory.
            auto bytes=memory_.read(header.job_id,selected.absolute_pid,header.match_bits,
                Runtime::add_time(header.buffer_offset,offset),count,selected.resource_index,header.rel);
            SEStoPDS_pkt data{}; data.bth_type=Semantic_Response_with_Data_Header;
            auto& result=data.bth_header.Semantic_Response_with_Data_Header;
            result.opcode=2; result.return_code=1; result.job_id=header.job_id;
            result.read_request_msg_id=header.msg_id; result.payload_length=count;
            result.modified_length=header.request_length; result.message_offset=offset;
            data.payload=std::move(bytes);
            if (header.request_length<=host_.services().max_ack_data_size) {
                // §3.5.17: PDS keeps only this PSN's required-delivery marker,
                // never a post-transmit snapshot of the READ result.
                SES_PDS_rsp response{}; response.PDCID=request.PDCID; response.rx_pkt_handle=request.rx_pkt_handle;
                response.rsp_len=20+count; response.gtd_del=true; response.rsp=std::move(data);
                if (!host_.manager().pushSESResponse(response)) throw std::runtime_error("PDS rejected READ data ACK");
                message.completed=message.end_seen; trace_.record(node_,"read_ack_data",count); host_.wake();
                return;
            }
            uint16_t token=0;
            for (size_t attempt=0;attempt<UINT16_MAX;++attempt) {
                if (++next_read_response_==0) ++next_read_response_;
                if (!read_returns_.count(next_read_response_)) { token=next_read_response_; break; }
            }
            if (!token) throw std::logic_error("READ response token budget exhausted");
            result.response_message_id=token;
            read_returns_.emplace(token,ReadReturn{request,{}}); ++message.read_returns_pending;
            if (!host_.submit_return_data(request,data)) {
                read_returns_.erase(token); --message.read_returns_pending;
                reject(SemanticReturnCode::Undeliverable); return;
            }
            trace_.record(node_,"read_return_data",count);
            // No forward ACK yet. Its eventual DEFAULT follows this reverse
            // packet's semantic completion, bounding data storage and keeping
            // the initiator's original message ID leased until delivery.
        } catch (const MemoryAccessError& error) { reject(memory_code(error.code)); }
    }
    void receive(const PDC_SES_req& request) {
        if (request.delivery_mode==UUD) { receive_datagram(request); return; }
        if (request.pkt.bth_type==Semantic_Response_with_Data_Header) { receive_return_data(request); return; }
        if (request.pkt.bth_type!=Standard_Header) { reply(request,SemanticReturnCode::UnsupportedOperation,0); return; }
        if (request.pkt.bth_header.Standard_Header.opcode==2) { receive_read(request); return; }
        auto interpreted_header=request.pkt.bth_header.Standard_Header;
        // §3.3.5 / §3.4.4.6.1: AI Base accepts DEFERRABLE_SEND (0x08) as SEND.
        // Interpret a copy: restart tokens remain intact in the captured wire
        // request, but cannot become an RMA address or a posted-buffer offset.
        const bool deferrable_as_send=interpreted_header.opcode==0x08;
        if (deferrable_as_send) {
            interpreted_header.opcode=static_cast<uint8_t>(OperationType::Send);
            if (interpreted_header.som) trace_.record(node_,"deferrable_as_send",interpreted_header.msg_id);
        }
        const auto& header=interpreted_header;
        const auto key=receive_message_key(request);
        auto found=incoming_.find(key);
        if (found==incoming_.end()) throw std::logic_error("PDS forwarded an unreserved standard SES message");
        auto& message=found->second;
        if (header.som && message.opcode==0x0f && header.opcode!=0x0f)
            message.opcode=header.opcode; // Late SOM identifies an earlier MSG_ERROR's resource space.
        if (header.eom) { message.end_seen=true; message.completion_psn=request.orig_psn; }
        if (header.som && header.hd) message.immediate_data=header.diff.som_true.header_data;
        if (message.first_error) {
            // A RUD EOM/MSG_ERROR may arrive before SOM and before its header
            // data. Capture that data above, but never perform another lookup
            // or memory access for an already rejected message.
            reject_message(request,message,*message.first_error); return;
        }
        const auto reject=[&](SemanticReturnCode code,std::optional<uint8_t> generation={}) {
            reject_message(request,message,code,generation);
        };
        if (header.rel && !memory_.has_job(header.job_id)) { reject(SemanticReturnCode::BadJob); return; }
        const bool message_error=header.opcode==0x0f;
        const bool poisoned=header.ie || message_error;
        ResourceSelection selected{};
        try {
            if (message.initialized) {
                // A resource generation changes admission for new messages.
                // Already accepted messages keep their selection and drain;
                // MR permission and revocation remain checked on each access.
                selected={message.pid,message.resource_index,message.error_generation};
            } else {
                const auto original_opcode=message_error?message.opcode:static_cast<uint8_t>(header.opcode);
                selected=resources_.resolve(header.job_id,header.rel,header.PIDonFEP,header.resource_index,
                    original_opcode==5?ResourceSpace::Send:ResourceSpace::Rma,header.ri_generation);
            }
        } catch (const AddressingError& error) { reject(error.code,error.generation); return; }
        if (header.version || (header.hd && header.opcode!=1 && header.opcode!=5 && !message_error) ||
            (header.opcode!=0 && header.opcode!=1 && header.opcode!=3 && header.opcode!=5 && !message_error) ||
            (message_error && !header.eom)) {
            reject(SemanticReturnCode::UnsupportedOperation); return;
        }
        const auto offset=header.som?0:header.diff.som_false.message_offset;
        const auto count=request.pkt.payload.size();
        const auto& atomic_extension=request.pkt.eth_header.Atomic_Operation_Extension_Header;
        if (header.opcode==3 && !poisoned) {
            if (atomic_extension.atomic_datatype>7) { reject(SemanticReturnCode::AtomicUnsupportedDatatype); return; }
            if (atomic_extension.atomic_opcode>12 || atomic_extension.atomic_opcode==11 ||
                atomic_extension.semantic_contol || atomic_extension.rsvd) { reject(SemanticReturnCode::AtomicUnsupportedOperation); return; }
            const auto width=integer_atomic_width(static_cast<IntegerAtomicDatatype>(atomic_extension.atomic_datatype));
            if (header.request_length%width || count%width || offset%width) { reject(SemanticReturnCode::AtomicUnsupportedSize); return; }
            if (header.buffer_offset%width) { reject(SemanticReturnCode::AtomicUnaligned); return; }
        }
        if (offset>header.request_length || count>header.request_length-offset ||
            (!header.som && count!=header.diff.som_false.payload_length) ||
            (!message_error && header.eom && offset+count!=header.request_length) ||
            (header.opcode==0 && header.request_length)) {
            reject(SemanticReturnCode::UnsupportedSize); return;
        }
        try {
            if (!message.initialized) {
                message.pid=selected.absolute_pid; message.resource_index=selected.resource_index;
                message.wire_pid=header.PIDonFEP; message.relative_addressing=header.rel;
                if (header.opcode==1 && !poisoned)
                    memory_.authorize(header.job_id,selected.absolute_pid,header.match_bits,
                        header.buffer_offset,header.request_length,Access::Write,selected.resource_index,header.rel);
                else if (header.opcode==3 && !poisoned) {
                    const auto& region=memory_.authorize(header.job_id,selected.absolute_pid,header.match_bits,
                        header.buffer_offset,header.request_length,Access::Atomic,selected.resource_index,header.rel);
                    if ((region.permissions&3u)!=3u) { reject(SemanticReturnCode::OperationViolation); return; }
                    message.atomic_operation=atomic_extension.atomic_opcode;
                    message.atomic_datatype=atomic_extension.atomic_datatype;
                } else if (header.opcode==5) {
                    auto posted=std::find_if(posted_.begin(),posted_.end(),[&](const Posted& receive) {
                        return (!header.rel || receive.job==header.job_id) && receive.pid==selected.absolute_pid &&
                            receive.resource_index==selected.resource_index;
                    });
                    if (posted==posted_.end()) {
                        if (poisoned) { reject(SemanticReturnCode::InitiatorError); return; }
                        // §3.4.4.6.1: a non-deferring target must tell a
                        // deferrable source NO_MATCH/0 or OK/full length. It
                        // cannot silently choose ordinary ROD buffering here.
                        if (request.delivery_mode==RUD || deferrable_as_send) { reject(SemanticReturnCode::NoMatch); return; }
                        if (header.request_length>unexpected_limit_-unexpected_bytes_) {
                            const auto generation=resources_.disable_for_exhaustion(selected.absolute_pid,
                                selected.resource_index,ResourceSpace::Send);
                            disabled_generations_[{selected.absolute_pid,selected.resource_index}]=generation;
                            reject(SemanticReturnCode::DisabledGeneration,generation); return;
                        }
                        message.unexpected=std::make_shared<SparseMemory>(message.total);
                        message.receive_order=++next_receive_order_;
                        unexpected_order_.emplace(message.receive_order,key);
                        unexpected_bytes_+=message.total;
                    } else {
                    // Bind the posting before reporting truncation or initiator
                    // failure, so the target gets one error completion too.
                    const auto receive=*posted; posted_.erase(posted);
                    message.key=receive.key; message.base=receive.offset; message.context=receive.context;
                    message.receive_registration=receive.registration;
                    message.matched_receive=true;
                    if (!poisoned && receive.capacity<header.request_length) {
                        message.target_error=CompletionStatus::Truncated;
                        reject(SemanticReturnCode::UnsupportedSize); return;
                    }
                    if (!poisoned) memory_.authorize_registration(receive.registration,header.job_id,receive.pid,receive.offset,
                        header.request_length,Access::Write,selected.resource_index);
                    }
                }
                message.initialized=true;
            }
            if (poisoned) { reject(SemanticReturnCode::InitiatorError); return; }
            if (message.pid!=selected.absolute_pid || message.resource_index!=selected.resource_index ||
                message.wire_pid!=header.PIDonFEP || message.relative_addressing!=bool(header.rel) ||
                message.error_generation!=header.ri_generation ||
                message.opcode!=header.opcode || message.total!=header.request_length) {
                reject(SemanticReturnCode::OperationViolation); return;
            }
            if ((header.opcode==1 || header.opcode==3) &&
                (message.key!=header.match_bits || message.base!=header.buffer_offset || message.has_immediate!=bool(header.hd))) {
                reject(SemanticReturnCode::OperationViolation); return;
            }
            if (header.opcode==3 && (message.atomic_operation!=atomic_extension.atomic_opcode ||
                message.atomic_datatype!=atomic_extension.atomic_datatype)) { reject(SemanticReturnCode::OperationViolation); return; }
            if (message.completed) { reply(request,SemanticReturnCode::Ok,message.total); return; }
            auto position=message.segments.lower_bound(offset);
            if (position!=message.segments.end() && position->first==offset && position->second==count) return;
            if ((position!=message.segments.end() && offset+count>position->first) ||
                (position!=message.segments.begin() && std::prev(position)->first+std::prev(position)->second>offset)) {
                reject(SemanticReturnCode::OperationViolation); return;
            }
            if (message.unexpected) message.unexpected->write(offset,request.pkt.payload.data(),count);
            else if (header.opcode==3) {
                auto operands=request.pkt.payload;
                convert_integer_atomic_byte_order(operands,static_cast<IntegerAtomicDatatype>(message.atomic_datatype));
                memory_.atomic_elements(header.job_id,message.pid,message.key,Runtime::add_time(message.base,offset),
                    static_cast<IntegerAtomicOperation>(message.atomic_operation),
                    static_cast<IntegerAtomicDatatype>(message.atomic_datatype),operands,message.resource_index,message.relative_addressing);
            } else if (message.receive_registration) memory_.write_registration(*message.receive_registration,
                header.job_id,message.pid,Runtime::add_time(message.base,offset),request.pkt.payload,message.resource_index);
            else if (header.opcode!=0) memory_.write(header.job_id,message.pid,message.key,
                Runtime::add_time(message.base,offset),request.pkt.payload,message.resource_index,message.relative_addressing);
            // Coalesce adjacent intervals: ordered large messages retain one
            // record; RUD retains only holes allowed by the PDS receive window.
            uint32_t merged_offset=offset,merged_length=static_cast<uint32_t>(count);
            if (position!=message.segments.begin()) {
                auto previous=std::prev(position);
                if (previous->first+previous->second==offset) {
                    merged_offset=previous->first; merged_length+=previous->second;
                    message.segments.erase(previous);
                }
            }
            if (position!=message.segments.end() && offset+count==position->first) {
                merged_length+=position->second; message.segments.erase(position);
            }
            message.segments.emplace(merged_offset,merged_length); message.received+=count;
            if (message.unexpected && message.received==message.total) {
                // Delivery-complete SEND waits for application placement. Hold
                // its real EOM request handle; ACK Request sees SES processing.
                message.deferred_response=request;
                return;
            }
            if (message.received==message.total) {
                message.completed=true; message.completion_reported=true; message.completion_psn=request.orig_psn;
                if (header.opcode==5) completions_.push_back({0,message.context,CompletionStatus::Success,message.total,1,true,message.immediate_data});
                if (header.opcode==1 && message.immediate_data)
                    completions_.push_back({0,0,CompletionStatus::Success,message.total,1,true,message.immediate_data});
                trace_.record(node_,"memory_delivered",message.total);
                reply(request,SemanticReturnCode::Ok,message.total);
            } else reply(request,SemanticReturnCode::Ok,0,false);
        } catch (const MemoryAccessError& error) { reject(memory_code(error.code)); }
    }
    void receive_datagram(const PDC_SES_req& request) {
        if (request.pkt.bth_type!=Standard_Header) return;
        const auto& header=request.pkt.bth_header.Standard_Header;
        // §3.4.2.13–14: one packet, DATAGRAM_SEND only, message ID zero.
        // No responses or deduplication are provided for unreliable delivery.
        if (header.opcode!=7 || header.version || header.msg_id || header.dc ||
            !header.som || !header.eom || header.ie ||
            header.request_length!=request.pkt.payload.size() || (header.rel && !memory_.has_job(header.job_id))) return;
        ResourceSelection selected{};
        try {
            selected=resources_.resolve(header.job_id,header.rel,header.PIDonFEP,header.resource_index,
                ResourceSpace::Send,header.ri_generation);
        } catch (const AddressingError&) { return; }
        auto posted=std::find_if(posted_.begin(),posted_.end(),[&](const Posted& receive) {
            return (!header.rel || receive.job==header.job_id) && receive.pid==selected.absolute_pid &&
                receive.resource_index==selected.resource_index;
        });
        if (posted==posted_.end() || posted->capacity<request.pkt.payload.size()) return;
        try {
            memory_.write_registration(posted->registration,header.job_id,posted->pid,posted->offset,request.pkt.payload,selected.resource_index);
            completions_.push_back({0,posted->context,CompletionStatus::Success,
                static_cast<uint32_t>(request.pkt.payload.size()),0,true,
                header.hd?std::optional<uint64_t>{header.diff.som_true.header_data}:std::nullopt});
            posted_.erase(posted);
        } catch (const MemoryAccessError&) {
            // Unreliable receive errors are local drops, never ACK/NACKs.
        }
    }
};
} // namespace UET::SES
