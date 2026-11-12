#pragma once
#include "MemoryRegistry.hpp"
#include "SemanticReturnCode.hpp"
#include "ResourceDirectory.hpp"
#include "../Runtime/PdsHost.hpp"
#include <deque>
#include <tuple>
#include <optional>

namespace UET::SES {

enum class OperationType : uint8_t { Noop=0, Write=1, Read=2, Atomic=3, Send=5, DatagramSend=7 };
enum class CompletionStatus { Success, LocalSuccess, LocalError, Unsupported, InvalidRequest, RemoteError, Timeout, Cancelled, ResourceExhausted };
struct Operation {
    OperationType type = OperationType::Send;
    pdc_mode delivery_mode = ROD; // Reliable ordered by default; RUD permits packet reordering.
    uint32_t peer = 0;
    uint32_t job = 1;
    uint16_t target_pid = 1;
    uint16_t target_resource = 1;
    uint64_t remote_key = 0;
    uint64_t remote_offset = 0;
    uint64_t context = 0;
    std::vector<uint8_t> payload;
    IntegerAtomicOperation atomic_operation = IntegerAtomicOperation::Sum;
    IntegerAtomicDatatype atomic_datatype = IntegerAtomicDatatype::Uint64;
    std::optional<uint64_t> immediate_data; // Write-with-immediate remote CQ data.
    bool relative_addressing=true;
    uint8_t target_generation=0;
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
};
struct EndpointCapabilities {
    bool noop=true, send=true, write=true;
    bool datagram_send=true;
    bool relative_addressing=true, absolute_addressing=true;
    bool read=false, atomic=true, libfabric=false, write_immediate=true;
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
             Runtime::Time timeout=100*Runtime::kMillisecond,MemoryRegistry* domain_memory=nullptr)
        : node_(node), host_(host), loop_(loop), trace_(trace), mtu_(payload_mtu), timeout_(timeout),
          memory_(domain_memory?*domain_memory:private_memory_) {
        if (!mtu_ || mtu_>8192 || !timeout_) throw std::invalid_argument("invalid SES configuration");
        host_.set_request_handler([this](const PDC_SES_req& request) { receive(request); });
        host_.set_response_handler([this](const PDC_SES_rsp& response) { respond(response); });
        host_.set_context_event_handler([this](const Runtime::PdcEvent& event) { context_event(event); });
        host_.set_datagram_transmit_handler([this](uint16_t message,Runtime::SendResult result) {
            const auto pending=pending_.find(message);
            if (pending==pending_.end()) return;
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
        if (!is_datagram && operation.delivery_mode!=ROD && operation.delivery_mode!=RUD) {
            complete_local(CompletionStatus::Unsupported); return id;
        }
        if (operation.type!=OperationType::Noop && operation.type!=OperationType::Send &&
            operation.type!=OperationType::Write && !is_atomic && !is_datagram) {
            complete_local(CompletionStatus::Unsupported); return id;
        }
        size_t atomic_width=1;
        if (is_atomic) {
            if (static_cast<uint8_t>(operation.atomic_datatype)>7 ||
                static_cast<uint8_t>(operation.atomic_operation)>12 ||
                operation.atomic_operation==IntegerAtomicOperation::Read) {
                complete_local(CompletionStatus::Unsupported); return id;
            }
            atomic_width=integer_atomic_width(operation.atomic_datatype);
            if (operation.payload.empty() || operation.payload.size()%atomic_width ||
                operation.remote_offset%atomic_width || mtu_<atomic_width) {
                complete_local(CompletionStatus::InvalidRequest); return id;
            }
        }
        if (!operation.peer || !memory_.has_job(operation.job) || operation.target_pid>0xfff || operation.target_resource>0xfff ||
            operation.payload.size()>UINT32_MAX || (is_datagram && operation.payload.size()>mtu_) ||
            (operation.immediate_data && operation.type!=OperationType::Write) ||
            (operation.type==OperationType::Noop && !operation.payload.empty())) {
            complete_local(CompletionStatus::InvalidRequest); return id;
        }
        uint16_t message=0;
        for (size_t i=0; i<UINT16_MAX; ++i) {
            if (++next_message_==0) ++next_message_;
            if (!pending_.count(next_message_) && !message_leases_.count(next_message_)) { message=next_message_; break; }
        }
        if (!message) { complete_local(CompletionStatus::ResourceExhausted); return id; }
        Pending pending{id,operation.context,static_cast<uint32_t>(operation.payload.size()),0,operation.peer,operation.job};
        pending.is_datagram=is_datagram;
        pending_.emplace(message,pending);
        try {
            for (size_t offset=0;;) {
                const auto fragment_capacity=is_atomic?mtu_-(mtu_%atomic_width):mtu_;
                const auto count=std::min(fragment_capacity,operation.payload.size()-offset);
                SES_PDS_req request{};
                request.src_fep=node_; request.dst_fep=operation.peer;
                request.mode=is_datagram?UUD:operation.delivery_mode;
                request.next_hdr=UET_HDR_REQUEST_STD; request.rod_context=1; request.lock_pdc=true;
                request.tx_pkt_handle=message; request.pkt.bth_type=Standard_Header;
                auto& semantic_header=request.pkt.bth_header.Standard_Header;
                semantic_header.opcode=static_cast<uint8_t>(operation.type); semantic_header.version=0;
                semantic_header.som=offset==0; semantic_header.eom=offset+count==operation.payload.size();
                semantic_header.dc=!is_datagram; semantic_header.rel=operation.relative_addressing;
                semantic_header.ri_generation=operation.target_generation;
                semantic_header.msg_id=is_datagram?0:message; semantic_header.job_id=operation.job; semantic_header.PIDonFEP=operation.target_pid;
                semantic_header.resource_index=operation.target_resource; semantic_header.buffer_offset=operation.remote_offset;
                semantic_header.initiator=node_; semantic_header.match_bits=operation.remote_key;
                semantic_header.request_length=operation.payload.size();
                if (operation.immediate_data) {
                    semantic_header.hd=1;
                    if (!offset) semantic_header.diff.som_true.header_data=*operation.immediate_data;
                }
                if (is_atomic) {
                    request.pkt.eth_type=Atomic_Operation_Extension_Header;
                    auto& extension=request.pkt.eth_header.Atomic_Operation_Extension_Header;
                    extension.atomic_opcode=static_cast<uint8_t>(operation.atomic_operation);
                    extension.atomic_datatype=static_cast<uint8_t>(operation.atomic_datatype);
                }
                if (offset) { semantic_header.diff.som_false.payload_length=count; semantic_header.diff.som_false.message_offset=offset; }
                request.pkt.payload.assign(operation.payload.begin()+offset,operation.payload.begin()+offset+count);
                if (is_atomic) convert_integer_atomic_byte_order(request.pkt.payload,operation.atomic_datatype);
                request.pkt_len=static_cast<uint16_t>(44+(is_atomic?4:0)+count);
                if (!host_.submit(request)) throw std::runtime_error("PDS rejected operation");
                offset+=count;
                if (offset==operation.payload.size()) break;
            }
            std::weak_ptr<int> life=lifetime_;
            pending_.at(message).timer=loop_.after(timeout_,[this,life,message] {
                if (life.expired()) return;
                finish(message,CompletionStatus::Timeout,0,0);
            });
        } catch (...) {
            finish(message,CompletionStatus::ResourceExhausted,0,0);
            throw;
        }
        return id;
    }
    void post_receive(uint32_t job, uint16_t pid, uint64_t key, uint64_t offset,
                       uint32_t capacity, uint64_t context=0,uint16_t resource_index=1) {
        if (closed_) throw std::logic_error("endpoint closed");
        memory_.authorize(job,pid,key,offset,capacity,Access::Write,resource_index);
        if (posted_.size()>=4096) throw std::runtime_error("receive queue full");
        posted_.push_back({job,pid,key,offset,capacity,context,resource_index});
    }
    bool poll_completion(Completion& completion) {
        if (completions_.empty()) return false;
        completion=completions_.front(); completions_.pop_front(); return true;
    }
    size_t pending() const { return pending_.size(); }
    size_t retained_receive_messages() const { return incoming_.size(); }
    size_t leased_message_ids() const { return message_leases_.size(); }
    void close() {
        if (closed_) return;
        closed_=true; lifetime_.reset();
        host_.set_request_handler({}); host_.set_response_handler({});
        host_.set_datagram_transmit_handler({});
        host_.set_context_event_handler({});
        while (!pending_.empty()) finish(pending_.begin()->first,CompletionStatus::Cancelled,0,0);
        incoming_.clear(); posted_.clear(); message_leases_.clear(); peer_cumulative_acks_.clear();
    }
private:
    struct Pending {
        uint64_t id,context; uint32_t length; Runtime::TimerId timer; uint32_t peer,job;
        uint16_t local_pdc=UINT16_MAX;
        uint32_t connection_start_psn=0,last_transmitted_psn=0;
        bool is_datagram=false;
        bool end_of_message_transmitted=false;
    };
    using ConnectionKey=std::tuple<uint32_t,uint16_t,uint32_t>;
    struct MessageLease { ConnectionKey connection; uint32_t last_psn; bool end_of_message_transmitted; };
    struct Posted { uint32_t job; uint16_t pid; uint64_t key,offset; uint32_t capacity; uint64_t context; uint16_t resource_index; };
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
    std::map<ConnectionKey,uint32_t> peer_cumulative_acks_;
    std::deque<Posted> posted_;
    std::map<MessageKey,Incoming> incoming_;
    std::deque<Completion> completions_;

    void finish(uint16_t message, CompletionStatus status, uint32_t length, uint8_t code,uint8_t remote_generation=0) {
        const auto it=pending_.find(message);
        if (it==pending_.end()) return;
        loop_.cancel(it->second.timer);
        completions_.push_back({it->second.id,it->second.context,status,length,code,false,{},remote_generation});
        trace_.record(node_,"operation_complete",it->second.id);
        if (!it->second.is_datagram && !closed_) {
            const ConnectionKey connection{it->second.peer,it->second.local_pdc,it->second.connection_start_psn};
            const auto peer_ack=peer_cumulative_acks_.find(connection);
            if (it->second.local_pdc==UINT16_MAX || !it->second.end_of_message_transmitted || peer_ack==peer_cumulative_acks_.end() ||
                peer_ack->second-it->second.last_transmitted_psn>=0x80000000u)
                message_leases_[message]={connection,it->second.last_transmitted_psn,it->second.end_of_message_transmitted};
        }
        pending_.erase(it);
    }

    void context_event(const Runtime::PdcEvent& event) {
        if (event.kind==Runtime::PdcEventKind::RequestRejected) {
            const auto pending=pending_.find(event.message_id);
            if (pending!=pending_.end() && pending->second.peer==event.peer && pending->second.job==event.job)
                finish(event.message_id,CompletionStatus::ResourceExhausted,0,0);
            // Rejected requests never acquired a transmit PSN. PDS has removed
            // every queued fragment, so no late packet can use this message ID.
            message_leases_.erase(event.message_id);
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
            } else if (auto lease=message_leases_.find(event.message_id);lease!=message_leases_.end()) {
                lease->second={connection,event.sequence,lease->second.end_of_message_transmitted || event.end_of_message};
            }
        } else if (event.kind==Runtime::PdcEventKind::PeerCumulativeAcknowledged) {
            auto previous=peer_cumulative_acks_.find(connection);
            if (previous!=peer_cumulative_acks_.end() && event.sequence-previous->second>=0x80000000u) return;
            peer_cumulative_acks_[connection]=event.sequence;
            for (auto lease=message_leases_.begin();lease!=message_leases_.end();) {
                if (lease->second.connection==connection && lease->second.end_of_message_transmitted &&
                    event.sequence-lease->second.last_psn<0x80000000u)
                    lease=message_leases_.erase(lease);
                else ++lease;
            }
        } else {
            for (auto message=incoming_.begin();message!=incoming_.end();) {
                const auto& key=message->first;
                const bool same_context=std::get<0>(key)==event.peer && std::get<1>(key)==event.local_pdc &&
                    std::get<5>(key)==event.connection_start_psn;
                const bool retired=event.kind==Runtime::PdcEventKind::ConnectionClosed ||
                    (message->second.completed && event.sequence-message->second.completion_psn<0x80000000u);
                if (same_context && retired) message=incoming_.erase(message); else ++message;
            }
            if (event.kind==Runtime::PdcEventKind::ConnectionClosed) {
                std::vector<uint16_t> failed_messages;
                for (const auto& operation:pending_)
                    if (ConnectionKey{operation.second.peer,operation.second.local_pdc,operation.second.connection_start_psn}==connection)
                        failed_messages.push_back(operation.first);
                for (const auto message:failed_messages)
                    finish(message,event.failure==Runtime::PdcFailureReason::RetryExhausted?CompletionStatus::Timeout:
                        CompletionStatus::RemoteError,0,0);
                for (auto lease=message_leases_.begin();lease!=message_leases_.end();)
                    if (lease->second.connection==connection) lease=message_leases_.erase(lease); else ++lease;
                peer_cumulative_acks_.erase(connection);
            }
        }
    }
    void respond(const PDC_SES_rsp& response) {
        if (response.pkt.bth_type!=Semantic_Response_Header) return;
        const auto& semantic_header=response.pkt.bth_header.Semantic_Response_Header;
        const auto it=pending_.find(semantic_header.message_id);
        if (it==pending_.end()) return;
        if (response.source_fep!=it->second.peer || semantic_header.job_id!=it->second.job || semantic_header.version) return;
        if (response.PDCID!=it->second.local_pdc || response.connection_start_psn!=it->second.connection_start_psn) return;
        if (semantic_header.opcode>1) return;
        // §3.4.6: a successful response for an intermediate packet does not
        // complete the application message. In RUD, an explicit full-length
        // response may accompany the gap-filling packet after EOM arrived.
        // A DEFAULT_RESPONSE instead inherits its individual packet's scope.
        const bool explicit_full_response=semantic_header.opcode==1 && semantic_header.modified_length==it->second.length;
        if (semantic_header.return_code==1 && (!it->second.end_of_message_transmitted ||
            (!explicit_full_response && response.original_sequence!=it->second.last_transmitted_psn))) return;
        const uint32_t completed_length=semantic_header.opcode==0 && !semantic_header.modified_length?
            it->second.length:semantic_header.modified_length;
        finish(semantic_header.message_id,semantic_header.return_code==1?CompletionStatus::Success:CompletionStatus::RemoteError,
            completed_length,semantic_header.return_code,semantic_header.ri_generation);
    }
    void reply(const PDC_SES_req& request, uint8_t code, uint32_t length, bool semantic=true,
                std::optional<uint8_t> returned_generation={}) {
        SES_PDS_rsp response{}; response.PDCID=request.PDCID;
        response.rx_pkt_handle=request.rx_pkt_handle; response.rsp_len=semantic?12:0;
        response.gtd_del=semantic;
        response.rsp.bth_type=Semantic_Response_Header;
        auto& semantic_header=response.rsp.bth_header.Semantic_Response_Header;
        semantic_header.opcode=1; semantic_header.version=0; semantic_header.return_code=code;
        semantic_header.job_id=request.pkt.bth_header.Standard_Header.job_id;
        semantic_header.message_id=request.pkt.bth_header.Standard_Header.msg_id; semantic_header.modified_length=length;
        semantic_header.ri_generation=returned_generation.value_or(request.pkt.bth_header.Standard_Header.ri_generation);
        if (!host_.manager().pushSESResponse(response)) throw std::runtime_error("PDS rejected semantic response");
        host_.wake();
    }
    void reply(const PDC_SES_req& request,SemanticReturnCode code,uint32_t length,bool semantic=true,
                std::optional<uint8_t> returned_generation={}) {
        reply(request,static_cast<uint8_t>(code),length,semantic,returned_generation);
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
    void receive(const PDC_SES_req& request) {
        if (request.delivery_mode==UUD) { receive_datagram(request); return; }
        if (request.pkt.bth_type!=Standard_Header) { reply(request,SemanticReturnCode::UnsupportedOperation,0); return; }
        const auto& semantic_header=request.pkt.bth_header.Standard_Header;
        if (semantic_header.rel && !memory_.has_job(semantic_header.job_id)) { reply(request,SemanticReturnCode::BadJob,0); return; }
        ResourceSelection selected{};
        try {
            selected=resources_.resolve(semantic_header.job_id,semantic_header.rel,semantic_header.PIDonFEP,
                semantic_header.resource_index,semantic_header.opcode==5?ResourceSpace::Send:ResourceSpace::Rma,
                semantic_header.ri_generation);
        } catch (const AddressingError& error) { reply(request,error.code,0,true,error.generation); return; }
        if (semantic_header.version || semantic_header.ie || (semantic_header.hd && semantic_header.opcode!=1) ||
            (semantic_header.opcode!=0 && semantic_header.opcode!=1 && semantic_header.opcode!=3 && semantic_header.opcode!=5)) {
            reply(request,SemanticReturnCode::UnsupportedOperation,0); return;
        }
        const auto offset=semantic_header.som?0:semantic_header.diff.som_false.message_offset;
        const auto count=request.pkt.payload.size();
        const auto& atomic_extension=request.pkt.eth_header.Atomic_Operation_Extension_Header;
        if (semantic_header.opcode==3) {
            if (atomic_extension.atomic_datatype>7) { reply(request,SemanticReturnCode::AtomicUnsupportedDatatype,0); return; }
            if (atomic_extension.atomic_opcode>12 || atomic_extension.atomic_opcode==11 ||
                atomic_extension.semantic_contol || atomic_extension.rsvd) { reply(request,SemanticReturnCode::AtomicUnsupportedOperation,0); return; }
            const auto width=integer_atomic_width(static_cast<IntegerAtomicDatatype>(atomic_extension.atomic_datatype));
            if (semantic_header.request_length%width || count%width || offset%width) { reply(request,SemanticReturnCode::AtomicUnsupportedSize,0); return; }
            if (semantic_header.buffer_offset%width) { reply(request,SemanticReturnCode::AtomicUnaligned,0); return; }
        }
        if (offset>semantic_header.request_length || count>semantic_header.request_length-offset ||
            (!semantic_header.som && count!=semantic_header.diff.som_false.payload_length) ||
            (semantic_header.eom && offset+count!=semantic_header.request_length) || (semantic_header.opcode==0 && semantic_header.request_length)) {
            reply(request,SemanticReturnCode::UnsupportedSize,0); return;
        }
        const MessageKey key{request.source_fep,request.PDCID,semantic_header.job_id,semantic_header.initiator,
            semantic_header.msg_id,request.connection_start_psn};
        try {
            auto found=incoming_.find(key);
            if (found==incoming_.end()) {
                if (incoming_.size()>=4096) { reply(request,SemanticReturnCode::Undeliverable,0); return; }
                Incoming incoming{static_cast<uint8_t>(semantic_header.opcode),static_cast<uint32_t>(semantic_header.request_length),semantic_header.match_bits,semantic_header.buffer_offset,
                                  selected.absolute_pid,0};
                incoming.resource_index=selected.resource_index; incoming.wire_pid=semantic_header.PIDonFEP;
                incoming.relative_addressing=semantic_header.rel;
                if (semantic_header.opcode==1) memory_.authorize(semantic_header.job_id,selected.absolute_pid,semantic_header.match_bits,
                    semantic_header.buffer_offset,semantic_header.request_length,Access::Write,selected.resource_index);
                else if (semantic_header.opcode==3) {
                    const auto& region=memory_.authorize(semantic_header.job_id,selected.absolute_pid,semantic_header.match_bits,
                        semantic_header.buffer_offset,semantic_header.request_length,Access::Atomic,selected.resource_index);
                    if ((region.permissions&3u)!=3u) { reply(request,SemanticReturnCode::OperationViolation,0); return; }
                    incoming.atomic_operation=atomic_extension.atomic_opcode;
                    incoming.atomic_datatype=atomic_extension.atomic_datatype;
                }
                else if (semantic_header.opcode==5) {
                    auto posted=std::find_if(posted_.begin(),posted_.end(),[&](const Posted& posted_receive) {
                        return (!semantic_header.rel || posted_receive.job==semantic_header.job_id) && posted_receive.pid==selected.absolute_pid &&
                            posted_receive.resource_index==selected.resource_index;
                    });
                    if (posted==posted_.end()) { reply(request,SemanticReturnCode::NoMatch,0); return; }
                    if (posted->capacity<semantic_header.request_length) { reply(request,SemanticReturnCode::UnsupportedSize,0); return; }
                    memory_.authorize(semantic_header.job_id,posted->pid,posted->key,posted->offset,semantic_header.request_length,
                        Access::Write,selected.resource_index);
                    incoming.key=posted->key; incoming.base=posted->offset; incoming.context=posted->context;
                    posted_.erase(posted);
                }
                incoming.has_immediate=semantic_header.hd;
                found=incoming_.emplace(key,std::move(incoming)).first;
            }
            auto& message=found->second;
            if (message.pid!=selected.absolute_pid || message.resource_index!=selected.resource_index ||
                message.wire_pid!=semantic_header.PIDonFEP || message.relative_addressing!=bool(semantic_header.rel)) {
                reply(request,SemanticReturnCode::OperationViolation,0); return;
            }
            if (message.opcode!=semantic_header.opcode || message.total!=semantic_header.request_length) { reply(request,SemanticReturnCode::OperationViolation,0); return; }
            if ((semantic_header.opcode==1 || semantic_header.opcode==3) &&
                (message.key!=semantic_header.match_bits || message.base!=semantic_header.buffer_offset || message.has_immediate!=bool(semantic_header.hd))) {
                reply(request,SemanticReturnCode::OperationViolation,0); return;
            }
            if (semantic_header.opcode==3 && (message.atomic_operation!=atomic_extension.atomic_opcode ||
                message.atomic_datatype!=atomic_extension.atomic_datatype)) { reply(request,SemanticReturnCode::OperationViolation,0); return; }
            if (semantic_header.som && semantic_header.hd) message.immediate_data=semantic_header.diff.som_true.header_data;
            if (message.completed) { reply(request,SemanticReturnCode::Ok,message.total); return; }
            auto position=message.segments.lower_bound(offset);
            if (position!=message.segments.end() && position->first==offset && position->second==count) return;
            if ((position!=message.segments.end() && offset+count>position->first) ||
                (position!=message.segments.begin() && std::prev(position)->first+std::prev(position)->second>offset)) {
                reply(request,SemanticReturnCode::OperationViolation,0); return;
            }
            if (semantic_header.opcode==3) {
                auto operands=request.pkt.payload;
                convert_integer_atomic_byte_order(operands,static_cast<IntegerAtomicDatatype>(message.atomic_datatype));
                memory_.atomic_elements(semantic_header.job_id,message.pid,message.key,Runtime::add_time(message.base,offset),
                    static_cast<IntegerAtomicOperation>(message.atomic_operation),
                    static_cast<IntegerAtomicDatatype>(message.atomic_datatype),operands,message.resource_index);
            } else if (semantic_header.opcode!=0) memory_.write(semantic_header.job_id,message.pid,message.key,
                Runtime::add_time(message.base,offset),request.pkt.payload,message.resource_index);
            message.segments.emplace(offset,count); message.received+=count;
            if (message.received==message.total) {
                message.completed=true;
                message.completion_psn=request.orig_psn;
                if (semantic_header.opcode==5) completions_.push_back({0,message.context,CompletionStatus::Success,message.total,1,true});
                if (semantic_header.opcode==1 && message.immediate_data)
                    completions_.push_back({0,0,CompletionStatus::Success,message.total,1,true,message.immediate_data});
                trace_.record(node_,"memory_delivered",message.total);
                reply(request,SemanticReturnCode::Ok,message.total);
            } else reply(request,SemanticReturnCode::Ok,0,false);
        } catch (const MemoryAccessError& error) { reply(request,memory_code(error.code),0); }
    }
    void receive_datagram(const PDC_SES_req& request) {
        if (request.pkt.bth_type!=Standard_Header) return;
        const auto& header=request.pkt.bth_header.Standard_Header;
        // §3.4.2.13–14: one packet, DATAGRAM_SEND only, message ID zero.
        // No responses or deduplication are provided for unreliable delivery.
        if (header.opcode!=7 || header.version || header.msg_id || header.dc ||
            !header.som || !header.eom || header.hd || header.ie ||
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
            memory_.write(header.job_id,posted->pid,posted->key,posted->offset,request.pkt.payload,selected.resource_index);
            completions_.push_back({0,posted->context,CompletionStatus::Success,
                static_cast<uint32_t>(request.pkt.payload.size()),0,true});
            posted_.erase(posted);
        } catch (const MemoryAccessError&) {
            // Unreliable receive errors are local drops, never ACK/NACKs.
        }
    }
};
} // namespace UET::SES
