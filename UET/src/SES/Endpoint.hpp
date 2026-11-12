#pragma once
#include "MemoryRegistry.hpp"
#include "SemanticReturnCode.hpp"
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
};
struct Completion {
    uint64_t operation;
    uint64_t context;
    CompletionStatus status;
    uint32_t length;
    uint8_t remote_code;
    bool receive;
    std::optional<uint64_t> immediate_data;
};
struct EndpointCapabilities {
    bool noop=true, send=true, write=true;
    bool datagram_send=true;
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
             Runtime::Time timeout=100*Runtime::kMillisecond)
        : node_(node), host_(host), loop_(loop), trace_(trace), mtu_(payload_mtu), timeout_(timeout) {
        if (!mtu_ || mtu_>8192 || !timeout_) throw std::invalid_argument("invalid SES configuration");
        host_.set_request_handler([this](const PDC_SES_req& request) { receive(request); });
        host_.set_response_handler([this](const PDC_SES_rsp& response) { respond(response); });
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
            if (!pending_.count(next_message_)) { message=next_message_; break; }
        }
        if (!message) { complete_local(CompletionStatus::ResourceExhausted); return id; }
        Pending pending{id,operation.context,static_cast<uint32_t>(operation.payload.size()),0,operation.peer,operation.job};
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
                auto& h=request.pkt.bth_header.Standard_Header;
                h.opcode=static_cast<uint8_t>(operation.type); h.version=0;
                h.som=offset==0; h.eom=offset+count==operation.payload.size(); h.dc=!is_datagram; h.rel=1;
                h.msg_id=is_datagram?0:message; h.job_id=operation.job; h.PIDonFEP=operation.target_pid;
                h.resource_index=operation.target_resource; h.buffer_offset=operation.remote_offset;
                h.initiator=node_; h.match_bits=operation.remote_key;
                h.request_length=operation.payload.size();
                if (operation.immediate_data) {
                    h.hd=1;
                    if (!offset) h.diff.som_true.header_data=*operation.immediate_data;
                }
                if (is_atomic) {
                    request.pkt.eth_type=Atomic_Operation_Extension_Header;
                    auto& extension=request.pkt.eth_header.Atomic_Operation_Extension_Header;
                    extension.atomic_opcode=static_cast<uint8_t>(operation.atomic_operation);
                    extension.atomic_datatype=static_cast<uint8_t>(operation.atomic_datatype);
                }
                if (offset) { h.diff.som_false.payload_length=count; h.diff.som_false.message_offset=offset; }
                request.pkt.payload.assign(operation.payload.begin()+offset,operation.payload.begin()+offset+count);
                request.pkt_len=static_cast<uint16_t>(44+count);
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
                       uint32_t capacity, uint64_t context=0) {
        if (closed_) throw std::logic_error("endpoint closed");
        memory_.authorize(job,pid,key,offset,capacity,Access::Write);
        if (posted_.size()>=4096) throw std::runtime_error("receive queue full");
        posted_.push_back({job,pid,key,offset,capacity,context});
    }
    bool poll_completion(Completion& completion) {
        if (completions_.empty()) return false;
        completion=completions_.front(); completions_.pop_front(); return true;
    }
    size_t pending() const { return pending_.size(); }
    void close() {
        if (closed_) return;
        closed_=true; lifetime_.reset();
        host_.set_request_handler({}); host_.set_response_handler({});
        host_.set_datagram_transmit_handler({});
        while (!pending_.empty()) finish(pending_.begin()->first,CompletionStatus::Cancelled,0,0);
        incoming_.clear(); posted_.clear();
    }
private:
    struct Pending { uint64_t id,context; uint32_t length; Runtime::TimerId timer; uint32_t peer,job; };
    struct Posted { uint32_t job; uint16_t pid; uint64_t key,offset; uint32_t capacity; uint64_t context; };
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
    };
    using MessageKey=std::tuple<uint32_t,uint16_t,uint32_t,uint32_t,uint16_t>;
    uint32_t node_;
    Runtime::PdsHost& host_;
    Runtime::EventLoop& loop_;
    Runtime::Trace& trace_;
    size_t mtu_;
    Runtime::Time timeout_;
    MemoryRegistry memory_;
    EndpointCapabilities capabilities_;
    std::shared_ptr<int> lifetime_=std::make_shared<int>(0);
    bool closed_=false;
    uint64_t next_operation_=0;
    uint16_t next_message_=0;
    std::map<uint16_t,Pending> pending_;
    std::deque<Posted> posted_;
    std::map<MessageKey,Incoming> incoming_;
    std::deque<Completion> completions_;

    void finish(uint16_t message, CompletionStatus status, uint32_t length, uint8_t code) {
        const auto it=pending_.find(message);
        if (it==pending_.end()) return;
        loop_.cancel(it->second.timer);
        completions_.push_back({it->second.id,it->second.context,status,length,code,false});
        trace_.record(node_,"operation_complete",it->second.id);
        pending_.erase(it);
    }
    void respond(const PDC_SES_rsp& response) {
        if (response.pkt.bth_type!=Semantic_Response_Header) return;
        const auto& h=response.pkt.bth_header.Semantic_Response_Header;
        const auto it=pending_.find(h.message_id);
        if (it==pending_.end()) return;
        if (response.source_fep!=it->second.peer || h.job_id!=it->second.job || h.version) return;
        finish(h.message_id,h.return_code==1?CompletionStatus::Success:CompletionStatus::RemoteError,h.modified_length,h.return_code);
    }
    void reply(const PDC_SES_req& request, uint8_t code, uint32_t length, bool semantic=true) {
        SES_PDS_rsp response{}; response.PDCID=request.PDCID;
        response.rx_pkt_handle=request.rx_pkt_handle; response.rsp_len=semantic?12:0;
        response.gtd_del=semantic;
        response.rsp.bth_type=Semantic_Response_Header;
        auto& h=response.rsp.bth_header.Semantic_Response_Header;
        h.opcode=1; h.version=0; h.return_code=code;
        h.job_id=request.pkt.bth_header.Standard_Header.job_id;
        h.message_id=request.pkt.bth_header.Standard_Header.msg_id; h.modified_length=length;
        if (!host_.manager().pushSESResponse(response)) throw std::runtime_error("PDS rejected semantic response");
        host_.wake();
    }
    void reply(const PDC_SES_req& request,SemanticReturnCode code,uint32_t length,bool semantic=true) {
        reply(request,static_cast<uint8_t>(code),length,semantic);
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
        const auto& h=request.pkt.bth_header.Standard_Header;
        if (!memory_.has_job(h.job_id)) { reply(request,SemanticReturnCode::BadJob,0); return; }
        if (h.PIDonFEP!=1) { reply(request,SemanticReturnCode::BadPid,0); return; }
        if (h.resource_index!=1) { reply(request,SemanticReturnCode::BadIndex,0); return; }
        if (h.ri_generation) { reply(request,SemanticReturnCode::BadGeneration,0); return; }
        if (h.version || h.ie || (h.hd && h.opcode!=1) || !h.rel ||
            (h.opcode!=0 && h.opcode!=1 && h.opcode!=3 && h.opcode!=5)) {
            reply(request,SemanticReturnCode::UnsupportedOperation,0); return;
        }
        const auto offset=h.som?0:h.diff.som_false.message_offset;
        const auto count=request.pkt.payload.size();
        const auto& atomic_extension=request.pkt.eth_header.Atomic_Operation_Extension_Header;
        if (h.opcode==3) {
            if (atomic_extension.atomic_datatype>7) { reply(request,SemanticReturnCode::AtomicUnsupportedDatatype,0); return; }
            if (atomic_extension.atomic_opcode>12 || atomic_extension.atomic_opcode==11 ||
                atomic_extension.semantic_contol || atomic_extension.rsvd) { reply(request,SemanticReturnCode::AtomicUnsupportedOperation,0); return; }
            const auto width=integer_atomic_width(static_cast<IntegerAtomicDatatype>(atomic_extension.atomic_datatype));
            if (h.request_length%width || count%width || offset%width) { reply(request,SemanticReturnCode::AtomicUnsupportedSize,0); return; }
            if (h.buffer_offset%width) { reply(request,SemanticReturnCode::AtomicUnaligned,0); return; }
        }
        if (offset>h.request_length || count>h.request_length-offset ||
            (!h.som && count!=h.diff.som_false.payload_length) ||
            (h.eom && offset+count!=h.request_length) || (h.opcode==0 && h.request_length)) {
            reply(request,SemanticReturnCode::UnsupportedSize,0); return;
        }
        const MessageKey key{request.source_fep,request.PDCID,h.job_id,h.initiator,h.msg_id};
        try {
            auto found=incoming_.find(key);
            if (found==incoming_.end()) {
                if (incoming_.size()>=4096) { reply(request,SemanticReturnCode::Undeliverable,0); return; }
                Incoming incoming{static_cast<uint8_t>(h.opcode),static_cast<uint32_t>(h.request_length),h.match_bits,h.buffer_offset,
                                  static_cast<uint16_t>(h.PIDonFEP),0};
                if (h.opcode==1) memory_.authorize(h.job_id,h.PIDonFEP,h.match_bits,h.buffer_offset,h.request_length,Access::Write);
                else if (h.opcode==3) {
                    const auto& region=memory_.authorize(h.job_id,h.PIDonFEP,h.match_bits,h.buffer_offset,h.request_length,Access::Atomic);
                    if ((region.permissions&3u)!=3u) { reply(request,SemanticReturnCode::OperationViolation,0); return; }
                    incoming.atomic_operation=atomic_extension.atomic_opcode;
                    incoming.atomic_datatype=atomic_extension.atomic_datatype;
                }
                else if (h.opcode==5) {
                    auto posted=std::find_if(posted_.begin(),posted_.end(),[&](const Posted& p) { return p.job==h.job_id && p.pid==h.PIDonFEP; });
                    if (posted==posted_.end()) { reply(request,SemanticReturnCode::NoMatch,0); return; }
                    if (posted->capacity<h.request_length) { reply(request,SemanticReturnCode::UnsupportedSize,0); return; }
                    memory_.authorize(posted->job,posted->pid,posted->key,posted->offset,h.request_length,Access::Write);
                    incoming.key=posted->key; incoming.base=posted->offset; incoming.context=posted->context;
                    posted_.erase(posted);
                }
                incoming.has_immediate=h.hd;
                found=incoming_.emplace(key,std::move(incoming)).first;
            }
            auto& message=found->second;
            if (message.opcode!=h.opcode || message.total!=h.request_length) { reply(request,SemanticReturnCode::OperationViolation,0); return; }
            if ((h.opcode==1 || h.opcode==3) &&
                (message.key!=h.match_bits || message.base!=h.buffer_offset || message.has_immediate!=bool(h.hd))) {
                reply(request,SemanticReturnCode::OperationViolation,0); return;
            }
            if (h.opcode==3 && (message.atomic_operation!=atomic_extension.atomic_opcode ||
                message.atomic_datatype!=atomic_extension.atomic_datatype)) { reply(request,SemanticReturnCode::OperationViolation,0); return; }
            if (h.som && h.hd) message.immediate_data=h.diff.som_true.header_data;
            if (message.completed) { reply(request,SemanticReturnCode::Ok,message.total); return; }
            auto position=message.segments.lower_bound(offset);
            if (position!=message.segments.end() && position->first==offset && position->second==count) return;
            if ((position!=message.segments.end() && offset+count>position->first) ||
                (position!=message.segments.begin() && std::prev(position)->first+std::prev(position)->second>offset)) {
                reply(request,SemanticReturnCode::OperationViolation,0); return;
            }
            if (h.opcode==3) {
                memory_.atomic_elements(h.job_id,message.pid,message.key,Runtime::add_time(message.base,offset),
                    static_cast<IntegerAtomicOperation>(message.atomic_operation),
                    static_cast<IntegerAtomicDatatype>(message.atomic_datatype),request.pkt.payload);
            } else if (h.opcode!=0) memory_.write(h.job_id,message.pid,message.key,Runtime::add_time(message.base,offset),request.pkt.payload);
            message.segments.emplace(offset,count); message.received+=count;
            if (message.received==message.total) {
                message.completed=true;
                if (h.opcode==5) completions_.push_back({0,message.context,CompletionStatus::Success,message.total,1,true});
                if (h.opcode==1 && message.immediate_data)
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
            !header.som || !header.eom || header.hd || header.ie || !header.rel ||
            header.PIDonFEP!=1 || header.resource_index!=1 || header.ri_generation ||
            header.request_length!=request.pkt.payload.size() || !memory_.has_job(header.job_id)) return;
        auto posted=std::find_if(posted_.begin(),posted_.end(),[&](const Posted& receive) {
            return receive.job==header.job_id && receive.pid==header.PIDonFEP;
        });
        if (posted==posted_.end() || posted->capacity<request.pkt.payload.size()) return;
        try {
            memory_.write(posted->job,posted->pid,posted->key,posted->offset,request.pkt.payload);
            completions_.push_back({0,posted->context,CompletionStatus::Success,
                static_cast<uint32_t>(request.pkt.payload.size()),0,true});
            posted_.erase(posted);
        } catch (const MemoryAccessError&) {
            // Unreliable receive errors are local drops, never ACK/NACKs.
        }
    }
};
} // namespace UET::SES
