#pragma once
#include "MemoryRegistry.hpp"
#include "../Runtime/PdsHost.hpp"
#include <deque>
#include <tuple>

namespace UET::SES {

enum class OperationType : uint8_t { Noop=0, Write=1, Read=2, Atomic=3, Send=5 };
enum class CompletionStatus { Success, Unsupported, InvalidRequest, RemoteError, Timeout, Cancelled, ResourceExhausted };
struct Operation {
    OperationType type = OperationType::Send;
    uint32_t peer = 0;
    uint32_t job = 1;
    uint16_t target_pid = 1;
    uint16_t target_resource = 1;
    uint64_t remote_key = 0;
    uint64_t remote_offset = 0;
    uint64_t context = 0;
    std::vector<uint8_t> payload;
};
struct Completion {
    uint64_t operation;
    uint64_t context;
    CompletionStatus status;
    uint32_t length;
    uint8_t remote_code;
    bool receive;
};
struct EndpointCapabilities {
    bool noop=true, send=true, write=true;
    bool read=false, atomic=false, libfabric=false;
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
        if (operation.type!=OperationType::Noop && operation.type!=OperationType::Send && operation.type!=OperationType::Write) {
            complete_local(CompletionStatus::Unsupported); return id;
        }
        if (!operation.peer || !memory_.has_job(operation.job) || operation.target_pid>0xfff || operation.target_resource>0xfff ||
            operation.payload.size()>UINT32_MAX || (operation.type==OperationType::Noop && !operation.payload.empty())) {
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
                const auto count=std::min(mtu_,operation.payload.size()-offset);
                SES_PDS_req request{};
                request.src_fep=node_; request.dst_fep=operation.peer; request.mode=ROD;
                request.next_hdr=UET_HDR_REQUEST_STD; request.rod_context=1; request.lock_pdc=true;
                request.tx_pkt_handle=message; request.pkt.bth_type=Standard_Header;
                auto& h=request.pkt.bth_header.Standard_Header;
                h.opcode=static_cast<uint8_t>(operation.type); h.version=0;
                h.som=offset==0; h.eom=offset+count==operation.payload.size(); h.dc=1; h.rel=1;
                h.msg_id=message; h.job_id=operation.job; h.PIDonFEP=operation.target_pid;
                h.resource_index=operation.target_resource; h.buffer_offset=operation.remote_offset;
                h.initiator=node_; h.match_bits=operation.remote_key;
                h.request_length=operation.payload.size();
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
    static uint8_t memory_code(MemoryError error) {
        switch(error) {
        case MemoryError::WrongJob: return 0x1b;
        case MemoryError::WrongEndpoint: return 0x1a;
        case MemoryError::InvalidKey: return 0x1c;
        case MemoryError::Permission: return 0x17;
        case MemoryError::Bounds: return 0x1d;
        case MemoryError::Alignment: return 0x12;
        }
        return 0x20;
    }
    void receive(const PDC_SES_req& request) {
        if (request.pkt.bth_type!=Standard_Header) { reply(request,0x06,0); return; }
        const auto& h=request.pkt.bth_header.Standard_Header;
        if (!memory_.has_job(h.job_id)) { reply(request,0x1b,0); return; }
        if (h.PIDonFEP!=1 || h.resource_index!=1 || h.ri_generation) { reply(request,0x1a,0); return; }
        if (h.version || h.ie || h.hd || !h.rel || (h.opcode!=0 && h.opcode!=1 && h.opcode!=5)) {
            reply(request,0x06,0); return;
        }
        const auto offset=h.som?0:h.diff.som_false.message_offset;
        const auto count=request.pkt.payload.size();
        if (offset>h.request_length || count>h.request_length-offset ||
            (!h.som && count!=h.diff.som_false.payload_length) ||
            (h.eom && offset+count!=h.request_length) || (h.opcode==0 && h.request_length)) {
            reply(request,0x07,0); return;
        }
        const MessageKey key{request.source_fep,request.PDCID,h.job_id,h.initiator,h.msg_id};
        try {
            auto found=incoming_.find(key);
            if (found==incoming_.end()) {
                if (incoming_.size()>=4096) { reply(request,0x1f,0); return; }
                Incoming incoming{static_cast<uint8_t>(h.opcode),static_cast<uint32_t>(h.request_length),h.match_bits,h.buffer_offset,
                                  static_cast<uint16_t>(h.PIDonFEP),0};
                if (h.opcode==1) memory_.authorize(h.job_id,h.PIDonFEP,h.match_bits,h.buffer_offset,h.request_length,Access::Write);
                else if (h.opcode==5) {
                    auto posted=std::find_if(posted_.begin(),posted_.end(),[&](const Posted& p) { return p.job==h.job_id && p.pid==h.PIDonFEP; });
                    if (posted==posted_.end()) { reply(request,0x05,0); return; }
                    if (posted->capacity<h.request_length) { reply(request,0x22,0); return; }
                    memory_.authorize(posted->job,posted->pid,posted->key,posted->offset,h.request_length,Access::Write);
                    incoming.key=posted->key; incoming.base=posted->offset; incoming.context=posted->context;
                    posted_.erase(posted);
                }
                found=incoming_.emplace(key,std::move(incoming)).first;
            }
            auto& message=found->second;
            if (message.opcode!=h.opcode || message.total!=h.request_length) { reply(request,0x18,0); return; }
            if (h.opcode==1 && (message.key!=h.match_bits || message.base!=h.buffer_offset)) { reply(request,0x18,0); return; }
            if (message.completed) { reply(request,1,message.total); return; }
            auto position=message.segments.lower_bound(offset);
            if (position!=message.segments.end() && position->first==offset && position->second==count) return;
            if ((position!=message.segments.end() && offset+count>position->first) ||
                (position!=message.segments.begin() && std::prev(position)->first+std::prev(position)->second>offset)) {
                reply(request,0x18,0); return;
            }
            if (h.opcode!=0) memory_.write(h.job_id,message.pid,message.key,Runtime::add_time(message.base,offset),request.pkt.payload);
            message.segments.emplace(offset,count); message.received+=count;
            if (message.received==message.total) {
                message.completed=true;
                if (h.opcode==5) completions_.push_back({0,message.context,CompletionStatus::Success,message.total,1,true});
                trace_.record(node_,"memory_delivered",message.total);
                reply(request,1,message.total);
            } else reply(request,1,0,false);
        } catch (const MemoryAccessError& error) { reply(request,memory_code(error.code),0); }
    }
};
} // namespace UET::SES
