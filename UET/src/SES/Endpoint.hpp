#pragma once
#include "MemoryRegistry.hpp"
#include "SemanticReturnCode.hpp"
#include "ResourceDirectory.hpp"
#include "PayloadSource.hpp"
#include "ReadCoverage.hpp"
#include "ByteCoverage.hpp"
#include "RendezvousMemory.hpp"
#include "SynchronizationState.hpp"
#include "../PDS/DefaultSemanticResponse.hpp"
#include "../Runtime/PdsHost.hpp"
#include <deque>
#include <tuple>
#include <optional>

namespace UET::SES {

enum class OperationType : uint8_t { Noop=0, Write=1, Read=2, Atomic=3, FetchingAtomic=4, Send=5, RendezvousSend=6, DatagramSend=7, DeferrableSend=8, TaggedSend=9, RendezvousTaggedSend=10, DeferrableTaggedSend=11, SynchronizedWrite=16, SynchronizedAtomic=17 };
enum class CompletionStatus { Success, LocalSuccess, LocalError, Unsupported, InvalidRequest, RemoteError, Timeout, Cancelled, ResourceExhausted, Truncated };
// A local registered destination for returned READ/atomic data. This descriptor never goes
// on the wire; the peer supplies only checked data, never a local host pointer.
struct ReadResultBuffer {
    uint64_t key=0,offset=0;
    uint32_t capacity=0;
    uint16_t pid=1,resource_index=1;
};
// Both operations use the same local registration descriptor. Their wire
// response/recovery policies remain different (§3.5.17).
using AtomicResultBuffer=ReadResultBuffer;
// Trusted local source registration. The advertised rendezvous alias is a
// separate, read-only registration bound to this exact original identity.
struct RendezvousBuffer {
    uint64_t key=0,offset=0;
    uint32_t length=0;
    uint16_t pid=1,resource_index=1;
    uint8_t generation=0;
};
// This handle is local authority, not a received identifier. Its weak identity
// prevents attaching an old group to a replacement or unrelated Endpoint.
class SynchronizedGroup {
public:
    uint16_t wire_identifier() const { return wire_group_; }
    uint16_t message_count() const { return message_count_; }
private:
    friend class Endpoint;
    SynchronizedGroup(uint64_t owner,uint16_t wire_group,uint16_t message_count,uint32_t peer,uint32_t job,
                      std::weak_ptr<int> authority)
        :owner_(owner),wire_group_(wire_group),message_count_(message_count),peer_(peer),job_(job),authority_(authority) {}
    uint64_t owner_;
    uint16_t wire_group_,message_count_;
    uint32_t peer_,job_;
    std::weak_ptr<int> authority_;
};
enum class RequestHeaderFormat { Standard, Small, Medium };
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
    uint64_t tag=0; // Tagged SEND match bits; an RMA key remains a separate API value.
    std::optional<uint32_t> peer_initiator_id; // Expected reverse RTR/READ rank; defaults to peer node proxy.
    std::optional<uint32_t> initiator_id; // Job-level rank (§3.4.2.3.4); default node ID is simulator policy.
    std::vector<uint8_t> payload;
    IntegerAtomicOperation atomic_operation = IntegerAtomicOperation::Sum;
    IntegerAtomicDatatype atomic_datatype = IntegerAtomicDatatype::Uint64;
    std::optional<uint64_t> immediate_data; // Remote CQ data: WRITE, SEND or DATAGRAM_SEND.
    bool relative_addressing=true;
    uint8_t target_generation=0;
    std::shared_ptr<const PayloadSource> payload_source; // Optional lazy bytes; cannot accompany a nonempty payload vector.
    uint32_t read_length=0;
    std::optional<ReadResultBuffer> read_result;
    std::vector<uint8_t> atomic_compare; // One native little-endian compare/mask element, for dual-operand fetching only.
    std::optional<AtomicResultBuffer> atomic_result;
    std::optional<RendezvousBuffer> rendezvous_source;
    uint32_t rendezvous_eager_length=0;
    bool zero_length_atomic=false; // §3.4.2.12: explicit zero-byte put/get, distinct from READ's ignored input operand.
    std::shared_ptr<const SynchronizedGroup> synchronization;
    // §3.4.3.2: explicit single-packet format selection. Standard stays the
    // default; selecting a format does not expand its supported operations.
    RequestHeaderFormat header_format=RequestHeaderFormat::Standard;
};
// Ignore bits apply to the tag only. An omitted initiator matches any source;
// a specified rank is interpreted inside the posting's JobID, even with absolute addressing.
struct TaggedReceiveMatch {
    uint64_t tag=0,ignore=0;
    std::optional<uint32_t> initiator;
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
    std::optional<uint64_t> tag; // Actual received tag, including bits ignored by the posting.
};
struct EndpointCapabilities {
    bool noop=true, send=true, write=true;
    bool optimized_small_write=true,optimized_medium_write=true,optimized_medium_send=true;
    bool datagram_send=true;
    bool rudi_write=true,rudi_read=true; // Idempotent-safe registered memory; no target CQ or PDC.
    bool relative_addressing=true, absolute_addressing=true;
    bool read=true, atomic=true, libfabric=false, write_immediate=true;
    bool rendezvous_send=true,rendezvous_tagged_send=true; // Native registered-buffer transactions; no Profile claim.
    bool fetching_atomic=true, compare_atomic=true, tagged_send=true, directed_receive=true;
    bool synchronized_write=true,synchronized_integer_atomic=true; // Native bounded groups; no Profile claim.
    uint32_t max_read_length=UINT32_MAX;
    bool send_immediate=true, datagram_immediate=true, deferrable_send_as_send=true;
    bool deferrable_send=true, deferrable_tagged_send=true,deferrable_header_capture=false;
    bool deferrable_tagged_send_as_send=true; // Target compatibility; not source deferral/RTR support.
    std::vector<IntegerAtomicDatatype> atomic_datatypes={IntegerAtomicDatatype::Int8,IntegerAtomicDatatype::Uint8,
        IntegerAtomicDatatype::Int16,IntegerAtomicDatatype::Uint16,IntegerAtomicDatatype::Int32,
        IntegerAtomicDatatype::Uint32,IntegerAtomicDatatype::Int64,IntegerAtomicDatatype::Uint64};
    std::vector<IntegerAtomicDatatype> fetching_atomic_datatypes={IntegerAtomicDatatype::Int8,IntegerAtomicDatatype::Uint8,
        IntegerAtomicDatatype::Int16,IntegerAtomicDatatype::Uint16,IntegerAtomicDatatype::Int32,
        IntegerAtomicDatatype::Uint32,IntegerAtomicDatatype::Int64,IntegerAtomicDatatype::Uint64,
        IntegerAtomicDatatype::Int128,IntegerAtomicDatatype::Uint128};
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
             size_t receive_message_limit=4096,size_t unexpected_buffer_bytes=256*1024,size_t read_response_limit=8,
             size_t read_result_window=8)
        : node_(node), host_(host), loop_(loop), trace_(trace), mtu_(payload_mtu), timeout_(timeout),
          memory_(domain_memory?*domain_memory:private_memory_),submission_window_(submission_window),receive_message_limit_(receive_message_limit),
          unexpected_limit_(unexpected_buffer_bytes),read_response_limit_(read_response_limit),read_result_window_(read_result_window),
          synchronization_ids_(host.services().next_synchronization_group_id),
          synchronized_target_groups_(64,timeout,receive_message_limit) {
        if (!mtu_ || mtu_>8192 || !timeout_ || !submission_window_ || !receive_message_limit_ ||
            !read_response_limit_ || read_response_limit_>UINT16_MAX || !read_result_window_ || read_result_window_>32640)
            throw std::invalid_argument("invalid SES configuration");
        capabilities_.optimized_small_write=capabilities_.optimized_medium_write=capabilities_.optimized_medium_send=host_.services().standard_wire;
        capabilities_.rudi_write=capabilities_.rudi_read=host_.services().standard_wire;
        host_.configure_semantic_payload_mtu(static_cast<uint32_t>(mtu_));
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

    std::shared_ptr<const SynchronizedGroup> begin_synchronized_group(uint32_t peer,uint32_t job,uint16_t messages) {
        if (closed_ || !peer || !messages || !memory_.has_job(job)) throw std::invalid_argument("invalid synchronized group");
        if (next_synchronization_owner_==UINT64_MAX) return {};
        const auto wire_group=synchronization_ids_.allocate();
        if (!wire_group) return {};
        const auto owner=++next_synchronization_owner_;
        auto handle=std::shared_ptr<const SynchronizedGroup>(new SynchronizedGroup(owner,*wire_group,messages,peer,job,lifetime_));
        SynchronizedSourceGroup group; group.handle=handle;
        std::weak_ptr<int> life=lifetime_;
        group.deadline=loop_.after(timeout_,[this,life,owner] {
            if (!life.expired()) abandon_synchronized_group(owner);
        });
        synchronized_source_groups_.emplace(owner,std::move(group));
        return handle;
    }
    size_t retained_synchronized_groups() const { return synchronized_target_groups_.active_groups(); }
    size_t retained_synchronized_members() const { return synchronized_target_groups_.retained_members(); }
    size_t retained_synchronized_actions() const { return synchronized_target_actions_.size(); }
    void configure_synchronized_tracking(size_t maximum_groups=64) {
        if (!maximum_groups || synchronized_target_groups_.active_groups() || synchronized_target_groups_.retained_members())
            throw std::invalid_argument("invalid synchronization group limit/state");
        synchronized_target_groups_=SynchronizationGroups(maximum_groups,timeout_,receive_message_limit_);
    }
    size_t active_synchronized_source_groups() const { return synchronized_source_groups_.size(); }
    bool cancel_synchronized(uint64_t operation) {
        const auto found=synchronized_sources_.find(operation); if (found==synchronized_sources_.end()) return false;
        const auto message=found->second->active_message;
        if (message && pending_.count(message)) finish(message,CompletionStatus::Cancelled,0,0);
        else complete_synchronized_source(operation,CompletionStatus::Cancelled,0,0,0);
        feed_submissions(); return true;
    }

    uint64_t submit(Operation operation) {
        if (closed_) throw std::logic_error("endpoint closed");
        if (next_operation_==UINT64_MAX) throw std::overflow_error("operation ids exhausted");
        const auto application_operation_id=++next_operation_;
        if (operation.type==OperationType::SynchronizedWrite || operation.type==OperationType::SynchronizedAtomic)
            start_synchronized_source(std::move(operation),application_operation_id);
        else if (operation.synchronization)
            completions_.push_back({application_operation_id,operation.context,CompletionStatus::InvalidRequest,0,0,false});
        else if (operation.type==OperationType::RendezvousSend || operation.type==OperationType::RendezvousTaggedSend)
            start_rendezvous_source(std::move(operation),application_operation_id);
        else if (operation.type==OperationType::DeferrableSend || operation.type==OperationType::DeferrableTaggedSend)
            start_deferrable_source(std::move(operation),application_operation_id);
        else submit_message(std::move(operation),application_operation_id);
        return application_operation_id;
    }
private:
    // A user operation and a wire message have different identities. Internal
    // continuations will retain the application's ID while allocating a fresh
    // MID and using the same original SES/PDS submission path.
    uint16_t submit_message(Operation operation,uint64_t application_operation_id,uint32_t deferrable_token=0,uint32_t restart_owner=0,uint64_t rendezvous_owner=0,uint64_t rendezvous_read_owner=0,uint64_t synchronization_owner=0) {
        if (closed_) throw std::logic_error("endpoint closed");
        const auto complete_local=[&](CompletionStatus status) {
            if (synchronization_owner) complete_synchronized_source(synchronization_owner,status,0,0,0);
            else if (rendezvous_read_owner) rendezvous_read_complete(rendezvous_read_owner,status,0,0);
            else if (rendezvous_owner) complete_rendezvous_source(rendezvous_owner,status,0,0);
            else if (restart_owner) fail_deferred_target(restart_owner,status,0);
            else if (deferrable_token) complete_deferrable_source(deferrable_token,status,0,0);
            else completions_.push_back({application_operation_id,operation.context,status,0,0,false});
        };
        if (pending_.size() >= 4096) { complete_local(CompletionStatus::ResourceExhausted); return 0; }
        const bool is_rendezvous=rendezvous_owner!=0;
        const bool is_restart=restart_owner!=0;
        const bool is_datagram=operation.type==OperationType::DatagramSend;
        const bool is_fetching_atomic=operation.type==OperationType::FetchingAtomic;
        const bool is_synchronized_write=operation.type==OperationType::SynchronizedWrite;
        const bool is_atomic=operation.type==OperationType::Atomic || operation.type==OperationType::SynchronizedAtomic || is_fetching_atomic;
        const bool is_read=operation.type==OperationType::Read;
        const bool is_rudi=operation.delivery_mode==RUDI;
        if (is_rudi && (!capabilities_.rudi_write || (operation.type!=OperationType::Write && !is_read) || operation.immediate_data ||
            synchronization_owner || rendezvous_read_owner || !(operation.remote_key&MemoryRegistry::kIdempotentSafe))) {
            complete_local(CompletionStatus::Unsupported); return 0;
        }
        const bool is_deferrable=operation.type==OperationType::DeferrableSend || operation.type==OperationType::DeferrableTaggedSend;
        if (!is_datagram && operation.delivery_mode!=ROD && operation.delivery_mode!=RUD && !is_rudi) {
            complete_local(CompletionStatus::Unsupported); return 0;
        }
        if (operation.type!=OperationType::Noop && operation.type!=OperationType::Send &&
            operation.type!=OperationType::Write && !is_synchronized_write && operation.type!=OperationType::TaggedSend && !is_atomic && !is_datagram && !is_read && !is_restart && !is_rendezvous && !(is_deferrable && deferrable_token)) {
            complete_local(CompletionStatus::Unsupported); return 0;
        }
        if (!is_rendezvous && (operation.rendezvous_source || operation.rendezvous_eager_length)) {
            complete_local(CompletionStatus::InvalidRequest); return 0;
        }
        uint64_t payload_length=operation.payload_source?operation.payload_source->size():operation.payload.size();
        const bool optimized=operation.header_format!=RequestHeaderFormat::Standard;
        if (optimized) {
            const bool small=operation.header_format==RequestHeaderFormat::Small;
            const bool medium=operation.header_format==RequestHeaderFormat::Medium;
            const bool write=operation.type==OperationType::Write;
            const bool send=operation.type==OperationType::Send || operation.type==OperationType::TaggedSend;
            if (!host_.services().standard_wire || (!small && !medium) || operation.delivery_mode==RUDI || is_datagram || payload_length>mtu_ ||
                (operation.type!=OperationType::Noop && !write && !(medium && send)) || (write && operation.immediate_data)) {
                complete_local(CompletionStatus::Unsupported); return 0;
            }
            if (small && write) {
                try { MemoryKeyFormat::validate(operation.remote_key,KeyAssignment::Provider); }
                catch (const std::invalid_argument&) { complete_local(CompletionStatus::InvalidRequest); return 0; }
                if (!(operation.remote_key&MemoryKeyFormat::Optimized)) { complete_local(CompletionStatus::InvalidRequest); return 0; }
            }
        }
        if (operation.zero_length_atomic && (!is_atomic || payload_length || operation.payload_source ||
            (operation.atomic_operation!=IntegerAtomicOperation::Read && operation.atomic_operation!=IntegerAtomicOperation::Write))) {
            complete_local(CompletionStatus::InvalidRequest); return 0;
        }
        if ((!is_read && !is_restart && (operation.read_length || operation.read_result)) ||
            (!is_fetching_atomic && (operation.atomic_result || !operation.atomic_compare.empty())) ||
            (is_read && (payload_length || operation.payload_source || operation.immediate_data))) {
            complete_local(CompletionStatus::InvalidRequest); return 0;
        }
        if (operation.payload_source && !operation.payload.empty()) {
            complete_local(CompletionStatus::InvalidRequest); return 0;
        }
        std::optional<Region> read_registration;
        bool authorized_foreign_rendezvous_job=false;
        if (is_read && (operation.read_length || operation.read_result)) {
            if (!operation.read_result || operation.read_result->capacity<operation.read_length ||
                operation.read_result->pid>0xfff || operation.read_result->resource_index>0xfff) {
                complete_local(CompletionStatus::InvalidRequest); return 0;
            }
            const auto& destination=*operation.read_result;
            try {
                if (rendezvous_read_owner) {
                    const auto owner=rendezvous_targets_.find(rendezvous_read_owner);
                    if (owner==rendezvous_targets_.end() || !owner->second->receive)
                        throw MemoryAccessError(MemoryError::InvalidKey);
                    const auto& receive=*owner->second->receive;
                    if (destination.key!=receive.key || destination.pid!=receive.pid || destination.resource_index!=receive.resource_index)
                        throw MemoryAccessError(MemoryError::InvalidKey);
                    read_registration=memory_.authorize_registration(receive.registration,operation.job,destination.pid,
                        destination.offset,operation.read_length,Access::Write,destination.resource_index);
                    // UE 1.1 §3.4.4.2: an absolute AnyJob posting can accept a
                    // sender's Job without installing that Job locally. Only
                    // this target-owned reverse READ inherits the validated
                    // posting's authority; public submissions still need a
                    // local Job, and the original registration remains pinned.
                    authorized_foreign_rendezvous_job=!owner->second->header.rel &&
                        owner->second->header.job_id==operation.job && read_registration->allow_any_job;
                } else read_registration=memory_.authorize_local(operation.job,destination.pid,destination.key,
                    destination.offset,operation.read_length,Access::Write,destination.resource_index);
            } catch (const MemoryAccessError&) { complete_local(CompletionStatus::LocalError); return 0; }
        }
        size_t atomic_width=1;
        if (is_atomic) {
            if (static_cast<uint8_t>(operation.atomic_datatype)>(is_fetching_atomic?9:7) ||
                static_cast<uint8_t>(operation.atomic_operation)>(is_fetching_atomic?0x13:12) ||
                (!is_fetching_atomic && operation.atomic_operation==IntegerAtomicOperation::Read)) {
                complete_local(CompletionStatus::Unsupported); return 0;
            }
            atomic_width=integer_atomic_width(operation.atomic_datatype);
            if ((!is_fetching_atomic && ((!payload_length && operation.atomic_operation!=IntegerAtomicOperation::Write) || payload_length%atomic_width)) ||
                operation.remote_offset%atomic_width || mtu_<atomic_width) {
                complete_local(CompletionStatus::InvalidRequest); return 0;
            }
        }
        std::optional<Region> atomic_registration;
        if (is_fetching_atomic) {
            const bool dual_operand=dual_operand_atomic(operation.atomic_operation);
            const auto result_length=operation.zero_length_atomic?size_t{0}:atomic_width;
            if (operation.payload_source || operation.immediate_data || (!operation.atomic_result && result_length) ||
                (operation.atomic_result && (operation.atomic_result->capacity<result_length || operation.atomic_result->pid>0xfff ||
                operation.atomic_result->resource_index>0xfff)) || mtu_<(dual_operand?32:atomic_width) ||
                (operation.zero_length_atomic && !operation.atomic_compare.empty())) {
                complete_local(CompletionStatus::InvalidRequest); return 0;
            }
            if (!operation.zero_length_atomic && operation.atomic_operation==IntegerAtomicOperation::Read && operation.payload.empty())
                operation.payload.resize(atomic_width); // Atomic READ still carries one element on the wire.
            try {
                if (!operation.zero_length_atomic) operation.payload=fetching_atomic_wire_operands(operation.payload,operation.atomic_compare,
                    operation.atomic_operation,operation.atomic_datatype);
            } catch (const std::invalid_argument&) { complete_local(CompletionStatus::InvalidRequest); return 0; }
            payload_length=operation.payload.size();
            try {
                if (operation.atomic_result) {
                    const auto& destination=*operation.atomic_result;
                    atomic_registration=memory_.authorize_local(operation.job,destination.pid,destination.key,
                        destination.offset,result_length,Access::Write,destination.resource_index);
                }
            } catch (const MemoryAccessError&) { complete_local(CompletionStatus::LocalError); return 0; }
        }
        if (!operation.peer || (!memory_.has_job(operation.job) && !authorized_foreign_rendezvous_job) || operation.source_pid>0xfff || operation.target_pid>0xfff || operation.target_resource>0xfff ||
            payload_length>UINT32_MAX || (is_datagram && payload_length>mtu_) ||
            (operation.immediate_data && operation.type!=OperationType::Write && !is_synchronized_write && operation.type!=OperationType::Send && operation.type!=OperationType::TaggedSend && !is_datagram && !is_deferrable && !is_rendezvous) ||
            (operation.type==OperationType::Noop && payload_length)) {
            complete_local(CompletionStatus::InvalidRequest); return 0;
        }
        uint16_t message=0;
        for (size_t i=0; i<UINT16_MAX; ++i) {
            if (++next_message_==0) ++next_message_;
            if (!pending_.count(next_message_) && !message_leases_.count(next_message_)) { message=next_message_; break; }
        }
        if (!message) { complete_local(CompletionStatus::ResourceExhausted); return 0; }
        const uint32_t transfer_length=(is_read || is_restart)?operation.read_length:static_cast<uint32_t>(payload_length);
        Pending pending{application_operation_id,operation.context,transfer_length,0,operation.peer,operation.job};
        // Data ACK has no RI-generation field. Preserve the admitted request's
        // generation instead of reporting zero after a nonzero-generation READ
        // or fetching atomic (e.g. following a provider BAD_GENERATION retry).
        pending.returned_generation=operation.target_generation; pending.deferrable_token=deferrable_token;
        pending.restart_owner=restart_owner; pending.rendezvous_owner=rendezvous_owner;
        pending.rendezvous_read_owner=rendezvous_read_owner;
        pending.synchronization_owner=synchronization_owner;
        pending.wire_semantic_format=operation.header_format==RequestHeaderFormat::Small?Optimized_Header:
            operation.header_format==RequestHeaderFormat::Medium?Small_Message_RMA_Header:Standard_Header;
        pending.is_datagram=is_datagram;
        pending.is_rudi=is_rudi;
        pending.is_read=is_read; pending.read_result=operation.read_result;
        pending.read_registration=std::move(read_registration);
        pending.is_fetching_atomic=is_fetching_atomic; pending.atomic_result=operation.atomic_result;
        pending.atomic_registration=std::move(atomic_registration);
        pending.atomic_result_length=operation.zero_length_atomic?0:static_cast<uint32_t>(atomic_width);
        pending_.emplace(message,pending);
        try {
            auto source=operation.payload_source;
            if (!source) source=std::make_shared<VectorPayload>(std::move(operation.payload));
            operation.payload_source.reset();
            sources_.emplace(message,SourceMessage{std::move(operation),std::move(source),
                transfer_length,0,0,false});
            sources_.at(message).deferrable_token=deferrable_token;
            sources_.at(message).restart_owner=restart_owner;
            if (synchronization_owner) synchronized_sources_.at(synchronization_owner)->active_message=message;
            if (rendezvous_read_owner) rendezvous_targets_.at(rendezvous_read_owner)->active_read_message=message;
            if (rendezvous_owner) {
                const auto transaction=rendezvous_sources_.at(rendezvous_owner);
                auto& transfer=sources_.at(message);
                transaction->active_message=message; transfer.rendezvous_owner=rendezvous_owner;
                transfer.rendezvous_total=transaction->total_length;
                auto& extension=transfer.rendezvous_extension;
                extension.eager_length=transaction->eager_length;
                extension.read_PIDonFEP=transaction->original_operation.rendezvous_source->pid;
                extension.read_resource_index=transaction->original_operation.rendezvous_source->resource_index;
                extension.read_ri_generation=transaction->original_operation.rendezvous_source->generation;
                extension.read_offset=0; extension.read_mem_key=transaction->alias_registration.key;
            }
            if (deferrable_token) {
                const auto transaction=deferred_sources_.at(deferrable_token);
                transaction->active_message=message;
                sources_.at(message).restart_tokens=(uint64_t{deferrable_token}<<32)|transaction->target_token;
            }
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
        return message;
    }
public:
    void post_receive(uint32_t job, uint16_t pid, uint64_t key, uint64_t offset,
                       uint32_t capacity, uint64_t context=0,uint16_t resource_index=1,std::optional<uint32_t> initiator={}) {
        post_buffer(job,pid,key,offset,capacity,context,resource_index,{},initiator);
    }
    void post_tagged_receive(uint32_t job,uint16_t pid,uint64_t key,uint64_t offset,uint32_t capacity,
                             TaggedReceiveMatch match,uint64_t context=0,uint16_t resource_index=1) {
        post_buffer(job,pid,key,offset,capacity,context,resource_index,match);
    }
    bool poll_completion(Completion& completion) {
        if (completions_.empty()) return false;
        completion=completions_.front(); completions_.pop_front(); return true;
    }
    size_t pending() const {
        size_t count=deferred_sources_.size()+rendezvous_sources_.size()+synchronized_sources_.size();
        for (const auto& operation:pending_) if (!operation.second.deferrable_token && !operation.second.restart_owner &&
            !operation.second.rendezvous_owner && !operation.second.rendezvous_read_owner && !operation.second.synchronization_owner) ++count;
        return count;
    }
    // Simulator policy: enable bounded, header-only unexpected deferral (J=0).
    // The default remains the interoperable non-deferring target of §3.4.4.6.1.
    void enable_deferrable_capture(size_t header_limit=64,std::optional<uint32_t> initiator={}) {
        if (!header_limit || !deferred_targets_.empty() || !incoming_.empty() || !pending_.empty() || !deferred_sources_.empty()) throw std::invalid_argument("invalid deferrable capture limit/state");
        deferred_header_limit_=header_limit; target_restart_initiator_=initiator.value_or(node_);
        capabilities_.deferrable_header_capture=true;
    }
    size_t captured_deferrable_headers() const { return deferred_targets_.size(); }
    size_t pending_deferrable_sends() const { return deferred_sources_.size(); }
    bool cancel_rendezvous(uint64_t operation) {
        if (!rendezvous_sources_.count(operation)) return false;
        terminate_rendezvous_source(operation,CompletionStatus::Cancelled); return true;
    }
    bool cancel_deferrable(uint64_t operation) {
        for (const auto& entry:deferred_sources_) if (entry.second->operation==operation) {
            terminate_deferrable_source(entry.first,CompletionStatus::Cancelled); return true;
        }
        return false;
    }
    size_t retained_rendezvous_receives() const { return rendezvous_targets_.size()+rendezvous_receive_errors_.size(); }
    void configure_rendezvous(size_t limit=64,std::optional<uint32_t> read_initiator={}) {
        if (!limit || !rendezvous_targets_.empty()) throw std::invalid_argument("invalid rendezvous header limit/state");
        rendezvous_target_limit_=limit; rendezvous_read_initiator_=read_initiator;
    }
    bool cancel_read(uint64_t operation) {
        if (!operation) return false; // ID0 is reserved for private protocol work.
        for (const auto& pending:pending_) if (pending.second.id==operation && pending.second.is_read) {
            // Local cancellation stops further placement, not packets already
            // on the fabric. Their reverse DEFAULTs still drain PDS state.
            finish(pending.first,CompletionStatus::Cancelled,static_cast<uint32_t>(pending.second.read_results.bytes()),0);
            return true;
        }
        return false;
    }
    bool cancel_rudi(uint64_t operation) {
        for (const auto& pending:pending_) if (pending.second.id==operation && pending.second.is_rudi) {
            finish(pending.first,CompletionStatus::Cancelled,static_cast<uint32_t>(pending.second.read_results.bytes()),0);
            return true;
        }
        return false;
    }
    bool transport_pending(uint64_t operation) const {
        if (!operation) return false;
        if (rendezvous_sources_.count(operation)) return true;
        if (synchronized_sources_.count(operation)) return true;
        for (const auto& transaction:deferred_sources_) if (transaction.second->operation==operation) return true;
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
    size_t pending_read_results() const {
        size_t count=0;
        for (const auto& operation:pending_) count+=operation.second.read_requests_awaiting_data.size();
        return count;
    }
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
        while (!deferred_sources_.empty()) complete_deferrable_source(deferred_sources_.begin()->first,CompletionStatus::Cancelled,0,0);
        while (!rendezvous_sources_.empty()) complete_rendezvous_source(rendezvous_sources_.begin()->first,CompletionStatus::Cancelled,0,0);
        while (!synchronized_source_groups_.empty()) abandon_synchronized_group(synchronized_source_groups_.begin()->first);
        for (const auto& timer:synchronized_target_timers_) loop_.cancel(timer.second);
        synchronized_target_timers_.clear(); synchronized_target_actions_.clear();
        synchronized_target_groups_=SynchronizationGroups{};
        while (!deferred_targets_.empty()) fail_deferred_target(deferred_targets_.begin()->first,CompletionStatus::Cancelled,0);
        while (!rendezvous_targets_.empty()) fail_rendezvous_target(rendezvous_targets_.begin()->first,CompletionStatus::Cancelled,0,0);
        while (!rendezvous_receive_errors_.empty()) complete_deferred_rendezvous_error(rendezvous_receive_errors_.begin()->first);
        incoming_.clear(); rendezvous_order_.clear(); deferred_order_.clear(); unexpected_order_.clear(); unexpected_bytes_=0; disabled_generations_.clear();
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
        bool started=false; // Packet history, independent of byte offset for zero-byte markers.
        uint32_t deferrable_token=0,restart_owner=0;
        uint64_t restart_tokens=0;
        uint64_t rendezvous_owner=0;
        uint32_t rendezvous_total=0;
        SES_Rendezvous_Extension_Header rendezvous_extension{};
    };
    struct Pending {
        uint64_t id,context; uint32_t length; Runtime::TimerId timer; uint32_t peer,job;
        uint16_t local_pdc=UINT16_MAX;
        uint32_t connection_start_psn=0,last_transmitted_psn=0;
        SES_BTH_header_type wire_semantic_format=Standard_Header;
        bool is_datagram=false;
        bool is_rudi=false,rudi_all_submitted=false;
        std::set<uint32_t> awaiting_rudi_responses; // Locally unique packet IDs, not PSNs.
        bool is_read=false;
        bool is_fetching_atomic=false,atomic_result_placed=false;
        uint32_t atomic_result_length=0;
        std::optional<AtomicResultBuffer> atomic_result;
        std::optional<Region> atomic_registration;
        std::optional<ReadResultBuffer> read_result;
        std::optional<Region> read_registration;
        ReadCoverage read_results;
        std::set<uint32_t> read_requests_awaiting_data;
        bool end_of_message_transmitted=false;
        // Only outstanding PSNs are retained, so a multi-gigabyte stream
        // consumes the PDS window's space rather than one entry per fragment.
        std::set<uint32_t> awaiting_semantic_responses;
        uint32_t completed_length=0;
        uint8_t returned_generation=0;
        uint32_t deferrable_token=0,restart_owner=0;
        uint64_t rendezvous_owner=0,rendezvous_read_owner=0;
        uint64_t synchronization_owner=0;
    };
    using ConnectionKey=std::tuple<uint32_t,uint16_t,uint32_t>;
    struct RestartRequest {
        uint32_t target_token,offset,length;
        bool operator==(const RestartRequest& other) const {
            return target_token==other.target_token && offset==other.offset && length==other.length;
        }
    };
    struct DeferredSource {
        enum class Phase { Sending, WaitingForRestart, Backoff };
        Operation original;
        std::shared_ptr<const PayloadSource> payload;
        uint64_t operation;
        uint32_t token,total,offset=0,length=0,target_token=0;
        uint16_t active_message=0,retiring_message=0;
        Phase phase=Phase::Sending;
        bool first_response_seen=false,deferred=false,restarted=false,backoff_ready=false;
        uint8_t success_opcode=0,success_list=0;
        uint32_t retries=0;
        Runtime::TimerId deadline=0,backoff=0;
        std::optional<RestartRequest> pending_restart,last_restart;
        std::set<ConnectionKey> connections;
    };
    struct MessageLease {
        ConnectionKey connection;
        uint32_t last_psn;
        bool end_of_message_transmitted;
        uint64_t operation;
        // A peer may accept READ before sending its data. Forward Clear alone
        // cannot retire a failed READ MID while unique return data is late.
        bool requires_connection_retirement=false;
        bool connection_close_requested=false;
    };
    struct Posted {
        uint32_t job; uint16_t pid; uint64_t key,offset; uint32_t capacity;
        uint64_t context; uint16_t resource_index; Region registration;
        std::optional<TaggedReceiveMatch> match;
        std::optional<uint32_t> initiator; // Untagged/UUD source rank; tagged criteria carry their own rank.
    };
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
        uint32_t end_of_message_psn=0; // Actual EOM PSN; the last placement can be an earlier RUD packet.
        uint16_t resource_index=1,wire_pid=1;
        bool relative_addressing=true;
        bool initialized=false,matched_receive=false,completion_reported=false,end_seen=false;
        std::optional<SemanticReturnCode> first_error;
        // §3.4.4.3: only the first error response for a message owns a
        // guaranteed-delivery slot. Later packets repeat the sticky error
        // explicitly, without creating additional guaranteed responses.
        bool error_response_generated=false;
        uint8_t error_generation=0;
        uint8_t response_list=0; // Table3-26: EXPECTED0 / OVERFLOW1; survives late placement.
        CompletionStatus target_error=CompletionStatus::RemoteError;
        std::shared_ptr<SparseMemory> unexpected;
        uint64_t receive_order=0,tag=0;
        std::optional<PDC_SES_req> deferred_response;
        std::optional<Region> receive_registration;
        uint32_t captured_header=0,reserved_restart=0,deferrable_source_token=0;
        uint64_t rendezvous_target=0;
        bool rendezvous_eager=false;
        uint32_t rendezvous_semantic_length=0; // Sticky result survives retiring the logical receive.
        ReadCoverage read_requests;
        size_t read_returns_pending=0;
        uint64_t synchronization_member=0;
        uint16_t synchronization_group=0,synchronization_count=0;
        bool synchronized_atomic=false;
        bool synchronization_start_seen=false;
        std::optional<Region> synchronization_registration;
        std::vector<uint8_t> synchronization_operands;
        std::vector<PDC_SES_req> synchronization_responses;
        std::optional<SemanticReturnCode> synchronization_admission_error;
    };
    struct DeferredTarget {
        uint32_t token,source_token,peer;
        SES_Standard_Header header;
        ResourceSelection selected;
        std::optional<uint64_t> immediate;
        std::optional<Posted> receive;
        uint64_t arrival_order;
        bool initial_end=false,initial_start=false,restart_started=false,restart_sent=false;
        std::optional<ConnectionKey> initial_connection;
    };
    std::map<uint32_t,std::shared_ptr<DeferredTarget>> deferred_targets_;
    std::map<uint64_t,uint32_t> deferred_order_;
    size_t deferred_header_limit_=0;
    uint32_t target_restart_initiator_=0; // Configured local Job rank; default node proxy is simulator policy.
    // Peer, local PDC, Job, initiator rank, message identity, PDC incarnation.
    // The identity slot holds either a 16-bit MID or a marked 32-bit PSN.
    using MessageKey=std::tuple<uint32_t,uint16_t,uint32_t,uint32_t,uint64_t,uint32_t>;
    static constexpr uint64_t kPacketMessageIdentity=uint64_t{1}<<32;
    // A rejected eager continuation may precede SOM. Preserve only its one
    // receive CQ until header data arrives; the owning Incoming bounds this
    // state and retires it on Clear/Close (§3.4.6.4.1).
    std::map<MessageKey,Completion> rendezvous_receive_errors_;
    struct RendezvousSourceTransaction {
        enum class Phase { Eager, Backoff, WaitingForRead };
        Operation original_operation;
        std::shared_ptr<const PayloadSource> registered_source;
        Region alias_registration;
        uint64_t application_operation_id;
        uint16_t source_absolute_pid=0,source_resource_index=1;
        uint32_t total_length,eager_length,accepted_eager_length=0,attempt=0,retries=0;
        uint16_t active_message=0,retiring_message=0;
        Phase phase=Phase::Eager;
        bool first_response_received=false,eager_completed=false,read_completed=false,backoff_ready=false;
        uint8_t success_opcode=0,success_list=0,success_generation=0;
        Runtime::TimerId deadline=0,backoff=0;
        ByteCoverage confirmed_bytes;
        struct ReadAcknowledgement {
            uint32_t length;
            ReadCoverage confirmed;
            bool end_confirmed=false;
        };
        std::map<MessageKey,ReadAcknowledgement> reads;
        std::set<ConnectionKey> connections;
    };
    struct RendezvousTargetTransaction {
        uint64_t id,arrival_order;
        MessageKey eager_message;
        SES_Standard_Header header;
        SES_Rendezvous_Extension_Header extension;
        ResourceSelection selected;
        uint32_t peer,accepted_eager,semantic_length;
        std::optional<Posted> receive;
        std::optional<uint64_t> immediate;
        ReadCoverage eager_bytes,wire_eager_bytes;
        ByteCoverage placed_bytes;
        std::optional<uint32_t> sent_eager_length;
        uint32_t highest_eager_end=0;
        bool first_response_generated=false;
        bool start_seen=false,end_seen=false,eager_completed=false,read_submitted=false,read_completed=false;
        uint16_t active_read_message=0;
        std::set<ConnectionKey> connections;
    };
    std::map<uint64_t,std::shared_ptr<RendezvousTargetTransaction>> rendezvous_targets_;
    std::map<uint64_t,uint64_t> rendezvous_order_; // Semantic arrival -> target-owned transaction.
    size_t rendezvous_target_limit_=64;
    uint64_t next_rendezvous_target_=0;
    std::optional<uint32_t> rendezvous_read_initiator_; // Internal READ sender rank; node proxy by default.
    std::set<std::tuple<uint16_t,uint16_t,ResourceSpace>> rendezvous_disabled_resources_;
    std::map<uint64_t,std::shared_ptr<RendezvousSourceTransaction>> rendezvous_sources_;
    std::map<uint64_t,uint64_t> rendezvous_source_aliases_; // Advertised MR key -> local user operation ID.
    size_t rendezvous_source_limit_=64;
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
    std::map<uint32_t,std::shared_ptr<DeferredSource>> deferred_sources_;
    size_t deferred_source_limit_=64;
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
    std::map<std::tuple<uint16_t,uint16_t,ResourceSpace>,uint8_t> disabled_generations_;
    std::map<uint16_t,SourceMessage> sources_;
    std::deque<uint16_t> submission_order_;
    // A bounded target packet budget is independent of whole-message slots.
    // Holding each original READ ACK until its return packet completes keeps
    // PDS payload storage and response tokens bounded (§3.5.20.2.2).
    size_t read_response_limit_;
    size_t read_result_window_;
    uint16_t next_read_response_=0;
    struct ReadReservation {
        MessageKey message; bool processed=false;
        std::function<void()> data_confirmed; // Local rendezvous ownership only; empty for ordinary READ.
        std::function<void()> data_failed;
    };
    std::map<ReadPacketIdentity,ReadReservation> read_packet_reservations_;
    struct ReadReturn {
        PDC_SES_req original;
        std::optional<uint32_t> sequence;
    };
    std::map<uint16_t,ReadReturn> read_returns_;

    struct SynchronizedSourceGroup {
        std::shared_ptr<const SynchronizedGroup> handle;
        uint32_t submitted=0,finished=0;
        bool completing_submitted=false,all_confirmed=true;
        Runtime::TimerId deadline=0;
    };
    struct SynchronizedSource {
        Operation original;
        std::shared_ptr<const PayloadSource> payload;
        uint64_t operation=0;
        uint16_t active_message=0,retiring_message=0;
        uint32_t retries=0;
        bool retry_ready=false;
        bool waiting_for_writes=false;
        Runtime::TimerId backoff=0;
        std::set<ConnectionKey> connections;
    };
    struct SynchronizedTargetAction {
        uint64_t owner=0,member=0;
        PDC_SES_req request; // Metadata plus at most one <=8-byte atomic operand.
        ResourceSelection selected{};
        std::optional<Region> registration;
        std::optional<uint64_t> immediate;
        uint32_t length=0;
        bool atomic=false;
        std::vector<PDC_SES_req> responses;
    };
    SynchronizationIdPool synchronization_ids_;
    static constexpr size_t kMaximumSynchronizedSourceMembers=4096;
    uint64_t next_synchronization_owner_=0;
    std::map<uint64_t,SynchronizedSourceGroup> synchronized_source_groups_;
    std::map<uint64_t,std::shared_ptr<SynchronizedSource>> synchronized_sources_;
    SynchronizationGroups synchronized_target_groups_;
    std::map<uint64_t,SynchronizedTargetAction> synchronized_target_actions_;
    std::map<uint64_t,Runtime::TimerId> synchronized_target_timers_;
    bool cancelling_synchronized_incarnation_=false;

    void abandon_synchronized_group(uint64_t owner) {
        const auto found=synchronized_source_groups_.find(owner); if (found==synchronized_source_groups_.end()) return;
        const auto handle=found->second.handle;
        loop_.cancel(found->second.deadline); synchronized_source_groups_.erase(found);
        synchronization_ids_.release(handle->wire_group_,false);
        std::vector<uint64_t> operations;
        for (const auto& source:synchronized_sources_)
            if (source.second->original.synchronization->owner_==owner) operations.push_back(source.first);
        for (const auto operation:operations) {
            const auto source=synchronized_sources_.find(operation); if (source==synchronized_sources_.end()) continue;
            const auto message=source->second->active_message;
            if (message && pending_.count(message)) finish(message,closed_?CompletionStatus::Cancelled:CompletionStatus::Timeout,0,0);
            else complete_synchronized_source(operation,closed_?CompletionStatus::Cancelled:CompletionStatus::Timeout,0,0,0);
        }
        if (!closed_) feed_submissions(); // Any started message still drains its reliable error tail.
    }
    void start_synchronized_source(Operation operation,uint64_t application_operation_id) {
        const auto handle=operation.synchronization;
        const auto group=handle?synchronized_source_groups_.find(handle->owner_):synchronized_source_groups_.end();
        const bool completing=operation.type==OperationType::SynchronizedAtomic || operation.immediate_data.has_value();
        const bool atomic=operation.type==OperationType::SynchronizedAtomic;
        const auto payload_size=operation.payload_source?operation.payload_source->size():operation.payload.size();
        if (!handle || handle->authority_.lock()!=lifetime_ || group==synchronized_source_groups_.end() ||
            group->second.handle!=handle || handle->peer_!=operation.peer || handle->job_!=operation.job ||
            group->second.submitted>=handle->message_count_ || (completing && group->second.completing_submitted) ||
            (!completing && !group->second.completing_submitted && group->second.submitted+1==handle->message_count_) ||
            operation.source_pid>0xfff || operation.target_pid>0xfff || operation.target_resource>0xfff ||
            (operation.delivery_mode!=RUD && operation.delivery_mode!=ROD) ||
            (atomic && (operation.immediate_data || static_cast<uint8_t>(operation.atomic_datatype)>7 ||
             payload_size>8 || operation.remote_offset%integer_atomic_width(operation.atomic_datatype) ||
             integer_atomic_width(operation.atomic_datatype)>mtu_))) {
            completions_.push_back({application_operation_id,operation.context,CompletionStatus::InvalidRequest,0,0,false}); return;
        }
        if (atomic && (static_cast<uint8_t>(operation.atomic_operation)>12 || operation.atomic_operation==IntegerAtomicOperation::Read)) {
            completions_.push_back({application_operation_id,operation.context,CompletionStatus::Unsupported,0,0,false}); return;
        }
        if (synchronized_sources_.size()>=kMaximumSynchronizedSourceMembers) {
            completions_.push_back({application_operation_id,operation.context,CompletionStatus::ResourceExhausted,0,0,false}); return;
        }
        auto source=std::make_shared<SynchronizedSource>(); source->operation=application_operation_id;
        source->payload=operation.payload_source;
        if (!source->payload) source->payload=std::make_shared<VectorPayload>(std::move(operation.payload));
        operation.payload_source.reset(); source->original=std::move(operation);
        ++group->second.submitted; group->second.completing_submitted|=completing;
        synchronized_sources_.emplace(application_operation_id,source);
        // A completing atomic may wait behind an arbitrary amount of WRITE
        // data. Sending it first on the same finite PDC would block Clear and
        // could fill the window before the writes arrive. There is no ordering
        // requirement on its operand payload (§3.4.9.6), so defer its first
        // transmission until the other logical members have acknowledged.
        source->waiting_for_writes=atomic;
        if (atomic) drive_synchronized_sources();
        else queue_synchronized_attempt(application_operation_id);
    }
    void queue_synchronized_attempt(uint64_t operation) {
        const auto found=synchronized_sources_.find(operation);
        if (found==synchronized_sources_.end() || closed_ || found->second->active_message) return;
        auto request=found->second->original; request.payload_source=found->second->payload;
        if (request.zero_length_atomic && !request.payload_source->size()) request.payload_source.reset();
        found->second->retry_ready=false; found->second->waiting_for_writes=false;
        submit_message(std::move(request),operation,0,0,0,0,operation);
    }
    void complete_synchronized_source(uint64_t operation,CompletionStatus status,uint32_t length,uint8_t code,uint8_t generation) {
        const auto found=synchronized_sources_.find(operation); if (found==synchronized_sources_.end()) return;
        const auto source=found->second; synchronized_sources_.erase(found); loop_.cancel(source->backoff);
        completions_.push_back({operation,source->original.context,status,length,code,false,{},generation});
        trace_.record(node_,"operation_complete",operation);
        const auto group=synchronized_source_groups_.find(source->original.synchronization->owner_);
        if (group==synchronized_source_groups_.end()) { drive_synchronized_sources(); return; }
        ++group->second.finished;
        // Error completion can precede reliable tail/Clear retirement. Such
        // groups are deliberately quarantined; success requires every ACK.
        group->second.all_confirmed&=status==CompletionStatus::Success;
        if (group->second.finished==group->second.handle->message_count_ && group->second.completing_submitted) {
            synchronization_ids_.release(group->second.handle->wire_group_,group->second.all_confirmed);
            loop_.cancel(group->second.deadline); synchronized_source_groups_.erase(group);
        }
        drive_synchronized_sources();
    }
    void synchronized_message_complete(uint64_t operation,uint16_t message,CompletionStatus status,uint32_t length,uint8_t code,uint8_t generation) {
        const auto found=synchronized_sources_.find(operation); if (found==synchronized_sources_.end()) return;
        const auto source=found->second; source->active_message=0; source->retiring_message=message;
        if (status==CompletionStatus::RemoteError && (code==2 || code==4)) {
            source->original.target_generation=generation;
            const auto exponent=std::min(source->retries++,uint32_t{4});
            const auto delay=std::min<Runtime::Time>(10*Runtime::kMillisecond,Runtime::kMillisecond<<exponent);
            std::weak_ptr<int> life=lifetime_;
            source->backoff=loop_.after(delay,[this,life,operation] {
                if (life.expired()) return;
                const auto retry=synchronized_sources_.find(operation); if (retry==synchronized_sources_.end()) return;
                retry->second->backoff=0; retry->second->retry_ready=true; drive_synchronized_sources();
            });
            feed_submissions(); return;
        }
        complete_synchronized_source(operation,status,length,code,generation);
    }
    void drive_synchronized_sources() {
        if (closed_ || cancelling_synchronized_incarnation_) return;
        std::vector<uint64_t> ready;
        for (const auto& source:synchronized_sources_) {
            const auto group=synchronized_source_groups_.find(source.second->original.synchronization->owner_);
            if (group==synchronized_source_groups_.end()) continue;
            if (source.second->waiting_for_writes && group!=synchronized_source_groups_.end() &&
                group->second.submitted==group->second.handle->message_count_ &&
                group->second.finished+1==group->second.handle->message_count_) ready.push_back(source.first);
            else if (source.second->retry_ready && !sources_.count(source.second->retiring_message) &&
                !message_leases_.count(source.second->retiring_message)) {
                const auto& operation=source.second->original;
                const bool older_recovery=std::any_of(synchronized_sources_.begin(),synchronized_sources_.end(),[&](const auto& other) {
                    const auto& earlier=other.second->original;
                    return other.first<source.first && other.second->retries &&
                        std::tie(earlier.peer,earlier.job,earlier.target_pid,earlier.target_resource,earlier.relative_addressing)==
                        std::tie(operation.peer,operation.job,operation.target_pid,operation.target_resource,operation.relative_addressing);
                });
                // §3.4.4.7.3.2: only the oldest failed message probes the
                // recovered generation until a successful acknowledgement.
                if (!older_recovery) ready.push_back(source.first);
            }
        }
        for (const auto operation:ready) queue_synchronized_attempt(operation);
    }
    static const SES_Synchronized_Operation_Extension_Header& synchronization_extension(const SEStoPDS_pkt& packet) {
        return packet.bth_header.Standard_Header.opcode==0x11?
            packet.eth_header.Synchronized_Atomic_Extension_Headers.synchronization:
            packet.eth_header.Synchronized_Operation_Extension_Header;
    }
    void arm_synchronized_target(uint64_t owner) {
        std::weak_ptr<int> life=lifetime_;
        synchronized_target_timers_[owner]=loop_.after(timeout_,[this,life,owner] {
            if (life.expired()) return;
            synchronized_target_timers_.erase(owner);
            for (const auto expired:synchronized_target_groups_.expire(loop_.now())) {
                synchronized_target_actions_.erase(expired);
                trace_.record(node_,"synchronized_group_expired",expired);
            }
        });
    }
    void drive_synchronized_target(uint64_t owner) {
        const auto group=synchronized_target_groups_.snapshot(owner);
        if (!group || (group->state!=SynchronizationGroups::State::Ready && group->state!=SynchronizationGroups::State::Completed)) return;
        if (const auto timer=synchronized_target_timers_.find(owner);timer!=synchronized_target_timers_.end()) {
            loop_.cancel(timer->second); synchronized_target_timers_.erase(timer);
        }
        const auto found=synchronized_target_actions_.find(owner);
        if (group->state!=SynchronizationGroups::State::Ready) {
            if (found!=synchronized_target_actions_.end()) synchronized_target_actions_.erase(found);
            return;
        }
        if (found==synchronized_target_actions_.end()) throw std::logic_error("ready synchronized group has no completing action");
        auto action=std::move(found->second); synchronized_target_actions_.erase(found);
        // Mark before issuing callbacks: the aggregate action executes once,
        // independently of per-message PDS replay and receive-state Clear.
        if (!synchronized_target_groups_.action_completed(owner)) throw std::logic_error("synchronized action changed state");
        if (!action.atomic) {
            completions_.push_back({0,0,CompletionStatus::Success,action.length,1,true,action.immediate});
        } else {
            const auto message=incoming_.find(receive_message_key(action.request));
            if (message==incoming_.end()) throw std::logic_error("synchronized atomic lost Incoming before its group barrier");
            if (!action.registration) throw std::logic_error("synchronized atomic has no pinned registration at its group barrier");
            const auto& header=action.request.pkt.bth_header.Standard_Header;
            try {
                // Preserve the original registration identity across the
                // barrier. A revoked/reused numeric key is never rebound.
                memory_.authorize_registration(*action.registration,header.job_id,action.selected.absolute_pid,
                    header.buffer_offset,action.length,Access::Atomic,action.selected.resource_index,MemoryAccessOrigin::RemoteRequest);
                memory_.atomic_elements(header.job_id,action.selected.absolute_pid,header.match_bits,header.buffer_offset,
                    static_cast<IntegerAtomicOperation>(message->second.atomic_operation),
                    static_cast<IntegerAtomicDatatype>(message->second.atomic_datatype),action.request.pkt.payload,
                    action.selected.resource_index,header.rel);
                message->second.completed=true;
                for (const auto& response:action.responses) reply(response,SemanticReturnCode::Ok,action.length);
                trace_.record(node_,"synchronized_atomic_executed",action.length);
            } catch (const MemoryAccessError& error) {
                reject_message(action.request,message->second,memory_code(error.code));
                for (const auto& response:action.responses)
                    if (response.orig_psn!=action.request.orig_psn) reply_error(response,message->second);
            }
        }
        trace_.record(node_,"synchronized_group_completed",owner);
    }
    void process_synchronized_member(Incoming& message,bool failed) {
        if (!message.synchronization_member) return;
        const auto group=synchronized_target_groups_.member_snapshot(message.synchronization_member);
        if (!group) throw std::logic_error("missing synchronized member ownership");
        if (failed && message.first_error && !message.initialized &&
            (*message.first_error==SemanticReturnCode::BadGeneration || *message.first_error==SemanticReturnCode::DisabledGeneration)) {
            synchronized_target_groups_.rollback(message.synchronization_member); message.synchronization_member=0;
            if (!synchronized_target_groups_.snapshot(group->owner)) {
                const auto timer=synchronized_target_timers_.find(group->owner);
                if (timer!=synchronized_target_timers_.end()) { loop_.cancel(timer->second); synchronized_target_timers_.erase(timer); }
            }
            return; // Recoverable address rejection did not admit a logical group member.
        }
        if (synchronized_target_groups_.processed(message.synchronization_member,failed)) {
            if (failed && message.first_error) trace_.record(node_,"synchronized_member_failed",static_cast<uint8_t>(*message.first_error));
            drive_synchronized_target(group->owner);
        }
    }
    void finish_synchronized_receive(const PDC_SES_req& request,Incoming& message,const ResourceSelection& selected) {
        const auto group=synchronized_target_groups_.member_snapshot(message.synchronization_member);
        if (!group) throw std::logic_error("synchronized completion lost its group");
        const bool completing=message.synchronized_atomic || message.has_immediate;
        if (completing && group->state==SynchronizationGroups::State::Collecting && !synchronized_target_actions_.count(group->owner)) {
            SynchronizedTargetAction action;
            action.owner=group->owner; action.member=message.synchronization_member;
            action.request=rendezvous_response_handle(request); action.selected=selected;
            action.registration=message.synchronization_registration; action.immediate=message.immediate_data;
            action.length=message.total; action.atomic=message.synchronized_atomic;
            if (action.atomic) {
                action.request.pkt.payload=message.synchronization_operands;
                action.responses=std::move(message.synchronization_responses);
            }
            synchronized_target_actions_.emplace(group->owner,std::move(action));
        }
        process_synchronized_member(message,false);
        // A held delivery-complete atomic produces no provisional response.
        // §3.4.4.3 forbids acknowledging the final received packet before its
        // completion semantics; NO_RESPONSE is promotable to DEFAULT (§3.5.13).
    }

    void recover_rendezvous_resources() {
        if (rendezvous_targets_.size()>=rendezvous_target_limit_) return;
        for (const auto& key:rendezvous_disabled_resources_) {
            const auto disabled=disabled_generations_.find(key);
            if (disabled==disabled_generations_.end()) continue;
            resources_.recover_after_exhaustion(std::get<0>(key),std::get<1>(key),std::get<2>(key),disabled->second);
            disabled_generations_.erase(disabled);
        }
        rendezvous_disabled_resources_.clear();
    }
    void retire_rendezvous_target(uint64_t id) {
        const auto found=rendezvous_targets_.find(id); if (found==rendezvous_targets_.end()) return;
        rendezvous_order_.erase(found->second->arrival_order); rendezvous_targets_.erase(found);
        recover_rendezvous_resources();
    }
    static std::optional<uint64_t> rendezvous_tag(const RendezvousTargetTransaction& transaction) {
        return transaction.header.opcode==10?std::optional<uint64_t>{static_cast<uint64_t>(transaction.header.match_bits)}:std::nullopt;
    }
    void complete_deferred_rendezvous_error(const MessageKey& message,std::optional<uint64_t> immediate={}) {
        const auto found=rendezvous_receive_errors_.find(message); if (found==rendezvous_receive_errors_.end()) return;
        if (immediate) found->second.immediate_data=immediate;
        completions_.push_back(found->second); rendezvous_receive_errors_.erase(found);
    }
    void fail_rendezvous_target(uint64_t id,CompletionStatus status,uint8_t code,uint32_t read_bytes) {
        const auto found=rendezvous_targets_.find(id); if (found==rendezvous_targets_.end()) return;
        const auto transaction=found->second;
        const auto active=transaction->active_read_message;
        if (const auto read=pending_.find(active);read!=pending_.end())
            read_bytes=std::max(read_bytes,static_cast<uint32_t>(read->second.read_results.bytes()));
        // Remove logical ownership before cancelling the private READ: its
        // completion callback must not generate a second receive completion.
        retire_rendezvous_target(id);
        const auto incoming=incoming_.find(transaction->eager_message);
        if (incoming!=incoming_.end() && !incoming->second.completed) {
            auto& message=incoming->second;
            if (!message.first_error) message.first_error=code?static_cast<SemanticReturnCode>(code):SemanticReturnCode::Undeliverable;
            message.completed=message.end_seen;
            if (message.deferred_response) {
                reply_error(*message.deferred_response,message); message.deferred_response.reset();
            }
        }
        if (pending_.count(active)) finish(active,CompletionStatus::Cancelled,read_bytes,0);
        if (transaction->receive) {
            const auto placed=static_cast<uint32_t>(transaction->placed_bytes.bytes());
            Completion completion{0,transaction->receive->context,status,placed,code,true,transaction->immediate,0,
                transaction->header.request_length,rendezvous_tag(*transaction)};
            if (!closed_ && transaction->header.hd && !transaction->start_seen && incoming!=incoming_.end())
                rendezvous_receive_errors_.emplace(transaction->eager_message,std::move(completion));
            else completions_.push_back(std::move(completion));
        }
    }
    void maybe_complete_rendezvous_target(uint64_t id) {
        const auto found=rendezvous_targets_.find(id); if (found==rendezvous_targets_.end()) return;
        const auto transaction=found->second;
        if (!transaction->receive || !transaction->eager_completed || !transaction->read_completed) return;
        completions_.push_back({0,transaction->receive->context,CompletionStatus::Success,
            transaction->header.request_length,1,true,transaction->immediate,0,0,rendezvous_tag(*transaction)});
        retire_rendezvous_target(id);
        trace_.record(node_,"rendezvous_receive_complete",id);
    }
    void rendezvous_read_complete(uint64_t id,CompletionStatus status,uint32_t length,uint8_t code) {
        const auto found=rendezvous_targets_.find(id); if (found==rendezvous_targets_.end()) return;
        const auto transaction=found->second;
        transaction->active_read_message=0;
        if (status!=CompletionStatus::Success) { fail_rendezvous_target(id,status,code,length); return; }
        transaction->read_completed=true; maybe_complete_rendezvous_target(id);
    }
    void start_rendezvous_read(const std::shared_ptr<RendezvousTargetTransaction>& transaction) {
        if (!transaction->receive || transaction->read_submitted) return;
        transaction->read_submitted=true;
        const auto& receive=*transaction->receive;
        const auto& extension=transaction->extension;
        Operation read; read.type=OperationType::Read; read.delivery_mode=RUD;
        read.peer=transaction->peer; read.job=transaction->header.job_id;
        read.source_pid=receive.pid; read.target_pid=extension.read_PIDonFEP;
        read.target_resource=extension.read_resource_index; read.target_generation=extension.read_ri_generation;
        // §3.4.5.3 permits reading more than strictly necessary. This native
        // policy reads the whole message, so an early/truncated eager portion
        // cannot leave a gap. Registered placement coverage merges overlaps.
        read.remote_key=extension.read_mem_key; read.remote_offset=extension.read_offset;
        read.read_length=transaction->header.request_length;
        read.relative_addressing=transaction->header.rel;
        read.initiator_id=rendezvous_read_initiator_.value_or(node_);
        read.read_result=ReadResultBuffer{receive.key,receive.offset,
            read.read_length,receive.pid,receive.resource_index};
        // A real zero-length READ supplies the second completion point when
        // eager covers the full message. The descriptor remains pinned too.
        submit_message(std::move(read),0,0,0,0,transaction->id);
        trace_.record(node_,"rendezvous_read_started",transaction->id);
    }
    bool bind_rendezvous_posting(const std::shared_ptr<RendezvousTargetTransaction>& transaction,const Posted& receive) {
        transaction->receive=receive; rendezvous_order_.erase(transaction->arrival_order);
        const auto incoming=incoming_.find(transaction->eager_message);
        const auto fail=[&](SemanticReturnCode code,CompletionStatus status) {
            if (incoming!=incoming_.end() && !incoming->second.first_error) incoming->second.first_error=code;
            fail_rendezvous_target(transaction->id,status,static_cast<uint8_t>(code),0); return false;
        };
        if (receive.capacity<transaction->header.request_length)
            return fail(SemanticReturnCode::UnsupportedSize,CompletionStatus::Truncated);
        try {
            memory_.authorize_registration(receive.registration,transaction->header.job_id,receive.pid,receive.offset,
                transaction->header.request_length,Access::Write,receive.resource_index);
        } catch (const MemoryAccessError& error) { return fail(memory_code(error.code),CompletionStatus::LocalError); }
        return true;
    }
    void match_rendezvous_target(uint64_t id) {
        const auto found=rendezvous_targets_.find(id); if (found==rendezvous_targets_.end()) return;
        const auto transaction=found->second; if (transaction->receive) return;
        const auto& header=transaction->header;
        const auto posted=std::find_if(posted_.begin(),posted_.end(),[&](const Posted& receive) {
            return posting_matches(receive,header.job_id,transaction->selected.absolute_pid,transaction->selected.resource_index,
                header.rel,header.opcode==10,header.match_bits,header.initiator);
        });
        if (posted==posted_.end()) return;
        const auto receive=*posted; posted_.erase(posted);
        // A late posting cannot change the original eager acceptance of zero.
        if (bind_rendezvous_posting(transaction,receive)) start_rendezvous_read(transaction);
    }
    static PDC_SES_req rendezvous_response_handle(const PDC_SES_req& request) {
        // Keep only the protocol handle/header while waiting for a RUD hole.
        // Eager bytes have already been placed or intentionally discarded.
        PDC_SES_req handle{};
        handle.PDCID=request.PDCID; handle.rx_pkt_handle=request.rx_pkt_handle;
        handle.orig_psn=request.orig_psn; handle.source_fep=request.source_fep;
        handle.connection_start_psn=request.connection_start_psn; handle.delivery_mode=request.delivery_mode;
        handle.pkt.bth_type=Standard_Header; handle.pkt.bth_header=request.pkt.bth_header;
        return handle;
    }
    void receive_rendezvous(const PDC_SES_req& request) {
        const auto& header=request.pkt.bth_header.Standard_Header;
        auto& message=incoming_.at(receive_message_key(request));
        if (header.som && header.hd)
            complete_deferred_rendezvous_error(receive_message_key(request),static_cast<uint64_t>(header.diff.som_true.header_data));
        message.completion_reported=true; // Only the root owns an application CQ.
        if (header.eom) { message.end_seen=true; message.end_of_message_psn=request.orig_psn; }
        const auto reject=[&](SemanticReturnCode code,std::optional<uint8_t> generation={}) {
            reject_message(request,message,code,generation);
            if (message.rendezvous_target) fail_rendezvous_target(message.rendezvous_target,
                CompletionStatus::RemoteError,static_cast<uint8_t>(code),0);
        };
        if (message.first_error) { reject(*message.first_error); return; }
        if (header.rel && !memory_.has_job(header.job_id)) { reject(SemanticReturnCode::BadJob); return; }
        const bool abort=header.opcode==0x0f;
        if (header.version || (!abort && header.opcode!=6 && header.opcode!=10) ||
            (!abort && request.pkt.eth_type!=Rendezvous_Extension_Header) || (abort && !header.eom)) {
            reject(SemanticReturnCode::UnsupportedOperation); return;
        }
        if (abort || header.ie) { reject(SemanticReturnCode::InitiatorError); return; }
        const auto& extension=request.pkt.eth_header.Rendezvous_Extension_Header;
        const uint32_t offset=header.som?0:header.diff.som_false.message_offset;
        const auto count=request.pkt.payload.size();
        if (extension.eager_length>header.request_length || extension.read_offset>UINT64_MAX-header.request_length ||
            offset>extension.eager_length || count>extension.eager_length-offset ||
            (!header.som && count!=header.diff.som_false.payload_length)) {
            reject(SemanticReturnCode::UnsupportedSize); return;
        }
        std::shared_ptr<RendezvousTargetTransaction> transaction;
        if (!message.rendezvous_target) {
            ResourceSelection selected{};
            try {
                selected=resources_.resolve(header.job_id,header.rel,header.PIDonFEP,header.resource_index,
                    header.opcode==10?ResourceSpace::Tagged:ResourceSpace::Send,header.ri_generation);
            } catch (const AddressingError& error) { reject(error.code,error.generation); return; }
            if (rendezvous_targets_.size()>=rendezvous_target_limit_ || next_rendezvous_target_==UINT64_MAX) {
                if (request.delivery_mode==ROD) {
                    const auto space=header.opcode==10?ResourceSpace::Tagged:ResourceSpace::Send;
                    const auto generation=resources_.disable_for_exhaustion(selected.absolute_pid,selected.resource_index,space);
                    const auto key=std::make_tuple(selected.absolute_pid,selected.resource_index,space);
                    disabled_generations_[key]=generation; rendezvous_disabled_resources_.insert(key);
                    reject(SemanticReturnCode::DisabledGeneration,generation);
                } else reject(SemanticReturnCode::NoMatch);
                return;
            }
            const auto posted=std::find_if(posted_.begin(),posted_.end(),[&](const Posted& receive) {
                return posting_matches(receive,header.job_id,selected.absolute_pid,selected.resource_index,
                    header.rel,header.opcode==10,header.match_bits,header.initiator);
            });
            const bool expected=posted!=posted_.end();
            transaction=std::make_shared<RendezvousTargetTransaction>();
            transaction->id=++next_rendezvous_target_; transaction->arrival_order=++next_receive_order_;
            transaction->eager_message=receive_message_key(request); transaction->header=header; transaction->extension=extension;
            // A failed posting must still retain valid CQ header data from
            // this SOM. Binding can report truncation before payload handling.
            transaction->start_seen=header.som;
            if (header.som && header.hd) transaction->immediate=header.diff.som_true.header_data;
            transaction->selected=selected; transaction->peer=request.source_fep;
            transaction->accepted_eager=expected?static_cast<uint32_t>(extension.eager_length):0;
            transaction->semantic_length=expected?static_cast<uint32_t>(header.request_length):0;
            transaction->connections.insert({request.source_fep,request.PDCID,request.connection_start_psn});
            rendezvous_targets_.emplace(transaction->id,transaction);
            message.rendezvous_target=transaction->id; message.response_list=expected?0:1; message.initialized=true;
            message.rendezvous_semantic_length=transaction->semantic_length;
            message.pid=selected.absolute_pid; message.resource_index=selected.resource_index;
            message.wire_pid=header.PIDonFEP; message.relative_addressing=header.rel;
            if (expected) {
                const auto receive=*posted; posted_.erase(posted);
                if (!bind_rendezvous_posting(transaction,receive)) { reply_error(request,message); return; }
            } else rendezvous_order_.emplace(transaction->arrival_order,transaction->id);
        } else {
            const auto found=rendezvous_targets_.find(message.rendezvous_target);
            if (found==rendezvous_targets_.end()) {
                if (message.completed) reply(request,SemanticReturnCode::Ok,message.rendezvous_semantic_length);
                else reject(SemanticReturnCode::OperationViolation);
                return;
            }
            transaction=found->second;
        }
        const auto& original=transaction->header; const auto& advertised=transaction->extension;
        if (header.opcode!=original.opcode || header.request_length!=original.request_length || header.rel!=original.rel ||
            header.PIDonFEP!=original.PIDonFEP || header.resource_index!=original.resource_index || header.ri_generation!=original.ri_generation ||
            header.hd!=original.hd || (header.opcode==10 && header.match_bits!=original.match_bits) ||
            extension.eager_length!=advertised.eager_length || extension.read_PIDonFEP!=advertised.read_PIDonFEP ||
            extension.read_resource_index!=advertised.read_resource_index || extension.read_ri_generation!=advertised.read_ri_generation ||
            extension.read_offset!=advertised.read_offset || extension.read_mem_key!=advertised.read_mem_key ||
            (header.som && header.hd && transaction->start_seen && transaction->immediate!=
                std::optional<uint64_t>{static_cast<uint64_t>(header.diff.som_true.header_data)})) {
            reject(SemanticReturnCode::OperationViolation); return;
        }
        if (header.som) { transaction->start_seen=true; if (header.hd) transaction->immediate=header.diff.som_true.header_data; }
        if (header.eom) transaction->end_seen=true;
        const auto wire_end=static_cast<uint32_t>(offset+count);
        if (count) {
            if (transaction->wire_eager_bytes.add(offset,static_cast<uint32_t>(count),extension.eager_length)!=ReadCoverage::Addition::Added) {
                reject(SemanticReturnCode::OperationViolation); return;
            }
            transaction->highest_eager_end=std::max(transaction->highest_eager_end,wire_end);
        }
        if (header.eom) {
            if (transaction->sent_eager_length && *transaction->sent_eager_length!=wire_end) {
                reject(SemanticReturnCode::OperationViolation); return;
            }
            transaction->sent_eager_length=wire_end;
        }
        if (transaction->sent_eager_length && transaction->highest_eager_end>*transaction->sent_eager_length) {
            reject(SemanticReturnCode::OperationViolation); return;
        }
        const uint32_t placed=offset>=transaction->accepted_eager?0:static_cast<uint32_t>(
            std::min<uint64_t>(count,transaction->accepted_eager-offset));
        if (placed) {
            if (transaction->eager_bytes.add(offset,placed,transaction->accepted_eager)!=ReadCoverage::Addition::Added) {
                reject(SemanticReturnCode::OperationViolation); return;
            }
            try {
                std::vector<uint8_t> bytes(request.pkt.payload.begin(),request.pkt.payload.begin()+placed);
                const auto& receive=*transaction->receive;
                memory_.write_registration(receive.registration,header.job_id,receive.pid,receive.offset+offset,bytes,receive.resource_index);
                transaction->placed_bytes.cover(offset,placed,transaction->header.request_length);
            } catch (const MemoryAccessError& error) { reject(memory_code(error.code)); return; }
        }
        message.received=transaction->eager_bytes.bytes();
        // Conservative native completion waits for all constructed eager
        // bytes through the real EOM offset, including discarded bytes. The
        // advertised cap can be larger after the sender shortens its transfer.
        transaction->eager_completed=transaction->start_seen && transaction->end_seen && transaction->sent_eager_length &&
            transaction->wire_eager_bytes.bytes()==*transaction->sent_eager_length &&
            transaction->eager_bytes.bytes()==std::min(transaction->accepted_eager,*transaction->sent_eager_length);
        message.completed=transaction->eager_completed;
        if (header.eom && !transaction->eager_completed) message.deferred_response=rendezvous_response_handle(request);
        else {
            reply(request,SemanticReturnCode::Ok,transaction->semantic_length,
                !transaction->first_response_generated || transaction->eager_completed || message.response_list);
            transaction->first_response_generated=true;
        }
        if (transaction->eager_completed && message.deferred_response) {
            reply(*message.deferred_response,SemanticReturnCode::Ok,transaction->semantic_length); message.deferred_response.reset();
        }
        // Eager and READ are separate wire messages (§3.4.5.3). Retiring this
        // Incoming does not retire the retained header or complete the user.
        if (transaction->receive) start_rendezvous_read(transaction);
        maybe_complete_rendezvous_target(transaction->id);
    }

    void start_rendezvous_source(Operation operation,uint64_t application_operation_id) {
        const auto local_failure=[&](CompletionStatus status) {
            completions_.push_back({application_operation_id,operation.context,status,0,0,false});
        };
        if (!operation.rendezvous_source || !operation.payload.empty() || operation.payload_source ||
            operation.read_length || operation.read_result || operation.atomic_result || !operation.atomic_compare.empty() ||
            operation.zero_length_atomic || operation.remote_offset || operation.remote_key ||
            !operation.peer || !memory_.has_job(operation.job) || operation.source_pid>0xfff || operation.target_pid>0xfff ||
            operation.target_resource>0xfff || (operation.delivery_mode!=RUD && operation.delivery_mode!=ROD)) {
            local_failure(CompletionStatus::InvalidRequest); return;
        }
        const auto source=*operation.rendezvous_source;
        if (source.pid>0xfff || source.resource_index>0xfff || operation.rendezvous_eager_length>source.length) {
            local_failure(CompletionStatus::InvalidRequest); return;
        }
        if (rendezvous_sources_.size()>=rendezvous_source_limit_) { local_failure(CompletionStatus::ResourceExhausted); return; }
        std::shared_ptr<RendezvousSourceTransaction> transaction;
        try {
            const auto selected=resources_.resolve(operation.job,operation.relative_addressing,source.pid,source.resource_index,
                ResourceSpace::Rma,source.generation);
            const auto registration=memory_.authorize(operation.job,selected.absolute_pid,source.key,source.offset,source.length,
                Access::Read,selected.resource_index,operation.relative_addressing,MemoryAccessOrigin::RendezvousSource);
            transaction=std::make_shared<RendezvousSourceTransaction>();
            transaction->registered_source=std::make_shared<RegisteredReadPayload>(memory_,registration,operation.job,
                selected.absolute_pid,selected.resource_index,source.offset,source.length);
            transaction->source_absolute_pid=selected.absolute_pid; transaction->source_resource_index=selected.resource_index;
        } catch (const MemoryAccessError&) { local_failure(CompletionStatus::LocalError); return; }
        catch (const AddressingError&) { local_failure(CompletionStatus::LocalError); return; }
        catch (const std::bad_alloc&) { local_failure(CompletionStatus::ResourceExhausted); return; }
        transaction->application_operation_id=application_operation_id;
        transaction->total_length=source.length; transaction->eager_length=operation.rendezvous_eager_length;
        transaction->original_operation=std::move(operation);
        rendezvous_sources_.emplace(application_operation_id,transaction);
        std::weak_ptr<int> life=lifetime_;
        transaction->deadline=loop_.after(timeout_,[this,life,application_operation_id] {
            if (!life.expired()) terminate_rendezvous_source(application_operation_id,CompletionStatus::Timeout);
        });
        queue_rendezvous_attempt(application_operation_id);
    }
    void queue_rendezvous_attempt(uint64_t operation) {
        const auto found=rendezvous_sources_.find(operation); if (found==rendezvous_sources_.end() || closed_) return;
        const auto transaction=found->second;
        // A retry advertises a fresh key. Old READ acknowledgements keep their
        // attempt number and cannot complete this new eager/READ transaction.
        rendezvous_source_aliases_.erase(transaction->alias_registration.key);
        memory_.deregister(transaction->alias_registration);
        try {
            RegionOptions options; options.resource_index=transaction->source_resource_index; options.bind_zero_pid=true;
            transaction->alias_registration=memory_.register_storage(transaction->original_operation.job,
                transaction->source_absolute_pid,std::make_shared<ReadOnlyPayloadStorage>(transaction->registered_source),
                static_cast<uint8_t>(Access::Read),options);
        } catch (const MemoryAccessError&) { complete_rendezvous_source(operation,CompletionStatus::LocalError,0,0); return; }
        catch (const std::exception&) { complete_rendezvous_source(operation,CompletionStatus::ResourceExhausted,0,0); return; }
        rendezvous_source_aliases_.emplace(transaction->alias_registration.key,operation);
        ++transaction->attempt; transaction->phase=RendezvousSourceTransaction::Phase::Eager;
        transaction->first_response_received=false; transaction->eager_completed=false; transaction->read_completed=false;
        transaction->backoff_ready=false; transaction->confirmed_bytes=ByteCoverage{}; transaction->reads.clear();
        auto request=transaction->original_operation;
        request.payload_source=std::make_shared<SlicedPayload>(transaction->registered_source,0,transaction->eager_length);
        submit_message(std::move(request),operation,0,0,operation);
        trace_.record(node_,"rendezvous_eager_started",operation);
    }
    void complete_rendezvous_source(uint64_t operation,CompletionStatus status,uint32_t length,uint8_t code,uint8_t generation=0) {
        const auto found=rendezvous_sources_.find(operation); if (found==rendezvous_sources_.end()) return;
        const auto transaction=found->second; rendezvous_sources_.erase(found);
        loop_.cancel(transaction->deadline); loop_.cancel(transaction->backoff);
        rendezvous_source_aliases_.erase(transaction->alias_registration.key);
        memory_.deregister(transaction->alias_registration);
        transaction->registered_source.reset();
        completions_.push_back({operation,transaction->original_operation.context,status,
            status==CompletionStatus::Success?transaction->total_length:length,code,false,{},generation});
        trace_.record(node_,"operation_complete",operation);
    }
    void terminate_rendezvous_source(uint64_t operation,CompletionStatus status) {
        const auto found=rendezvous_sources_.find(operation); if (found==rendezvous_sources_.end()) return;
        const auto active=found->second->active_message;
        if (active && pending_.count(active)) { finish(active,status,0,0); feed_submissions(); }
        else complete_rendezvous_source(operation,status,0,0);
    }
    void maybe_complete_rendezvous_source(uint64_t operation) {
        const auto found=rendezvous_sources_.find(operation); if (found==rendezvous_sources_.end()) return;
        const auto transaction=found->second;
        if (transaction->eager_completed && transaction->read_completed && transaction->reads.empty() &&
            transaction->confirmed_bytes.bytes()==transaction->total_length)
            complete_rendezvous_source(operation,CompletionStatus::Success,transaction->total_length,1,
                transaction->success_generation);
    }
    void rendezvous_eager_complete(uint64_t operation,uint16_t message,CompletionStatus status,uint32_t length,uint8_t code,uint8_t generation) {
        const auto found=rendezvous_sources_.find(operation); if (found==rendezvous_sources_.end()) return;
        const auto transaction=found->second;
        if (transaction->active_message!=message) return;
        transaction->active_message=0; transaction->retiring_message=message;
        if (status==CompletionStatus::Success) {
            transaction->success_generation=generation;
            transaction->eager_completed=true; transaction->phase=RendezvousSourceTransaction::Phase::WaitingForRead;
            transaction->confirmed_bytes.cover(0,transaction->accepted_eager_length,transaction->total_length);
            trace_.record(node_,"rendezvous_eager_complete",operation); maybe_complete_rendezvous_source(operation); return;
        }
        if (status==CompletionStatus::RemoteError && code>=2 && code<=5) {
            if (code==2 || code==4) transaction->original_operation.target_generation=generation;
            transaction->phase=RendezvousSourceTransaction::Phase::Backoff;
            const auto exponent=std::min(transaction->retries++,uint32_t{4});
            const auto delay=std::min<Runtime::Time>(10*Runtime::kMillisecond,Runtime::kMillisecond<<exponent);
            std::weak_ptr<int> life=lifetime_;
            transaction->backoff=loop_.after(delay,[this,life,operation] {
                if (life.expired()) return;
                const auto retry=rendezvous_sources_.find(operation); if (retry==rendezvous_sources_.end()) return;
                retry->second->backoff=0; retry->second->backoff_ready=true; drive_rendezvous_sources();
            });
            feed_submissions(); return;
        }
        complete_rendezvous_source(operation,status,length,code,generation);
    }
    void drive_rendezvous_sources() {
        if (closed_) return;
        std::vector<uint64_t> ready;
        for (const auto& entry:rendezvous_sources_) {
            const auto& transaction=*entry.second;
            if (transaction.phase==RendezvousSourceTransaction::Phase::Backoff && transaction.backoff_ready &&
                !message_leases_.count(transaction.retiring_message) && !sources_.count(transaction.retiring_message)) ready.push_back(entry.first);
        }
        for (const auto operation:ready) queue_rendezvous_attempt(operation);
    }
    void handle_rendezvous_result(uint16_t message,const SES_Semantic_Response_Header& semantic) {
        const auto pending=pending_.find(message); if (pending==pending_.end()) return;
        const auto found=rendezvous_sources_.find(pending->second.rendezvous_owner); if (found==rendezvous_sources_.end()) return;
        const auto transaction=found->second;
        // Table3-26 reports processed bytes, never a count beyond the
        // original message. Reject malformed error results too: otherwise an
        // untrusted response could expose an impossible application CQ length.
        if (semantic.opcode==1 && semantic.modified_length>transaction->total_length) {
            finish(message,CompletionStatus::RemoteError,0,static_cast<uint8_t>(SemanticReturnCode::OperationViolation));
            feed_submissions(); return;
        }
        if (semantic.return_code!=1) {
            finish(message,CompletionStatus::RemoteError,semantic.modified_length,semantic.return_code,semantic.ri_generation);
            feed_submissions(); return;
        }
        const auto modified=semantic.opcode==0?transaction->total_length:static_cast<uint32_t>(semantic.modified_length);
        const auto accepted=std::min(transaction->eager_length,modified);
        if (modified>transaction->total_length || (transaction->first_response_received &&
            (transaction->accepted_eager_length!=accepted || transaction->success_opcode!=semantic.opcode ||
                transaction->success_list!=semantic.list))) {
            finish(message,CompletionStatus::RemoteError,0,static_cast<uint8_t>(SemanticReturnCode::OperationViolation));
            feed_submissions(); return;
        }
        pending->second.returned_generation=semantic.ri_generation;
        if (!transaction->first_response_received) {
            transaction->first_response_received=true; transaction->accepted_eager_length=accepted;
            transaction->success_opcode=semantic.opcode; transaction->success_list=semantic.list;
            feed_submissions();
        }
        const auto active=pending_.find(message);
        if (active!=pending_.end() && active->second.end_of_message_transmitted && active->second.awaiting_semantic_responses.empty())
            finish(message,CompletionStatus::Success,accepted,1,semantic.ri_generation);
    }
    void confirm_rendezvous_read(uint64_t operation,uint32_t attempt,MessageKey message,
                                 uint32_t message_offset,uint32_t original_offset,uint32_t count,bool end) {
        const auto found=rendezvous_sources_.find(operation); if (found==rendezvous_sources_.end() || found->second->attempt!=attempt) return;
        const auto transaction=found->second;
        const auto read=transaction->reads.find(message); if (read==transaction->reads.end()) return;
        if (read->second.confirmed.add(message_offset,count,read->second.length)==ReadCoverage::Addition::Invalid ||
            !transaction->confirmed_bytes.cover(original_offset,count,transaction->total_length))
            throw std::logic_error("invalid locally tracked rendezvous READ confirmation");
        read->second.end_confirmed|=end;
        if (read->second.end_confirmed && read->second.confirmed.bytes()==read->second.length) {
            transaction->read_completed=true; transaction->reads.erase(read);
        }
        trace_.record(node_,"rendezvous_read_confirmed",operation); maybe_complete_rendezvous_source(operation);
    }
    bool bind_rendezvous_read(const PDC_SES_req& request,uint32_t offset,uint32_t count) {
        const auto& header=request.pkt.bth_header.Standard_Header;
        const auto owner=rendezvous_source_aliases_.find(header.match_bits);
        if (owner==rendezvous_source_aliases_.end()) return true; // Ordinary MR READ.
        const auto application_operation=owner->second;
        const auto found=rendezvous_sources_.find(application_operation); if (found==rendezvous_sources_.end()) throw std::logic_error("orphaned rendezvous MR alias");
        const auto transaction=found->second; const auto& operation=transaction->original_operation;
        auto& incoming=incoming_.at(receive_message_key(request));
        const auto reject=[&](SemanticReturnCode code) { reject_message(request,incoming,code); return false; };
        if (header.job_id!=operation.job) return reject(SemanticReturnCode::PermissionViolation);
        if (request.source_fep!=operation.peer || header.initiator!=operation.peer_initiator_id.value_or(operation.peer))
            return reject(SemanticReturnCode::OperationViolation);
        const auto& source=*operation.rendezvous_source;
        if (header.rel!=operation.relative_addressing || header.PIDonFEP!=source.pid || header.resource_index!=source.resource_index)
            return reject(SemanticReturnCode::OperationViolation);
        if (header.buffer_offset>transaction->total_length || header.request_length>transaction->total_length-header.buffer_offset) {
            reject(SemanticReturnCode::BadAddress); terminate_rendezvous_source(application_operation,CompletionStatus::RemoteError); return false;
        }
        const auto key=receive_message_key(request);
        auto [read,inserted]=transaction->reads.try_emplace(key,RendezvousSourceTransaction::ReadAcknowledgement{static_cast<uint32_t>(header.request_length)});
        if (!inserted && read->second.length!=header.request_length) return reject(SemanticReturnCode::OperationViolation);
        transaction->connections.insert({request.source_fep,request.PDCID,request.connection_start_psn});
        const auto attempt=transaction->attempt;
        const auto original_offset=static_cast<uint32_t>(header.buffer_offset)+offset;
        const bool end=header.eom;
        auto& credit=read_packet_reservations_.at(ReadPacketIdentity::from(request));
        credit.data_confirmed=[this,application_operation,attempt,key,offset,original_offset,count,end] {
            confirm_rendezvous_read(application_operation,attempt,key,offset,original_offset,count,end);
        };
        credit.data_failed=[this,application_operation,attempt] {
            const auto active=rendezvous_sources_.find(application_operation);
            if (active!=rendezvous_sources_.end() && active->second->attempt==attempt)
                terminate_rendezvous_source(application_operation,CompletionStatus::RemoteError);
        };
        return true;
    }

    void start_deferrable_source(Operation operation,uint64_t application_operation_id) {
        const auto local_failure=[&](CompletionStatus status) {
            completions_.push_back({application_operation_id,operation.context,status,0,0,false});
        };
        if (operation.payload_source && !operation.payload.empty()) { local_failure(CompletionStatus::InvalidRequest); return; }
        const auto length=operation.payload_source?operation.payload_source->size():operation.payload.size();
        if (length>UINT32_MAX) { local_failure(CompletionStatus::InvalidRequest); return; }
        auto& token_cursor=host_.services().next_semantic_restart_token;
        if (deferred_sources_.size()>=deferred_source_limit_ || !token_cursor || token_cursor>UINT32_MAX) {
            local_failure(CompletionStatus::ResourceExhausted); return;
        }
        auto transaction=std::make_shared<DeferredSource>();
        transaction->payload=operation.payload_source?operation.payload_source:std::make_shared<VectorPayload>(std::move(operation.payload));
        operation.payload.clear(); operation.payload_source=transaction->payload;
        transaction->original=std::move(operation); transaction->operation=application_operation_id;
        transaction->token=static_cast<uint32_t>(token_cursor++); transaction->total=static_cast<uint32_t>(length);
        transaction->length=transaction->total;
        deferred_sources_.emplace(transaction->token,transaction);
        const auto token=transaction->token; std::weak_ptr<int> life=lifetime_;
        // One deadline covers every wire message, backoff and RTR wait. A
        // fresh MID must not reset the application's transaction timeout.
        transaction->deadline=loop_.after(timeout_,[this,life,token] {
            if (!life.expired()) terminate_deferrable_source(token,CompletionStatus::Timeout);
        });
        trace_.record(node_,"deferrable_started",application_operation_id);
        queue_deferrable_attempt(token);
    }
    void queue_deferrable_attempt(uint32_t token) {
        const auto found=deferred_sources_.find(token); if (found==deferred_sources_.end() || closed_) return;
        const auto transaction=found->second;
        transaction->phase=DeferredSource::Phase::Sending;
        transaction->first_response_seen=false; transaction->deferred=false; transaction->backoff_ready=false;
        auto request=transaction->original;
        request.payload_source=std::make_shared<SlicedPayload>(transaction->payload,transaction->offset,transaction->length);
        // Table2-30: ordered initial/eager deferrable data can use ROD,
        // while the restarted transfer uses RUD and its reserved target token.
        if (transaction->restarted) request.delivery_mode=RUD;
        submit_message(std::move(request),transaction->operation,token);
    }
    void complete_deferrable_source(uint32_t token,CompletionStatus status,uint32_t length,uint8_t code,uint8_t generation=0) {
        const auto found=deferred_sources_.find(token); if (found==deferred_sources_.end()) return;
        const auto transaction=found->second; deferred_sources_.erase(found);
        loop_.cancel(transaction->deadline); loop_.cancel(transaction->backoff);
        completions_.push_back({transaction->operation,transaction->original.context,status,
            status==CompletionStatus::Success?transaction->total:length,code,false,{},generation});
        trace_.record(node_,"operation_complete",transaction->operation);
        transaction->payload.reset(); transaction->original.payload_source.reset();
    }
    void terminate_deferrable_source(uint32_t token,CompletionStatus status) {
        const auto found=deferred_sources_.find(token); if (found==deferred_sources_.end()) return;
        const auto transaction=found->second;
        if (transaction->active_message && pending_.count(transaction->active_message)) {
            finish(transaction->active_message,status,0,0);
            // An early semantic error may have only one packet in flight;
            // explicitly drive its MSG_ERROR/EOM tail before retiring the MID.
            feed_submissions();
        } else complete_deferrable_source(token,status,0,0);
    }
    void deferrable_message_complete(uint32_t token,uint16_t message,CompletionStatus status,uint32_t length,uint8_t code,uint8_t generation) {
        const auto found=deferred_sources_.find(token); if (found==deferred_sources_.end()) return;
        const auto transaction=found->second;
        if (transaction->active_message!=message) return;
        transaction->active_message=0; transaction->retiring_message=message;
        if (status==CompletionStatus::Success) {
            if (transaction->deferred) {
                transaction->phase=DeferredSource::Phase::WaitingForRestart;
                trace_.record(node_,"deferrable_waiting_rtr",transaction->operation);
                drive_deferrable_sources();
            } else complete_deferrable_source(token,status,transaction->total,1,generation);
            return;
        }
        if (status==CompletionStatus::RemoteError && !transaction->target_token && code>=2 && code<=5) {
            if (code==2 || code==4) transaction->original.target_generation=generation;
            transaction->phase=DeferredSource::Phase::Backoff;
            transaction->pending_restart.reset(); transaction->backoff_ready=false;
            const auto exponent=std::min(transaction->retries++,uint32_t{4});
            const auto delay=std::min<Runtime::Time>(10*Runtime::kMillisecond,Runtime::kMillisecond<<exponent);
            std::weak_ptr<int> life=lifetime_;
            transaction->backoff=loop_.after(delay,[this,life,token] {
                if (life.expired()) return;
                const auto retry=deferred_sources_.find(token); if (retry==deferred_sources_.end()) return;
                retry->second->backoff=0; retry->second->backoff_ready=true; drive_deferrable_sources();
            });
            feed_submissions();
            return;
        }
        const auto processed=static_cast<uint32_t>(std::min<uint64_t>(transaction->total,uint64_t{transaction->offset}+length));
        complete_deferrable_source(token,status,processed,code,generation);
    }
    void drive_deferrable_sources() {
        if (closed_) return;
        std::vector<uint32_t> ready;
        for (const auto& entry:deferred_sources_) {
            const auto& transaction=*entry.second;
            if (transaction.phase==DeferredSource::Phase::WaitingForRestart && transaction.pending_restart) ready.push_back(entry.first);
            else if (transaction.phase==DeferredSource::Phase::Backoff && transaction.backoff_ready &&
                !message_leases_.count(transaction.retiring_message) && !sources_.count(transaction.retiring_message)) ready.push_back(entry.first);
        }
        for (const auto token:ready) {
            const auto found=deferred_sources_.find(token); if (found==deferred_sources_.end()) continue;
            const auto transaction=found->second;
            if (transaction->phase==DeferredSource::Phase::WaitingForRestart) {
                const auto restart=*transaction->pending_restart;
                transaction->pending_restart.reset(); transaction->last_restart=restart;
                transaction->offset=restart.offset; transaction->length=restart.length;
                transaction->target_token=restart.target_token; transaction->restarted=true;
                trace_.record(node_,"deferrable_restarted",transaction->operation);
            }
            queue_deferrable_attempt(token);
        }
    }
    void handle_deferrable_result(uint16_t message,const SES_Semantic_Response_Header& semantic) {
        const auto operation=pending_.find(message); if (operation==pending_.end()) return;
        const auto found=deferred_sources_.find(operation->second.deferrable_token);
        if (found==deferred_sources_.end()) return;
        const auto transaction=found->second;
        if (semantic.return_code!=1) {
            finish(message,CompletionStatus::RemoteError,semantic.modified_length,semantic.return_code,semantic.ri_generation);
            // Completion releases the application source immediately, but an
            // early rejection still needs its metadata-only MSG_ERROR/EOM.
            feed_submissions();
            return;
        }
        operation->second.returned_generation=semantic.ri_generation;
        // §3.4.4.3: one message cannot change its successful response
        // encoding or its acceptance decision midway through transmission.
        const auto modified=semantic.opcode==0?transaction->length:semantic.modified_length;
        const bool deferred=semantic.opcode==1 && !modified && (transaction->length || semantic.list==1);
        if ((!deferred && modified!=transaction->length) || (deferred && transaction->target_token) ||
            (transaction->first_response_seen && (transaction->deferred!=deferred ||
                transaction->success_opcode!=semantic.opcode || transaction->success_list!=semantic.list))) {
            finish(message,CompletionStatus::RemoteError,0,static_cast<uint8_t>(SemanticReturnCode::OperationViolation));
            feed_submissions(); return;
        }
        if (!transaction->first_response_seen) {
            // DEFAULT reconstructs full length even for the compact query
            // encoding. OVERFLOW distinguishes deferral from EXPECTED zero.
            transaction->success_opcode=semantic.opcode; transaction->success_list=semantic.list;
            transaction->first_response_seen=true; transaction->deferred=deferred;
            if (deferred) trace_.record(node_,"deferrable_deferred",transaction->operation);
            feed_submissions();
        }
        const auto still_pending=pending_.find(message);
        if (still_pending!=pending_.end() && still_pending->second.end_of_message_transmitted && still_pending->second.awaiting_semantic_responses.empty())
            finish(message,CompletionStatus::Success,transaction->deferred?0:transaction->length,1,still_pending->second.returned_generation);
    }

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
            std::shared_ptr<DeferredSource> deferred;
            if (transfer.deferrable_token && !transfer.aborting) {
                const auto transaction=deferred_sources_.find(transfer.deferrable_token);
                if (transaction==deferred_sources_.end()) throw std::logic_error("missing deferred source transaction");
                deferred=transaction->second;
                if (transfer.started && !deferred->first_response_seen) break;
            }
            std::shared_ptr<RendezvousSourceTransaction> rendezvous;
            if (transfer.rendezvous_owner && !transfer.aborting) {
                const auto transaction=rendezvous_sources_.find(transfer.rendezvous_owner);
                if (transaction==rendezvous_sources_.end()) throw std::logic_error("missing rendezvous source transaction");
                rendezvous=transaction->second;
                if (transfer.started && !rendezvous->first_response_received) break;
            }
            const bool datagram=operation.type==OperationType::DatagramSend;
            const bool fetching_atomic=operation.type==OperationType::FetchingAtomic;
            const bool atomic=operation.type==OperationType::Atomic || operation.type==OperationType::SynchronizedAtomic || fetching_atomic;
            const bool restart=transfer.restart_owner!=0;
            const bool read=operation.type==OperationType::Read && !transfer.aborting;
            if (read && pending_.at(message).read_requests_awaiting_data.size()>=read_result_window_) break;
            const auto atomic_width=atomic?integer_atomic_width(operation.atomic_datatype):1;
            const auto fragment_capacity=mtu_-(mtu_%atomic_width);
            const bool deferred_end=deferred && deferred->deferred && transfer.started;
            const auto transfer_end=rendezvous && rendezvous->first_response_received?rendezvous->accepted_eager_length:transfer.length;
            const auto remaining=transfer.offset>=transfer_end?uint64_t{0}:transfer_end-transfer.offset;
            auto count=(transfer.aborting || deferred_end || restart)?size_t{0}:static_cast<size_t>(std::min<uint64_t>(fragment_capacity,remaining));
            SES_PDS_req request{};
            request.src_fep=node_; request.dst_fep=operation.peer;
            request.source_pid=operation.source_pid;
            request.mode=datagram?UUD:operation.delivery_mode;
            request.next_hdr=UET_HDR_REQUEST_STD; request.rod_context=1; request.lock_pdc=true;
            request.tx_pkt_handle=message; request.pkt.bth_type=Standard_Header;
            // Queue establishment through the original manager's transmit
            // path. An SES backoff timer must not allocate/mutate a PDC itself.
            request.establish_with_control=operation.type==OperationType::SynchronizedAtomic;
            auto& header=request.pkt.bth_header.Standard_Header;
            header.opcode=transfer.aborting?0x0f:static_cast<uint8_t>(operation.type); header.version=0;
            header.som=!transfer.started;
            header.eom=transfer.aborting || deferred_end || restart || (transfer.offset+count>=transfer_end && (!deferred || deferred->first_response_seen) &&
                (!rendezvous || rendezvous->first_response_received));
            header.dc=!datagram; header.rel=operation.relative_addressing; header.ri_generation=operation.target_generation;
            header.msg_id=datagram?0:message; header.job_id=operation.job; header.PIDonFEP=operation.target_pid;
            header.resource_index=operation.target_resource;
            // MSG_ERROR must retain tokens even after the logical transaction
            // has released its source, so a reserved target can retire too.
            header.buffer_offset=transfer.deferrable_token?transfer.restart_tokens:operation.remote_offset;
            header.initiator=operation.initiator_id.value_or(node_);
            header.match_bits=(operation.type==OperationType::TaggedSend || operation.type==OperationType::DeferrableTaggedSend || operation.type==OperationType::RendezvousTaggedSend)?operation.tag:operation.remote_key;
            header.request_length=transfer.rendezvous_owner?transfer.rendezvous_total:transfer.length;
            if (transfer.rendezvous_owner && !transfer.aborting) {
                request.pkt.eth_type=Rendezvous_Extension_Header;
                request.pkt.eth_header.Rendezvous_Extension_Header=transfer.rendezvous_extension;
            }
            if (operation.immediate_data) {
                header.hd=1;
                if (header.som) header.diff.som_true.header_data=*operation.immediate_data;
            }
            if (atomic && !transfer.aborting) {
                request.pkt.eth_type=Atomic_Operation_Extension_Header;
                auto& extension=request.pkt.eth_header.Atomic_Operation_Extension_Header;
                extension.atomic_opcode=static_cast<uint8_t>(operation.atomic_operation);
                extension.atomic_datatype=static_cast<uint8_t>(operation.atomic_datatype);
            }
            if (operation.synchronization && !transfer.aborting) {
                const auto atomic_extension=request.pkt.eth_header.Atomic_Operation_Extension_Header;
                request.pkt.eth_type=atomic?Synchronized_Atomic_Extension_Headers:Synchronized_Operation_Extension_Header;
                auto& synchronization=atomic?request.pkt.eth_header.Synchronized_Atomic_Extension_Headers.synchronization:
                    request.pkt.eth_header.Synchronized_Operation_Extension_Header;
                synchronization.sync_group=operation.synchronization->wire_group_;
                synchronization.sync_count=(atomic || operation.immediate_data)?operation.synchronization->message_count_:0;
                if (atomic) request.pkt.eth_header.Synchronized_Atomic_Extension_Headers.atomic=atomic_extension;
            }
            if (!header.som) {
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
            // Fetching operands were encoded once at submission; dual operand
            // fields are padded16B slots, not a vector of datatype elements.
            if (atomic && !fetching_atomic && !transfer.aborting)
                convert_integer_atomic_byte_order(request.pkt.payload,operation.atomic_datatype);
            request.pkt_len=static_cast<uint16_t>(44+((atomic && !transfer.aborting)?4:(transfer.rendezvous_owner && !transfer.aborting)?24:0)+
                ((operation.synchronization && !transfer.aborting)?4:0)+request.pkt.payload.size());
            const bool end_of_message=header.eom;
            if (!read_failed && operation.header_format!=RequestHeaderFormat::Standard) {
                const auto standard=header;
                const bool medium=operation.header_format==RequestHeaderFormat::Medium;
                const auto fill=[&](auto& optimized_header) {
                    optimized_header={}; optimized_header.opcode=standard.opcode; optimized_header.dc=standard.dc;
                    optimized_header.ie=standard.ie; optimized_header.rel=standard.rel;
                    optimized_header.som=standard.som; optimized_header.eom=standard.eom;
                    optimized_header.request_length=standard.request_length; optimized_header.ri_generation=standard.ri_generation;
                    optimized_header.job_id=standard.job_id; optimized_header.PIDonFEP=standard.PIDonFEP;
                    optimized_header.resource_index=standard.resource_index; optimized_header.buffer_offset=standard.buffer_offset;
                };
                request.next_hdr=medium?UET_HDR_REQUEST_MEDIUM:UET_HDR_REQUEST_SMALL;
                request.pkt.bth_type=medium?Small_Message_RMA_Header:Optimized_Header;
                if (medium) {
                    auto& optimized_header=request.pkt.bth_header.Small_Message_RMA_Header; fill(optimized_header);
                    optimized_header.hd=standard.hd;
                    if (standard.hd) optimized_header.header_data=standard.diff.som_true.header_data;
                    optimized_header.initiator=standard.initiator; optimized_header.match_bits=standard.match_bits;
                } else {
                    auto& optimized_header=request.pkt.bth_header.Optimized_Header; fill(optimized_header);
                    if (standard.opcode==1) optimized_header.resource_index=operation.remote_key&0xfff;
                }
                request.pkt_len=static_cast<uint16_t>((medium?32:20)+request.pkt.payload.size());
            }
            const bool rudi=operation.delivery_mode==RUDI;
            if (rudi && read_failed) {
                // A stateless peer has no message to terminate with MSG_ERROR.
                finish(message,CompletionStatus::LocalError,0,static_cast<uint8_t>(SemanticReturnCode::InitiatorError)); return;
            }
            if (rudi) {
                const auto packet_id=host_.submit_rudi(request);
                if (!packet_id) { finish(message,CompletionStatus::ResourceExhausted,0,0); return; }
                pending_.at(message).awaiting_rudi_responses.insert(*packet_id);
                pending_.at(message).rudi_all_submitted=end_of_message;
            } else if (!host_.submit(request)) throw std::runtime_error("PDS rejected operation fragment");
            transfer.started=true;
            if (read) pending_.at(message).read_requests_awaiting_data.insert(static_cast<uint32_t>(transfer.offset));
            ++queued_fragments_; ++transfer.queued; transfer.offset+=count;
            if (end_of_message) { transfer.all_submitted=true; submission_order_.pop_front(); }
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
        const bool rudi=it->second.is_rudi;
        if (rudi) {
            host_.cancel_queued_message(it->second.peer,it->second.job,message);
            discard_source(message); // Stop payload reads and packet timers before exposing completion.
        }
        if (status!=CompletionStatus::Success && status!=CompletionStatus::LocalSuccess) {
            if (auto source=sources_.find(message);source!=sources_.end()) {
                // §3.4.6.4.1: already queued fragments own byte copies. Stop
                // reading the application before exposing its error completion;
                // replace the unsent tail by one reliable EOM MSG_ERROR packet.
                source->second.source.reset();
                source->second.aborting=!source->second.all_submitted;
            }
        }
        const auto deferrable_token=it->second.deferrable_token;
        const auto restart_owner=it->second.restart_owner;
        const auto rendezvous_owner=it->second.rendezvous_owner;
        const auto rendezvous_read_owner=it->second.rendezvous_read_owner;
        const auto synchronization_owner=it->second.synchronization_owner;
        if (!deferrable_token && !restart_owner && !rendezvous_owner && !rendezvous_read_owner && !synchronization_owner) {
            completions_.push_back({it->second.id,it->second.context,status,length,code,false,{},remote_generation});
            trace_.record(node_,"operation_complete",it->second.id);
        } else trace_.record(node_,"wire_message_complete",message);
        if (!it->second.is_datagram && !rudi && !closed_) {
            const ConnectionKey connection{it->second.peer,it->second.local_pdc,it->second.connection_start_psn};
            const auto cleared=transmit_clear_frontiers_.find(connection);
            const bool missing_read_data=it->second.is_read && it->second.read_results.bytes()<it->second.length;
            if (missing_read_data || it->second.local_pdc==UINT16_MAX || !it->second.end_of_message_transmitted || cleared==transmit_clear_frontiers_.end() ||
                cleared->second-it->second.last_transmitted_psn>=0x80000000u)
                message_leases_[message]={connection,it->second.last_transmitted_psn,it->second.end_of_message_transmitted,it->second.id,missing_read_data,false};
            if (missing_read_data && it->second.local_pdc!=UINT16_MAX)
                message_leases_.at(message).connection_close_requested=host_.request_connection_close(it->second.local_pdc);
        }
        const bool finish_read_tail=it->second.is_read && status!=CompletionStatus::Success && status!=CompletionStatus::LocalSuccess;
        pending_.erase(it);
        if (synchronization_owner) synchronized_message_complete(synchronization_owner,message,status,length,code,remote_generation);
        if (deferrable_token) deferrable_message_complete(deferrable_token,message,status,length,code,remote_generation);
        if (rendezvous_read_owner) rendezvous_read_complete(rendezvous_read_owner,status,length,code);
        if (rendezvous_owner) rendezvous_eager_complete(rendezvous_owner,message,status,length,code,remote_generation);
        if (restart_owner && status!=CompletionStatus::Success) fail_deferred_target(restart_owner,status,code);
        if (finish_read_tail || rudi) feed_submissions();
    }

    void context_event(const Runtime::PdcEvent& event) {
        if (event.kind==Runtime::PdcEventKind::ConnectionClosed && event.failure!=Runtime::PdcFailureReason::None) {
            cancelling_synchronized_incarnation_=true;
            std::vector<uint64_t> synchronized_failed;
            for (const auto& source:synchronized_sources_)
                if (source.second->connections.count({event.peer,event.local_pdc,event.connection_start_psn})) synchronized_failed.push_back(source.first);
            for (const auto operation:synchronized_failed) {
                const auto source=synchronized_sources_.find(operation); if (source==synchronized_sources_.end()) continue;
                const auto active=source->second->active_message;
                const auto status=event.failure==Runtime::PdcFailureReason::RetryExhausted?CompletionStatus::Timeout:CompletionStatus::RemoteError;
                if (active && pending_.count(active)) {
                    const auto& pending=pending_.at(active);
                    if (ConnectionKey{pending.peer,pending.local_pdc,pending.connection_start_psn}==
                        ConnectionKey{event.peer,event.local_pdc,event.connection_start_psn}) discard_source(active);
                    finish(active,status,0,0);
                }
                else complete_synchronized_source(operation,status,0,0,0);
            }
            cancelling_synchronized_incarnation_=false;
            std::vector<uint32_t> failed;
            for (const auto& transaction:deferred_sources_)
                if (transaction.second->connections.count({event.peer,event.local_pdc,event.connection_start_psn})) failed.push_back(transaction.first);
            for (const auto token:failed) {
                const auto found=deferred_sources_.find(token); if (found==deferred_sources_.end()) continue;
                const auto transaction=found->second;
                const auto active=pending_.find(transaction->active_message);
                if (active!=pending_.end() && ConnectionKey{active->second.peer,active->second.local_pdc,
                    active->second.connection_start_psn}==ConnectionKey{event.peer,event.local_pdc,event.connection_start_psn})
                    discard_source(transaction->active_message); // This PDC cannot carry an abort tail.
                terminate_deferrable_source(token,event.failure==Runtime::PdcFailureReason::RetryExhausted?
                    CompletionStatus::Timeout:CompletionStatus::RemoteError);
            }
            std::vector<uint64_t> rendezvous_failed;
            for (const auto& transaction:rendezvous_sources_)
                if (transaction.second->connections.count({event.peer,event.local_pdc,event.connection_start_psn})) rendezvous_failed.push_back(transaction.first);
            for (const auto operation:rendezvous_failed) {
                const auto found=rendezvous_sources_.find(operation); if (found==rendezvous_sources_.end()) continue;
                const auto active=pending_.find(found->second->active_message);
                if (active!=pending_.end() && ConnectionKey{active->second.peer,active->second.local_pdc,active->second.connection_start_psn}==
                    ConnectionKey{event.peer,event.local_pdc,event.connection_start_psn}) discard_source(active->first);
                terminate_rendezvous_source(operation,event.failure==Runtime::PdcFailureReason::RetryExhausted?
                    CompletionStatus::Timeout:CompletionStatus::RemoteError);
            }
            failed.clear();
            for (const auto& target:deferred_targets_)
                if (target.second->initial_connection==std::optional<ConnectionKey>{{event.peer,event.local_pdc,event.connection_start_psn}})
                    failed.push_back(target.first);
            for (const auto token:failed) fail_deferred_target(token,CompletionStatus::RemoteError,
                static_cast<uint8_t>(SemanticReturnCode::Undeliverable));
            std::vector<uint64_t> failed_receives;
            for (const auto& receive:rendezvous_targets_)
                if (receive.second->connections.count({event.peer,event.local_pdc,event.connection_start_psn})) failed_receives.push_back(receive.first);
            for (const auto receive:failed_receives) fail_rendezvous_target(receive,
                event.failure==Runtime::PdcFailureReason::RetryExhausted?CompletionStatus::Timeout:CompletionStatus::RemoteError,
                static_cast<uint8_t>(SemanticReturnCode::Undeliverable),0);
        }
        if (event.kind==Runtime::PdcEventKind::ReceiveCleared || event.kind==Runtime::PdcEventKind::ConnectionClosed) {
            for (auto credit=read_packet_reservations_.begin();credit!=read_packet_reservations_.end();) {
                const auto& packet=credit->first;
                const bool context=packet.peer==event.peer && packet.local_pdc==event.local_pdc &&
                    packet.connection_start_psn==event.connection_start_psn;
                if (context && (event.kind==Runtime::PdcEventKind::ConnectionClosed || event.sequence-packet.sequence<0x80000000u))
                {
                    const auto confirmed=credit->second.data_confirmed;
                    credit=read_packet_reservations_.erase(credit);
                    if (confirmed && (event.kind==Runtime::PdcEventKind::ReceiveCleared || event.failure==Runtime::PdcFailureReason::None)) confirmed();
                }
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
        if (event.local_pdc>=MAX_PDC && event.local_pdc<MAX_PDC*2) {
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
            feed_submissions(); drive_deferrable_sources(); drive_rendezvous_sources();
            return;
        }
        const ConnectionKey connection{event.peer,event.local_pdc,event.connection_start_psn};
        if (event.kind==Runtime::PdcEventKind::RequestTransmitted) {
            if (auto operation=pending_.find(event.message_id);operation!=pending_.end() &&
                operation->second.peer==event.peer && operation->second.job==event.job) {
                if (operation->second.synchronization_owner) {
                    const auto source=synchronized_sources_.find(operation->second.synchronization_owner);
                    if (source!=synchronized_sources_.end()) source->second->connections.insert(connection);
                }
                if (operation->second.deferrable_token) {
                    const auto transaction=deferred_sources_.find(operation->second.deferrable_token);
                    if (transaction!=deferred_sources_.end()) transaction->second->connections.insert(connection);
                }
                if (operation->second.rendezvous_owner) {
                    const auto transaction=rendezvous_sources_.find(operation->second.rendezvous_owner);
                    if (transaction!=rendezvous_sources_.end()) transaction->second->connections.insert(connection);
                }
                if (operation->second.rendezvous_read_owner) {
                    const auto owner=rendezvous_targets_.find(operation->second.rendezvous_read_owner);
                    if (owner!=rendezvous_targets_.end()) owner->second->connections.insert(connection);
                }
                operation->second.local_pdc=event.local_pdc;
                operation->second.connection_start_psn=event.connection_start_psn;
                operation->second.last_transmitted_psn=event.sequence;
                operation->second.end_of_message_transmitted|=event.end_of_message;
                if (!operation->second.is_datagram)
                    operation->second.awaiting_semantic_responses.insert(event.sequence);
            } else if (auto lease=message_leases_.find(event.message_id);lease!=message_leases_.end()) {
                auto& retained=lease->second;
                retained.connection=connection; retained.last_psn=event.sequence;
                retained.end_of_message_transmitted|=event.end_of_message;
                if (retained.requires_connection_retirement && !retained.connection_close_requested)
                    retained.connection_close_requested=host_.request_connection_close(event.local_pdc);
            }
            fragment_transmitted(event.message_id);
        } else if (event.kind==Runtime::PdcEventKind::TransmitCleared) {
            auto previous=transmit_clear_frontiers_.find(connection);
            if (previous!=transmit_clear_frontiers_.end() && event.sequence-previous->second>=0x80000000u) return;
            transmit_clear_frontiers_[connection]=event.sequence;
            for (auto lease=message_leases_.begin();lease!=message_leases_.end();) {
                if (lease->second.connection==connection && !lease->second.requires_connection_retirement && lease->second.end_of_message_transmitted &&
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
                    (message->second.completed && event.sequence-message->second.end_of_message_psn<0x80000000u);
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
                        if (unfinished.rendezvous_target) fail_rendezvous_target(unfinished.rendezvous_target,
                            unfinished.target_error,static_cast<uint8_t>(SemanticReturnCode::Undeliverable),0);
                        if (unfinished.reserved_restart) retire_deferred_target(unfinished.reserved_restart);
                    }
                    release_unexpected(message->second);
                    complete_deferred_rendezvous_error(key);
                    if (message->second.synchronization_member) {
                        if (event.kind==Runtime::PdcEventKind::ConnectionClosed) process_synchronized_member(message->second,true);
                        synchronized_target_groups_.cleared(message->second.synchronization_member);
                    }
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
        drive_deferrable_sources(); drive_rendezvous_sources(); drive_synchronized_sources();
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
        const auto credit=read_packet_reservations_.find(ReadPacketIdentity::from(original));
        const auto confirmed=credit==read_packet_reservations_.end()?std::function<void()>{}:credit->second.data_confirmed;
        const auto failed=credit==read_packet_reservations_.end()?std::function<void()>{}:credit->second.data_failed;
        read_packet_reservations_.erase(ReadPacketIdentity::from(original));
        if (header.return_code==1 && confirmed) confirmed();
        if (header.return_code!=1 && failed) failed();
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
    void maybe_complete_returned_data(uint16_t message) {
        const auto found=pending_.find(message);
        if (found==pending_.end()) return;
        const auto& operation=found->second;
        if (operation.is_read && operation.read_results.bytes()==operation.length &&
            operation.end_of_message_transmitted && operation.awaiting_semantic_responses.empty())
            finish(message,CompletionStatus::Success,operation.length,static_cast<uint8_t>(SemanticReturnCode::Ok),operation.returned_generation);
        else if (operation.is_fetching_atomic && operation.atomic_result_placed &&
            operation.end_of_message_transmitted && operation.awaiting_semantic_responses.empty())
            finish(message,CompletionStatus::Success,operation.atomic_result_length,static_cast<uint8_t>(SemanticReturnCode::Ok),operation.returned_generation);
    }
    void place_atomic_result(uint16_t message,const SEStoPDS_pkt& packet) {
        const auto found=pending_.find(message);
        if (found==pending_.end()) return;
        auto& operation=found->second;
        const auto& header=packet.bth_header.Semantic_Response_with_Data_Header;
        if (!operation.is_fetching_atomic || operation.atomic_result_placed) return;
        if (header.version || header.opcode!=2 || header.return_code!=1 || header.message_offset ||
            header.modified_length!=operation.length || header.payload_length!=operation.atomic_result_length ||
            packet.payload.size()!=operation.atomic_result_length) {
            finish(message,CompletionStatus::LocalError,0,0); return;
        }
        try {
            auto native_bytes=packet.payload;
            std::reverse(native_bytes.begin(),native_bytes.end()); // Exactly one network-order element.
            if (operation.atomic_registration) {
                const auto& destination=*operation.atomic_result;
                if (native_bytes.empty()) memory_.authorize_registration(*operation.atomic_registration,operation.job,destination.pid,
                    destination.offset,0,Access::Write,destination.resource_index);
                else memory_.write_registration(*operation.atomic_registration,operation.job,destination.pid,
                    destination.offset,native_bytes,destination.resource_index);
            }
        } catch (const MemoryAccessError&) { finish(message,CompletionStatus::LocalError,0,0); return; }
        operation.atomic_result_placed=true;
        trace_.record(node_,"atomic_result_placed",operation.atomic_result_length);
        maybe_complete_returned_data(message);
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
        if (addition==ReadCoverage::Addition::Added && !operation.read_requests_awaiting_data.erase(offset)) {
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
        if (addition==ReadCoverage::Addition::Added && operation.rendezvous_read_owner) {
            const auto owner=rendezvous_targets_.find(operation.rendezvous_read_owner);
            if (owner!=rendezvous_targets_.end()) owner->second->placed_bytes.cover(offset,
                static_cast<uint32_t>(packet.payload.size()),owner->second->header.request_length);
        }
        trace_.record(node_,"read_result_placed",operation.read_results.bytes());
        maybe_complete_returned_data(message);
        feed_submissions();
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
        if (response.delivery_mode==RUDI) { respond_rudi(response); return; }
        if (response.original_request_format==Optimized_Header || response.original_request_format==Small_Message_RMA_Header) {
            const auto pending=pending_.find(response.local_submission_id);
            if (pending==pending_.end() || pending->second.wire_semantic_format!=response.original_request_format ||
                response.pkt.bth_type!=Semantic_Response_Header || response.pkt.bth_header.Semantic_Response_Header.message_id) return;
            auto projected=response; projected.original_request_format=Standard_Header;
            projected.pkt.bth_header.Semantic_Response_Header.message_id=response.local_submission_id;
            // This projection never reaches the encoder. The ordinary engine
            // still verifies FEP, PDC incarnation, Job and outstanding PSN.
            respond(projected); return;
        }
        if (response.PDCID>=MAX_PDC && response.PDCID<MAX_PDC*2) { complete_read_return(response); return; }
        if (response.pkt.bth_type==Semantic_Response_with_Data_Header) {
            const auto& header=response.pkt.bth_header.Semantic_Response_with_Data_Header;
            const auto pending=pending_.find(header.read_request_msg_id);
            if (pending==pending_.end() || (!pending->second.is_read && !pending->second.is_fetching_atomic)) return;
            auto& operation=pending->second;
            if (response.source_fep!=operation.peer || header.job_id!=operation.job ||
                response.PDCID!=operation.local_pdc || response.connection_start_psn!=operation.connection_start_psn ||
                !operation.awaiting_semantic_responses.erase(response.original_sequence)) return;
            if (operation.is_fetching_atomic) place_atomic_result(header.read_request_msg_id,response.pkt);
            else place_read_result(header.read_request_msg_id,response.pkt);
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
        if (it->second.rendezvous_owner) {
            handle_rendezvous_result(semantic_header.message_id,semantic_header); return;
        }
        if (it->second.deferrable_token) {
            handle_deferrable_result(semantic_header.message_id,semantic_header);
            return;
        }
        if (semantic_header.return_code!=1) {
            finish(semantic_header.message_id,CompletionStatus::RemoteError,
                it->second.is_read?static_cast<uint32_t>(it->second.read_results.bytes()):semantic_header.modified_length,
                semantic_header.return_code,semantic_header.ri_generation);
            return;
        }
        // A positive forward READ result accepts the request; success still
        // requires all returned data to be placed (§3.5.20.2.2).
        if (it->second.is_read || it->second.is_fetching_atomic) { maybe_complete_returned_data(semantic_header.message_id); return; }
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
    void respond_rudi(const PDC_SES_rsp& response) {
        const auto message=response.rudi_message_id;
        const auto found=pending_.find(message);
        if (found==pending_.end() || !found->second.is_rudi || response.source_fep!=found->second.peer ||
            !found->second.awaiting_rudi_responses.erase(response.rudi_packet_id)) return;
        if (response.rudi_timed_out) { finish(message,CompletionStatus::Timeout,0,0); return; }
        const bool read=found->second.is_read;
        if (response.pkt.bth_type==Semantic_Response_Header) {
            const auto& header=response.pkt.bth_header.Semantic_Response_Header;
            if (header.return_code!=1) {
                finish(message,CompletionStatus::RemoteError,0,header.return_code,header.ri_generation); return;
            }
            if (read || header.modified_length!=found->second.length) {
                finish(message,CompletionStatus::LocalError,0,0); return;
            }
            found->second.completed_length+=std::min<uint32_t>(mtu_,found->second.length-response.rudi_request_offset);
            found->second.returned_generation=header.ri_generation;
        } else if (read) place_read_result(message,response.pkt);
        else { finish(message,CompletionStatus::LocalError,0,0); return; }
        // Keep the ordinary source producer bounded by actual per-packet
        // responses. RUDI has no PDC window to provide this storage bound.
        fragment_transmitted(message);
        const auto active=pending_.find(message);
        if (active!=pending_.end() && active->second.rudi_all_submitted && active->second.awaiting_rudi_responses.empty()) {
            const auto length=read?static_cast<uint32_t>(active->second.read_results.bytes()):active->second.completed_length;
            if (length!=active->second.length) finish(message,CompletionStatus::LocalError,length,0);
            else finish(message,CompletionStatus::Success,length,1,active->second.returned_generation);
        }
    }
    void reply(const PDC_SES_req& request, uint8_t code, uint32_t length, bool report_message_result=true,
                std::optional<uint8_t> returned_generation={},ResponseDelivery delivery=ResponseDelivery::Guaranteed) {
        SES_PDS_rsp response{}; response.PDCID=request.PDCID;
        response.rx_pkt_handle=request.rx_pkt_handle; response.rsp_len=12;
        response.rsp.bth_type=Semantic_Response_Header;
        auto& semantic_header=response.rsp.bth_header.Semantic_Response_Header;
        // A fully processed intermediate packet can return DEFAULT immediately
        // (§3.5.13). If EOM arrives before a RUD hole is filled, keep its result
        // as NO_RESPONSE (Table 3-24, RC_NULL); it cannot finish the message.
        // Deferrable-as-SEND instead signals acceptance with OK/full length
        // (§3.4.4.6.1); the source still needs results for every data packet.
        const bool incomplete_end=!report_message_result && request.pkt.bth_header.Standard_Header.eom &&
            request.pkt.bth_header.Standard_Header.opcode!=0x08 && request.pkt.bth_header.Standard_Header.opcode!=0x0b;
        semantic_header.version=0; semantic_header.return_code=incomplete_end?0:code;
        semantic_header.job_id=request.pkt.bth_header.Standard_Header.job_id;
        semantic_header.message_id=request.pkt.bth_header.Standard_Header.msg_id;
        semantic_header.modified_length=!report_message_result && !incomplete_end?
            request.pkt.bth_header.Standard_Header.request_length:length;
        semantic_header.ri_generation=returned_generation.value_or(request.pkt.bth_header.Standard_Header.ri_generation);
        const auto received_message=incoming_.find(receive_message_key(request));
        if (received_message!=incoming_.end()) semantic_header.list=received_message->second.response_list;
        // §3.4.4.3: all non-error results of one message retain the same
        // encoding. A full EXPECTED success is DEFAULT even at EOM; its
        // guaranteed-delivery marker still requests Clear to retire state.
        // Buffered unexpected payload uses OVERFLOW throughout, including
        // after late placement. Its non-default list requires RESPONSE and
        // guaranteed delivery; it must never be hidden by ACK coalescing.
        const auto& request_header=request.pkt.bth_header.Standard_Header;
        const bool default_result=!incomplete_end && code==1 && !semantic_header.list &&
            semantic_header.modified_length==request_header.request_length &&
            semantic_header.ri_generation==request_header.ri_generation;
        semantic_header.opcode=incomplete_end?3:default_result?0:1;
        response.gtd_del=!incomplete_end && delivery==ResponseDelivery::Guaranteed &&
            (report_message_result || !default_result);
        if (!host_.manager().pushSESResponse(response)) throw std::runtime_error("PDS rejected semantic response");
        host_.wake();
    }
    void reply(const PDC_SES_req& request,SemanticReturnCode code,uint32_t length,bool report_message_result=true,
                std::optional<uint8_t> returned_generation={},ResponseDelivery delivery=ResponseDelivery::Guaranteed) {
        reply(request,static_cast<uint8_t>(code),length,report_message_result,returned_generation,delivery);
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
    static uint8_t nondeferring_send_opcode(uint8_t opcode) {
        // §3.4.4.6.1 applies to both nonmatching and tagged deferrable SEND.
        // This target policy ignores restart tokens and accepts only full
        // delivery or NO_MATCH; it never promises a later RTR.
        return opcode==0x08?0x05:opcode==0x0b?0x09:opcode;
    }
    static ResourceSpace message_space(uint8_t opcode) {
        return opcode==5?ResourceSpace::Send:opcode==9?ResourceSpace::Tagged:ResourceSpace::Rma;
    }
    static bool posting_matches(const Posted& receive,uint32_t job,uint16_t pid,uint16_t resource_index,
                                bool relative,bool tagged,uint64_t tag,uint32_t initiator) {
        if (receive.match.has_value()!=tagged || (relative && receive.job!=job) ||
            receive.pid!=pid || receive.resource_index!=resource_index) return false;
        // §3.4.2.3.4: directed matching applies to SEND/UUD as well as tag.
        // A rank never acquires meaning outside its JobID, even with an
        // absolute PID. Network FEP identity and this rank are distinct fields.
        const auto required_initiator=tagged?receive.match->initiator:receive.initiator;
        if (required_initiator && (receive.job!=job || *required_initiator!=initiator)) return false;
        if (!tagged) return true;
        const auto& match=*receive.match;
        // §3.4.2.3.5: one FIFO among all matching exact/wildcard postings.
        return !((tag^match.tag)&~match.ignore);
    }
    void post_buffer(uint32_t job,uint16_t pid,uint64_t key,uint64_t offset,uint32_t capacity,
                     uint64_t context,uint16_t resource_index,std::optional<TaggedReceiveMatch> match,std::optional<uint32_t> initiator={}) {
        if (closed_) throw std::logic_error("endpoint closed");
        const auto registration=memory_.authorize_local(job,pid,key,offset,capacity,Access::Write,resource_index);
        if (posted_.size()>=4096) throw std::runtime_error("receive queue full");
        const auto space=match?ResourceSpace::Tagged:ResourceSpace::Send;
        posted_.push_back({job,pid,key,offset,capacity,context,resource_index,registration,std::move(match),initiator});
        match_unexpected();
        const auto disabled=disabled_generations_.find({pid,resource_index,space});
        if (disabled!=disabled_generations_.end()) {
            resources_.recover_after_exhaustion(pid,resource_index,space,disabled->second);
            disabled_generations_.erase(disabled);
        }
    }
    static std::optional<uint64_t> received_tag(const Incoming& message) {
        return message.opcode==9?std::optional<uint64_t>{message.tag}:std::nullopt;
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
        // All buffered message kinds compete in one semantic arrival order.
        // The kind is local metadata, not a wire token or an MR namespace.
        enum class BufferedKind { Payload, DeferrableHeader, RendezvousHeader };
        std::map<uint64_t,std::pair<BufferedKind,uint64_t>> arrivals;
        for (const auto& entry:deferred_order_) arrivals.emplace(entry.first,std::make_pair(BufferedKind::DeferrableHeader,entry.second));
        for (const auto& entry:rendezvous_order_) arrivals.emplace(entry.first,std::make_pair(BufferedKind::RendezvousHeader,entry.second));
        for (const auto& entry:unexpected_order_) arrivals.emplace(entry.first,std::make_pair(BufferedKind::Payload,0));
        for (const auto& arrival:arrivals) {
            if (arrival.second.first==BufferedKind::DeferrableHeader) { match_deferred_target(static_cast<uint32_t>(arrival.second.second)); continue; }
            if (arrival.second.first==BufferedKind::RendezvousHeader) { match_rendezvous_target(arrival.second.second); continue; }
            const auto order=unexpected_order_.find(arrival.first);
            if (order==unexpected_order_.end()) continue;
            const auto key=order->second;
            auto found=incoming_.find(key);
            if (found==incoming_.end() || !found->second.unexpected) { unexpected_order_.erase(order); continue; }
            auto& message=found->second;
            auto posted=std::find_if(posted_.begin(),posted_.end(),[&](const Posted& receive) {
                return posting_matches(receive,std::get<2>(key),message.pid,message.resource_index,
                    message.relative_addressing,message.opcode==9,message.tag,std::get<3>(key));
            });
            if (posted==posted_.end()) continue;
            const auto receive=*posted; posted_.erase(posted);
            message.key=receive.key; message.base=receive.offset; message.context=receive.context;
            message.receive_registration=receive.registration;
            message.matched_receive=true;
            auto buffered=message.unexpected;
            release_unexpected(message);
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
                if (message.end_seen && message.received==message.total) {
                    message.completed=true; message.completion_reported=true;
                    completions_.push_back({0,message.context,CompletionStatus::Success,message.total,1,true,message.immediate_data,0,0,received_tag(message)});
                    if (message.deferred_response) {
                        message.end_of_message_psn=message.deferred_response->orig_psn;
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
        const bool unsolicited_completion=message.opcode!=static_cast<uint8_t>(OperationType::Send) && message.opcode!=9 && has_header_data;
        if (!message.matched_receive && !unsolicited_completion) return;
        Completion completion{0,message.context,message.target_error,static_cast<uint32_t>(message.received),
            static_cast<uint8_t>(*message.first_error),true,
            has_header_data?message.immediate_data:std::optional<uint64_t>{},message.error_generation};
        completion.original_length=message.total; completion.tag=received_tag(message);
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
        if (message.synchronization_member && !message.initialized &&
            (code==SemanticReturnCode::BadGeneration || code==SemanticReturnCode::DisabledGeneration))
            message.completion_reported=true; // No target resource was admitted for this retryable attempt.
        report_receive_error(message);
        if (message.reserved_restart) retire_deferred_target(message.reserved_restart);
        process_synchronized_member(message,true);
        if (message.opcode==2) {
            const auto credit=read_packet_reservations_.find(ReadPacketIdentity::from(request));
            if (credit!=read_packet_reservations_.end()) {
                const auto failed=credit->second.data_failed;
                credit->second.data_confirmed={}; credit->second.data_failed={};
                if (failed) failed(); // An error ACK never confirms payload delivery.
            }
        }
        // The packet that exposed the error gets the first guarantee. A
        // previously held EOM may also need an explicit result, but it must
        // not steal that guarantee merely because its handle was deferred.
        reply_error(request,message);
        for (const auto& response:message.synchronization_responses)
            if (response.orig_psn!=request.orig_psn) reply_error(response,message);
        message.synchronization_responses.clear();
        if (message.deferred_response) {
            if (message.deferred_response->orig_psn!=request.orig_psn)
                reply_error(*message.deferred_response,message);
            message.deferred_response.reset();
        }
    }
    static MessageKey receive_message_key(const PDC_SES_req& request) {
        const auto& header=request.pkt.bth_header.Standard_Header;
        const bool no_mid=request.request_wire_format==Optimized_Header || request.request_wire_format==Small_Message_RMA_Header;
        // Optimized messages contain exactly one packet. Mark its full PSN so
        // PSN0 cannot alias STD MID0 on a shared RUD/ROD connection.
        const uint64_t identity=no_mid?kPacketMessageIdentity|request.orig_psn:header.msg_id;
        return {request.source_fep,request.PDCID,header.job_id,header.initiator,identity,request.connection_start_psn};
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
            const uint8_t opcode=header.opcode==0x10?1:header.opcode==0x11?3:header.opcode==6?5:header.opcode==10?9:nondeferring_send_opcode(header.opcode);
            Incoming message{opcode,static_cast<uint32_t>(header.request_length),header.match_bits,header.buffer_offset,0,0};
            message.has_immediate=header.hd; message.error_generation=header.ri_generation; message.tag=header.match_bits;
            message.rendezvous_eager=header.opcode==6 || header.opcode==10;
            if (message.rendezvous_eager) message.completion_reported=true; // The transaction owns the single receive CQ.
            if (request.request_wire_format==Standard_Header && (header.opcode==0x10 || header.opcode==0x11)) {
                const bool atomic=header.opcode==0x11;
                if (request.pkt.eth_type!=(atomic?Synchronized_Atomic_Extension_Headers:Synchronized_Operation_Extension_Header))
                    message.synchronization_admission_error=SemanticReturnCode::OperationViolation;
                else {
                    const auto& extension=synchronization_extension(request.pkt);
                    const auto previous=synchronized_target_groups_.current({request.source_fep,extension.sync_group});
                    // All source ACKs may precede the receiver applying Clear,
                    // including this request's piggyback Clear queued by PDS.
                    // Wait for its retirement event instead of rejecting legal
                    // group reuse as an excess member of the completed group.
                    if (previous && previous->state==SynchronizationGroups::State::Completed)
                        return Runtime::SemanticAdmission::NoSynchronizationState;
                    const auto reservation=synchronized_target_groups_.reserve({request.source_fep,extension.sync_group},
                        header.job_id,atomic || header.hd,extension.sync_count,loop_.now());
                    if (reservation.status==SynchronizationGroups::Admission::NoState)
                        return Runtime::SemanticAdmission::NoSynchronizationState;
                    if (reservation.status==SynchronizationGroups::Admission::NoMessageState)
                        return Runtime::SemanticAdmission::Rejected;
                    message.synchronization_member=reservation.member; message.synchronization_group=extension.sync_group;
                    message.synchronization_count=extension.sync_count; message.synchronized_atomic=atomic;
                    if (reservation.new_group) arm_synchronized_target(reservation.owner);
                    if (reservation.status!=SynchronizationGroups::Admission::Accepted)
                        message.synchronization_admission_error=reservation.status==SynchronizationGroups::Admission::WrongJob?
                            SemanticReturnCode::PermissionViolation:SemanticReturnCode::OperationViolation;
                }
            }
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
        if (found->second.synchronization_member) {
            const auto group=synchronized_target_groups_.member_snapshot(found->second.synchronization_member);
            synchronized_target_groups_.rollback(found->second.synchronization_member);
            if (group && !synchronized_target_groups_.snapshot(group->owner)) {
                const auto timer=synchronized_target_timers_.find(group->owner);
                if (timer!=synchronized_target_timers_.end()) { loop_.cancel(timer->second); synchronized_target_timers_.erase(timer); }
            }
        }
        incoming_.erase(found);
    }
    void retire_deferred_target(uint32_t token) {
        const auto found=deferred_targets_.find(token); if (found==deferred_targets_.end()) return;
        deferred_order_.erase(found->second->arrival_order);
        deferred_targets_.erase(found);
    }
    void fail_deferred_target(uint32_t token,CompletionStatus status,uint8_t code) {
        const auto found=deferred_targets_.find(token); if (found==deferred_targets_.end()) return;
        const auto target=found->second;
        if (target->receive && target->restart_started) {
            // The restarted Incoming owns application delivery. Poison it
            // before dropping token authority, so late data cannot place bytes
            // after a fatal PDC/control failure or endpoint cancellation.
            for (auto& incoming:incoming_) if (incoming.second.reserved_restart==token) {
                auto& message=incoming.second;
                if (!message.first_error) message.first_error=SemanticReturnCode::Undeliverable;
                message.target_error=status; report_receive_error(message);
            }
        } else if (target->receive) {
            const auto& receive=*target->receive;
            completions_.push_back({0,receive.context,status,0,code,true,target->immediate,0,
                target->header.request_length,target->header.opcode==0x0b?std::optional<uint64_t>{static_cast<uint64_t>(target->header.match_bits)}:std::nullopt});
        }
        retire_deferred_target(token);
    }
    void match_deferred_target(uint32_t token) {
        const auto found=deferred_targets_.find(token); if (found==deferred_targets_.end()) return;
        const auto target=found->second;
        if (target->receive) return;
        const auto& header=target->header;
        const auto posted=std::find_if(posted_.begin(),posted_.end(),[&](const Posted& receive) {
            return posting_matches(receive,header.job_id,target->selected.absolute_pid,target->selected.resource_index,
                header.rel,header.opcode==0x0b,header.match_bits,header.initiator);
        });
        if (posted==posted_.end()) return;
        target->receive=*posted; posted_.erase(posted);
        deferred_order_.erase(target->arrival_order);
        if (target->initial_end && target->initial_start) send_restart(target);
    }
    void send_restart(const std::shared_ptr<DeferredTarget>& target) {
        // §3.4.4.6 / Figure3-14: J=0 is a header-only capture policy. A
        // nonzero target token reserves this exact posting, not a future key
        // lookup. RTR itself uses the same reliable PDS/MID/Clear lifecycle.
        if (target->restart_sent) return;
        target->restart_sent=true;
        Operation control;
        control.type=static_cast<OperationType>(0x0c); control.delivery_mode=RUD;
        control.peer=target->peer; control.job=target->header.job_id;
        control.source_pid=target->selected.absolute_pid;
        control.target_pid=target->header.PIDonFEP; control.target_resource=target->header.resource_index;
        control.initiator_id=target_restart_initiator_;
        control.remote_key=(uint64_t{target->token}<<32)|target->source_token;
        control.remote_offset=0; control.read_length=target->header.request_length;
        control.relative_addressing=target->header.rel;
        // ID0 is private protocol work. Public submit cannot obtain the
        // restart_owner capability or impersonate an internal RTR producer.
        submit_message(std::move(control),0,0,target->token);
        trace_.record(node_,"deferrable_rtr_sent",target->token);
    }
    bool deferred_metadata_matches(const DeferredTarget& target,const PDC_SES_req& request) const {
        const auto& current=request.pkt.bth_header.Standard_Header;
        const auto& original=target.header;
        return request.source_fep==target.peer && current.job_id==original.job_id &&
            current.initiator==original.initiator && (current.opcode==original.opcode || (current.opcode==0x0f && current.eom)) &&
            current.rel==original.rel && current.PIDonFEP==original.PIDonFEP && current.resource_index==original.resource_index &&
            current.match_bits==original.match_bits && current.request_length==original.request_length &&
            current.ri_generation==original.ri_generation &&
            current.hd==original.hd && (!current.som || !current.hd || !target.initial_start ||
                target.immediate==std::optional<uint64_t>{current.diff.som_true.header_data});
    }
    bool receive_deferrable_target(const PDC_SES_req& request) {
        const auto& header=request.pkt.bth_header.Standard_Header;
        const auto found=incoming_.find(receive_message_key(request));
        if (found==incoming_.end()) return false;
        auto& message=found->second;
        const bool deferrable=header.opcode==0x08 || header.opcode==0x0b;
        const bool reserved_abort=header.opcode==0x0f && static_cast<uint32_t>(header.buffer_offset);
        if (!message.captured_header && ((!deferrable && !reserved_abort) || !deferred_header_limit_)) return false;
        if (header.eom) { message.end_seen=true; message.end_of_message_psn=request.orig_psn; }
        const auto reject=[&](SemanticReturnCode code,std::optional<uint8_t> generation={}) {
            reject_message(request,message,code,generation);
        };
        if (message.first_error) { reject_message(request,message,*message.first_error); return true; }
        if (header.rel && !memory_.has_job(header.job_id)) { reject(SemanticReturnCode::BadJob); return true; }
        const uint32_t source_token=static_cast<uint32_t>(header.buffer_offset>>32);
        const uint32_t target_token=static_cast<uint32_t>(header.buffer_offset);
        if (message.reserved_restart) {
            if (target_token!=message.reserved_restart || source_token!=message.deferrable_source_token) {
                reject(SemanticReturnCode::OperationViolation); return true;
            }
            return false;
        }
        std::shared_ptr<DeferredTarget> target;
        if (message.captured_header) {
            const auto captured=deferred_targets_.find(message.captured_header);
            if (captured==deferred_targets_.end()) { reject(SemanticReturnCode::OperationViolation); return true; }
            target=captured->second;
        } else if (target_token) {
            const auto captured=deferred_targets_.find(target_token);
            if (captured==deferred_targets_.end() || captured->second->source_token!=source_token ||
                !captured->second->receive || captured->second->restart_started || !captured->second->initial_end ||
                !deferred_metadata_matches(*captured->second,request)) {
                reject(SemanticReturnCode::OperationViolation); return true;
            }
            target=captured->second;
            // The token pins one posting. Even a revoked/reused public MR key
            // cannot replace the registration identity stored in this record.
            const auto& receive=*target->receive;
            message.pid=target->selected.absolute_pid; message.resource_index=target->selected.resource_index;
            message.wire_pid=header.PIDonFEP; message.relative_addressing=header.rel;
            message.key=receive.key; message.base=receive.offset; message.context=receive.context;
            message.receive_registration=receive.registration; message.matched_receive=true;
            message.initialized=true; message.reserved_restart=target_token; message.deferrable_source_token=source_token;
            message.opcode=nondeferring_send_opcode(target->header.opcode);
            target->restart_started=true;
            if (header.opcode==0x0f || header.ie) return false; // Poisoned data never touches MR storage.
            try {
                if (receive.capacity<header.request_length) {
                    message.target_error=CompletionStatus::Truncated; reject(SemanticReturnCode::UnsupportedSize); return true;
                }
                memory_.authorize_registration(receive.registration,header.job_id,receive.pid,receive.offset,
                    header.request_length,Access::Write,receive.resource_index);
            } catch (const MemoryAccessError& error) { reject(memory_code(error.code)); return true; }
            return false; // Ordinary data placement retains all per-fragment checks.
        } else if (message.initialized) return false; // Sticky full acceptance.
        else {
            ResourceSelection selected{};
            try {
                selected=resources_.resolve(header.job_id,header.rel,header.PIDonFEP,header.resource_index,
                    header.opcode==0x0b?ResourceSpace::Tagged:ResourceSpace::Send,header.ri_generation);
            } catch (const AddressingError& error) { reject(error.code,error.generation); return true; }
            const auto posted=std::find_if(posted_.begin(),posted_.end(),[&](const Posted& receive) {
                return posting_matches(receive,header.job_id,selected.absolute_pid,selected.resource_index,
                    header.rel,header.opcode==0x0b,header.match_bits,header.initiator);
            });
            if (posted!=posted_.end()) return false;
            auto& token_cursor=host_.services().next_semantic_restart_token;
            // Only the initial TARGET token is required to be zero. A peer
            // may legitimately allocate source token0 (§3.4.3.1); its identity
            // remains the checked FEP/Job/rank tuple, not a truthiness test.
            if (deferred_targets_.size()>=deferred_header_limit_ || !token_cursor || token_cursor>UINT32_MAX) {
                reject(SemanticReturnCode::NoMatch); return true;
            }
            const auto existing_token=std::find_if(deferred_targets_.begin(),deferred_targets_.end(),[&](const auto& captured) {
                return captured.second->peer==request.source_fep && captured.second->source_token==source_token;
            });
            if (existing_token!=deferred_targets_.end()) {
                reject(existing_token->second->header.job_id==header.job_id?
                    SemanticReturnCode::OperationViolation:SemanticReturnCode::PermissionViolation);
                return true;
            }
            // Reject malformed requests before allocating a transaction header.
            const auto offset=header.som?0:header.diff.som_false.message_offset;
            if (header.version || header.ie || offset>header.request_length || request.pkt.payload.size()>header.request_length-offset ||
                (!header.som && header.diff.som_false.payload_length!=request.pkt.payload.size())) {
                reject(header.ie?SemanticReturnCode::InitiatorError:SemanticReturnCode::UnsupportedSize); return true;
            }
            target=std::make_shared<DeferredTarget>();
            target->token=static_cast<uint32_t>(token_cursor++); target->source_token=source_token;
            target->peer=request.source_fep; target->header=header; target->selected=selected;
            target->arrival_order=++next_receive_order_;
            target->initial_connection=ConnectionKey{request.source_fep,request.PDCID,request.connection_start_psn};
            deferred_targets_.emplace(target->token,target); deferred_order_.emplace(target->arrival_order,target->token);
            message.captured_header=target->token; message.initialized=true;
            message.pid=selected.absolute_pid; message.resource_index=selected.resource_index;
            message.wire_pid=header.PIDonFEP; message.relative_addressing=header.rel;
            message.response_list=1; message.completion_reported=true;
            trace_.record(node_,"deferrable_header_captured",source_token);
        }
        if (header.opcode==0x0f || header.ie) {
            fail_deferred_target(target->token,CompletionStatus::RemoteError,static_cast<uint8_t>(SemanticReturnCode::InitiatorError));
            reject(SemanticReturnCode::InitiatorError); return true;
        }
        const auto offset=header.som?0:header.diff.som_false.message_offset;
        if (!deferred_metadata_matches(*target,request) || source_token!=target->source_token || target_token ||
            header.version || offset>header.request_length || request.pkt.payload.size()>header.request_length-offset ||
            (!header.som && header.diff.som_false.payload_length!=request.pkt.payload.size())) {
            fail_deferred_target(target->token,CompletionStatus::RemoteError,static_cast<uint8_t>(SemanticReturnCode::OperationViolation));
            reject(SemanticReturnCode::OperationViolation); return true;
        }
        if (header.som) {
            target->initial_start=true;
            if (header.hd) target->immediate=header.diff.som_true.header_data;
        }
        if (header.eom) { target->initial_end=true; message.completed=true; }
        // Header capture deliberately retains no eager bytes. All initial
        // packets report the same OVERFLOW/OK/0, including the early EOM.
        reply(request,SemanticReturnCode::Ok,0);
        if (target->initial_end && target->initial_start) {
            if (target->receive) send_restart(target); else match_unexpected();
        }
        return true;
    }

    void receive_restart(const PDC_SES_req& request) {
        const auto& header=request.pkt.bth_header.Standard_Header;
        const auto reserved=incoming_.find(receive_message_key(request));
        if (reserved==incoming_.end()) throw std::logic_error("unreserved RTR control message");
        auto& message=reserved->second;
        message.completion_reported=true; // Protocol control never consumes a receive or posts its own CQ.
        if (header.eom) { message.end_seen=true; message.end_of_message_psn=request.orig_psn; }
        const auto reject=[&](SemanticReturnCode code) { reject_message(request,message,code); };
        if (message.first_error) { reply_error(request,message); return; }
        if (header.version || !header.som || !header.eom || !request.pkt.payload.empty()) {
            reject(SemanticReturnCode::UnsupportedSize); return;
        }
        if (header.ie) { reject(SemanticReturnCode::InitiatorError); return; }
        if (header.rel && !memory_.has_job(header.job_id)) { reject(SemanticReturnCode::BadJob); return; }
        // Tokens are sender/receiver relative on each wire message. RTR is
        // sent in the reverse direction: its low half identifies this FEP's
        // original initiating transaction; the high half is the peer's token.
        const auto source_token=static_cast<uint32_t>(header.match_bits);
        const auto found=deferred_sources_.find(source_token);
        if (found==deferred_sources_.end()) { reject(SemanticReturnCode::OperationViolation); return; }
        const auto transaction=found->second;
        const auto expected_peer_rank=transaction->original.peer_initiator_id.value_or(transaction->original.peer);
        if (header.job_id!=transaction->original.job) { reject(SemanticReturnCode::PermissionViolation); return; }
        if (request.source_fep!=transaction->original.peer || header.initiator!=expected_peer_rank) {
            reject(SemanticReturnCode::OperationViolation); return;
        }
        if (header.buffer_offset>UINT32_MAX-1u || header.buffer_offset>transaction->total ||
            header.request_length>transaction->total-header.buffer_offset) {
            reject(SemanticReturnCode::BadAddress); return;
        }
        const RestartRequest restart{static_cast<uint32_t>(header.match_bits>>32),static_cast<uint32_t>(header.buffer_offset),
            static_cast<uint32_t>(header.request_length)};
        const bool same_reserved=restart.target_token && transaction->last_restart && *transaction->last_restart==restart;
        if (!same_reserved) {
            if (transaction->phase==DeferredSource::Phase::Backoff ||
                (transaction->first_response_seen && !transaction->deferred && transaction->phase==DeferredSource::Phase::Sending) ||
                (transaction->pending_restart && !(*transaction->pending_restart==restart))) {
                reject(SemanticReturnCode::OperationViolation); return;
            }
            transaction->pending_restart=restart;
        }
        // All identity/range checks precede token consumption. A bad Job,
        // rank or length must not steal another transaction's restart state.
        message.initialized=true; message.completed=true;
        reply(request,SemanticReturnCode::Ok,header.request_length);
        drive_deferrable_sources();
    }

    void receive_read(const PDC_SES_req& request) {
        const auto& header=request.pkt.bth_header.Standard_Header;
        auto& message=incoming_.at(receive_message_key(request));
        if (header.eom) { message.end_seen=true; message.end_of_message_psn=request.orig_psn; }
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
            (!header.som && header.diff.som_false.payload_length) || offset%mtu_) {
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
        if (!bind_rendezvous_read(request,offset,count)) return;
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
            if (header.request_length<=host_.services().max_ack_data_size || host_.services().max_ack_data_size>=mtu_) {
                // §3.5.17: PDS keeps only this PSN's required-delivery marker,
                // never a post-transmit snapshot of the READ result.
                SES_PDS_rsp response{}; response.PDCID=request.PDCID; response.rx_pkt_handle=request.rx_pkt_handle;
                response.rsp_len=20+count; response.gtd_del=true; response.rsp=std::move(data);
                if (!host_.manager().pushSESResponse(response)) throw std::runtime_error("PDS rejected READ data ACK");
                message.completed=message.end_seen && message.read_requests.bytes()==message.total;
                trace_.record(node_,"read_ack_data",count); host_.wake();
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
    void receive_fetching_atomic(const PDC_SES_req& request) {
        const auto& header=request.pkt.bth_header.Standard_Header;
        const auto found=incoming_.find(receive_message_key(request));
        if (found==incoming_.end()) throw std::logic_error("PDS forwarded an unreserved fetching atomic");
        auto& message=found->second;
        if (header.eom) { message.end_seen=true; message.end_of_message_psn=request.orig_psn; }
        if (message.first_error) { reply_error(request,message); return; }
        // §3.5.17: completed fetching requests are replayed by the PDS unique
        // response cache. A READ-style re-execution must never reach this code.
        if (message.completed) { reply(request,SemanticReturnCode::OperationViolation,0); return; }
        const auto reject=[&](SemanticReturnCode code,std::optional<uint8_t> generation={}) {
            reject_message(request,message,code,generation);
        };
        if (header.version || !header.som || !header.eom || header.hd) {
            reject(SemanticReturnCode::AtomicUnsupportedSize); return;
        }
        if (header.ie) { reject(SemanticReturnCode::InitiatorError); return; }
        if (header.rel && !memory_.has_job(header.job_id)) { reject(SemanticReturnCode::BadJob); return; }
        const auto& extension=request.pkt.eth_header.Atomic_Operation_Extension_Header;
        if (extension.atomic_datatype>9) { reject(SemanticReturnCode::AtomicUnsupportedDatatype); return; }
        // Table3-29: CACHEABLE permits caching, rather than requiring it;
        // CPU_COHERENT is naturally satisfied by this serialized host-memory
        // event model. Ignore the reserved middle bits, reject unknown vendor
        // control encodings. Neither flag weakens MR checks or replay caching.
        if (extension.atomic_opcode>0x13 || (extension.semantic_contol&0xe0) || extension.rsvd) {
            reject(SemanticReturnCode::AtomicUnsupportedOperation); return;
        }
        const auto datatype=static_cast<IntegerAtomicDatatype>(extension.atomic_datatype);
        const auto operation=static_cast<IntegerAtomicOperation>(extension.atomic_opcode);
        const auto width=integer_atomic_width(datatype);
        const bool zero_length=header.request_length==0 &&
            (operation==IntegerAtomicOperation::Read || operation==IntegerAtomicOperation::Write);
        if ((!zero_length && header.request_length!=(dual_operand_atomic(operation)?32:width)) ||
            request.pkt.payload.size()!=header.request_length) { reject(SemanticReturnCode::AtomicUnsupportedSize); return; }
        if (header.buffer_offset%width) { reject(SemanticReturnCode::AtomicUnaligned); return; }
        ResourceSelection selected{};
        try {
            selected=resources_.resolve(header.job_id,header.rel,header.PIDonFEP,header.resource_index,
                ResourceSpace::Rma,header.ri_generation);
        } catch (const AddressingError& error) { reject(error.code,error.generation); return; }
        try {
            const auto operands=zero_length?FetchingAtomicOperands{}:decode_fetching_atomic_operands(request.pkt.payload,operation,datatype);
            auto previous=memory_.fetch_atomic_element(header.job_id,selected.absolute_pid,header.match_bits,
                header.buffer_offset,operation,datatype,operands.operand,operands.compare_or_mask,
                selected.resource_index,header.rel,zero_length);
            convert_integer_atomic_byte_order(previous,datatype);
            SES_PDS_rsp response{}; response.PDCID=request.PDCID; response.rx_pkt_handle=request.rx_pkt_handle;
            response.rsp_len=20+previous.size(); response.gtd_del=true;
            response.rsp.bth_type=Semantic_Response_with_Data_Header;
            auto& result=response.rsp.bth_header.Semantic_Response_with_Data_Header;
            result.opcode=2; result.return_code=1; result.job_id=header.job_id;
            result.read_request_msg_id=header.msg_id; result.payload_length=previous.size();
            result.modified_length=header.request_length; response.rsp.payload=std::move(previous);
            message.pid=selected.absolute_pid; message.resource_index=selected.resource_index;
            message.initialized=true; message.completed=true; message.completion_reported=true;
            message.received=header.request_length; message.segments.emplace(0,header.request_length);
            // PDS retains the old value until Clear, including when the MR is
            // changed or revoked after execution. SES retains no second copy.
            if (!host_.manager().pushSESResponse(response)) throw std::runtime_error("PDS rejected fetching atomic result");
            host_.wake(); trace_.record(node_,"fetching_atomic_executed",zero_length?0:width);
        } catch (const MemoryAccessError& error) { reject(memory_code(error.code)); }
    }
    // §3.4.2.13 / §3.5.23: inspect and place each packet independently.
    // Duplicates repeat the idempotent access. There is no Incoming record,
    // message assembly, recovery cache, target CQ, or Clear lifetime here.
    void receive_rudi(const PDC_SES_req& request) {
        if (request.pkt.bth_type!=Standard_Header) return;
        const auto& header=request.pkt.bth_header.Standard_Header;
        const auto respond=[&](SemanticReturnCode code,uint8_t generation) {
            SEStoPDS_pkt response{}; response.bth_type=Semantic_Response_Header;
            auto& result=response.bth_header.Semantic_Response_Header;
            result.opcode=1; result.return_code=static_cast<uint8_t>(code); result.job_id=header.job_id;
            result.message_id=header.msg_id; result.ri_generation=generation;
            result.modified_length=code==SemanticReturnCode::Ok?header.request_length:0;
            host_.respond_rudi(request,response); // A full output queue is recovered by source RTO.
        };
        const auto reject=[&](SemanticReturnCode code) { respond(code,header.ri_generation); };
        if (request.next_hdr!=UET_HDR_REQUEST_STD || header.version || header.hd || (header.opcode!=1 && header.opcode!=2)) {
            reject(SemanticReturnCode::UnsupportedOperation); return;
        }
        if (header.ie) { reject(SemanticReturnCode::InitiatorError); return; }
        if (header.rel && !memory_.has_job(header.job_id)) { reject(SemanticReturnCode::BadJob); return; }
        const uint32_t offset=header.som?0:header.diff.som_false.message_offset;
        const bool read=header.opcode==2;
        if (offset>header.request_length || request.pkt.payload.size()>header.request_length-offset ||
            request.pkt.payload.size()>mtu_ || (read && (!request.pkt.payload.empty() || offset%mtu_ ||
                (!header.som && header.diff.som_false.payload_length))) ||
            (!read && !header.som && header.diff.som_false.payload_length!=request.pkt.payload.size())) {
            reject(SemanticReturnCode::UnsupportedSize); return;
        }
        // Private rendezvous aliases require ACK/Clear-confirmed ownership.
        // An unacknowledged RUDI response cannot satisfy that contract. Do not
        // inherit the trusted RendezvousSource memory-access origin here.
        if (rendezvous_source_aliases_.count(header.match_bits)) { reject(SemanticReturnCode::UnsupportedOperation); return; }
        ResourceSelection selected{};
        try {
            selected=resources_.resolve(header.job_id,header.rel,header.PIDonFEP,header.resource_index,ResourceSpace::Rma,header.ri_generation);
        } catch (const AddressingError& error) { respond(error.code,error.generation); return; }
        const auto count=read?std::min<uint32_t>(mtu_,header.request_length-offset):static_cast<uint32_t>(request.pkt.payload.size());
        try {
            const auto& registration=memory_.authorize(header.job_id,selected.absolute_pid,header.match_bits,header.buffer_offset,
                header.request_length,read?Access::Read:Access::Write,selected.resource_index,header.rel);
            if (!registration.idempotent_safe) { reject(SemanticReturnCode::OperationViolation); return; }
            // Authorizing the full [base,base+request_length) span above proves
            // this addition fits. No wire address is a process pointer.
            const auto placement_offset=header.buffer_offset+offset;
            if (!read) {
                memory_.write(header.job_id,selected.absolute_pid,header.match_bits,placement_offset,request.pkt.payload,selected.resource_index,header.rel);
                trace_.record(node_,"rudi_write_placed",count); respond(SemanticReturnCode::Ok,selected.generation); return;
            }
            SEStoPDS_pkt response{}; response.bth_type=Semantic_Response_with_Data_Header;
            response.payload=memory_.read(header.job_id,selected.absolute_pid,header.match_bits,placement_offset,count,selected.resource_index,header.rel);
            auto& result=response.bth_header.Semantic_Response_with_Data_Header;
            result.opcode=2; result.return_code=1; result.job_id=header.job_id; result.read_request_msg_id=header.msg_id;
            result.message_offset=offset; result.payload_length=count; result.modified_length=header.request_length;
            host_.respond_rudi(request,response); trace_.record(node_,"rudi_read_executed",count);
        } catch (const MemoryAccessError& error) { reject(memory_code(error.code)); }
    }
    void receive(const PDC_SES_req& request) {
        const bool small=request.request_wire_format==Optimized_Header;
        const bool medium=request.request_wire_format==Small_Message_RMA_Header;
        if (!small && !medium) { receive_standard(request); return; }
        const auto found=incoming_.find(receive_message_key(request));
        if (found==incoming_.end()) throw std::logic_error("optimized request lacks admitted owner");
        auto& owner=found->second;
        const auto reject=[&](SemanticReturnCode code,std::optional<uint8_t> generation={}) {
            owner.end_seen=true; owner.end_of_message_psn=request.orig_psn;
            reject_message(request,owner,code,generation);
        };
        const auto& header=request.pkt.bth_header.Standard_Header;
        if (!header.som || !header.eom || header.request_length>mtu_) { reject(SemanticReturnCode::UnsupportedSize); return; }
        if ((header.opcode!=0 && header.opcode!=1 && !(medium && (header.opcode==5 || header.opcode==9))) ||
            (header.opcode==1 && header.hd)) { reject(SemanticReturnCode::UnsupportedOperation); return; }
        if (!small || header.opcode!=1) { receive_standard(request); return; }
        if (header.rel && !memory_.has_job(header.job_id)) { reject(SemanticReturnCode::BadJob); return; }
        try {
            const auto selected=resources_.resolve(header.job_id,header.rel,header.PIDonFEP,header.resource_index,
                ResourceSpace::Rma,header.ri_generation);
            auto projected=request;
            projected.pkt.bth_header.Standard_Header.match_bits=memory_.resolve_optimized_key(header.job_id,selected.absolute_pid,
                header.resource_index,header.rel);
            // Admission could reserve only the elided index, not the key's
            // region metadata. Bind that placeholder once to the resolved key
            // before the ordinary WRITE consistency and permission checks.
            if (!owner.initialized) owner.key=projected.pkt.bth_header.Standard_Header.match_bits;
            // Resolving an index is not access authorization. The existing
            // WRITE path below still checks live MR rights, scope and bounds.
            receive_standard(projected);
        } catch (const AddressingError& error) { reject(error.code,error.generation); }
        catch (const MemoryAccessError& error) { reject(memory_code(error.code)); }
    }
    void receive_standard(const PDC_SES_req& request) {
        if (request.delivery_mode==RUDI) { receive_rudi(request); return; }
        if (request.delivery_mode==UUD) { receive_datagram(request); return; }
        if (request.pkt.bth_type==Semantic_Response_with_Data_Header) { receive_return_data(request); return; }
        if (request.pkt.bth_type!=Standard_Header) { reply(request,SemanticReturnCode::UnsupportedOperation,0); return; }
        if (request.pkt.bth_header.Standard_Header.opcode==0x0c) { receive_restart(request); return; }
        const auto incoming=incoming_.find(receive_message_key(request));
        if (incoming!=incoming_.end() && incoming->second.rendezvous_eager) { receive_rendezvous(request); return; }
        if (receive_deferrable_target(request)) return;
        if (request.pkt.bth_header.Standard_Header.opcode==2) { receive_read(request); return; }
        if (request.pkt.bth_header.Standard_Header.opcode==4) { receive_fetching_atomic(request); return; }
        auto interpreted_header=request.pkt.bth_header.Standard_Header;
        // §3.3.5 / §3.4.4.6.1: a non-deferring target treats deferrable
        // SEND/TSEND as their ordinary forms. Interpret a copy: restart tokens
        // remain intact on the wire but are never an RMA or placement offset.
        const bool deferrable_as_send=interpreted_header.opcode==0x08 || interpreted_header.opcode==0x0b;
        const bool synchronized_write=interpreted_header.opcode==0x10;
        const bool synchronized_atomic=interpreted_header.opcode==0x11;
        if (synchronized_write) interpreted_header.opcode=1;
        if (synchronized_atomic) interpreted_header.opcode=3;
        if (deferrable_as_send) {
            interpreted_header.opcode=nondeferring_send_opcode(interpreted_header.opcode);
            if (interpreted_header.som) trace_.record(node_,"deferrable_as_send",interpreted_header.msg_id);
        }
        const auto& header=interpreted_header;
        const auto key=receive_message_key(request);
        auto found=incoming_.find(key);
        if (found==incoming_.end()) throw std::logic_error("PDS forwarded an unreserved standard SES message");
        auto& message=found->second;
        // Capture terminal/header metadata before validating synchronized
        // membership. A retryable address error may already have rolled its
        // provisional member back, but its old MID must still drain to EOM.
        if (header.som && message.opcode==0x0f && header.opcode!=0x0f)
            message.opcode=header.opcode;
        if (header.eom) { message.end_seen=true; message.end_of_message_psn=request.orig_psn; }
        if (header.som && header.hd) message.immediate_data=header.diff.som_true.header_data;
        if (message.first_error) {
            reject_message(request,message,*message.first_error); return;
        }
        if (synchronized_write || synchronized_atomic) {
            if (header.som) message.synchronization_start_seen=true;
            if (message.synchronization_admission_error) {
                if (header.som && header.hd) message.immediate_data=header.diff.som_true.header_data;
                if (header.eom) { message.end_seen=true; message.end_of_message_psn=request.orig_psn; }
                reject_message(request,message,*message.synchronization_admission_error); return;
            }
            if (request.pkt.eth_type!=(synchronized_atomic?Synchronized_Atomic_Extension_Headers:Synchronized_Operation_Extension_Header)) {
                reject_message(request,message,SemanticReturnCode::OperationViolation); return;
            }
            const auto& extension=synchronization_extension(request.pkt);
            if (!message.synchronization_member || message.synchronized_atomic!=synchronized_atomic ||
                message.synchronization_group!=extension.sync_group || message.synchronization_count!=extension.sync_count) {
                reject_message(request,message,SemanticReturnCode::OperationViolation); return;
            }
        } else if (message.synchronization_member && header.opcode!=0x0f) {
            reject_message(request,message,SemanticReturnCode::OperationViolation); return;
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
                    message_space(original_opcode),header.ri_generation);
            }
        } catch (const AddressingError& error) { reject(error.code,error.generation); return; }
        if (header.version || (header.hd && header.opcode!=1 && header.opcode!=5 && header.opcode!=9 && !message_error) ||
            (header.opcode!=0 && header.opcode!=1 && header.opcode!=3 && header.opcode!=5 && header.opcode!=9 && !message_error) ||
            (message_error && !header.eom)) {
            reject(SemanticReturnCode::UnsupportedOperation); return;
        }
        const auto offset=header.som?0:header.diff.som_false.message_offset;
        const auto count=request.pkt.payload.size();
        const auto& atomic_extension=synchronized_atomic?request.pkt.eth_header.Synchronized_Atomic_Extension_Headers.atomic:
            request.pkt.eth_header.Atomic_Operation_Extension_Header;
        if (header.opcode==3 && !poisoned) {
            if (atomic_extension.atomic_datatype>7) { reject(SemanticReturnCode::AtomicUnsupportedDatatype); return; }
            if (atomic_extension.atomic_opcode>12 || atomic_extension.atomic_opcode==11 ||
                atomic_extension.semantic_contol || atomic_extension.rsvd) { reject(SemanticReturnCode::AtomicUnsupportedOperation); return; }
            const auto width=integer_atomic_width(static_cast<IntegerAtomicDatatype>(atomic_extension.atomic_datatype));
            if (header.request_length%width || count%width || offset%width) { reject(SemanticReturnCode::AtomicUnsupportedSize); return; }
            if (header.buffer_offset%width) { reject(SemanticReturnCode::AtomicUnaligned); return; }
            if (synchronized_atomic && (header.hd || header.request_length>8)) {
                reject(SemanticReturnCode::AtomicUnsupportedSize); return;
            }
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
                    if (synchronized_atomic) {
                        message.synchronization_registration=region;
                        message.synchronization_operands.resize(message.total);
                    }
                    message.atomic_operation=atomic_extension.atomic_opcode;
                    message.atomic_datatype=atomic_extension.atomic_datatype;
                } else if (header.opcode==5 || header.opcode==9) {
                    auto posted=std::find_if(posted_.begin(),posted_.end(),[&](const Posted& receive) {
                        return posting_matches(receive,header.job_id,selected.absolute_pid,selected.resource_index,
                            header.rel,header.opcode==9,header.match_bits,header.initiator);
                    });
                    if (posted==posted_.end()) {
                        if (poisoned) { reject(SemanticReturnCode::InitiatorError); return; }
                        // §3.4.4.6.1: a non-deferring target must tell a
                        // deferrable source NO_MATCH/0 or OK/full length. It
                        // cannot silently choose ordinary ROD buffering here.
                        if (request.delivery_mode==RUD || deferrable_as_send) { reject(SemanticReturnCode::NoMatch); return; }
                        if (header.request_length>unexpected_limit_-unexpected_bytes_) {
                            const auto generation=resources_.disable_for_exhaustion(selected.absolute_pid,
                                selected.resource_index,message_space(header.opcode));
                            disabled_generations_[{selected.absolute_pid,selected.resource_index,message_space(header.opcode)}]=generation;
                            reject(SemanticReturnCode::DisabledGeneration,generation); return;
                        }
                        message.response_list=1;
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
            if (header.opcode==9 && (message.tag!=header.match_bits || message.has_immediate!=bool(header.hd))) {
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
                if (synchronized_atomic) {
                    std::copy(operands.begin(),operands.end(),message.synchronization_operands.begin()+offset);
                    // At most8 nonempty byte fragments plus SOM/EOM markers.
                    // Empty middle packets have no memory effect to defer.
                    if (count || header.som || header.eom) {
                        if (message.synchronization_responses.size()>=10) { reject(SemanticReturnCode::OperationViolation); return; }
                        message.synchronization_responses.push_back(rendezvous_response_handle(request));
                    }
                }
                else memory_.atomic_elements(header.job_id,message.pid,message.key,Runtime::add_time(message.base,offset),
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
            // A zero-byte packet is a marker, not a covered byte interval.
            // Recording [0,0) would make a later zero EOM look like a duplicate
            // of a zero SOM and suppress its completion/semantic response.
            if (merged_length) message.segments.emplace(merged_offset,merged_length);
            message.received+=count;
            if (message.unexpected && message.end_seen && message.received==message.total) {
                // Delivery-complete SEND waits for application placement. Hold
                // its real EOM request handle; ACK Request sees SES processing.
                message.deferred_response=request;
                return;
            }
            // §3.4.2.14: byte coverage and EOM are independent. A sender
            // can finish its bytes before a separate zero-payload end marker;
            // never report application success or retire state before EOM.
            if (message.end_seen && message.received==message.total &&
                (!message.synchronization_member || message.synchronization_start_seen)) {
                // §3.4.2.14 / §3.5.11.4.3: the packet filling the last RUD
                // hole may precede EOM in PSN order. Retire only when Clear
                // reaches the EOM recorded on arrival, not this last placement.
                // Buffered atomic operands are not a finished wire message:
                // its real final response still belongs to the group action.
                message.completed=!synchronized_atomic; message.completion_reported=true;
                if (header.opcode==5 || header.opcode==9) completions_.push_back({0,message.context,CompletionStatus::Success,message.total,1,true,message.immediate_data,0,0,received_tag(message)});
                if (header.opcode==1 && message.immediate_data && !message.synchronization_member)
                    completions_.push_back({0,0,CompletionStatus::Success,message.total,1,true,message.immediate_data});
                if (message.reserved_restart) retire_deferred_target(message.reserved_restart);
                trace_.record(node_,"memory_delivered",message.total);
                if (message.synchronization_member) {
                    finish_synchronized_receive(request,message,selected);
                    if (synchronized_atomic) return; // The aggregate action owns this real response handle.
                }
                reply(request,SemanticReturnCode::Ok,message.total);
            } else if (synchronized_atomic && (count || header.som || header.eom)) return;
            else reply(request,SemanticReturnCode::Ok,0,false);
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
            return posting_matches(receive,header.job_id,selected.absolute_pid,selected.resource_index,
                header.rel,false,0,header.initiator);
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
