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

enum class OperationType : uint8_t { Noop=0, Write=1, Read=2, Atomic=3, FetchingAtomic=4, Send=5, RendezvousSend=6, DatagramSend=7, DeferrableSend=8, TaggedSend=9, RendezvousTaggedSend=10, DeferrableTaggedSend=11, TaggedAtomic=13, TaggedFetchingAtomic=14, SynchronizedWrite=16, SynchronizedAtomic=17 };
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
    bool optimized_small_atomic=true,optimized_medium_atomic=true;
    bool optimized_small_fetching_atomic=true,optimized_medium_fetching_atomic=true;
    bool optimized_small_read=true,optimized_medium_read=true;
    bool datagram_send=true;
    bool rudi_write=true,rudi_read=true; // Idempotent-safe registered memory; no target CQ or PDC.
    bool relative_addressing=true, absolute_addressing=true;
    bool use_once_rma=true; // Native RegionOptions; not a public libfabric extension claim.
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
// This header declares the API and its owned state; Endpoint.cpp implements
// lifecycle and transaction transitions so consumers do not recompile them.
class Endpoint {
public:
    Endpoint(uint32_t node, Runtime::PdsHost& host, Runtime::EventLoop& loop,
             Runtime::Trace& trace, size_t payload_mtu=1024,
             Runtime::Time timeout=100*Runtime::kMillisecond,MemoryRegistry* domain_memory=nullptr,size_t submission_window=8,
             size_t receive_message_limit=4096,size_t unexpected_buffer_bytes=256*1024,size_t read_response_limit=8,
             size_t read_result_window=8);
    ~Endpoint();
    Endpoint(const Endpoint&) = delete;
    Endpoint& operator=(const Endpoint&) = delete;
    MemoryRegistry& memory();
    ResourceDirectory& resources();
    const EndpointCapabilities& capabilities() const;

    std::shared_ptr<const SynchronizedGroup> begin_synchronized_group(uint32_t peer,uint32_t job,uint16_t messages);
    size_t retained_synchronized_groups() const;
    size_t retained_synchronized_members() const;
    size_t retained_synchronized_actions() const;
    void configure_synchronized_tracking(size_t maximum_groups=64);
    size_t active_synchronized_source_groups() const;
    bool cancel_synchronized(uint64_t operation);

    uint64_t submit(Operation operation);
private:
    // A user operation and a wire message have different identities. Internal
    // continuations will retain the application's ID while allocating a fresh
    // MID and using the same original SES/PDS submission path.
    uint16_t submit_message(Operation operation,uint64_t application_operation_id,uint32_t deferrable_token=0,uint32_t restart_owner=0,uint64_t rendezvous_owner=0,uint64_t rendezvous_read_owner=0,uint64_t synchronization_owner=0);
public:
    void post_receive(uint32_t job, uint16_t pid, uint64_t key, uint64_t offset,
                       uint32_t capacity, uint64_t context=0,uint16_t resource_index=1,std::optional<uint32_t> initiator={});
    void post_tagged_receive(uint32_t job,uint16_t pid,uint64_t key,uint64_t offset,uint32_t capacity,
                             TaggedReceiveMatch match,uint64_t context=0,uint16_t resource_index=1);
    bool poll_completion(Completion& completion);
    size_t pending() const;
    // Simulator policy: enable bounded, header-only unexpected deferral (J=0).
    // The default remains the interoperable non-deferring target of §3.4.4.6.1.
    void enable_deferrable_capture(size_t header_limit=64,std::optional<uint32_t> initiator={});
    size_t captured_deferrable_headers() const;
    size_t pending_deferrable_sends() const;
    bool cancel_rendezvous(uint64_t operation);
    bool cancel_deferrable(uint64_t operation);
    size_t retained_rendezvous_receives() const;
    void configure_rendezvous(size_t limit=64,std::optional<uint32_t> read_initiator={});
    bool cancel_read(uint64_t operation);
    bool cancel_rudi(uint64_t operation);
    bool transport_pending(uint64_t operation) const;
    uint64_t unexpected_bytes() const;
    size_t queued_fragments() const;
    size_t receive_intervals() const;
    size_t retained_read_packets() const;
    size_t pending_read_returns() const;
    size_t pending_read_results() const;
    size_t retained_receive_messages() const;
    size_t leased_message_ids() const;
    void close();
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
        uint64_t tagged_buffer_offset=0; // STD tagged atomic offset within the selected posting, never an MR key.
        std::optional<PDC_SES_req> deferred_response;
        std::optional<Region> receive_registration;
        // Pin both the registration incarnation and the logical RMA owner.
        // RX handles change on READ re-execution; this capability must not.
        std::optional<Region> rma_registration;
        RmaMessageOwnerToken rma_owner;
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
    using MessageKey=Runtime::RetiredSemanticReceives::Key;
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

    void abandon_synchronized_group(uint64_t owner);
    void start_synchronized_source(Operation operation,uint64_t application_operation_id);
    void queue_synchronized_attempt(uint64_t operation);
    void complete_synchronized_source(uint64_t operation,CompletionStatus status,uint32_t length,uint8_t code,uint8_t generation);
    void synchronized_message_complete(uint64_t operation,uint16_t message,CompletionStatus status,uint32_t length,uint8_t code,uint8_t generation);
    void drive_synchronized_sources();
    static const SES_Synchronized_Operation_Extension_Header& synchronization_extension(const SEStoPDS_pkt& packet);
    void arm_synchronized_target(uint64_t owner);
    void drive_synchronized_target(uint64_t owner);
    void process_synchronized_member(Incoming& message,bool failed);
    void finish_synchronized_receive(const PDC_SES_req& request,Incoming& message,const ResourceSelection& selected);

    void recover_rendezvous_resources();
    void retire_rendezvous_target(uint64_t id);
    static std::optional<uint64_t> rendezvous_tag(const RendezvousTargetTransaction& transaction);
    void complete_deferred_rendezvous_error(const MessageKey& message,std::optional<uint64_t> immediate={});
    void fail_rendezvous_target(uint64_t id,CompletionStatus status,uint8_t code,uint32_t read_bytes);
    void maybe_complete_rendezvous_target(uint64_t id);
    void rendezvous_read_complete(uint64_t id,CompletionStatus status,uint32_t length,uint8_t code);
    void start_rendezvous_read(const std::shared_ptr<RendezvousTargetTransaction>& transaction);
    bool bind_rendezvous_posting(const std::shared_ptr<RendezvousTargetTransaction>& transaction,const Posted& receive);
    void match_rendezvous_target(uint64_t id);
    static PDC_SES_req rendezvous_response_handle(const PDC_SES_req& request);
    void receive_rendezvous(const PDC_SES_req& request);

    void start_rendezvous_source(Operation operation,uint64_t application_operation_id);
    void queue_rendezvous_attempt(uint64_t operation);
    void complete_rendezvous_source(uint64_t operation,CompletionStatus status,uint32_t length,uint8_t code,uint8_t generation=0);
    void terminate_rendezvous_source(uint64_t operation,CompletionStatus status);
    void maybe_complete_rendezvous_source(uint64_t operation);
    void rendezvous_eager_complete(uint64_t operation,uint16_t message,CompletionStatus status,uint32_t length,uint8_t code,uint8_t generation);
    void drive_rendezvous_sources();
    void handle_rendezvous_result(uint16_t message,const SES_Semantic_Response_Header& semantic);
    void confirm_rendezvous_read(uint64_t operation,uint32_t attempt,MessageKey message,
                                 uint32_t message_offset,uint32_t original_offset,uint32_t count,bool end);
    bool bind_rendezvous_read(const PDC_SES_req& request,uint32_t offset,uint32_t count);

    void start_deferrable_source(Operation operation,uint64_t application_operation_id);
    void queue_deferrable_attempt(uint32_t token);
    void complete_deferrable_source(uint32_t token,CompletionStatus status,uint32_t length,uint8_t code,uint8_t generation=0);
    void terminate_deferrable_source(uint32_t token,CompletionStatus status);
    void deferrable_message_complete(uint32_t token,uint16_t message,CompletionStatus status,uint32_t length,uint8_t code,uint8_t generation);
    void drive_deferrable_sources();
    void handle_deferrable_result(uint16_t message,const SES_Semantic_Response_Header& semantic);

    // This is a producer queue bound, not a second PDS window. The real PDC
    // still owns PSNs, outstanding packets, congestion/recovery and retransmits.
    // FIFO submission keeps all fragments of an ordered message ahead of the
    // next message. At most submission_window_ fragments wait to enter PDS TX.
    void feed_submissions(bool drain_abort_tails=false);
    void fragment_transmitted(uint16_t message);
    void discard_source(uint16_t message);


    void finish(uint16_t message, CompletionStatus status, uint32_t length, uint8_t code,uint8_t remote_generation=0);

    void context_event(const Runtime::PdcEvent& event);
    void complete_read_return(const PDC_SES_rsp& response);
    void maybe_complete_returned_data(uint16_t message);
    void place_atomic_result(uint16_t message,const SEStoPDS_pkt& packet);
    void place_read_result(uint16_t message,const SEStoPDS_pkt& packet);
    void receive_return_data(const PDC_SES_req& request);
    void respond(const PDC_SES_rsp& response);
    enum class ResponseDelivery { Guaranteed, BestEffort };
    void respond_rudi(const PDC_SES_rsp& response);
    void reply(const PDC_SES_req& request, uint8_t code, uint32_t length, bool report_message_result=true,
                std::optional<uint8_t> returned_generation={},ResponseDelivery delivery=ResponseDelivery::Guaranteed);
    void reply(const PDC_SES_req& request,SemanticReturnCode code,uint32_t length,bool report_message_result=true,
                std::optional<uint8_t> returned_generation={},ResponseDelivery delivery=ResponseDelivery::Guaranteed);
    void reply_error(const PDC_SES_req& request,Incoming& message);
    static SemanticReturnCode memory_code(MemoryError error);
    static uint8_t nondeferring_send_opcode(uint8_t opcode);
    static ResourceSpace message_space(uint8_t opcode);
    static bool posting_matches(const Posted& receive,uint32_t job,uint16_t pid,uint16_t resource_index,
                                bool relative,bool tagged,uint64_t tag,uint32_t initiator);
    void post_buffer(uint32_t job,uint16_t pid,uint64_t key,uint64_t offset,uint32_t capacity,
                     uint64_t context,uint16_t resource_index,std::optional<TaggedReceiveMatch> match,std::optional<uint32_t> initiator={});
    static std::optional<uint64_t> received_tag(const Incoming& message);
    void release_unexpected(Incoming& message);
    void retire_rma_registration(Incoming& message);
    void match_unexpected();

    // First-error state belongs to a whole message, not to its first packet.
    // §3.4.6.1: arrival order chooses the first error, including in RUD.
    // Retain it through EOM + PDS Clear so a later posting cannot rescue a
    // rejected message or receive any of its remaining bytes.
    void report_receive_error(Incoming& message);
    void reject_message(const PDC_SES_req& request,Incoming& message,SemanticReturnCode code,
                        std::optional<uint8_t> generation={});
    static MessageKey receive_message_key(const PDC_SES_req& request);
    Runtime::SemanticAdmission reserve_receive_message(const PDC_SES_req& request);
    void cancel_receive_reservation(const PDC_SES_req& request);
    void retire_deferred_target(uint32_t token);
    void fail_deferred_target(uint32_t token,CompletionStatus status,uint8_t code);
    void match_deferred_target(uint32_t token);
    void send_restart(const std::shared_ptr<DeferredTarget>& target);
    bool deferred_metadata_matches(const DeferredTarget& target,const PDC_SES_req& request) const;
    bool receive_deferrable_target(const PDC_SES_req& request);

    void receive_restart(const PDC_SES_req& request);

    void receive_read(const PDC_SES_req& request);
    void receive_fetching_atomic(const PDC_SES_req& request);
    bool bind_tagged_atomic_buffer(const PDC_SES_req& request,Incoming& message,const ResourceSelection& selected,uint32_t target_length);
    // §3.4.2.13 / §3.5.23: inspect and place each packet independently.
    // Duplicates repeat the idempotent access. There is no Incoming record,
    // message assembly, recovery cache, target CQ, or Clear lifetime here.
    void receive_rudi(const PDC_SES_req& request);
    void receive(const PDC_SES_req& request);
    void receive_standard(const PDC_SES_req& request);
    void receive_datagram(const PDC_SES_req& request);
};
} // namespace UET::SES
