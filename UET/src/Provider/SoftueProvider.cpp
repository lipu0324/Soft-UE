// Manual-progress libfabric 2.0 adapter. Application operations enter the same
// SES/PDS kernel as virtual-time experiments; the outer UDP frame tunnel is
// deliberately an unprivileged laboratory transport, not a raw NIC provider.
#include "../SES/Endpoint.hpp"
#include "../Runtime/UdpFramePort.hpp"
#include <rdma/providers/fi_prov.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_domain.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_eq.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_atomic.h>
#include <rdma/fi_tagged.h>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <optional>
#include <type_traits>

namespace {
using namespace UET;
constexpr uint64_t datagram_caps=FI_MSG|FI_SEND|FI_RECV|FI_REMOTE_CQ_DATA|FI_DIRECTED_RECV;
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__==__ORDER_LITTLE_ENDIAN__
constexpr bool native_atomic_platform=true;
#else
constexpr bool native_atomic_platform=false;
#endif
constexpr uint64_t supported_caps=datagram_caps|FI_TAGGED|FI_RMA|FI_READ|FI_WRITE|FI_REMOTE_READ|FI_REMOTE_WRITE|
    (native_atomic_platform?FI_ATOMIC:0);
// The single application FIFO waits for final completion before initiating
// its successor, including while a recoverable semantic error is retried.
// It therefore enforces FI_FENCE for every transmit (§3.4.2.7.1.1), even
// across peers. This conservative policy trades concurrency for simplicity.
constexpr size_t maximum_inject_bytes=256; // Advertised local copy bound, not a protocol MTU.
constexpr uint64_t completion_levels=FI_INJECT_COMPLETE|FI_TRANSMIT_COMPLETE|FI_DELIVERY_COMPLETE;
// libfabric completion levels are minimum guarantees (fi_cq(3)). For RDM we
// choose the stronger globally-observable completion for every level: all PDS
// receipts plus semantic success, with SES DC requested. This also makes a
// later DELIVERY_COMPLETE|FENCE cover prior weaker-level operations. No early
// CQ or early buffer reuse is promised by INJECT_COMPLETE in this policy.
// UUD uses local transmit acceptance and never promises remote completion.
constexpr uint64_t supported_operation_flags=FI_COMPLETION|completion_levels|FI_FENCE|FI_INJECT;
constexpr uint64_t datagram_operation_flags=FI_COMPLETION|FI_INJECT_COMPLETE|FI_TRANSMIT_COMPLETE|FI_FENCE|FI_INJECT;
// §2.2.6 defines two independent ordering predicates. A cross-operation flag
// can participate in both. The provider's one application FIFO also supplies
// source-side fencing between ordered operations using different PDC modes.
constexpr uint64_t send_ordering_modes=FI_ORDER_RAS|FI_ORDER_SAR|FI_ORDER_SAS|FI_ORDER_SAW|FI_ORDER_WAS;
constexpr uint64_t read_write_ordering_modes=FI_ORDER_ATOMIC_RAR|FI_ORDER_ATOMIC_RAW|FI_ORDER_ATOMIC_WAR|
    FI_ORDER_ATOMIC_WAW|FI_ORDER_RAR|FI_ORDER_RAS|FI_ORDER_RAW|FI_ORDER_RMA_RAR|FI_ORDER_RMA_RAW|
    FI_ORDER_RMA_WAR|FI_ORDER_RMA_WAW|FI_ORDER_SAR|FI_ORDER_SAW|FI_ORDER_WAR|FI_ORDER_WAS;
constexpr uint64_t supported_ordering_modes=send_ordering_modes|read_write_ordering_modes;

template<class Signature> struct Unsupported;
template<class Result,class... Arguments> struct Unsupported<Result(*)(Arguments...)> {
    static Result call(Arguments...) { return static_cast<Result>(-FI_ENOSYS); }
};
#define UNSUPPORTED(table,member) table.member=&Unsupported<decltype(table.member)>::call

// No C ABI callback may propagate a C++ exception into libfabric or an app.
template<class Callback> auto guarded(Callback callback) noexcept -> decltype(callback()) {
    using Result=decltype(callback());
    try { return callback(); }
    catch (const std::bad_alloc&) { return static_cast<Result>(-FI_ENOMEM); }
    catch (const SES::MemoryAccessError&) { return static_cast<Result>(-FI_EACCES); }
    catch (const std::invalid_argument&) { return static_cast<Result>(-FI_EINVAL); }
    catch (...) { return static_cast<Result>(-FI_EOTHER); }
}

struct ProviderFabric;
struct ProviderDomain;
struct ProviderEndpoint;
struct ProviderAddressVector;
struct ProviderCompletionQueue;
struct ProviderEventQueue;
struct ProviderRegion;

struct ProviderFabric { fid_fabric handle{}; size_t domains=0,event_queues=0; };
struct ProviderDomain {
    fid_domain handle{};
    ProviderFabric* fabric=nullptr;
    size_t children=0;
    SES::MemoryRegistry memory;
    ProviderEndpoint* endpoint=nullptr;
    bool datagram=false;
};
struct ProviderAddressVector {
    fid_av handle{};
    ProviderDomain* domain=nullptr;
    size_t bindings=0;
    std::vector<std::optional<sockaddr_in>> addresses;
};
struct ProviderCompletionQueue {
    fid_cq handle{};
    ProviderDomain* domain=nullptr;
    size_t bindings=0;
    fi_cq_format format=FI_CQ_FORMAT_DATA;
    std::deque<fi_cq_tagged_entry> completions;
    std::deque<fi_cq_err_entry> errors;
};
// EQs contain control events (fi_eq(3)), separately from data-transfer CQs.
// The application owns its original event buffer; each FIFO record owns a copy.
struct ProviderEventQueue {
    struct Event { uint32_t type; std::vector<uint8_t> payload; };
    fid_eq handle{};
    ProviderFabric* fabric=nullptr;
    size_t bindings=0,capacity=256;
    bool writable=false;
    std::deque<Event> events;
};
struct ProviderRegion {
    fid_mr handle{};
    ProviderDomain* domain=nullptr;
    SES::Region region;
};
struct ApplicationOperation {
    void* context;
    uint64_t flags;
    void* buffer;
    uint64_t temporary_key=0;
    std::optional<SES::Operation> request;
    uint64_t native_operation=0;
    size_t retries=0;
    Runtime::Time retry_at=0;
    bool waiting_retry=false;
    bool suppress_success_completion=false; // inject APIs still report asynchronous failures.
};
struct ProviderEndpoint {
    fid_ep handle{};
    ProviderDomain* domain=nullptr;
    ProviderAddressVector* addresses=nullptr;
    ProviderCompletionQueue *send_cq=nullptr,*receive_cq=nullptr;
    ProviderEventQueue* event_queue=nullptr;
    sockaddr_in local_address{};
    bool enabled=false;
    bool datagram=false;
    bool directed_receive=false; // Opt-in fi_getinfo capability; otherwise src_addr is ignored.
    uint64_t next_receive_token=0;
    uint64_t message_ordering=0;
    uint64_t default_operation_flags=0;
    uint64_t next_transmit_token=0;
    Runtime::RealtimeRuntime runtime;
    Runtime::Trace trace{runtime.events(),0}; // API users do not opt into an in-memory experiment trace.
    std::unique_ptr<Runtime::UdpFramePort> port;
    std::unique_ptr<Runtime::PdsHost> host;
    std::unique_ptr<SES::Endpoint> semantic;
    std::map<uint64_t,ApplicationOperation> transmits,receives;
    std::deque<uint64_t> transmit_order;
    std::map<std::pair<uint32_t,SES::ResourceSpace>,uint8_t> peer_generations; // Generation belongs to each semantic resource space.
};

// fid is the first field in these Linux provider objects. These conversions
// are exclusively local handle lookups; network fields never enter this path.
template<class Owner,class Handle> Owner& owner(Handle* handle) { return *reinterpret_cast<Owner*>(handle); }

fi_ops object_ops{};
fi_ops_fabric fabric_ops{};
fi_ops_domain domain_ops{};
fi_ops_mr memory_ops{};
fi_ops_av address_ops{};
fi_ops_cq completion_ops{};
fi_ops_eq event_ops{};
fi_ops endpoint_object_ops{};
fi_ops_ep endpoint_ops{};
fi_ops_cm connection_ops{};
fi_ops_msg message_ops{};
fi_ops_tagged tagged_ops{};
fi_ops_rma rma_ops{};
fi_ops_atomic atomic_ops{};

std::optional<SES::IntegerAtomicDatatype> atomic_datatype(fi_datatype datatype) {
    switch (datatype) {
    case FI_INT8: return SES::IntegerAtomicDatatype::Int8;
    case FI_UINT8: return SES::IntegerAtomicDatatype::Uint8;
    case FI_INT16: return SES::IntegerAtomicDatatype::Int16;
    case FI_UINT16: return SES::IntegerAtomicDatatype::Uint16;
    case FI_INT32: return SES::IntegerAtomicDatatype::Int32;
    case FI_UINT32: return SES::IntegerAtomicDatatype::Uint32;
    case FI_INT64: return SES::IntegerAtomicDatatype::Int64;
    case FI_UINT64: return SES::IntegerAtomicDatatype::Uint64;
    case FI_INT128: return SES::IntegerAtomicDatatype::Int128;
    case FI_UINT128: return SES::IntegerAtomicDatatype::Uint128;
    default: return {};
    }
}
std::optional<SES::IntegerAtomicOperation> atomic_operation(fi_op operation) {
    using Operation=SES::IntegerAtomicOperation;
    switch (operation) {
    case FI_MIN: return Operation::Minimum;
    case FI_MAX: return Operation::Maximum;
    case FI_SUM: return Operation::Sum;
    case FI_DIFF: return Operation::Difference;
    case FI_PROD: return Operation::Product;
    case FI_LOR: return Operation::LogicalOr;
    case FI_LAND: return Operation::LogicalAnd;
    case FI_BOR: return Operation::BitwiseOr;
    case FI_BAND: return Operation::BitwiseAnd;
    case FI_LXOR: return Operation::LogicalXor;
    case FI_BXOR: return Operation::BitwiseXor;
    case FI_ATOMIC_WRITE: return Operation::Write;
    case FI_ATOMIC_READ: return Operation::Read;
    default: return {};
    }
}
std::optional<SES::IntegerAtomicOperation> compare_atomic_operation(fi_op operation) {
    using Operation=SES::IntegerAtomicOperation;
    switch (operation) {
    case FI_CSWAP: return Operation::CompareSwapEqual;
    case FI_CSWAP_NE: return Operation::CompareSwapNotEqual;
    case FI_CSWAP_LE: return Operation::CompareSwapLessEqual;
    case FI_CSWAP_LT: return Operation::CompareSwapLess;
    case FI_CSWAP_GE: return Operation::CompareSwapGreaterEqual;
    case FI_CSWAP_GT: return Operation::CompareSwapGreater;
    case FI_MSWAP: return Operation::MaskedSwap;
    default: return {};
    }
}
int query_atomic(fid_domain* domain,fi_datatype datatype,fi_op operation,fi_atomic_attr* attributes,uint64_t flags) {
    if (!attributes) return -FI_EINVAL;
    *attributes={0,0};
    const auto native_type=atomic_datatype(datatype);
    const bool fetching=flags==FI_FETCH_ATOMIC,comparing=flags==FI_COMPARE_ATOMIC;
    const auto native_operation=comparing?compare_atomic_operation(operation):atomic_operation(operation);
    if (!native_atomic_platform || (domain && owner<ProviderDomain>(domain).datagram) ||
        (flags && !fetching && !comparing) || !native_type || !native_operation ||
        (!flags && (*native_operation==SES::IntegerAtomicOperation::Read || SES::integer_atomic_width(*native_type)>8)))
        return -FI_EOPNOTSUPP;
    attributes->size=SES::integer_atomic_width(*native_type);
    attributes->count=flags?1:16*1024*1024/attributes->size;
    return 0;
}

void initialize_fid(fid& handle,size_t kind,void* context,fi_ops* operations=&object_ops) {
    handle.fclass=kind; handle.context=context; handle.ops=operations;
}

int completion_error(const SES::Completion& completion) {
    switch (completion.status) {
    case SES::CompletionStatus::Timeout: return FI_ETIMEDOUT;
    case SES::CompletionStatus::Cancelled: return FI_ECANCELED;
    case SES::CompletionStatus::ResourceExhausted: return FI_ENOSPC;
    case SES::CompletionStatus::Unsupported: return FI_EOPNOTSUPP;
    case SES::CompletionStatus::Truncated: return FI_ETRUNC;
    case SES::CompletionStatus::RemoteError:
        return completion.remote_code==0x1c || completion.remote_code==0x17 || completion.remote_code==0x18?
            FI_EACCES:FI_EIO;
    default: return FI_EIO;
    }
}

void queue_completion(ProviderCompletionQueue& queue,const ApplicationOperation& application,
                      const SES::Completion& completion) {
    if (completion.status==SES::CompletionStatus::Success || completion.status==SES::CompletionStatus::LocalSuccess) {
        if (application.suppress_success_completion) return;
        fi_cq_tagged_entry entry{};
        entry.op_context=application.context; entry.flags=application.flags;
        entry.len=completion.length; entry.buf=application.buffer;
        if (completion.immediate_data) { entry.flags|=FI_REMOTE_CQ_DATA; entry.data=*completion.immediate_data; }
        entry.tag=completion.tag.value_or(application.request?application.request->tag:0);
        queue.completions.push_back(entry);
    } else {
        fi_cq_err_entry error{};
        error.op_context=application.context; error.flags=application.flags; error.buf=application.buffer;
        error.len=completion.length; error.err=completion_error(completion); error.prov_errno=completion.remote_code;
        if (completion.original_length>completion.length) error.olen=completion.original_length-completion.length;
        if (completion.immediate_data) { error.flags|=FI_REMOTE_CQ_DATA; error.data=*completion.immediate_data; }
        error.tag=completion.tag.value_or(application.request?application.request->tag:0);
        queue.errors.push_back(error);
    }
}

std::pair<uint32_t,SES::ResourceSpace> generation_key(const SES::Operation& request) {
    const auto space=request.type==SES::OperationType::Send?SES::ResourceSpace::Send:
        request.type==SES::OperationType::TaggedSend?SES::ResourceSpace::Tagged:SES::ResourceSpace::Rma;
    return {request.peer,space};
}

void drive_transmissions(ProviderEndpoint& endpoint) {
    if (endpoint.transmit_order.empty()) return;
    auto& application=endpoint.transmits.at(endpoint.transmit_order.front());
    if (application.native_operation && !application.waiting_retry) return;
    if (application.waiting_retry && (endpoint.runtime.events().now()<application.retry_at ||
        endpoint.semantic->transport_pending(application.native_operation))) return;
    auto& request=*application.request;
    if (!application.waiting_retry) request.target_generation=endpoint.peer_generations[generation_key(request)];
    application.native_operation=endpoint.semantic->submit(request);
    application.waiting_retry=false;
}

void enqueue_transmission(ProviderEndpoint& endpoint,SES::Operation request,ApplicationOperation application) {
    if (endpoint.next_transmit_token==UINT64_MAX) throw std::overflow_error("application transmit tokens exhausted");
    const auto token=++endpoint.next_transmit_token;
    // Table 2-29: SEND ordering chooses SEND's mode; R/W ordering chooses
    // RMA/ATOMIC's mode. Extra local serialization cannot replace this mapping.
    const auto ordering=(request.type==SES::OperationType::Send || request.type==SES::OperationType::TaggedSend)?send_ordering_modes:read_write_ordering_modes;
    request.delivery_mode=endpoint.datagram?UUD:(endpoint.message_ordering&ordering?ROD:RUD);
    request.context=token; application.request=std::move(request);
    endpoint.transmits.emplace(token,std::move(application)); endpoint.transmit_order.push_back(token);
    try { drive_transmissions(endpoint); }
    catch (...) {
        endpoint.transmits.erase(token);
        endpoint.transmit_order.erase(std::remove(endpoint.transmit_order.begin(),endpoint.transmit_order.end(),token),endpoint.transmit_order.end());
        throw;
    }
}

bool retry_semantic_error(ProviderEndpoint& endpoint,ApplicationOperation& application,const SES::Completion& completion) {
    if (completion.status!=SES::CompletionStatus::RemoteError || completion.remote_code<2 || completion.remote_code>5 ||
        endpoint.datagram || application.retries>=8) return false;
    auto& request=*application.request;
    if (completion.remote_code==2 || completion.remote_code==3) request.target_generation=completion.remote_generation;
    else if (completion.remote_code==4) request.target_generation=static_cast<uint8_t>(completion.remote_generation+1u);
    endpoint.peer_generations[generation_key(request)]=request.target_generation;
    // §3.4.4.7 / §3.4.6.3: retry the oldest operation, with bounded
    // exponential back-off for resource errors. A new message ID is allocated
    // only after EOM/Clear retires the previous attempt; its late fragments
    // therefore cannot steal a posting for the retry.
    const auto backoff=completion.remote_code==2?0:std::min<uint64_t>(100,uint64_t{1}<<application.retries);
    ++application.retries; application.waiting_retry=true;
    application.retry_at=Runtime::add_time(endpoint.runtime.events().now(),backoff*Runtime::kMillisecond);
    return true;
}

void progress(ProviderDomain& domain) {
    auto* endpoint=domain.endpoint;
    if (!endpoint || !endpoint->enabled) return;
    endpoint->port->progress();
    endpoint->runtime.progress();
    SES::Completion completion{};
    while (endpoint->semantic->poll_completion(completion)) {
        // Native receive tokens start at one. Context zero is reserved for
        // unsolicited WRITE-with-data notifications, which consume no RQ entry.
        // SEND data belongs to its posted receive and must retire that posting.
        if (completion.receive && completion.immediate_data && completion.context==0) {
            if (endpoint->receive_cq)
                queue_completion(*endpoint->receive_cq,{nullptr,FI_RMA|FI_REMOTE_WRITE,nullptr},completion);
        } else {
            auto& pending=completion.receive?endpoint->receives:endpoint->transmits;
            const auto found=pending.find(completion.context);
            if (found==pending.end()) continue;
            if (!completion.receive) {
                if (found->second.native_operation!=completion.operation) continue;
                if (retry_semantic_error(*endpoint,found->second,completion)) continue;
                if (completion.status==SES::CompletionStatus::Success)
                    endpoint->peer_generations[generation_key(*found->second.request)]=completion.remote_generation;
                endpoint->transmit_order.pop_front();
            }
            auto* queue=completion.receive?endpoint->receive_cq:endpoint->send_cq;
            if (queue) queue_completion(*queue,found->second,completion);
            if (found->second.temporary_key) domain.memory.deregister(found->second.temporary_key);
            pending.erase(found);
        }
    }
    // Simulator/provider admission policy: serialize application operations.
    // Keep newer ordered operations behind generation retries and supply
    // mixed RMA/message fences (§3.4.2.7.1.1). PDS still owns reliability.
    drive_transmissions(*endpoint);
}

void configure_peer(ProviderEndpoint& endpoint,const sockaddr_in& peer) {
    char ip[INET_ADDRSTRLEN];
    if (!::inet_ntop(AF_INET,&peer.sin_addr,ip,sizeof(ip))) throw std::invalid_argument("invalid peer address");
    const auto node=ntohs(peer.sin_port);
    if (node!=endpoint.port->node()) endpoint.port->add_peer(node,ip,node);
}

int close_object(fid* handle) {
    return guarded([&]() -> int {
        switch (handle->fclass) {
        case FI_CLASS_FABRIC: {
            auto& fabric=owner<ProviderFabric>(handle);
            if (fabric.domains || fabric.event_queues) return -FI_EBUSY;
            delete &fabric; return 0;
        }
        case FI_CLASS_DOMAIN: {
            auto& domain=owner<ProviderDomain>(handle);
            if (domain.children) return -FI_EBUSY;
            --domain.fabric->domains; delete &domain; return 0;
        }
        case FI_CLASS_AV: {
            auto& addresses=owner<ProviderAddressVector>(handle);
            if (addresses.bindings) return -FI_EBUSY;
            --addresses.domain->children; delete &addresses; return 0;
        }
        case FI_CLASS_CQ: {
            auto& queue=owner<ProviderCompletionQueue>(handle);
            if (queue.bindings) return -FI_EBUSY;
            --queue.domain->children; delete &queue; return 0;
        }
        case FI_CLASS_EQ: {
            auto& queue=owner<ProviderEventQueue>(handle);
            if (queue.bindings) return -FI_EBUSY;
            --queue.fabric->event_queues; delete &queue; return 0;
        }
        case FI_CLASS_MR: {
            auto& region=owner<ProviderRegion>(handle);
            region.domain->memory.deregister(region.region);
            --region.domain->children; delete &region; return 0;
        }
        case FI_CLASS_EP: {
            auto& endpoint=owner<ProviderEndpoint>(handle);
            if (!endpoint.transmits.empty()) return -FI_EBUSY;
            endpoint.semantic->close(); endpoint.host->close(); endpoint.port->close();
            for (const auto& receive:endpoint.receives)
                if (receive.second.temporary_key) endpoint.domain->memory.deregister(receive.second.temporary_key);
            if (endpoint.addresses) --endpoint.addresses->bindings;
            if (endpoint.send_cq) --endpoint.send_cq->bindings;
            if (endpoint.receive_cq) --endpoint.receive_cq->bindings;
            if (endpoint.event_queue) --endpoint.event_queue->bindings;
            endpoint.domain->endpoint=nullptr; --endpoint.domain->children;
            delete &endpoint; return 0;
        }
        default: return -FI_EINVAL;
        }
    });
}

int open_domain(fid_fabric* fabric,fi_info* info,fid_domain** result,void* context) {
    return guarded([&]() -> int {
        if (!result) return -FI_EINVAL;
        auto domain=std::make_unique<ProviderDomain>(); domain->fabric=&owner<ProviderFabric>(fabric);
        domain->datagram=info && info->ep_attr && info->ep_attr->type==FI_EP_DGRAM;
        domain->memory.add_job(1);
        initialize_fid(domain->handle.fid,FI_CLASS_DOMAIN,context);
        domain->handle.ops=&domain_ops; domain->handle.mr=&memory_ops;
        ++domain->fabric->domains; *result=&domain.release()->handle; return 0;
    });
}
int open_fabric(fi_fabric_attr*,fid_fabric** result,void* context) {
    return guarded([&]() -> int {
        if (!result) return -FI_EINVAL;
        auto fabric=std::make_unique<ProviderFabric>(); initialize_fid(fabric->handle.fid,FI_CLASS_FABRIC,context);
        fabric->handle.ops=&fabric_ops; fabric->handle.api_version=FI_VERSION(2,0);
        *result=&fabric.release()->handle; return 0;
    });
}
int open_addresses(fid_domain* domain,fi_av_attr* attributes,fid_av** result,void* context) {
    return guarded([&]() -> int {
        if (!result || !attributes || attributes->flags || attributes->rx_ctx_bits ||
            (attributes->type!=FI_AV_UNSPEC && attributes->type!=FI_AV_TABLE)) return -FI_EINVAL;
        auto addresses=std::make_unique<ProviderAddressVector>(); addresses->domain=&owner<ProviderDomain>(domain);
        initialize_fid(addresses->handle.fid,FI_CLASS_AV,context); addresses->handle.ops=&address_ops;
        ++addresses->domain->children; *result=&addresses.release()->handle; return 0;
    });
}
int insert_addresses(fid_av* handle,const void* buffer,size_t count,fi_addr_t* results,uint64_t flags,void*) {
    return guarded([&]() -> int {
        if (flags || (count && !buffer) || count>INT32_MAX) return -FI_EINVAL;
        auto& addresses=owner<ProviderAddressVector>(handle);
        const auto* input=static_cast<const sockaddr_in*>(buffer);
        for (size_t index=0;index<count;++index)
            if (input[index].sin_family!=AF_INET || !input[index].sin_port) return -FI_EADDRNOTAVAIL;
        for (size_t index=0;index<count;++index) {
            if (auto* endpoint=addresses.domain->endpoint;endpoint && endpoint->addresses==&addresses)
                configure_peer(*endpoint,input[index]);
            if (results) results[index]=addresses.addresses.size();
            addresses.addresses.push_back(input[index]);
        }
        return static_cast<int>(count);
    });
}
int lookup_address(fid_av* handle,fi_addr_t address,void* result,size_t* length) {
    if (!length) return -FI_EINVAL;
    auto& addresses=owner<ProviderAddressVector>(handle);
    if (address>=addresses.addresses.size() || !addresses.addresses[address]) return -FI_EADDRNOTAVAIL;
    const auto capacity=*length; *length=sizeof(sockaddr_in);
    if (!result || capacity<sizeof(sockaddr_in)) return -FI_ETOOSMALL;
    std::memcpy(result,&*addresses.addresses[address],sizeof(sockaddr_in)); return 0;
}
int remove_addresses(fid_av* handle,fi_addr_t* indices,size_t count,uint64_t flags) {
    if (flags || (count && !indices)) return -FI_EINVAL;
    auto& addresses=owner<ProviderAddressVector>(handle);
    if (addresses.bindings) return -FI_EBUSY;
    for (size_t index=0;index<count;++index) {
        if (indices[index]>=addresses.addresses.size()) return -FI_EADDRNOTAVAIL;
        addresses.addresses[indices[index]].reset();
    }
    return 0;
}

int open_completion_queue(fid_domain* domain,fi_cq_attr* attributes,fid_cq** result,void* context) {
    return guarded([&]() -> int {
        if (!attributes || !result || attributes->flags ||
            (attributes->wait_obj!=FI_WAIT_UNSPEC && attributes->wait_obj!=FI_WAIT_NONE)) return -FI_EINVAL;
        const auto format=attributes->format==FI_CQ_FORMAT_UNSPEC?FI_CQ_FORMAT_DATA:attributes->format;
        if (format!=FI_CQ_FORMAT_CONTEXT && format!=FI_CQ_FORMAT_MSG && format!=FI_CQ_FORMAT_DATA && format!=FI_CQ_FORMAT_TAGGED) return -FI_EINVAL;
        auto queue=std::make_unique<ProviderCompletionQueue>(); queue->domain=&owner<ProviderDomain>(domain); queue->format=format;
        initialize_fid(queue->handle.fid,FI_CLASS_CQ,context); queue->handle.ops=&completion_ops;
        ++queue->domain->children; *result=&queue.release()->handle; return 0;
    });
}
int open_event_queue(fid_fabric* fabric,fi_eq_attr* attributes,fid_eq** result,void* context) {
    return guarded([&]() -> int {
        const fi_eq_attr defaults{}; const auto& requested=attributes?*attributes:defaults;
        if (!result || requested.size>4096) return -FI_EINVAL;
        // Only nonblocking control polling is implemented. WAIT_UNSPEC asks
        // for sread support, so it must not silently become WAIT_NONE.
        if ((requested.flags&~FI_WRITE) || requested.wait_obj!=FI_WAIT_NONE || requested.wait_set)
            return -FI_EOPNOTSUPP;
        auto queue=std::make_unique<ProviderEventQueue>(); queue->fabric=&owner<ProviderFabric>(fabric);
        queue->capacity=requested.size?requested.size:256; queue->writable=requested.flags&FI_WRITE;
        initialize_fid(queue->handle.fid,FI_CLASS_EQ,context); queue->handle.ops=&event_ops;
        ++queue->fabric->event_queues; *result=&queue.release()->handle; return 0;
    });
}
ssize_t write_event(fid_eq* handle,uint32_t event,const void* buffer,size_t length,uint64_t flags) {
    return guarded([&]() -> ssize_t {
        auto& queue=owner<ProviderEventQueue>(handle);
        if (!queue.writable) return -FI_EOPNOTSUPP;
        if (flags || !buffer || length<sizeof(fi_eq_entry)) return -FI_EINVAL;
        if (length>4096) return -FI_EMSGSIZE; // Explicit local control-record bound.
        if (queue.events.size()>=queue.capacity) return -FI_EAGAIN;
        ProviderEventQueue::Event record{event,{}};
        const auto* bytes=static_cast<const uint8_t*>(buffer); record.payload.assign(bytes,bytes+length);
        queue.events.push_back(std::move(record)); return static_cast<ssize_t>(length);
    });
}
ssize_t read_event(fid_eq* handle,uint32_t* event,void* buffer,size_t length,uint64_t flags) {
    return guarded([&]() -> ssize_t {
        if (!event || (length && !buffer) || (flags&~FI_PEEK)) return -FI_EINVAL;
        auto& queue=owner<ProviderEventQueue>(handle);
        if (queue.events.empty()) return -FI_EAGAIN;
        const auto& record=queue.events.front();
        if (length<record.payload.size()) return -FI_ETOOSMALL; // Preserve the event for a larger read.
        *event=record.type; std::memcpy(buffer,record.payload.data(),record.payload.size());
        const auto bytes=static_cast<ssize_t>(record.payload.size());
        if (!(flags&FI_PEEK)) queue.events.pop_front();
        return bytes;
    });
}
ssize_t read_event_error(fid_eq*,fi_eq_err_entry* result,uint64_t flags) {
    if (!result || (flags&~FI_PEEK)) return -FI_EINVAL;
    // MR/AV are synchronous and RDM has no connection-management operations.
    // No asynchronous control-error producer is enabled in this adapter yet.
    return -FI_EAGAIN;
}
const char* event_error_string(fid_eq*,int error,const void*,char* buffer,size_t length) {
    const auto* description=fi_strerror(error);
    if (buffer && length) { std::snprintf(buffer,length,"%s",description); return buffer; }
    return description;
}
ssize_t read_completions(fid_cq* handle,void* result,size_t count) {
    return guarded([&]() -> ssize_t {
        if (count && !result) return -FI_EINVAL;
        auto& queue=owner<ProviderCompletionQueue>(handle); progress(*queue.domain);
        if (!count) return 0;
        if (queue.completions.empty()) return queue.errors.empty()?-FI_EAGAIN:-FI_EAVAIL;
        const auto available=std::min(count,queue.completions.size());
        for (size_t index=0;index<available;++index) {
            const auto& entry=queue.completions.front();
            if (queue.format==FI_CQ_FORMAT_TAGGED) static_cast<fi_cq_tagged_entry*>(result)[index]=entry;
            else if (queue.format==FI_CQ_FORMAT_DATA)
                static_cast<fi_cq_data_entry*>(result)[index]={entry.op_context,entry.flags,entry.len,entry.buf,entry.data};
            else if (queue.format==FI_CQ_FORMAT_MSG)
                static_cast<fi_cq_msg_entry*>(result)[index]={entry.op_context,entry.flags,entry.len};
            else static_cast<fi_cq_entry*>(result)[index]={entry.op_context};
            queue.completions.pop_front();
        }
        return static_cast<ssize_t>(available);
    });
}
ssize_t read_errors(fid_cq* handle,fi_cq_err_entry* result,uint64_t flags) {
    return guarded([&]() -> ssize_t {
        if (!result || flags) return -FI_EINVAL;
        auto& queue=owner<ProviderCompletionQueue>(handle); progress(*queue.domain);
        if (queue.errors.empty()) return -FI_EAGAIN;
        *result=queue.errors.front(); queue.errors.pop_front(); return 1;
    });
}
const char* error_string(fid_cq*,int,const void*,char* result,size_t length) {
    constexpr const char* description="Soft-UE remote semantic error (prov_errno is the UE return code)";
    if (result && length) { std::snprintf(result,length,"%s",description); return result; }
    return description;
}

int register_memory(fid* domain_handle,const void* buffer,size_t length,uint64_t access,uint64_t offset,
                    uint64_t requested_key,uint64_t flags,fid_mr** result,void* context) {
    return guarded([&]() -> int {
        if (!result || offset || flags || (length && !buffer)) return -FI_EINVAL;
        auto& domain=owner<ProviderDomain>(domain_handle);
        uint8_t permissions=0;
        if (access&FI_REMOTE_READ) permissions|=static_cast<uint8_t>(SES::Access::Read);
        if (access&FI_REMOTE_WRITE) permissions|=static_cast<uint8_t>(SES::Access::Write);
        if (access&FI_ATOMIC) permissions|=static_cast<uint8_t>(SES::Access::Atomic);
        auto region=std::make_unique<ProviderRegion>(); region->domain=&domain;
        SES::RegionOptions options;
        // §2.2.4.3.3: reg/regv and regattr with auth_key_size=0 authorize
        // any JobID. The endpoint's selected JobID does not narrow this MR.
        options.allow_any_job=true;
        // §2.2.5.3.4.1: keep requested metadata even with FI_MR_PROV_KEY.
        // Optimized headers are unavailable, so OPTIMIZED falls back to zero.
        options.idempotent_safe=(requested_key&SES::MemoryKeyFormat::IdempotentSafe)!=0;
        region->region=domain.memory.register_buffer(1,0,static_cast<uint8_t*>(const_cast<void*>(buffer)),length,permissions,options);
        initialize_fid(region->handle.fid,FI_CLASS_MR,context);
        region->handle.key=region->region.key; region->handle.mem_desc=region.get();
        ++domain.children; *result=&region.release()->handle; return 0;
    });
}

int endpoint_name(fid* handle,void* result,size_t* length) {
    if (!length) return -FI_EINVAL;
    const auto capacity=*length; *length=sizeof(sockaddr_in);
    if (!result || capacity<sizeof(sockaddr_in)) return -FI_ETOOSMALL;
    std::memcpy(result,&owner<ProviderEndpoint>(handle).local_address,sizeof(sockaddr_in)); return 0;
}
int bind_endpoint(fid* handle,fid* resource,uint64_t flags) {
    if (!resource) return -FI_EINVAL;
    auto& endpoint=owner<ProviderEndpoint>(handle);
    if (endpoint.enabled) return -FI_EOPBADSTATE;
    if (resource->fclass==FI_CLASS_AV) {
        auto& addresses=owner<ProviderAddressVector>(resource);
        if (flags || endpoint.addresses || addresses.domain!=endpoint.domain) return -FI_EINVAL;
        endpoint.addresses=&addresses; ++addresses.bindings; return 0;
    }
    if (resource->fclass==FI_CLASS_EQ) {
        auto& events=owner<ProviderEventQueue>(resource);
        if (flags || endpoint.event_queue || events.fabric!=endpoint.domain->fabric) return -FI_EINVAL;
        endpoint.event_queue=&events; ++events.bindings; return 0;
    }
    if (resource->fclass==FI_CLASS_CQ) {
        auto& queue=owner<ProviderCompletionQueue>(resource);
        if (queue.domain!=endpoint.domain || !(flags&(FI_TRANSMIT|FI_RECV)) || (flags&~(FI_TRANSMIT|FI_RECV))) return -FI_EINVAL;
        if (((flags&FI_TRANSMIT) && endpoint.send_cq) || ((flags&FI_RECV) && endpoint.receive_cq)) return -FI_EINVAL;
        if (flags&FI_TRANSMIT) { endpoint.send_cq=&queue; ++queue.bindings; }
        if (flags&FI_RECV) { endpoint.receive_cq=&queue; ++queue.bindings; }
        return 0;
    }
    return -FI_ENOSYS;
}
int control_endpoint(fid* handle,int command,void*) {
    return guarded([&]() -> int {
        if (command!=FI_ENABLE) return -FI_ENOSYS;
        auto& endpoint=owner<ProviderEndpoint>(handle);
        if (endpoint.enabled) return -FI_EOPBADSTATE;
        if (!endpoint.addresses || !endpoint.send_cq || !endpoint.receive_cq) return -FI_ENOCQ;
        for (const auto& peer:endpoint.addresses->addresses) if (peer) configure_peer(endpoint,*peer);
        endpoint.enabled=true; return 0;
    });
}

int open_endpoint(fid_domain* handle,fi_info* info,fid_ep** result,void* context) {
    return guarded([&]() -> int {
        auto& domain=owner<ProviderDomain>(handle);
        if (!info || !result || !info->ep_attr ||
            (info->ep_attr->type!=FI_EP_RDM && info->ep_attr->type!=FI_EP_DGRAM)) return -FI_EINVAL;
        const bool datagram=info->ep_attr->type==FI_EP_DGRAM;
        if (datagram!=domain.datagram) return -FI_EINVAL;
        if (info->caps&~(datagram?datagram_caps:supported_caps)) return -FI_EINVAL;
        const auto available_ordering=datagram?uint64_t{0}:supported_ordering_modes;
        if (!info->tx_attr || (info->tx_attr->msg_order&~available_ordering) ||
            (info->rx_attr && (info->rx_attr->msg_order&~available_ordering))) return -FI_EINVAL;
        if ((info->tx_attr->op_flags&~(datagram?datagram_operation_flags:supported_operation_flags)) ||
            info->tx_attr->inject_size>maximum_inject_bytes) return -FI_EINVAL;
        if (domain.endpoint) return -FI_ENOSPC; // Explicitly advertised: one endpoint per domain.
        auto endpoint=std::make_unique<ProviderEndpoint>(); endpoint->domain=&domain;
        endpoint->datagram=datagram; endpoint->directed_receive=info->caps&FI_DIRECTED_RECV;
        endpoint->message_ordering=info->tx_attr->msg_order;
        endpoint->default_operation_flags=info->tx_attr->op_flags;
        endpoint->local_address.sin_family=AF_INET;
        endpoint->local_address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        if (info->src_addr) {
            if (info->src_addrlen!=sizeof(sockaddr_in)) return -FI_EINVAL;
            std::memcpy(&endpoint->local_address,info->src_addr,sizeof(sockaddr_in));
            if (endpoint->local_address.sin_family!=AF_INET) return -FI_EINVAL;
        }
        char ip[INET_ADDRSTRLEN];
        if (!::inet_ntop(AF_INET,&endpoint->local_address.sin_addr,ip,sizeof(ip))) return -FI_EINVAL;
        endpoint->port=std::make_unique<Runtime::UdpFramePort>(0,ntohs(endpoint->local_address.sin_port),ip);
        endpoint->local_address.sin_port=htons(endpoint->port->local_port());
        endpoint->host=std::make_unique<Runtime::PdsHost>(endpoint->port->node(),endpoint->runtime.events(),endpoint->trace,*endpoint->port);
        endpoint->host->services().rto_ns=20*UET::Runtime::kMillisecond;
        // Manual progress can defer a valid semantic response. Use the same
        // wait as the initial RTO for SES-processing NACKs, without increasing
        // timeout backoff or rapidly consuming the common retry budget.
        endpoint->host->services().nack_retransmission_delays_ns[2]=endpoint->host->services().rto_ns;
        endpoint->semantic=std::make_unique<SES::Endpoint>(endpoint->port->node(),*endpoint->host,endpoint->runtime.events(),
            endpoint->trace,1024,5*1000*Runtime::kMillisecond,&domain.memory);
        initialize_fid(endpoint->handle.fid,FI_CLASS_EP,context,&endpoint_object_ops);
        endpoint->handle.ops=&endpoint_ops; endpoint->handle.cm=&connection_ops;
        endpoint->handle.msg=&message_ops; endpoint->handle.rma=&rma_ops;
        endpoint->handle.atomic=&atomic_ops; endpoint->handle.tagged=&tagged_ops;
        domain.endpoint=endpoint.get(); ++domain.children;
        *result=&endpoint.release()->handle; return 0;
    });
}

std::optional<uint32_t> resolve_peer(ProviderEndpoint& endpoint,fi_addr_t address) {
    if (!endpoint.addresses || address>=endpoint.addresses->addresses.size()) return {};
    const auto& peer=endpoint.addresses->addresses[address];
    if (!peer) return {};
    const auto node=ntohs(peer->sin_port);
    configure_peer(endpoint,*peer);
    return node;
}

ssize_t submit_operation(fid_ep* handle,const void* buffer,size_t length,fi_addr_t destination,
                          uint64_t offset,uint64_t key,void* context,bool write,std::optional<uint64_t> immediate={},
                          std::optional<uint64_t> flags={},bool suppress_success=false,std::optional<uint64_t> tag={}) {
    return guarded([&]() -> ssize_t {
        auto& endpoint=owner<ProviderEndpoint>(handle);
        if (!endpoint.enabled) return -FI_EOPBADSTATE;
        if ((write || tag.has_value()) && endpoint.datagram) return -FI_EOPNOTSUPP;
        if ((length && !buffer) || length>(endpoint.datagram?1024:uint64_t{UINT32_MAX})) return -FI_EMSGSIZE;
        const auto operation_flags=flags.value_or(endpoint.default_operation_flags);
        const bool inject=operation_flags&FI_INJECT;
        if (inject && length>maximum_inject_bytes) return -FI_EMSGSIZE;
        if (endpoint.transmits.size()>=4096) return -FI_EAGAIN;
        progress(*endpoint.domain);
        const auto peer=resolve_peer(endpoint,destination);
        if (!peer) return -FI_EADDRNOTAVAIL;
        SES::Operation operation; operation.type=tag?SES::OperationType::TaggedSend:write?SES::OperationType::Write:
            (endpoint.datagram?SES::OperationType::DatagramSend:SES::OperationType::Send);
        operation.peer=*peer; operation.remote_key=key; operation.remote_offset=offset; operation.immediate_data=immediate;
        operation.tag=tag.value_or(0);
        if (inject) {
            // FI_INJECT returns ownership before network progress. Keep an
            // owned, bounded copy for PDS and for any later semantic retry.
            if (length) operation.payload.assign(static_cast<const uint8_t*>(buffer),static_cast<const uint8_t*>(buffer)+length);
        } else {
            // Ordinary transfers retain application ownership until completion.
            // SES pulls bounded fragments, including for 4 GiB-1 messages.
            auto storage=std::make_shared<SES::BufferMemory>(static_cast<uint8_t*>(const_cast<void*>(buffer)),length);
            operation.payload_source=std::make_shared<SES::StoragePayload>(std::move(storage),0,length);
        }
        ApplicationOperation application{context,tag?FI_TAGGED|FI_SEND:write?FI_RMA|FI_WRITE:FI_MSG|FI_SEND,
            suppress_success?nullptr:const_cast<void*>(buffer)};
        application.suppress_success_completion=suppress_success;
        enqueue_transmission(endpoint,std::move(operation),std::move(application));
        return 0;
    });
}

ssize_t submit_atomic_operation(fid_ep* handle,const void* buffer,size_t count,fi_addr_t destination,
                       uint64_t offset,uint64_t key,fi_datatype datatype,fi_op operation,void* context,
                       std::optional<uint64_t> flags={},bool suppress_success=false) {
    return guarded([&]() -> ssize_t {
        auto& endpoint=owner<ProviderEndpoint>(handle);
        if (!endpoint.enabled) return -FI_EOPBADSTATE;
        if (endpoint.datagram) return -FI_EOPNOTSUPP;
        fi_atomic_attr limits{};
        const int supported=query_atomic(nullptr,datatype,operation,&limits,0);
        if (supported) return supported;
        if ((count && !buffer) || (!count && operation!=FI_ATOMIC_WRITE) || count>limits.count || offset%limits.size) return -FI_EINVAL;
        if ((flags.value_or(endpoint.default_operation_flags)&FI_INJECT) && count>maximum_inject_bytes/limits.size)
            return -FI_EMSGSIZE;
        if (endpoint.transmits.size()>=4096) return -FI_EAGAIN;
        progress(*endpoint.domain);
        const auto peer=resolve_peer(endpoint,destination);
        if (!peer) return -FI_EADDRNOTAVAIL;
        SES::Operation request; request.type=SES::OperationType::Atomic; request.peer=*peer;
        request.remote_key=key; request.remote_offset=offset;
        request.atomic_datatype=*atomic_datatype(datatype); request.atomic_operation=*atomic_operation(operation);
        const size_t bytes=count*limits.size; // count was bounded before multiplying.
        // Keep owned operands for FI_INJECT and semantic replay. Ordinary
        // bulk atomics also use this bounded (at most 16 MiB) operand vector.
        if (bytes) request.payload.assign(static_cast<const uint8_t*>(buffer),static_cast<const uint8_t*>(buffer)+bytes);
        // The native integer-memory model is little endian. The platform used
        // by this provider is Linux/little endian; SES separately encodes each
        // operand in network order. Fetching/CAS use a separate result path.
        ApplicationOperation application{context,FI_ATOMIC|FI_WRITE,suppress_success?nullptr:const_cast<void*>(buffer)};
        application.suppress_success_completion=suppress_success;
        enqueue_transmission(endpoint,std::move(request),std::move(application));
        return 0;
    });
}
ssize_t write_atomic(fid_ep* handle,const void* buffer,size_t count,void*,fi_addr_t destination,
                       uint64_t offset,uint64_t key,fi_datatype datatype,fi_op operation,void* context) {
    return submit_atomic_operation(handle,buffer,count,destination,offset,key,datatype,operation,context);
}
ssize_t inject_atomic(fid_ep* handle,const void* buffer,size_t count,fi_addr_t destination,
                       uint64_t offset,uint64_t key,fi_datatype datatype,fi_op operation) {
    return submit_atomic_operation(handle,buffer,count,destination,offset,key,datatype,operation,nullptr,FI_INJECT,true);
}
ssize_t write_atomic_vector(fid_ep* endpoint,const fi_ioc* buffers,void**,size_t count,fi_addr_t destination,
                             uint64_t offset,uint64_t key,fi_datatype datatype,fi_op operation,void* context) {
    if (!buffers || count!=1) return -FI_EINVAL;
    return write_atomic(endpoint,buffers[0].addr,buffers[0].count,nullptr,destination,offset,key,datatype,operation,context);
}
ssize_t write_atomic_message(fid_ep* endpoint,const fi_msg_atomic* message,uint64_t flags) {
    if (!message || !message->msg_iov || !message->rma_iov || message->iov_count!=1 || message->rma_iov_count!=1 ||
        (flags&~supported_operation_flags)) return -FI_EOPNOTSUPP;
    if (message->msg_iov[0].count!=message->rma_iov[0].count) return -FI_EINVAL;
    return submit_atomic_operation(endpoint,message->msg_iov[0].addr,message->msg_iov[0].count,
        message->addr,message->rma_iov[0].addr,message->rma_iov[0].key,message->datatype,message->op,message->context,flags);
}
int atomic_valid(fid_ep* handle,fi_datatype datatype,fi_op operation,size_t* count) {
    if (!count) return -FI_EINVAL;
    *count=0;
    if (owner<ProviderEndpoint>(handle).datagram) return -FI_EOPNOTSUPP;
    fi_atomic_attr attributes{};
    const auto status=query_atomic(nullptr,datatype,operation,&attributes,0);
    if (!status) *count=attributes.count;
    return status;
}
ssize_t submit_fetching_atomic(fid_ep* handle,const void* buffer,size_t count,const void* compare,
                void* result,fi_addr_t destination,uint64_t offset,uint64_t key,fi_datatype datatype,
                fi_op operation,void* context,bool comparing,std::optional<uint64_t> flags={}) {
    return guarded([&]() -> ssize_t {
        auto& endpoint=owner<ProviderEndpoint>(handle);
        if (!endpoint.enabled) return -FI_EOPBADSTATE;
        if (endpoint.datagram) return -FI_EOPNOTSUPP;
        const auto operation_flags=flags.value_or(endpoint.default_operation_flags);
        if (operation_flags&~(supported_operation_flags&~FI_INJECT)) return -FI_EOPNOTSUPP;
        fi_atomic_attr limits{};
        const auto supported=query_atomic(nullptr,datatype,operation,&limits,comparing?FI_COMPARE_ATOMIC:FI_FETCH_ATOMIC);
        if (supported) return supported;
        if (count>1 || (!count && (comparing || (operation!=FI_ATOMIC_READ && operation!=FI_ATOMIC_WRITE))) ||
            (count && !result) || (count && operation!=FI_ATOMIC_READ && !buffer) ||
            (comparing && !compare) || offset%limits.size) return -FI_EINVAL;
        if (endpoint.transmits.size()>=4096) return -FI_EAGAIN;
        progress(*endpoint.domain);
        const auto peer=resolve_peer(endpoint,destination);
        if (!peer) return -FI_EADDRNOTAVAIL;
        SES::Operation request; request.type=SES::OperationType::FetchingAtomic;
        request.peer=*peer; request.remote_key=key; request.remote_offset=offset;
        request.atomic_datatype=*atomic_datatype(datatype);
        request.atomic_operation=comparing?*compare_atomic_operation(operation):*atomic_operation(operation);
        request.zero_length_atomic=!count;
        request.payload.resize(count?limits.size:0);
        if (count && operation!=FI_ATOMIC_READ) std::memcpy(request.payload.data(),buffer,limits.size);
        if (comparing) {
            request.atomic_compare.resize(limits.size); std::memcpy(request.atomic_compare.data(),compare,limits.size);
            if (operation==FI_MSWAP) {
                // fi_atomic(3): new=(input & mask)|(old & ~mask).
                // UE Table3-27: new=(old & ue_mask)^ue_operand.
                // The two terms are disjoint after this per-byte conversion.
                for (size_t byte=0;byte<limits.size;++byte) {
                    request.payload[byte]&=request.atomic_compare[byte];
                    request.atomic_compare[byte]=static_cast<uint8_t>(~request.atomic_compare[byte]);
                }
            }
        }
        uint64_t local_result_key=0;
        if (count) {
            SES::RegionOptions local_result; local_result.local_placement_only=true;
            const auto registration=endpoint.domain->memory.register_buffer(1,1,static_cast<uint8_t*>(result),limits.size,
                static_cast<uint8_t>(SES::Access::Write),local_result);
            local_result_key=registration.key;
            request.atomic_result=SES::AtomicResultBuffer{registration.key,0,static_cast<uint32_t>(limits.size),1,1};
        }
        ApplicationOperation application{context,FI_ATOMIC|FI_READ,result,local_result_key};
        try { enqueue_transmission(endpoint,std::move(request),std::move(application)); }
        catch (...) { if (local_result_key) endpoint.domain->memory.deregister(local_result_key); throw; }
        return 0;
    });
}
ssize_t fetch_atomic(fid_ep* endpoint,const void* buffer,size_t count,void*,void* result,void*,
                fi_addr_t destination,uint64_t offset,uint64_t key,fi_datatype datatype,fi_op operation,void* context) {
    return submit_fetching_atomic(endpoint,buffer,count,nullptr,result,destination,offset,key,datatype,operation,context,false);
}
ssize_t compare_atomic(fid_ep* endpoint,const void* buffer,size_t count,void*,const void* compare,void*,
                void* result,void*,fi_addr_t destination,uint64_t offset,uint64_t key,fi_datatype datatype,fi_op operation,void* context) {
    return submit_fetching_atomic(endpoint,buffer,count,compare,result,destination,offset,key,datatype,operation,context,true);
}
ssize_t fetch_atomic_vector(fid_ep* endpoint,const fi_ioc* buffers,void**,size_t buffer_count,
                fi_ioc* results,void**,size_t result_count,fi_addr_t destination,uint64_t offset,uint64_t key,
                fi_datatype datatype,fi_op operation,void* context) {
    if (!results || result_count!=1 || results[0].count>1 || buffer_count>1 ||
        (operation!=FI_ATOMIC_READ && (!buffers || buffer_count!=1 || buffers[0].count!=results[0].count))) return -FI_EINVAL;
    return fetch_atomic(endpoint,operation==FI_ATOMIC_READ?nullptr:buffers[0].addr,results[0].count,nullptr,results[0].addr,nullptr,
        destination,offset,key,datatype,operation,context);
}
ssize_t compare_atomic_vector(fid_ep* endpoint,const fi_ioc* buffers,void**,size_t buffer_count,
                const fi_ioc* comparisons,void**,size_t comparison_count,fi_ioc* results,void**,size_t result_count,
                fi_addr_t destination,uint64_t offset,uint64_t key,fi_datatype datatype,fi_op operation,void* context) {
    if (!buffers || buffer_count!=1 || buffers[0].count!=1 || !comparisons || comparison_count!=1 ||
        comparisons[0].count!=1 || !results || result_count!=1 || results[0].count!=1) return -FI_EINVAL;
    return compare_atomic(endpoint,buffers[0].addr,1,nullptr,comparisons[0].addr,nullptr,results[0].addr,nullptr,
        destination,offset,key,datatype,operation,context);
}
ssize_t fetch_atomic_message(fid_ep* endpoint,const fi_msg_atomic* message,fi_ioc* results,void**,
                size_t result_count,uint64_t flags) {
    if (!message || !message->rma_iov || message->rma_iov_count!=1 || message->rma_iov[0].count>1 ||
        !results || result_count!=1 || results[0].count!=message->rma_iov[0].count || message->iov_count>1 ||
        (message->op!=FI_ATOMIC_READ && (!message->msg_iov || message->iov_count!=1 || message->msg_iov[0].count!=results[0].count)))
        return -FI_EINVAL;
    return submit_fetching_atomic(endpoint,message->op==FI_ATOMIC_READ?nullptr:message->msg_iov[0].addr,results[0].count,nullptr,
        results[0].addr,message->addr,message->rma_iov[0].addr,message->rma_iov[0].key,message->datatype,message->op,
        message->context,false,flags);
}
ssize_t compare_atomic_message(fid_ep* endpoint,const fi_msg_atomic* message,const fi_ioc* comparisons,void**,
                size_t comparison_count,fi_ioc* results,void**,size_t result_count,uint64_t flags) {
    if (!message || !message->msg_iov || message->iov_count!=1 || message->msg_iov[0].count!=1 ||
        !message->rma_iov || message->rma_iov_count!=1 || message->rma_iov[0].count!=1 ||
        !comparisons || comparison_count!=1 || comparisons[0].count!=1 || !results || result_count!=1 || results[0].count!=1)
        return -FI_EINVAL;
    return submit_fetching_atomic(endpoint,message->msg_iov[0].addr,1,comparisons[0].addr,results[0].addr,
        message->addr,message->rma_iov[0].addr,message->rma_iov[0].key,message->datatype,message->op,message->context,true,flags);
}
int returned_atomic_valid(fid_ep* handle,fi_datatype datatype,fi_op operation,size_t* count,uint64_t flags) {
    if (!count) return -FI_EINVAL;
    *count=0;
    if (owner<ProviderEndpoint>(handle).datagram) return -FI_EOPNOTSUPP;
    fi_atomic_attr limits{}; const auto supported=query_atomic(nullptr,datatype,operation,&limits,flags);
    if (!supported) *count=limits.count;
    return supported;
}
int fetch_atomic_valid(fid_ep* endpoint,fi_datatype datatype,fi_op operation,size_t* count) {
    return returned_atomic_valid(endpoint,datatype,operation,count,FI_FETCH_ATOMIC);
}
int compare_atomic_valid(fid_ep* endpoint,fi_datatype datatype,fi_op operation,size_t* count) {
    return returned_atomic_valid(endpoint,datatype,operation,count,FI_COMPARE_ATOMIC);
}
ssize_t send_message(fid_ep* endpoint,const void* buffer,size_t length,void*,fi_addr_t destination,void* context) {
    return submit_operation(endpoint,buffer,length,destination,0,0,context,false);
}
ssize_t send_message_data(fid_ep* endpoint,const void* buffer,size_t length,void*,uint64_t data,fi_addr_t destination,void* context) {
    return submit_operation(endpoint,buffer,length,destination,0,0,context,false,data);
}
ssize_t inject_message(fid_ep* endpoint,const void* buffer,size_t length,fi_addr_t destination) {
    return submit_operation(endpoint,buffer,length,destination,0,0,nullptr,false,{},FI_INJECT,true);
}
ssize_t inject_message_data(fid_ep* endpoint,const void* buffer,size_t length,uint64_t data,fi_addr_t destination) {
    return submit_operation(endpoint,buffer,length,destination,0,0,nullptr,false,data,FI_INJECT,true);
}
ssize_t send_vector(fid_ep* endpoint,const iovec* buffers,void**,size_t count,fi_addr_t destination,void* context) {
    if (count!=1 || !buffers) return -FI_EINVAL;
    return send_message(endpoint,buffers[0].iov_base,buffers[0].iov_len,nullptr,destination,context);
}
ssize_t send_message_flags(fid_ep* endpoint,const fi_msg* message,uint64_t flags) {
    const auto allowed=owner<ProviderEndpoint>(endpoint).datagram?datagram_operation_flags:supported_operation_flags;
    if (!message || !message->msg_iov || message->iov_count!=1 || (flags&~(allowed|FI_REMOTE_CQ_DATA))) return -FI_EOPNOTSUPP;
    const auto& local=message->msg_iov[0];
    return submit_operation(endpoint,local.iov_base,local.iov_len,message->addr,0,0,message->context,false,
        flags&FI_REMOTE_CQ_DATA?std::optional<uint64_t>{message->data}:std::nullopt,flags);
}
ssize_t post_application_receive(fid_ep* handle,void* buffer,size_t length,fi_addr_t source,void* context,
                                 std::optional<SES::TaggedReceiveMatch> match={}) {
    return guarded([&]() -> ssize_t {
        auto& endpoint=owner<ProviderEndpoint>(handle);
        if (!endpoint.enabled) return -FI_EOPBADSTATE;
        if (match && endpoint.datagram) return -FI_EOPNOTSUPP;
        std::optional<uint32_t> required_initiator;
        if (endpoint.directed_receive && source!=FI_ADDR_UNSPEC) {
            required_initiator=resolve_peer(endpoint,source);
            if (!required_initiator) return -FI_EADDRNOTAVAIL;
        }
        // This SOCKADDR_IN laboratory provider assigns each endpoint's UDP
        // node/port as its Job 1 rank proxy. The native interface independently
        // supports all 32 rank bits. FI_DIRECTED_RECV is explicitly requested;
        // without it, libfabric says to ignore src_addr rather than filter it.
        if (match) match->initiator=required_initiator;
        if ((length && !buffer) || length>UINT32_MAX) return -FI_EINVAL;
        if (endpoint.receives.size()>=4096) return -FI_EAGAIN;
        if (endpoint.next_receive_token==UINT64_MAX) return -FI_ENOSPC; // Keep native context zero reserved for RMA CQ data.
        progress(*endpoint.domain);
        SES::RegionOptions local_receive; local_receive.local_placement_only=true;
        const auto region=endpoint.domain->memory.register_buffer(1,1,static_cast<uint8_t*>(buffer),length,
            static_cast<uint8_t>(SES::Access::Write),local_receive);
        const auto token=++endpoint.next_receive_token;
        try {
            if (match) endpoint.semantic->post_tagged_receive(1,1,region.key,0,static_cast<uint32_t>(length),*match,token);
            else endpoint.semantic->post_receive(1,1,region.key,0,static_cast<uint32_t>(length),token,1,required_initiator);
            endpoint.receives.emplace(token,ApplicationOperation{context,(match?FI_TAGGED:FI_MSG)|FI_RECV,buffer,region.key});
        } catch (...) { endpoint.domain->memory.deregister(region.key); throw; }
        return 0;
    });
}
ssize_t receive_message(fid_ep* endpoint,void* buffer,size_t length,void*,fi_addr_t source,void* context) {
    return post_application_receive(endpoint,buffer,length,source,context);
}
ssize_t receive_vector(fid_ep* endpoint,const iovec* buffers,void**,size_t count,fi_addr_t source,void* context) {
    if (count!=1 || !buffers) return -FI_EINVAL;
    return receive_message(endpoint,buffers[0].iov_base,buffers[0].iov_len,nullptr,source,context);
}
ssize_t receive_message_flags(fid_ep* endpoint,const fi_msg* message,uint64_t flags) {
    if (!message || (flags&~FI_COMPLETION)) return -FI_EOPNOTSUPP;
    return receive_vector(endpoint,message->msg_iov,message->desc,message->iov_count,message->addr,message->context);
}
// Tagged and untagged operations share submission/registration ownership but
// keep distinct native receive spaces, generation recovery and CQ flags.
ssize_t send_tagged(fid_ep* endpoint,const void* buffer,size_t length,void*,fi_addr_t destination,uint64_t tag,void* context) {
    return submit_operation(endpoint,buffer,length,destination,0,0,context,false,{},{},false,tag);
}
ssize_t send_tagged_vector(fid_ep* endpoint,const iovec* buffers,void**,size_t count,fi_addr_t destination,uint64_t tag,void* context) {
    if (!buffers || count!=1) return -FI_EINVAL;
    return send_tagged(endpoint,buffers[0].iov_base,buffers[0].iov_len,nullptr,destination,tag,context);
}
ssize_t send_tagged_message(fid_ep* endpoint,const fi_msg_tagged* message,uint64_t flags) {
    if (!message || !message->msg_iov || message->iov_count!=1 || (flags&~(supported_operation_flags|FI_REMOTE_CQ_DATA)))
        return -FI_EOPNOTSUPP;
    const auto& buffer=message->msg_iov[0];
    return submit_operation(endpoint,buffer.iov_base,buffer.iov_len,message->addr,0,0,message->context,false,
        flags&FI_REMOTE_CQ_DATA?std::optional<uint64_t>{message->data}:std::nullopt,flags,false,message->tag);
}
ssize_t send_tagged_data(fid_ep* endpoint,const void* buffer,size_t length,void*,uint64_t data,fi_addr_t destination,uint64_t tag,void* context) {
    return submit_operation(endpoint,buffer,length,destination,0,0,context,false,data,{},false,tag);
}
ssize_t inject_tagged(fid_ep* endpoint,const void* buffer,size_t length,fi_addr_t destination,uint64_t tag) {
    return submit_operation(endpoint,buffer,length,destination,0,0,nullptr,false,{},FI_INJECT,true,tag);
}
ssize_t inject_tagged_data(fid_ep* endpoint,const void* buffer,size_t length,uint64_t data,fi_addr_t destination,uint64_t tag) {
    return submit_operation(endpoint,buffer,length,destination,0,0,nullptr,false,data,FI_INJECT,true,tag);
}
ssize_t receive_tagged(fid_ep* endpoint,void* buffer,size_t length,void*,fi_addr_t source,uint64_t tag,uint64_t ignore,void* context) {
    return post_application_receive(endpoint,buffer,length,source,context,SES::TaggedReceiveMatch{tag,ignore,{}});
}
ssize_t receive_tagged_vector(fid_ep* endpoint,const iovec* buffers,void**,size_t count,fi_addr_t source,uint64_t tag,uint64_t ignore,void* context) {
    if (!buffers || count!=1) return -FI_EINVAL;
    return receive_tagged(endpoint,buffers[0].iov_base,buffers[0].iov_len,nullptr,source,tag,ignore,context);
}
ssize_t receive_tagged_message(fid_ep* endpoint,const fi_msg_tagged* message,uint64_t flags) {
    // PEEK/CLAIM/DISCARD and multi-receive require their own state machines.
    // Reject them before allocating an automatic local registration.
    if (!message || (flags&~FI_COMPLETION)) return -FI_EOPNOTSUPP;
    return receive_tagged_vector(endpoint,message->msg_iov,message->desc,message->iov_count,message->addr,
        message->tag,message->ignore,message->context);
}
ssize_t write_memory(fid_ep* endpoint,const void* buffer,size_t length,void*,fi_addr_t destination,
                      uint64_t offset,uint64_t key,void* context) {
    return submit_operation(endpoint,buffer,length,destination,offset,key,context,true);
}
ssize_t submit_read(fid_ep* handle,void* buffer,size_t length,fi_addr_t destination,
                    uint64_t offset,uint64_t key,void* context,std::optional<uint64_t> flags={}) {
    return guarded([&]() -> ssize_t {
        auto& endpoint=owner<ProviderEndpoint>(handle);
        if (!endpoint.enabled) return -FI_EOPBADSTATE;
        if (endpoint.datagram) return -FI_EOPNOTSUPP;
        const auto operation_flags=flags.value_or(endpoint.default_operation_flags);
        // fi_readmsg(3): READ has no injection or remote CQ-data operation.
        if (operation_flags&~(supported_operation_flags&~FI_INJECT)) return -FI_EOPNOTSUPP;
        if ((length && !buffer) || length>UINT32_MAX) return -FI_EMSGSIZE;
        if (endpoint.transmits.size()>=4096) return -FI_EAGAIN;
        progress(*endpoint.domain);
        const auto peer=resolve_peer(endpoint,destination);
        if (!peer) return -FI_EADDRNOTAVAIL;
        SES::Operation request; request.type=SES::OperationType::Read;
        request.peer=*peer; request.remote_key=key; request.remote_offset=offset;
        request.read_length=static_cast<uint32_t>(length);
        ApplicationOperation application{context,FI_RMA|FI_READ,buffer};
        if (length) {
            // No FI_MR_LOCAL mode is required. Create a private, bounded local
            // placement registration, just as receive postings do. Its key
            // never appears on the wire; SES rechecks its exact identity for
            // every returned fragment (§3.4.5.2). The application keeps this
            // buffer valid until CQ completion, including semantic retries.
            SES::RegionOptions local_result; local_result.local_placement_only=true;
            const auto region=endpoint.domain->memory.register_buffer(1,1,static_cast<uint8_t*>(buffer),length,
                static_cast<uint8_t>(SES::Access::Write),local_result);
            application.temporary_key=region.key;
            request.read_result=SES::ReadResultBuffer{region.key,0,static_cast<uint32_t>(length),1,1};
        }
        const auto temporary_key=application.temporary_key;
        try { enqueue_transmission(endpoint,std::move(request),std::move(application)); }
        catch (...) { if (temporary_key) endpoint.domain->memory.deregister(temporary_key); throw; }
        return 0;
    });
}
ssize_t read_memory(fid_ep* endpoint,void* buffer,size_t length,void*,fi_addr_t destination,
                     uint64_t offset,uint64_t key,void* context) {
    return submit_read(endpoint,buffer,length,destination,offset,key,context);
}
ssize_t read_vector(fid_ep* endpoint,const iovec* buffers,void**,size_t count,fi_addr_t destination,
                     uint64_t offset,uint64_t key,void* context) {
    if (!buffers || count!=1) return -FI_EINVAL;
    return read_memory(endpoint,buffers[0].iov_base,buffers[0].iov_len,nullptr,destination,offset,key,context);
}
ssize_t read_message_flags(fid_ep* endpoint,const fi_msg_rma* message,uint64_t flags) {
    if (!message || !message->msg_iov || !message->rma_iov || message->iov_count!=1 || message->rma_iov_count!=1)
        return -FI_EINVAL;
    const auto& local=message->msg_iov[0]; const auto& remote=message->rma_iov[0];
    if (local.iov_len!=remote.len) return -FI_EINVAL;
    return submit_read(endpoint,local.iov_base,local.iov_len,message->addr,remote.addr,remote.key,message->context,flags);
}
ssize_t write_vector(fid_ep* endpoint,const iovec* buffers,void**,size_t count,fi_addr_t destination,
                      uint64_t offset,uint64_t key,void* context) {
    if (count!=1 || !buffers) return -FI_EINVAL;
    return write_memory(endpoint,buffers[0].iov_base,buffers[0].iov_len,nullptr,destination,offset,key,context);
}
ssize_t write_data(fid_ep* endpoint,const void* buffer,size_t length,void*,uint64_t immediate,
                    fi_addr_t destination,uint64_t offset,uint64_t key,void* context) {
    return submit_operation(endpoint,buffer,length,destination,offset,key,context,true,immediate);
}
ssize_t inject_write(fid_ep* endpoint,const void* buffer,size_t length,fi_addr_t destination,uint64_t offset,uint64_t key) {
    return submit_operation(endpoint,buffer,length,destination,offset,key,nullptr,true,{},FI_INJECT,true);
}
ssize_t inject_write_data(fid_ep* endpoint,const void* buffer,size_t length,uint64_t data,
                          fi_addr_t destination,uint64_t offset,uint64_t key) {
    return submit_operation(endpoint,buffer,length,destination,offset,key,nullptr,true,data,FI_INJECT,true);
}
ssize_t write_message_flags(fid_ep* endpoint,const fi_msg_rma* message,uint64_t flags) {
    if (!message || !message->msg_iov || !message->rma_iov || message->iov_count!=1 || message->rma_iov_count!=1 ||
        (flags&~(supported_operation_flags|FI_REMOTE_CQ_DATA))) return -FI_EOPNOTSUPP;
    const auto& local=message->msg_iov[0]; const auto& remote=message->rma_iov[0];
    if (local.iov_len!=remote.len) return -FI_EINVAL;
    return submit_operation(endpoint,local.iov_base,local.iov_len,message->addr,remote.addr,remote.key,message->context,true,
        flags&FI_REMOTE_CQ_DATA?std::optional<uint64_t>{message->data}:std::nullopt,flags);
}

int register_memory_vector(fid* handle,const iovec* buffers,size_t count,uint64_t access,uint64_t offset,
                             uint64_t key,uint64_t flags,fid_mr** result,void* context) {
    if (!buffers || count!=1) return -FI_EINVAL;
    return register_memory(handle,buffers[0].iov_base,buffers[0].iov_len,access,offset,key,flags,result,context);
}
int register_memory_attributes(fid* handle,const fi_mr_attr* attributes,uint64_t flags,fid_mr** result) {
    if (!attributes || attributes->iface!=FI_HMEM_SYSTEM || attributes->auth_key_size) return -FI_EOPNOTSUPP;
    return register_memory_vector(handle,attributes->mr_iov,attributes->iov_count,attributes->access,
        attributes->offset,attributes->requested_key,flags,result,attributes->context);
}

int get_information(uint32_t version,const char* node,const char* service,uint64_t flags,const fi_info* hints,fi_info** result) {
    return guarded([&]() -> int {
        if (!result) return -FI_EINVAL;
        *result=nullptr;
        const bool datagram=hints && hints->ep_attr && hints->ep_attr->type==FI_EP_DGRAM;
        const auto requested_directed=hints && ((hints->caps|(hints->rx_attr?hints->rx_attr->caps:0))&FI_DIRECTED_RECV);
        const auto available_caps=(datagram?datagram_caps:supported_caps)&
            ~(requested_directed?uint64_t{0}:FI_DIRECTED_RECV);
        if (version>FI_VERSION(2,0) || (flags&~(FI_SOURCE|FI_NUMERICHOST))) return -FI_ENODATA;
        if (hints) {
            // hints.mode lists modes the application can accommodate. This
            // provider requires none, so any application mode mask is usable.
            if ((hints->caps&~available_caps) ||
                (hints->addr_format!=FI_FORMAT_UNSPEC && hints->addr_format!=FI_SOCKADDR_IN)) return -FI_ENODATA;
            if (hints->ep_attr && hints->ep_attr->type!=FI_EP_UNSPEC &&
                hints->ep_attr->type!=FI_EP_RDM && hints->ep_attr->type!=FI_EP_DGRAM) return -FI_ENODATA;
            if (hints->domain_attr && ((hints->domain_attr->threading!=FI_THREAD_UNSPEC && hints->domain_attr->threading!=FI_THREAD_DOMAIN) ||
                hints->domain_attr->data_progress==FI_PROGRESS_AUTO || hints->domain_attr->auth_key_size ||
                (hints->domain_attr->mr_mode && !(hints->domain_attr->mr_mode&FI_MR_PROV_KEY)))) return -FI_ENODATA;
            // MR hints enumerate modes the application can follow (fi_info
            // passes all current modes). Return our required PROV_KEY subset,
            // rather than rejecting additional modes the application supports.
            if (hints->tx_attr && (hints->tx_attr->op_flags&~(datagram?datagram_operation_flags:supported_operation_flags))) return -FI_ENODATA;
            if (hints->tx_attr && hints->tx_attr->inject_size>maximum_inject_bytes) return -FI_ENODATA;
            if (hints->tx_attr && ((datagram && (hints->tx_attr->op_flags&FI_DELIVERY_COMPLETE)) ||
                (hints->tx_attr->msg_order&~(datagram?uint64_t{0}:supported_ordering_modes)))) return -FI_ENODATA;
            if (hints->rx_attr && (hints->rx_attr->msg_order&~(datagram?uint64_t{0}:supported_ordering_modes))) return -FI_ENODATA;
        }
        std::unique_ptr<fi_info,decltype(&fi_freeinfo)> information(fi_allocinfo(),fi_freeinfo);
        if (!information) return -FI_ENOMEM;
        auto& info=*information;
        info.caps=available_caps; info.mode=0; info.addr_format=FI_SOCKADDR_IN;
        info.ep_attr->type=datagram?FI_EP_DGRAM:FI_EP_RDM; info.ep_attr->protocol=FI_PROTO_UNSPEC;
        info.ep_attr->mem_tag_format=datagram?0:UINT64_MAX;
        info.ep_attr->max_msg_size=datagram?1024:UINT32_MAX; info.ep_attr->tx_ctx_cnt=1; info.ep_attr->rx_ctx_cnt=1;
        // The source FIFO waits for actual READ placement and all forward
        // semantic results before initiating a following WRITE (§3.4.2.7.1.2).
        // Thus even a lost data ACK cannot make a READ observe that later
        // WRITE on re-execution. These are whole-message local guarantees.
        info.ep_attr->max_order_waw_size=datagram?0:UINT32_MAX;
        info.ep_attr->max_order_raw_size=datagram?0:UINT32_MAX;
        info.ep_attr->max_order_war_size=datagram?0:UINT32_MAX;
        info.tx_attr->caps=available_caps&~(FI_RECV|FI_REMOTE_READ|FI_REMOTE_WRITE|FI_DIRECTED_RECV); info.tx_attr->size=4096;
        info.tx_attr->iov_limit=1; info.tx_attr->rma_iov_limit=1;
        info.tx_attr->inject_size=maximum_inject_bytes;
        const auto requested_flags=hints && hints->tx_attr?hints->tx_attr->op_flags:uint64_t{0};
        const auto requested_level=requested_flags&completion_levels;
        info.tx_attr->op_flags=(requested_flags&~completion_levels)|
            (requested_level?requested_level:datagram?FI_TRANSMIT_COMPLETE:FI_DELIVERY_COMPLETE);
        info.tx_attr->msg_order=datagram?uint64_t{0}:(hints && hints->tx_attr?hints->tx_attr->msg_order:uint64_t{FI_ORDER_SAS});
        info.tx_attr->comp_order=FI_ORDER_NONE;
        info.rx_attr->caps=available_caps&~(FI_SEND|FI_READ|FI_WRITE); info.rx_attr->size=4096;
        info.rx_attr->iov_limit=1;
        info.rx_attr->msg_order=datagram?uint64_t{0}:(hints && hints->rx_attr?hints->rx_attr->msg_order:uint64_t{FI_ORDER_SAS});
        info.rx_attr->comp_order=FI_ORDER_NONE;
        auto& attributes=*info.domain_attr;
        attributes.name=::strdup("softue"); attributes.threading=FI_THREAD_DOMAIN;
        attributes.control_progress=FI_PROGRESS_MANUAL; attributes.data_progress=FI_PROGRESS_MANUAL;
        attributes.resource_mgmt=FI_RM_ENABLED; attributes.av_type=FI_AV_TABLE;
        attributes.mr_mode=FI_MR_PROV_KEY; attributes.mr_key_size=6; attributes.cq_data_size=8;
        attributes.ep_cnt=1; attributes.cq_cnt=64; attributes.tx_ctx_cnt=1; attributes.rx_ctx_cnt=1;
        attributes.max_ep_tx_ctx=1; attributes.max_ep_rx_ctx=1; attributes.mr_iov_limit=1;
        info.fabric_attr->name=::strdup("softue-tunnel");
        // A core provider leaves prov_name empty; libfabric fills it in after
        // getinfo. Pre-filling it would look like a layered provider chain.
        info.fabric_attr->prov_version=FI_VERSION(0,2); info.fabric_attr->api_version=version;
        if (!attributes.name || !info.fabric_attr->name) return -FI_ENOMEM;
        sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        if (node && ::inet_pton(AF_INET,node,&address.sin_addr)!=1) return -FI_ENODATA;
        if (service) {
            char* end=nullptr; const auto port=std::strtoul(service,&end,10);
            if (!*service || *end || port>65535) return -FI_ENODATA;
            address.sin_port=htons(static_cast<uint16_t>(port));
        }
        void** destination=(flags&FI_SOURCE)?&info.src_addr:&info.dest_addr;
        size_t* destination_size=(flags&FI_SOURCE)?&info.src_addrlen:&info.dest_addrlen;
        if (node || service || (flags&FI_SOURCE)) {
            *destination=std::malloc(sizeof(address)); if (!*destination) return -FI_ENOMEM;
            std::memcpy(*destination,&address,sizeof(address)); *destination_size=sizeof(address);
        }
        if (hints && hints->src_addr) {
            if (hints->src_addrlen!=sizeof(address)) return -FI_ENODATA;
            std::free(info.src_addr); info.src_addr=std::malloc(sizeof(address));
            if (!info.src_addr) return -FI_ENOMEM;
            std::memcpy(info.src_addr,hints->src_addr,sizeof(address)); info.src_addrlen=sizeof(address);
        }
        *result=information.release(); return 0;
    });
}

void initialize_operations() {
    object_ops.size=sizeof(object_ops); object_ops.close=close_object;
    UNSUPPORTED(object_ops,bind); UNSUPPORTED(object_ops,control); UNSUPPORTED(object_ops,ops_open);
    UNSUPPORTED(object_ops,tostr); UNSUPPORTED(object_ops,ops_set);
    endpoint_object_ops=object_ops; endpoint_object_ops.bind=bind_endpoint; endpoint_object_ops.control=control_endpoint;
    fabric_ops.size=sizeof(fabric_ops); fabric_ops.domain=open_domain;
    UNSUPPORTED(fabric_ops,passive_ep); fabric_ops.eq_open=open_event_queue; UNSUPPORTED(fabric_ops,wait_open);
    UNSUPPORTED(fabric_ops,trywait); UNSUPPORTED(fabric_ops,domain2);
    domain_ops.size=sizeof(domain_ops); domain_ops.av_open=open_addresses;
    domain_ops.cq_open=open_completion_queue; domain_ops.endpoint=open_endpoint;
    UNSUPPORTED(domain_ops,scalable_ep); UNSUPPORTED(domain_ops,cntr_open); UNSUPPORTED(domain_ops,poll_open);
    UNSUPPORTED(domain_ops,stx_ctx); UNSUPPORTED(domain_ops,srx_ctx); domain_ops.query_atomic=query_atomic;
    UNSUPPORTED(domain_ops,query_collective); UNSUPPORTED(domain_ops,endpoint2);
    memory_ops.size=sizeof(memory_ops); memory_ops.reg=register_memory;
    memory_ops.regv=register_memory_vector; memory_ops.regattr=register_memory_attributes;
    address_ops.size=sizeof(address_ops); address_ops.insert=insert_addresses; address_ops.lookup=lookup_address;
    address_ops.remove=remove_addresses;
    UNSUPPORTED(address_ops,insertsvc); UNSUPPORTED(address_ops,insertsym); UNSUPPORTED(address_ops,av_set);
    UNSUPPORTED(address_ops,insert_auth_key); UNSUPPORTED(address_ops,lookup_auth_key); UNSUPPORTED(address_ops,set_user_id);
    address_ops.straddr=[](fid_av*,const void*,char*,size_t*) -> const char* { return nullptr; };
    completion_ops.size=sizeof(completion_ops); completion_ops.read=read_completions;
    completion_ops.readerr=read_errors; completion_ops.strerror=error_string;
    event_ops.size=sizeof(event_ops); event_ops.read=read_event; event_ops.write=write_event;
    event_ops.readerr=read_event_error; event_ops.strerror=event_error_string; UNSUPPORTED(event_ops,sread);
    UNSUPPORTED(completion_ops,readfrom); UNSUPPORTED(completion_ops,sread); UNSUPPORTED(completion_ops,sreadfrom); UNSUPPORTED(completion_ops,signal);
    endpoint_ops.size=sizeof(endpoint_ops);
    UNSUPPORTED(endpoint_ops,cancel); UNSUPPORTED(endpoint_ops,getopt); UNSUPPORTED(endpoint_ops,setopt);
    UNSUPPORTED(endpoint_ops,tx_ctx); UNSUPPORTED(endpoint_ops,rx_ctx); UNSUPPORTED(endpoint_ops,rx_size_left); UNSUPPORTED(endpoint_ops,tx_size_left);
    connection_ops.size=sizeof(connection_ops); connection_ops.getname=endpoint_name;
    UNSUPPORTED(connection_ops,setname); UNSUPPORTED(connection_ops,getpeer); UNSUPPORTED(connection_ops,connect);
    UNSUPPORTED(connection_ops,listen); UNSUPPORTED(connection_ops,accept); UNSUPPORTED(connection_ops,reject);
    UNSUPPORTED(connection_ops,shutdown); UNSUPPORTED(connection_ops,join);
    message_ops.size=sizeof(message_ops); message_ops.send=send_message; message_ops.sendv=send_vector;
    message_ops.sendmsg=send_message_flags; message_ops.recv=receive_message; message_ops.recvv=receive_vector;
    message_ops.recvmsg=receive_message_flags;
    message_ops.senddata=send_message_data;
    message_ops.inject=inject_message; message_ops.injectdata=inject_message_data;
    tagged_ops.size=sizeof(tagged_ops); tagged_ops.send=send_tagged; tagged_ops.sendv=send_tagged_vector;
    tagged_ops.sendmsg=send_tagged_message; tagged_ops.senddata=send_tagged_data;
    tagged_ops.inject=inject_tagged; tagged_ops.injectdata=inject_tagged_data;
    tagged_ops.recv=receive_tagged; tagged_ops.recvv=receive_tagged_vector; tagged_ops.recvmsg=receive_tagged_message;
    rma_ops.size=sizeof(rma_ops); rma_ops.write=write_memory; rma_ops.writev=write_vector;
    rma_ops.writemsg=write_message_flags; rma_ops.writedata=write_data;
    rma_ops.read=read_memory; rma_ops.readv=read_vector; rma_ops.readmsg=read_message_flags;
    rma_ops.inject=inject_write; rma_ops.injectdata=inject_write_data;
    atomic_ops.size=sizeof(atomic_ops); atomic_ops.write=write_atomic; atomic_ops.writev=write_atomic_vector;
    atomic_ops.writemsg=write_atomic_message; atomic_ops.writevalid=atomic_valid;
    atomic_ops.readwritevalid=fetch_atomic_valid; atomic_ops.compwritevalid=compare_atomic_valid;
    atomic_ops.inject=inject_atomic; atomic_ops.readwrite=fetch_atomic; atomic_ops.readwritev=fetch_atomic_vector;
    atomic_ops.readwritemsg=fetch_atomic_message; atomic_ops.compwrite=compare_atomic;
    atomic_ops.compwritev=compare_atomic_vector; atomic_ops.compwritemsg=compare_atomic_message;
}

} // namespace

extern "C" __attribute__((visibility("default"))) fi_provider* fi_prov_ini() {
    static const bool initialized=[] { initialize_operations(); return true; }();
    (void)initialized;
    static fi_provider provider{};
    provider.version=FI_VERSION(0,2); provider.fi_version=FI_VERSION(2,0);
    provider.name="softue"; provider.getinfo=get_information; provider.fabric=open_fabric;
    return &provider;
}
