#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include "../SES/Endpoint.hpp"
#include "../SES/SemanticRequestFields.hpp"
#include <array>
#include <iostream>
using namespace UET::Runtime;
using namespace UET::SES;

struct OptimizedAtomicPair {
    EventLoop loop; Trace trace{loop}; Fabric fabric{loop,trace,42};
    PdsHost source_host{1,loop,trace,fabric.add_host(1)},target_host{2,loop,trace,fabric.add_host(2)};
    Endpoint source{1,source_host,loop,trace,128},target{2,target_host,loop,trace,128};
    Region destination;
    OptimizedAtomicPair(RequestHeaderFormat format,bool congestion,uint8_t permissions=7) {
        fabric.add_link(1,2,{}); fabric.add_link(2,1,{});
        if (congestion) { source_host.enable_nscc({}); target_host.enable_nscc({}); }
        source.memory().add_job(1); target.memory().add_job(1);
        RegionOptions options;
        if (format==RequestHeaderFormat::Small) {
            options.requested_key=MemoryKeyFormat::Optimized|3;
            target.resources().configure_resource(1,3,ResourceSpace::Rma);
        }
        destination=target.memory().register_storage(1,1,std::make_shared<SparseMemory>(256),permissions,options);
    }
    ~OptimizedAtomicPair() {
        source.close(); target.close(); source_host.close(); target_host.close();
    }
};

static void arithmetic(RequestHeaderFormat format,pdc_mode mode,bool congestion,
                       IntegerAtomicDatatype datatype,uint8_t opcode,uint8_t expected,size_t elements=1) {
    OptimizedAtomicPair pair(format,congestion);
    const auto width=integer_atomic_width(datatype);
    // Independent vectors: target5, operand3. Expected values are a fixed
    // table below, never calculated by the implementation's atomic helper.
    std::vector<uint8_t> previous(elements*width),operand(elements*width),result(elements*width);
    for (size_t element=0;element<elements;++element) {
        previous[element*width]=5; operand[element*width]=3; result[element*width]=expected;
    }
    pair.destination.storage->write(16,previous.data(),previous.size());
    Operation operation; operation.type=OperationType::Atomic; operation.header_format=format;
    operation.delivery_mode=mode; operation.peer=2; operation.context=99;
    operation.remote_key=pair.destination.key; operation.remote_offset=16;
    operation.atomic_datatype=datatype; operation.atomic_operation=static_cast<IntegerAtomicOperation>(opcode);
    operation.payload=operand;
    size_t packets=0;
    pair.fabric.set_capture([&](Time,const Frame& frame) {
        const auto packet=UET::NetworkLayer::UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        if (packet.PDS_type!=RUOD_req_header || frame.source!=1) return;
        const auto fields=semantic_request_fields(packet.SESpkt);
        CHECK(fields && !fields->has_message_id && fields->header.opcode==3);
        CHECK(packet.SESpkt.eth_type==Atomic_Operation_Extension_Header);
        // Each network-order operand ends in3, including signed datatypes.
        std::vector<uint8_t> network_operand(operand.size());
        for (size_t element=0;element<elements;++element) network_operand[(element+1)*width-1]=3;
        CHECK(packet.SESpkt.payload==network_operand); ++packets;
    });
    const auto id=pair.source.submit(operation); pair.loop.run_until(5*kMillisecond);
    Completion completion{};
    CHECK(pair.source.poll_completion(completion) && completion.operation==id && completion.context==99 &&
        completion.status==CompletionStatus::Success && completion.length==operand.size());
    std::vector<uint8_t> actual(result.size()); pair.destination.storage->read(16,actual.data(),actual.size());
    CHECK(actual==result && packets==1 && !pair.source.poll_completion(completion) && !pair.target.poll_completion(completion));
    CHECK(!pair.source.leased_message_ids() && !pair.target.retained_receive_messages());
}

static void zero_write(RequestHeaderFormat format,pdc_mode mode) {
    OptimizedAtomicPair pair(format,false);
    const uint8_t sentinel=0x6b; pair.destination.storage->write(0,&sentinel,1);
    Operation operation; operation.type=OperationType::Atomic; operation.header_format=format;
    operation.delivery_mode=mode; operation.peer=2; operation.remote_key=pair.destination.key;
    operation.atomic_operation=IntegerAtomicOperation::Write; operation.zero_length_atomic=true;
    pair.source.submit(operation); pair.loop.run_until(5*kMillisecond);
    Completion completion{}; uint8_t actual=0; pair.destination.storage->read(0,&actual,1);
    CHECK(pair.source.poll_completion(completion) && completion.status==CompletionStatus::Success && !completion.length);
    CHECK(actual==sentinel && !pair.target.poll_completion(completion) && !pair.source.leased_message_ids());
}

// Independent PDS submission bypasses source SES datatype/permission checks.
static void rejected_target(RequestHeaderFormat format,pdc_mode mode,unsigned scenario) {
    OptimizedAtomicPair pair(format,false,scenario==0?uint8_t{1}:uint8_t{7});
    SES_PDS_req request{}; request.src_fep=1; request.dst_fep=2; request.source_pid=1;
    request.mode=mode; request.tx_pkt_handle=7;
    const bool small=format==RequestHeaderFormat::Small;
    request.next_hdr=small?UET_HDR_REQUEST_SMALL:UET_HDR_REQUEST_MEDIUM;
    request.pkt.bth_type=small?Optimized_Header:Small_Message_RMA_Header;
    const auto fill=[&](auto& header) {
        header.opcode=3; header.som=header.eom=header.rel=header.dc=1;
        header.job_id=1; header.PIDonFEP=1; header.resource_index=small?3:1; header.request_length=8;
        if (scenario==1) header.buffer_offset=1;
        if (scenario==2) header.buffer_offset=256;
    };
    if (small) fill(request.pkt.bth_header.Optimized_Header);
    else { auto& header=request.pkt.bth_header.Small_Message_RMA_Header; fill(header); header.match_bits=pair.destination.key; }
    request.pkt.eth_type=Atomic_Operation_Extension_Header;
    auto& extension=request.pkt.eth_header.Atomic_Operation_Extension_Header;
    extension.atomic_datatype=scenario==3?9:7; extension.atomic_opcode=scenario==4?11:2;
    if (scenario==5) extension.semantic_contol=1;
    request.pkt.payload.assign(8,0); request.pkt.payload.back()=1; request.pkt_len=(small?20:32)+4+8;
    const std::array<SemanticReturnCode,6> expected={SemanticReturnCode::OperationViolation,
        SemanticReturnCode::AtomicUnaligned,SemanticReturnCode::BadAddress,SemanticReturnCode::AtomicUnsupportedDatatype,
        SemanticReturnCode::AtomicUnsupportedOperation,SemanticReturnCode::AtomicUnsupportedOperation};
    size_t responses=0;
    pair.source_host.set_response_handler([&](const PDC_SES_rsp& response) {
        CHECK(response.pkt.bth_type==Semantic_Response_Header);
        const auto& header=response.pkt.bth_header.Semantic_Response_Header;
        CHECK(!header.message_id && header.return_code==static_cast<uint8_t>(expected[scenario])); ++responses;
    });
    CHECK(pair.source_host.submit(request)); pair.loop.run_until(5*kMillisecond);
    Completion completion{}; std::vector<uint8_t> actual(256); pair.destination.storage->read(0,actual.data(),actual.size());
    CHECK(responses==1 && actual==std::vector<uint8_t>(256) && !pair.target.poll_completion(completion));
    CHECK(!pair.target.retained_receive_messages());
}
int main() {
    try {
        const std::array<uint8_t,13> expected={3,5,8,2,15,1,1,7,1,0,6,0,3};
        size_t scenarios=0;
        for (auto format:{RequestHeaderFormat::Small,RequestHeaderFormat::Medium}) for (auto mode:{RUD,ROD}) {
            for (bool congestion:{false,true}) for (uint8_t datatype=0;datatype<8;++datatype)
                for (uint8_t opcode=0;opcode<13;++opcode) if (opcode!=11) {
                    arithmetic(format,mode,congestion,static_cast<IntegerAtomicDatatype>(datatype),opcode,expected[opcode]); ++scenarios;
                }
            arithmetic(format,mode,false,IntegerAtomicDatatype::Uint64,2,8,16); ++scenarios; // Full128B Payload MTU.
            zero_write(format,mode); ++scenarios;
            for (unsigned scenario=0;scenario<6;++scenario) { rejected_target(format,mode,scenario); ++scenarios; }
        }
        CHECK(scenarios==800);
        std::cout<<"PASS800 optimized integer atomic arithmetic, network operands, MTU/zero and independent target rejection\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
