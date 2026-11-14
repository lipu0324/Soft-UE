#include "SynchronizedTestFixture.hpp"

void invalid_source(unsigned scenario) {
    SynchronizedFixture fixture; const auto group=fixture.source.begin_synchronized_group(2,1,1);
    auto operation=fixture.completing(group,RUD,true);
    auto expected=CompletionStatus::InvalidRequest;
    switch (scenario) {
    case 0: operation.synchronization.reset(); break;
    case 1: operation.type=OperationType::Write; break;
    case 2: operation.peer=3; break;
    case 3: operation.job=2; break;
    case 4: operation.payload.resize(9); break;
    case 5: operation.atomic_datatype=IntegerAtomicDatatype::Int128; break;
    case 6: operation.immediate_data=1; break;
    case 7: operation.atomic_operation=IntegerAtomicOperation::Read; expected=CompletionStatus::Unsupported; break;
    case 8: operation.atomic_operation=IntegerAtomicOperation::MaskedSwap; expected=CompletionStatus::Unsupported; break;
    case 9: operation.remote_offset=129; break;
    case 10: operation.type=OperationType::SynchronizedWrite; break; // Missing the group's required completer.
    case 11: operation.source_pid=4096; break;
    case 12: operation.delivery_mode=UUD; break;
    case 13: operation.payload_source=std::make_shared<VectorPayload>(operation.payload); break;
    case 14: operation.read_result=ReadResultBuffer{}; break;
    case 15: operation.rendezvous_source=RendezvousBuffer{}; break;
    case 16: operation.synchronization=fixture.target.begin_synchronized_group(2,1,1); break;
    default: throw std::logic_error("unknown validation case");
    }
    size_t ses_requests=0;
    fixture.fabric.set_capture([&](Time,const Frame& frame) {
        const auto packet=UET::NetworkLayer::UetWireCodec::decode(frame.bytes.data(),frame.bytes.size()).packet;
        ses_requests+=packet.PDS_type==RUOD_req_header;
    });
    const auto submitted=fixture.source.submit(operation); fixture.loop.run(300000);
    Completion result{};
    if (!fixture.source.poll_completion(result) || result.status!=expected) {
        std::cerr<<"validation="<<scenario<<" status="<<unsigned(result.status)<<" expected="<<unsigned(expected)<<'\n';
        throw std::runtime_error("invalid synchronized operation produced an unexpected local result");
    }
    CHECK(result.operation==submitted && !fixture.source.poll_completion(result) && !ses_requests);
    CHECK(fixture.target.memory().read(1,1,fixture.destination.key,0,160)==std::vector<uint8_t>(160)); fixture.close();
}
void atomic_datatype(pdc_mode mode,uint8_t encoding,bool zero_length) {
    SynchronizedFixture fixture;
    const auto group=fixture.source.begin_synchronized_group(2,1,zero_length?1:2);
    auto atomic=fixture.completing(group,mode,true);
    atomic.atomic_datatype=static_cast<IntegerAtomicDatatype>(encoding);
    const auto width=size_t{1}<<(encoding/2);
    std::vector<uint8_t> initial(width); initial.front()=2;
    fixture.target.memory().write(1,1,fixture.destination.key,128,initial);
    atomic.payload.assign(zero_length?0:width,0);
    if (zero_length) { atomic.atomic_operation=IntegerAtomicOperation::Write; atomic.zero_length_atomic=true; }
    else atomic.payload.front()=3;
    fixture.source.submit(atomic);
    if (!zero_length) fixture.source.submit(fixture.write(group,mode,0,1));
    fixture.loop.run(300000);
    Completion result{}; size_t completed=0;
    while (fixture.source.poll_completion(result)) { CHECK(result.status==CompletionStatus::Success); ++completed; }
    CHECK(completed==(zero_length?1:2) && !fixture.target.poll_completion(result));
    auto expected=initial; if (!zero_length) expected.front()=5;
    CHECK(fixture.target.memory().read(1,1,fixture.destination.key,128,width)==expected);
    fixture.drained(); fixture.close();
}
void completing_atomic_before_more_than_a_window(pdc_mode mode) {
    SynchronizedFixture fixture;
    CHECK(fixture.target.memory().deregister(fixture.destination));
    fixture.destination=fixture.target.memory().register_region(1,1,4096,7);
    const auto group=fixture.source.begin_synchronized_group(2,1,2);
    auto atomic=fixture.completing(group,mode,true); atomic.remote_offset=3072;
    fixture.source.submit(atomic); fixture.source.submit(fixture.write(group,mode,0,2049));
    fixture.loop.run(300000);
    Completion result{}; size_t completed=0;
    while (fixture.source.poll_completion(result)) { CHECK(result.status==CompletionStatus::Success); ++completed; }
    CHECK(completed==2 && fixture.target.memory().read(1,1,fixture.destination.key,0,2049)==std::vector<uint8_t>(2049,0x35));
    CHECK(fixture.target.memory().read(1,1,fixture.destination.key,3072,8)==std::vector<uint8_t>({5,0,0,0,0,0,0,0}));
    fixture.drained(); fixture.close();
}
int main() {
    try {
        for (unsigned scenario=0;scenario<17;++scenario) invalid_source(scenario);
        for (auto mode:{RUD,ROD}) {
            for (uint8_t datatype=0;datatype<8;++datatype) for (bool zero:{false,true}) atomic_datatype(mode,datatype,zero);
            completing_atomic_before_more_than_a_window(mode);
        }
        std::cout<<"PASS51 synchronized source validation,8 integer types, zero-length atomic WRITE and window progress\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
