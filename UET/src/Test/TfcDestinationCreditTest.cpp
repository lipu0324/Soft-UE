#include "Check.hpp"
#include "../CMS/TfcDestinationCredit.hpp"
#include <array>
#include <iostream>
#include <vector>

using namespace UET::CMS;

namespace {
void literal_budget_and_release() {
    const TfcSourceConfig geometry{4096,512,256,256};
    TfcSourceCredit source(geometry);
    TfcDestinationCredit destination(geometry,4864); // 256 initial + literal 4608 maximum packet.
    destination.observe_credit_target(18); // Literal 4608-byte demand.
    CHECK(destination.allocate_credit()==0); // Initial credit and MTU reserve occupy all capacity.
    CHECK(source.on_send(4096)==4608);
    const auto lease=destination.accept_new_packet(4096);
    CHECK(destination.buffered_bytes()==4608);
    CHECK(destination.promised_credit_bytes()==-4352);
    CHECK(destination.allocate_credit()==0); // A held packet's storage cannot be lent again.
    CHECK(!source.can_send());
    check_throws<std::length_error>([&] { destination.accept_new_packet(4096); });
    CHECK(destination.buffered_bytes()==4608 && destination.buffer_count()==1);
    CHECK(destination.release_packet(lease));
    CHECK(!destination.release_packet(lease));
    CHECK(destination.allocate_credit()==4608);
    CHECK(destination.cumulative_credit_units()==18);
    CHECK(source.on_credit_update(18)==4608);
    CHECK(source.available_credit_bytes()==256);
    CHECK(destination.promised_credit_bytes()==256);
    CHECK(destination.allocate_credit()==0);
    CHECK(source.on_credit_update(18)==0); // Lost/duplicated feedback never grants twice.
}

void retained_packet_and_partial_grants() {
    const TfcSourceConfig geometry{64,256,256,256};
    TfcDestinationCredit destination(geometry,1792); // MTU reserve512 + initial256 + allocatable1024.
    destination.observe_credit_target(8);
    CHECK(destination.allocate_credit()==1024);
    CHECK(destination.promised_credit_bytes()==1280);
    const auto first=destination.accept_new_packet(64);
    const auto second=destination.accept_new_packet(64);
    const auto third=destination.accept_new_packet(64);
    CHECK(destination.buffered_bytes()==1536 && destination.promised_credit_bytes()==-256);
    CHECK(destination.allocate_credit()==0);
    check_throws<std::length_error>([&] { destination.accept_new_packet(64); });
    CHECK(destination.release_packet(second));
    CHECK(destination.allocate_credit()==512);
    CHECK(destination.granted_bytes()==1536);
    CHECK(destination.release_packet(first));
    CHECK(destination.allocate_credit()==512);
    CHECK(destination.granted_bytes()==2048);
    CHECK(destination.release_packet(third));
    CHECK(destination.allocate_credit()==0); // Fulfilled demand is a separate limit from physical room.
    CHECK(destination.buffer_count()==0 && destination.buffered_bytes()==0);
}

void zero_cost_bounds_and_counter_wrap() {
    const TfcSourceConfig geometry{64,256,0,1};
    TfcDestinationCredit destination(geometry,514);
    const auto empty=destination.accept_new_packet(0);
    CHECK(destination.buffer_count()==1 && destination.buffered_bytes()==0);
    CHECK(destination.promised_credit_bytes()==1);
    CHECK(destination.release_packet(empty));
    CHECK(!destination.release_packet(empty));
    check_throws<std::invalid_argument>([&] { destination.accept_new_packet(65); });
    CHECK(destination.promised_credit_bytes()==1 && destination.buffer_count()==0);
    destination.observe_credit_target(0x7fffff);
    destination.observe_credit_target(0xfffffe);
    destination.observe_credit_target(2);
    CHECK(destination.requested_bytes()==4294967808ULL);
    destination.observe_credit_target(1); // Reordered older target.
    destination.observe_credit_target(0x800002); // Ambiguous half-space jump.
    CHECK(destination.requested_bytes()==4294967808ULL);
    check_throws<std::invalid_argument>([&] { destination.observe_credit_target(0x1000000); });
    CHECK(destination.requested_bytes()==4294967808ULL);
    CHECK(destination.allocate_credit()==256); // Floor to wire units; one byte remains unallocated.
    CHECK(destination.cumulative_credit_units()==1);
    CHECK(destination.promised_credit_bytes()==257);
    CHECK(destination.allocate_credit()==0);
    check_throws<std::invalid_argument>([&] { TfcDestinationCredit invalid(geometry,256); });
    check_throws<std::invalid_argument>([&] { TfcDestinationCredit invalid(geometry,uint64_t{1}<<31); });
}

void all_geometries_and_reordered_release() {
    for (const uint32_t mtu : {1024,2048,4096,8192})
        for (uint32_t cell=256; cell<=9216; cell+=256)
            for (const uint32_t overhead : {0,1,128,256}) {
                const TfcSourceConfig geometry{mtu,cell,overhead,256};
                TfcSourceCredit source(geometry);
                const uint32_t maximum_cost=source.packet_credit_bytes(mtu);
                const uint64_t capacity=5*uint64_t{maximum_cost}+256;
                TfcDestinationCredit destination(geometry,capacity);
                // Enough demand for this finite experiment; the destination
                // still cannot allocate more than its physical reservation.
                destination.observe_credit_target(128*maximum_cost/256);
                std::vector<TfcDestinationCredit::BufferLease> held;
                const std::array<uint32_t,4> lengths{mtu,1,mtu/2,0};
                for (size_t round=0; round<32; ++round) {
                    destination.allocate_credit();
                    source.on_credit_update(destination.cumulative_credit_units());
                    size_t transmitted=0;
                    while (source.can_send() && transmitted<lengths.size()) {
                        const auto payload_bytes=lengths[transmitted++];
                        source.on_send(payload_bytes);
                        held.push_back(destination.accept_new_packet(payload_bytes));
                    }
                    CHECK(transmitted>0);
                    CHECK(destination.buffered_bytes()<=capacity);
                    CHECK(destination.promised_credit_bytes()==source.available_credit_bytes());
                    // PDS retries consume neither a second reservation nor
                    // source credit; no accept_new_packet call accompanies it.
                    const auto balance=source.available_credit_bytes();
                    CHECK(source.on_send(mtu,true)==0);
                    CHECK(source.available_credit_bytes()==balance);
                    for (auto lease=held.rbegin(); lease!=held.rend(); ++lease) {
                        CHECK(destination.release_packet(*lease));
                        CHECK(!destination.release_packet(*lease));
                    }
                    held.clear();
                    CHECK(destination.buffered_bytes()==0 && destination.buffer_count()==0);
                }
            }
}
}

int main() {
    try {
        literal_budget_and_release();
        retained_packet_and_partial_grants();
        zero_cost_bounds_and_counter_wrap();
        all_geometries_and_reordered_release();
        std::cout << "TFC destination literal budgets, bounds and 576 geometry experiments passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
