#include "Check.hpp"
#include "../CMS/TfcCredit.hpp"
#include <iostream>
using namespace UET::CMS;

static void specification_examples_and_cells() {
    TfcSourceConfig config; config.destination_cell_bytes=512;
    TfcSourceCredit cells(config);
    // §3.6.15.1: 4096B payload +256B overhead occupies nine512B cells.
    CHECK(cells.packet_credit_bytes(4096)==4608);
    CHECK(cells.packet_credit_bytes(0)==512 && cells.packet_credit_bytes(256)==512 && cells.packet_credit_bytes(257)==1024);
    config.destination_cell_bytes=9216; TfcSourceCredit packet_buffer(config);
    CHECK(packet_buffer.packet_credit_bytes(4096)==9216 && packet_buffer.packet_credit_bytes(0)==9216);
    config.payload_mtu_bytes=8192; config.destination_cell_bytes=8192;
    TfcSourceCredit two_large_cells(config);
    CHECK(two_large_cells.packet_credit_bytes(7936)==8192 && two_large_cells.packet_credit_bytes(7937)==16384);
    CHECK(two_large_cells.packet_credit_bytes(8192)==16384);
    for (uint32_t mtu:{1024u,2048u,4096u,8192u}) for (uint32_t cell=256;cell<=9216;cell+=256)
        for (uint32_t overhead:{0u,1u,255u,256u}) {
            config.payload_mtu_bytes=mtu; config.destination_cell_bytes=cell; config.packet_overhead_bytes=overhead;
            const TfcSourceCredit controller(config);
            const auto used=controller.packet_credit_bytes(mtu);
            CHECK(used>=mtu+overhead && used<mtu+overhead+cell && used%cell==0);
        }
}

static void credit_gate_and_retransmission() {
    TfcSourceCredit controller;
    CHECK(controller.available_credit_bytes()==256 && controller.can_send());
    CHECK(controller.on_send(4096)==4352 && controller.available_credit_bytes()==-4096);
    CHECK(!controller.can_send() && controller.can_send(true));
    CHECK(controller.on_send(4096,true)==0 && controller.available_credit_bytes()==-4096);
    check_throws<std::logic_error>([&] { controller.on_send(0); });
    CHECK(controller.on_credit_update(16)==4096 && controller.available_credit_bytes()==0 && !controller.can_send());
    CHECK(controller.on_credit_update(17)==256 && controller.available_credit_bytes()==256 && controller.can_send());
    CHECK(controller.on_credit_update(17)==0 && controller.on_credit_update(16)==0 && controller.available_credit_bytes()==256);
    CHECK(controller.on_send(0)==256 && !controller.can_send());

    TfcSourceConfig zero_overhead; zero_overhead.packet_overhead_bytes=0; zero_overhead.initial_credit_bytes=0;
    TfcSourceCredit empty(zero_overhead);
    CHECK(empty.packet_credit_bytes(0)==0 && !empty.can_send());
    check_throws<std::logic_error>([&] { empty.on_send(0); });
    CHECK(empty.can_send(true) && empty.on_send(0,true)==0);
    CHECK(empty.on_credit_update(1)==256 && empty.on_send(0)==0 && empty.available_credit_bytes()==256);
}

static void cumulative_wrap_and_overflow() {
    TfcSourceCredit wrapping;
    CHECK(wrapping.on_credit_update(0)==0);
    CHECK(wrapping.on_credit_update(0x7fffff)==2147483392ULL);
    CHECK(wrapping.on_credit_update(0xfffffe)==2147483392ULL);
    CHECK(wrapping.on_credit_update(2)==1024);
    CHECK(wrapping.available_credit_bytes()==4294968064LL);
    CHECK(wrapping.on_credit_update(0xffffff)==0 && wrapping.on_credit_update(2)==0);
    check_throws<std::invalid_argument>([&] { wrapping.on_credit_update(0x1000000); });
    CHECK(wrapping.available_credit_bytes()==4294968064LL);

    TfcSourceCredit ambiguous;
    CHECK(ambiguous.on_credit_update(0x800000)==0 && ambiguous.available_credit_bytes()==256);
    TfcSourceConfig maximum; maximum.initial_credit_bytes=INT64_MAX;
    TfcSourceCredit full(maximum);
    check_throws<std::overflow_error>([&] { full.on_credit_update(1); });
    CHECK(full.available_credit_bytes()==INT64_MAX);
    CHECK(full.on_send(0)==256 && full.on_credit_update(1)==256 && full.available_credit_bytes()==INT64_MAX);
}

static void invalid_configuration_and_packets() {
    for (uint32_t cell:{0u,255u,257u,9217u,UINT32_MAX}) {
        TfcSourceConfig config; config.destination_cell_bytes=cell;
        check_throws<std::invalid_argument>([&] { TfcSourceCredit invalid(config); });
    }
    for (uint32_t mtu:{0u,8193u,UINT32_MAX}) {
        TfcSourceConfig config; config.payload_mtu_bytes=mtu;
        check_throws<std::invalid_argument>([&] { TfcSourceCredit invalid(config); });
    }
    TfcSourceConfig config; config.packet_overhead_bytes=257;
    check_throws<std::invalid_argument>([&] { TfcSourceCredit invalid(config); });
    config.packet_overhead_bytes=256; config.initial_credit_bytes=255;
    check_throws<std::invalid_argument>([&] { TfcSourceCredit invalid(config); });
    config.packet_overhead_bytes=0; config.initial_credit_bytes=-1;
    check_throws<std::invalid_argument>([&] { TfcSourceCredit invalid(config); });
    TfcSourceCredit controller;
    check_throws<std::invalid_argument>([&] { controller.on_send(4097); });
    check_throws<std::invalid_argument>([&] { controller.on_send(UINT64_MAX,true); });
    CHECK(controller.available_credit_bytes()==256);
}

int main() {
    try {
        specification_examples_and_cells(); credit_gate_and_retransmission();
        cumulative_wrap_and_overflow(); invalid_configuration_and_packets();
        std::cout << "PASS TFC cell examples,576 configurations, signed credit gate, free retransmission and24bit grant boundaries\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
