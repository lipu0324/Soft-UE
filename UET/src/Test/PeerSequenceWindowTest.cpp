#include "Check.hpp"
#include "../PDS/PeerSequenceWindow.hpp"
#include <iostream>
using UET::PDS::PeerSequenceWindow;

int main() {
    PeerSequenceWindow window(1000);
    CHECK(window.allows(5000) && !window.advertised_range());
    CHECK(!window.observe(999,uint8_t{0})); // Zero encoding ignored without an override.
    CHECK(window.observe(1000,uint8_t{4}) && *window.advertised_range()==512);
    CHECK(window.allows(1512) && !window.allows(1513));
    CHECK(window.allows(999) && window.allows(1000));
    CHECK(!window.observe(1000,uint8_t{1}) && !window.observe(999,uint8_t{1}));
    CHECK(*window.advertised_range()==512); // Equal/old CACK cannot resize the range.
    CHECK(window.observe(1001,uint8_t{1}) && *window.advertised_range()==128);
    CHECK(window.allows(1129) && !window.allows(1130));
    CHECK(!window.observe(1100)); CHECK(window.allows(1228) && !window.allows(1229));
    CHECK(!window.observe(1099,uint8_t{0}) && *window.advertised_range()==128);
    CHECK(window.observe(1101,uint8_t{255}) && *window.advertised_range()==32640);
    PeerSequenceWindow overridden(1000,4);
    CHECK(overridden.observe(999,uint8_t{0}) && *overridden.advertised_range()==4);
    CHECK(overridden.allows(1003) && !overridden.allows(1004));
    CHECK(overridden.observe(1000,uint8_t{1}) && *overridden.advertised_range()==128);
    CHECK(overridden.observe(1001,uint8_t{0}) && *overridden.advertised_range()==4);
    PeerSequenceWindow wrapped(UINT32_MAX-3,4);
    CHECK(wrapped.observe(UINT32_MAX-4,uint8_t{0}));
    CHECK(wrapped.allows(UINT32_MAX) && !wrapped.allows(0));
    CHECK(wrapped.observe(UINT32_MAX-2,uint8_t{0}));
    CHECK(wrapped.allows(1) && !wrapped.allows(2));
    CHECK(wrapped.observe(0,uint8_t{0}));
    CHECK(!wrapped.observe(UINT32_MAX,uint8_t{255}));
    CHECK(wrapped.allows(4) && !wrapped.allows(5));
    check_throws<std::invalid_argument>([] { PeerSequenceWindow rejected(1,32641); });
    std::cout<<"PASS peer PSN range, zero override, stale ACK rejection and wrap arithmetic\n";
}
