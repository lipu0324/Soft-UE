#include "Check.hpp"
#include "../Runtime/Runtime.hpp"
#include "../PDS/PDC/RTOTimer/RTOTimer.hpp"
#include <iostream>
#include <limits>

using namespace UET::Runtime;

int main() {
    try {
        EventLoop loop;
        std::vector<int> order;
        loop.at(10, [&] { order.push_back(1); loop.at(10, [&] { order.push_back(3); }); });
        loop.at(10, [&] { order.push_back(2); });
        const auto cancelled = loop.at(5, [&] { throw std::runtime_error("cancelled event ran"); });
        CHECK(loop.cancel(cancelled)); CHECK(!loop.cancel(cancelled));
        CHECK(loop.run_until(9) == 0);
        CHECK(loop.run_until(10) == 3);
        CHECK(order == std::vector<int>({1,2,3})); CHECK(loop.pending() == 0);
        check_throws<std::invalid_argument>([&] { loop.at(9, []{}); });
        check_throws<std::invalid_argument>([&] { loop.run_until(9); });
        check_throws<std::overflow_error>([] { add_time(UINT64_MAX, 1); });
        size_t wakes = 0;
        Services services{loop, loop, [&] { ++wakes; }};
        std::vector<uint32_t> fired;
        {
            RTOTimer timer([&](uint32_t psn) { fired.push_back(psn); }, &services);
            CHECK(timer.startTimer(1, 1));
            CHECK(timer.stopTimer(1));
            CHECK(timer.startTimer(1, 2)); // Same PSN, different generation.
            loop.run_until(10 + kMillisecond);
            CHECK(fired.empty());
            CHECK(timer.updateRTO(1, 3));
            loop.run_until(10 + 3 * kMillisecond);
            CHECK(fired.empty());
            loop.run_until(10 + 4 * kMillisecond);
            CHECK(fired == std::vector<uint32_t>({1})); CHECK(wakes == 1);
            CHECK(timer.getActiveTimerCount() == 0);
            CHECK(timer.startTimer(2, 1, UINT16_MAX)); // Saturated backoff, no undefined shift.
            CHECK(timer.getTimerInfo(2).rto == 10000);
            CHECK(!timer.startTimer(3, 0));
            timer.clearAllTimers(); CHECK(loop.pending() == 0);
            CHECK(timer.startTimer(4, 1));
        }
        CHECK(loop.pending() == 0);
        loop.run(); CHECK(fired.size() == 1);
        Random a(42), b(42);
        for (size_t i=0; i<1000; ++i) CHECK(a.next() == b.next());
        CHECK(a.chance(1000000)); CHECK(!a.chance(0));
        check_throws<std::invalid_argument>([&] { a.chance(1000001); });
        EventLoop bounded;
        std::function<void()> again;
        again = [&] { bounded.after(0, again); };
        bounded.after(0, again);
        check_throws<std::runtime_error>([&] { bounded.run(10); });
        CHECK(bounded.executed() == 10);
        std::cout << "PASS: deterministic ordering, cancellation, timer lifetime/reuse, overflow and event budget\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
