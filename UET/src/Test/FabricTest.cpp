#include "Check.hpp"
#include "../Runtime/Fabric.hpp"
#include <iostream>
using namespace UET::Runtime;

int main() {
    try {
        EventLoop loop; Trace trace(loop); Fabric fabric(loop,trace,1);
        auto& source=fabric.add_host(1); auto& target=fabric.add_host(2);
        LinkConfig config; config.rate_bps=8000000000ULL; config.delay_ns=100;
        config.mtu=1000; config.buffer_bytes=2000;
        fabric.add_link(1,2,config);
        std::vector<Time> arrivals;
        target.set_receiver([&](Frame f) { CHECK(f.bytes.size()==1000); arrivals.push_back(loop.now()); });
        Frame frame; frame.source=1; frame.destination=2; frame.bytes.resize(1000);
        CHECK(source.try_send(frame)==SendResult::Accepted);
        CHECK(source.try_send(frame)==SendResult::Accepted);
        CHECK(source.try_send(frame)==SendResult::Accepted); // Tail drop is network loss.
        CHECK(fabric.stats(1,2).dropped==1);
        loop.run();
        CHECK(arrivals==std::vector<Time>({1100,2100}));
        CHECK(fabric.stats(1,2).queued_bytes==0);
        CHECK(fabric.stats(1,2).peak_queue_bytes==2000);
        frame.bytes.resize(1001); CHECK(source.try_send(frame)==SendResult::TooLarge);
        frame.bytes.resize(1000); fabric.set_link_up(1,2,false);
        CHECK(source.try_send(frame)==SendResult::NoRoute);
        fabric.set_link_up(1,2,true); CHECK(source.try_send(frame)==SendResult::Accepted);
        loop.run(); CHECK(arrivals.size()==3);

        EventLoop mesh_loop; Trace mesh_trace(mesh_loop); Fabric mesh(mesh_loop,mesh_trace,42);
        auto& a=mesh.add_host(1); auto& b=mesh.add_host(2); mesh.add_switch(10); mesh.add_switch(20);
        config.buffer_bytes=4000;
        for (auto sw : {10u,20u}) { mesh.add_link(1,sw,config); mesh.add_link(sw,2,config); }
        size_t delivered=0; b.set_receiver([&](Frame) { ++delivered; });
        frame.entropy=0; CHECK(a.try_send(frame)==SendResult::Accepted);
        frame.entropy=1; CHECK(a.try_send(frame)==SendResult::Accepted);
        mesh_loop.run(); CHECK(delivered==2);
        CHECK(mesh.stats(1,10).delivered==1); CHECK(mesh.stats(1,20).delivered==1);
        check_throws<std::invalid_argument>([&] { mesh.add_link(1,2,LinkConfig{0}); });
        std::cout << "PASS: analytic serialization/propagation, queue bounds, link failure/recovery and deterministic ECMP\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
