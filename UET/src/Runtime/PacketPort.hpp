#pragma once
#include <cstdint>
#include <functional>
#include <stdexcept>
#include <utility>
#include <vector>
#include "TransmitEvents.hpp"

namespace UET::Runtime {
struct Frame {
    uint32_t source = 0;
    uint32_t destination = 0;
    uint16_t entropy = 0;
    uint8_t traffic_class = 0;
    std::vector<uint8_t> bytes;
    uint64_t first_byte_arrival_ns=0;
    bool has_arrival_timestamp=false; // Behavioral MAC timing; real socket adapters leave this false.
    // Source NIC hooks run once, at first-bit departure. Subsequent switches
    // carry the resulting bytes and must not stamp the receiver service again.
    std::function<void(uint64_t,std::vector<uint8_t>&)> prepare_transmission;
    std::function<void(uint64_t,TransmitOutcome)> transmission_event;
};
inline void prepare_first_transmission(Frame& frame,uint64_t departure_ns) {
    auto prepare=std::move(frame.prepare_transmission);
    auto notify=std::move(frame.transmission_event);
    frame.prepare_transmission={}; frame.transmission_event={};
    const auto original_size=frame.bytes.size();
    if (prepare) prepare(departure_ns,frame.bytes);
    if (frame.bytes.size()!=original_size) throw std::logic_error("transmit preparation changed the admitted frame size");
    if (notify) notify(departure_ns,TransmitOutcome::Started);
}
inline void reject_before_transmission(Frame& frame,uint64_t rejection_ns) {
    auto notify=std::move(frame.transmission_event);
    frame.prepare_transmission={}; frame.transmission_event={};
    if (notify) notify(rejection_ns,TransmitOutcome::Rejected);
}
enum class SendResult { Accepted, WouldBlock, NoRoute, TooLarge, Closed };
struct IPacketPort {
    using Receiver = std::function<void(Frame)>;
    using Writable = std::function<void()>;
    virtual ~IPacketPort() = default;
    // False retains the explicit send-submission timing approximation. An
    // adapter returning true must run the source NIC hooks for accepted frames.
    virtual bool provides_transmit_timing() const { return false; }
    // Accepted transfers a copy to the backend; WouldBlock consumes nothing.
    // After WouldBlock, notify writable readiness instead of requiring polling.
    // Callbacks run on the owning runtime's progress/event-loop thread.
    virtual SendResult try_send(const Frame& frame) = 0;
    virtual void set_receiver(Receiver receiver) = 0;
    virtual void set_writable_handler(Writable callback) = 0;
};
} // namespace UET::Runtime
