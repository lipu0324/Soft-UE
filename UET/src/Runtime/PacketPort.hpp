#pragma once
#include <cstdint>
#include <functional>
#include <vector>

namespace UET::Runtime {
struct Frame {
    uint32_t source = 0;
    uint32_t destination = 0;
    uint16_t entropy = 0;
    uint8_t traffic_class = 0;
    std::vector<uint8_t> bytes;
};
enum class SendResult { Accepted, WouldBlock, NoRoute, TooLarge, Closed };
struct IPacketPort {
    using Receiver = std::function<void(Frame)>;
    using Writable = std::function<void()>;
    virtual ~IPacketPort() = default;
    // Accepted transfers a copy to the backend; WouldBlock consumes nothing.
    // After WouldBlock, notify writable readiness instead of requiring polling.
    // Callbacks run on the owning runtime's progress/event-loop thread.
    virtual SendResult try_send(const Frame& frame) = 0;
    virtual void set_receiver(Receiver receiver) = 0;
    virtual void set_writable_handler(Writable callback) = 0;
};
} // namespace UET::Runtime
