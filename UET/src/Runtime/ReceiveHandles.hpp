#pragma once
#include <cstdint>
#include <stdexcept>

namespace UET::Runtime {
// Local SES/PDS execution identity, never a UE wire field. A READ can execute
// again with the same PDC/epoch/PSN (§3.5.17), so those fields cannot identify
// the callback belonging to one particular execution.
using ReceivePacketHandle=uint64_t;
constexpr ReceivePacketHandle kInvalidReceivePacketHandle=UINT64_MAX;

class ReceiveHandleAllocator {
public:
    ReceiveHandleAllocator()=default;
    explicit ReceiveHandleAllocator(ReceivePacketHandle first_handle):next_handle_(first_handle) {
        if (!first_handle) throw std::invalid_argument("receive handle zero is reserved");
    }
    bool available() const { return next_handle_!=kInvalidReceivePacketHandle; }
    ReceivePacketHandle allocate() {
        if (!available()) throw std::overflow_error("receive execution identities exhausted");
        return next_handle_++; // Do not wrap onto a possibly delayed semantic callback.
    }
private:
    ReceivePacketHandle next_handle_=1;
};
} // namespace UET::Runtime
