#pragma once

#include "../Transport_Layer.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace UET::NetworkLayer {

// Explicit network representation for the PDS queue boundary. It carries the
// currently implemented PDS headers, the SES standard header, and owned bytes.
// C++ bit-field layout never crosses the transport boundary.
class PdsPacketCodec {
public:
    // IB RC segments larger messages internally; the receive slot is 8 KiB so
    // a full 4096-byte Soft-UE payload plus explicit headers fits one frame.
    static constexpr size_t kMaxPacketSize = 8192;
    static std::vector<uint8_t> encode(const PDStoNET_pkt& packet);
    static PDStoNET_pkt decode(const uint8_t* bytes, size_t size);
};

} // namespace UET::NetworkLayer
