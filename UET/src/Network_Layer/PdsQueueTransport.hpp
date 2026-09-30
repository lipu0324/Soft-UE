#pragma once

#include "PacketChannel.hpp"
#include "PdsPacketCodec.hpp"
#include "../PDS/PDC/process/ThreadSafeQueue.hpp"

#include <chrono>
#include <cstddef>

namespace UET::NetworkLayer {

// Bridges PDS public queues to any frame transport. A shared progress loop
// calls pump_*; this class owns no worker thread.
class PdsQueueTransport {
public:
    PdsQueueTransport(ThreadSafeQueue<PDStoNET_pkt>& outbound,
                      ThreadSafeQueue<PDStoNET_pkt>& inbound,
                      PacketChannel& channel)
        : outbound_(outbound), inbound_(inbound), channel_(channel) {}

    bool pump_outbound(std::chrono::milliseconds timeout);
    bool pump_inbound(std::chrono::milliseconds timeout);

    // Drive both queue directions once. The timeout is a single budget for
    // the whole call, so a quiet link does not double the caller's wait.
    // PacketTimeout means no inbound frame arrived during the remaining
    // budget; other transport failures are propagated.
    size_t progress(std::chrono::milliseconds timeout);

private:
    ThreadSafeQueue<PDStoNET_pkt>& outbound_;
    ThreadSafeQueue<PDStoNET_pkt>& inbound_;
    PacketChannel& channel_;
};

} // namespace UET::NetworkLayer
