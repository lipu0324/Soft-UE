#pragma once

#include "PacketChannel.hpp"
#include "PacketCodec.hpp"

#include <infiniband/verbs.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <deque>
#include <string>
#include <utility>
#include <vector>

namespace UET::NetworkLayer {

// One RC connection, one registered send slot, eight registered receive slots.
// The caller drives progress synchronously; no per-connection worker threads.
class RdmaChannel final : public PacketChannel {
public:
    struct Config {
        bool server = false;
        std::string peer_ip = "127.0.0.1"; // TCP control channel only
        uint16_t tcp_port = 18515;
        std::string device = "mlx5_1";
        uint8_t ib_port = 1;
    };

    explicit RdmaChannel(const Config& config);
    ~RdmaChannel() override;
    RdmaChannel(const RdmaChannel&) = delete;
    RdmaChannel& operator=(const RdmaChannel&) = delete;

    void send_packet(const std::vector<uint8_t>& bytes,
                     std::chrono::milliseconds timeout) override;
    std::vector<uint8_t> receive_packet(std::chrono::milliseconds timeout) override;

private:
    static constexpr size_t kSlotSize = 8192;
    static constexpr size_t kReceiveSlots = 8;
    static constexpr uint64_t kSendId = 0xffffffffull;

    void open_control(const Config& config);
    void open_verbs(const Config& config);
    void connect_qp();
    void post_receive(size_t index);
    void progress();
    void cleanup() noexcept;

    int control_fd_ = -1;
    ibv_context* context_ = nullptr;
    ibv_pd* pd_ = nullptr;
    ibv_cq* cq_ = nullptr;
    ibv_qp* qp_ = nullptr;
    ibv_mr* send_mr_ = nullptr;
    ibv_mr* recv_mr_ = nullptr;
    ibv_port_attr port_attr_{};
    uint32_t psn_ = 0;
    uint8_t port_ = 1;
    bool send_pending_ = false;
    std::array<uint8_t, kSlotSize> send_buffer_{};
    std::array<std::array<uint8_t, kSlotSize>, kReceiveSlots> receive_buffers_{};
    // A completed receive slot is reposted only after the application consumes
    // the frame, so the queue cannot grow beyond the registered slot count.
    std::deque<std::pair<size_t, std::vector<uint8_t>>> arrived_;
};

} // namespace UET::NetworkLayer
