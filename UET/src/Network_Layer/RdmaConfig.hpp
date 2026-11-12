#pragma once
#include <cstdint>
#include <string>

namespace UET::NetworkLayer {
struct RdmaConfig {
    bool server = false;
    std::string peer_ip = "127.0.0.1";
    uint16_t tcp_port = 18515;
    std::string device = "mlx5_1";
    uint8_t ib_port = 1;
};
} // namespace UET::NetworkLayer
