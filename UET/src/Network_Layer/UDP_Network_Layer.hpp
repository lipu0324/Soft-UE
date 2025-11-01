/*******************************************************************************
 * Copyright 2025 Soft UE Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 ******************************************************************************/

/**
 * @file             UDP_Network_Layer.hpp
 * @brief            UDP_Network_Layer.hpp
 * @author           softuegroup@gmail.com
 * @version          1.0.0
 * @date             2025-10-29
 * @copyright        Apache License Version 2.0
 *
 * @details
 * This header defines the UDP network layer class for PDS packet encapsulation and transmission.
 */




#ifndef UDP_NETWORK_LAYER_HPP
#define UDP_NETWORK_LAYER_HPP

#include <functional>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

#include "../Transport_Layer.hpp"

namespace UET {
namespace NetworkLayer {

/**
 * @brief UDP network layer forwarder
 * @details Encapsulates PDS packets as UDP payload for transmission and reception
 */
class UDPNetworkLayer {
public:
    using PacketCallback = std::function<void(const PDStoNET_pkt&, const std::string&, uint16_t)>;

    /**
     * @brief Constructor
     * @param local_port Local listening port
     */
    explicit UDPNetworkLayer(uint16_t local_port = 2887);
    
    /**
     * @brief Destructor
     */
    ~UDPNetworkLayer();

    // Disable copy and move
    UDPNetworkLayer(const UDPNetworkLayer&) = delete;
    UDPNetworkLayer& operator=(const UDPNetworkLayer&) = delete;
    UDPNetworkLayer(UDPNetworkLayer&&) = delete;
    UDPNetworkLayer& operator=(UDPNetworkLayer&&) = delete;

    /**
     * @brief Initialize UDP socket
     * @return true on success, false on failure
     */
    bool initialize();

    /**
     * @brief Send PDS packet
     * @param packet PDS packet
     * @param dest_ip Destination IP address
     * @param dest_port Destination port
     * @return Number of bytes sent on success, -1 on failure
     */
    int sendPacket(const PDStoNET_pkt& packet, const std::string& dest_ip, uint16_t dest_port);

    /**
     * @brief Receive packet (blocking mode)
     * @param timeout_ms Timeout in milliseconds, 0 for infinite wait
     * @return true on successful reception
     */
    bool receivePacket(int timeout_ms = 0);

    /**
     * @brief Receive packet (blocking mode) - Refactored
     * @param timeout_ms Timeout in milliseconds, 0 for infinite wait
     * @param packet Reference to store received packet
     * @return true on successful reception
     */
    bool receivePDStoNETPacket(int timeout_ms ,PDStoNET_pkt& packet);
    /**
     * @brief Set packet receive callback
     * @param callback Callback function
     */
    void setPacketCallback(PacketCallback callback);

    /**
     * @brief Get local port
     * @return Local port number
     */
    uint16_t getLocalPort() const { return local_port_; }

    /**
     * @brief Close socket
     */
    void close();

private:
    /**
     * @brief Serialize PDS packet to byte stream
     * @param packet PDS packet
     * @return Serialized byte stream
     */
    std::vector<uint8_t> serializePacket(const PDStoNET_pkt& packet);

    /**
     * @brief Deserialize PDS packet from byte stream
     * @param data Byte stream data
     * @param size Data size
     * @return Deserialized PDS packet
     */
    PDStoNET_pkt deserializePacket(const uint8_t* data, size_t size);

    uint16_t local_port_;
    int socket_fd_;
    bool initialized_;
    
    PacketCallback packet_callback_;
    
#ifdef _WIN32
    WSADATA wsa_data_;
#endif
};

} // namespace NetworkLayer
} // namespace UET

#endif // UDP_NETWORK_LAYER_HPP