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
 * @file             UDP_Network_Layer.cpp
 * @brief            UDP_Network_Layer.cpp
 * @author           softuegroup@gmail.com
 * @version          1.0.0
 * @date             2025-10-29
 * @copyright        Apache License Version 2.0
 *
 * @details
 * This file implements the UDP network layer for PDS packet transmission and reception.
 */


#include "UDP_Network_Layer.hpp"
#include <cstring>
#include <iostream>

namespace UET {
namespace NetworkLayer {

UDPNetworkLayer::UDPNetworkLayer(uint16_t local_port)
    : local_port_(local_port)
    , socket_fd_(-1)
    , initialized_(false)
{
}

UDPNetworkLayer::~UDPNetworkLayer()
{
    close();
}

bool UDPNetworkLayer::initialize()
{
    if (initialized_) {
        return true;
    }

#ifdef _WIN32
    // Initialize Windows Socket
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data_) != 0) {
        std::cerr << "WSAStartup failed" << std::endl;
        return false;
    }
#endif

    // Create UDP socket
    socket_fd_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd_ < 0) {
        std::cerr << "Failed to create socket" << std::endl;
#ifdef _WIN32
        WSACleanup();
#endif
        return false;
    }

    // Set socket option: allow address reuse
    int reuse = 1;
#ifdef _WIN32
    if (setsockopt(socket_fd_, SOL_SOCKET, SO_REUSEADDR, 
                   reinterpret_cast<const char*>(&reuse), sizeof(reuse)) < 0) {
#else
    if (setsockopt(socket_fd_, SOL_SOCKET, SO_REUSEADDR, 
                   &reuse, sizeof(reuse)) < 0) {
#endif
        std::cerr << "Failed to set SO_REUSEADDR" << std::endl;
    }

    // Bind to local port
    sockaddr_in local_addr{};
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = INADDR_ANY;
    local_addr.sin_port = htons(local_port_);

    if (bind(socket_fd_, reinterpret_cast<sockaddr*>(&local_addr), sizeof(local_addr)) < 0) {
        std::cerr << "Failed to bind port " << local_port_ << std::endl;
#ifdef _WIN32
        closesocket(socket_fd_);
        WSACleanup();
#else
        ::close(socket_fd_);
#endif
        socket_fd_ = -1;
        return false;
    }

    initialized_ = true;
    std::cout << "UDP network layer initialized successfully, listening on port: " << local_port_ << std::endl;
    return true;
}

int UDPNetworkLayer::sendPacket(const PDStoNET_pkt& packet, const std::string& dest_ip, uint16_t dest_port)
{
    if (!initialized_ || socket_fd_ < 0) {
        std::cerr << "UDP network layer not initialized" << std::endl;
        return -1;
    }

    // Serialize packet
    std::vector<uint8_t> buffer = serializePacket(packet);

    // Set destination address
    sockaddr_in dest_addr{};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(dest_port);
    
#ifdef _WIN32
    inet_pton(AF_INET, dest_ip.c_str(), &dest_addr.sin_addr);
#else
    if (inet_pton(AF_INET, dest_ip.c_str(), &dest_addr.sin_addr) <= 0) {
        std::cerr << "Invalid destination IP address: " << dest_ip << std::endl;
        return -1;
    }
#endif

    // Send packet
    int sent_bytes = sendto(socket_fd_, 
#ifdef _WIN32
                           reinterpret_cast<const char*>(buffer.data()),
#else
                           buffer.data(),
#endif
                           buffer.size(), 
                           0,
                           reinterpret_cast<sockaddr*>(&dest_addr), 
                           sizeof(dest_addr));

    if (sent_bytes < 0) {
        std::cerr << "Failed to send packet" << std::endl;
    } else {
        std::cout << "Packet sent successfully: " << sent_bytes << " bytes -> "
                  << dest_ip << ":" << dest_port << std::endl;
    }

    return sent_bytes;
}

bool UDPNetworkLayer::receivePacket(int timeout_ms)
{
    if (!initialized_ || socket_fd_ < 0) {
        std::cerr << "UDP network layer not initialized" << std::endl;
        return false;
    }

    // Set timeout
    if (timeout_ms > 0) {
#ifdef _WIN32
        DWORD timeout = timeout_ms;
        setsockopt(socket_fd_, SOL_SOCKET, SO_RCVTIMEO, 
                   reinterpret_cast<const char*>(&timeout), sizeof(timeout));
#else
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt(socket_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
    }

    // Receive buffer
    std::vector<uint8_t> buffer(65535);
    sockaddr_in sender_addr{};
    socklen_t sender_addr_len = sizeof(sender_addr);

    // Receive packet
    int recv_bytes = recvfrom(socket_fd_,
#ifdef _WIN32
                             reinterpret_cast<char*>(buffer.data()),
#else
                             buffer.data(),
#endif
                             buffer.size(),
                             0,
                             reinterpret_cast<sockaddr*>(&sender_addr),
                             &sender_addr_len);

    if (recv_bytes > 0) {
        // Get sender IP and port
        char sender_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sender_addr.sin_addr, sender_ip, INET_ADDRSTRLEN);
        uint16_t sender_port = ntohs(sender_addr.sin_port);

        std::cout << "Received packet: " << recv_bytes << " bytes <- "
                  << sender_ip << ":" << sender_port << std::endl;

        // Deserialize packet
        PDStoNET_pkt packet = deserializePacket(buffer.data(), recv_bytes);

        // Call callback function
        if (packet_callback_) {
            packet_callback_(packet, std::string(sender_ip), sender_port);
        }

        return true;
    } else if (recv_bytes < 0) {
#ifdef _WIN32
        int error = WSAGetLastError();
        if (error != WSAETIMEDOUT && error != WSAEWOULDBLOCK) {
            std::cerr << "Failed to receive packet, error code: " << error << std::endl;
        }
#else
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            std::cerr << "Failed to receive packet" << std::endl;
        }
#endif
    }

    return false;
}

bool UDPNetworkLayer::receivePDStoNETPacket(int timeout_ms , PDStoNET_pkt& packet)
{
    if (!initialized_ || socket_fd_ < 0) {
        std::cerr << "UDP network layer not initialized" << std::endl;
        return false;
    }

    // Set timeout
    if (timeout_ms > 0) {
#ifdef _WIN32
        DWORD timeout = timeout_ms;
        setsockopt(socket_fd_, SOL_SOCKET, SO_RCVTIMEO, 
                   reinterpret_cast<const char*>(&timeout), sizeof(timeout));
#else
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt(socket_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
    }

    // Receive buffer
    std::vector<uint8_t> buffer(65535);
    sockaddr_in sender_addr{};
    socklen_t sender_addr_len = sizeof(sender_addr);

    // Receive packet
    int recv_bytes = recvfrom(socket_fd_,
#ifdef _WIN32
                             reinterpret_cast<char*>(buffer.data()),
#else
                             buffer.data(),
#endif
                             buffer.size(),
                             0,
                             reinterpret_cast<sockaddr*>(&sender_addr),
                             &sender_addr_len);

    if (recv_bytes > 0) {
        // Get sender IP and port
        char sender_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sender_addr.sin_addr, sender_ip, INET_ADDRSTRLEN);
        uint16_t sender_port = ntohs(sender_addr.sin_port);

        std::cout << "Received packet: " << recv_bytes << " bytes <- "
                  << sender_ip << ":" << sender_port << std::endl;

        // Deserialize packet
        packet = deserializePacket(buffer.data(), recv_bytes);

        // Call callback function
        if (packet_callback_) {
            packet_callback_(packet, std::string(sender_ip), sender_port);
        }

        return true;
    } else if (recv_bytes < 0) {
#ifdef _WIN32
        int error = WSAGetLastError();
        if (error != WSAETIMEDOUT && error != WSAEWOULDBLOCK) {
            std::cerr << "Failed to receive packet, error code: " << error << std::endl;
        }
#else
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            std::cerr << "Failed to receive packet" << std::endl;
        }
#endif
    }

    return false;
}

void UDPNetworkLayer::setPacketCallback(PacketCallback callback)
{
    packet_callback_ = std::move(callback);
}

void UDPNetworkLayer::close()
{
    if (socket_fd_ != -1) {
#ifdef _WIN32
        closesocket(socket_fd_);
#else
        ::close(socket_fd_);
#endif
        socket_fd_ = -1;
    }

#ifdef _WIN32
    if (initialized_) {
        WSACleanup();
    }
#endif

    initialized_ = false;
}

std::vector<uint8_t> UDPNetworkLayer::serializePacket(const PDStoNET_pkt& packet)
{
    std::vector<uint8_t> buffer;
    
    // Add source FEP and destination FEP (8 bytes)
    buffer.insert(buffer.end(), 
                  reinterpret_cast<const uint8_t*>(&packet.src_fep),
                  reinterpret_cast<const uint8_t*>(&packet.src_fep) + sizeof(packet.src_fep));
    buffer.insert(buffer.end(),
                  reinterpret_cast<const uint8_t*>(&packet.dst_fep),
                  reinterpret_cast<const uint8_t*>(&packet.dst_fep) + sizeof(packet.dst_fep));
    
    // Add PDS header type (1 byte)
    buffer.push_back(static_cast<uint8_t>(packet.PDS_type));
    
    // Add corresponding header data based on PDS header type
    switch (packet.PDS_type) {
        case PDS_header_type::RUOD_req_header:
            buffer.insert(buffer.end(),
                         reinterpret_cast<const uint8_t*>(&packet.PDS_header.RUOD_req_header),
                         reinterpret_cast<const uint8_t*>(&packet.PDS_header.RUOD_req_header) + sizeof(packet.PDS_header.RUOD_req_header));
            break;
        case PDS_header_type::RUOD_ack_header:
            buffer.insert(buffer.end(),
                         reinterpret_cast<const uint8_t*>(&packet.PDS_header.RUOD_ack_header),
                         reinterpret_cast<const uint8_t*>(&packet.PDS_header.RUOD_ack_header) + sizeof(packet.PDS_header.RUOD_ack_header));
            break;
        case PDS_header_type::RUOD_cp_header:
            buffer.insert(buffer.end(),
                         reinterpret_cast<const uint8_t*>(&packet.PDS_header.RUOD_cp_header),
                         reinterpret_cast<const uint8_t*>(&packet.PDS_header.RUOD_cp_header) + sizeof(packet.PDS_header.RUOD_cp_header));
            break;
        case PDS_header_type::nack_header:
            buffer.insert(buffer.end(),
                         reinterpret_cast<const uint8_t*>(&packet.PDS_header.nack_header),
                         reinterpret_cast<const uint8_t*>(&packet.PDS_header.nack_header) + sizeof(packet.PDS_header.nack_header));
            break;
        default:
            break;
    }

    // TODO: Add SES layer data (if needed)
    
    return buffer;
}

PDStoNET_pkt UDPNetworkLayer::deserializePacket(const uint8_t* data, size_t size)
{
    PDStoNET_pkt packet{};
    size_t offset = 0;

    // Parse source FEP and destination FEP (8 bytes)
    if (size >= offset + sizeof(packet.src_fep)) {
        std::memcpy(&packet.src_fep, data + offset, sizeof(packet.src_fep));
        offset += sizeof(packet.src_fep);
    }
    if (size >= offset + sizeof(packet.dst_fep)) {
        std::memcpy(&packet.dst_fep, data + offset, sizeof(packet.dst_fep));
        offset += sizeof(packet.dst_fep);
    }

    // Parse PDS header type (1 byte)
    if (size >= offset + 1) {
        packet.PDS_type = static_cast<PDS_header_type>(data[offset]);
        offset += 1;
    }

    // Parse header data based on type
    switch (packet.PDS_type) {
        case PDS_header_type::RUOD_req_header:
            if (size >= offset + sizeof(packet.PDS_header.RUOD_req_header)) {
                std::memcpy(&packet.PDS_header.RUOD_req_header, 
                           data + offset, 
                           sizeof(packet.PDS_header.RUOD_req_header));
            }
            break;
        case PDS_header_type::RUOD_ack_header:
            if (size >= offset + sizeof(packet.PDS_header.RUOD_ack_header)) {
                std::memcpy(&packet.PDS_header.RUOD_ack_header,
                           data + offset,
                           sizeof(packet.PDS_header.RUOD_ack_header));
            }
            break;
        case PDS_header_type::RUOD_cp_header:
            if (size >= offset + sizeof(packet.PDS_header.RUOD_cp_header)) {
                std::memcpy(&packet.PDS_header.RUOD_cp_header,
                           data + offset,
                           sizeof(packet.PDS_header.RUOD_cp_header));
            }
            break;
        case PDS_header_type::nack_header:
            if (size >= offset + sizeof(packet.PDS_header.nack_header)) {
                std::memcpy(&packet.PDS_header.nack_header,
                           data + offset,
                           sizeof(packet.PDS_header.nack_header));
            }
            break;
        default:
            break;
    }

    // TODO: Parse SES layer data (if needed)

    return packet;
}

} // namespace NetworkLayer
} // namespace UET