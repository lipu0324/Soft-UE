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
#include <cerrno>
#include <cstring>
#include <iostream>

namespace UET {
namespace NetworkLayer {

namespace {
// UET UDP "wire format" framing (introduced to unblock FI_MSG style payload delivery):
//   u32  magic   = "UET1"
//   u8   version = 1
//   u8   flags   = 0 (reserved for future use)
//   u16  rsvd    = 0
//   u32  src_fep
//   u32  dst_fep
//   u8   pds_type
//   u16  pds_hdr_len + pds_hdr_bytes
//   u8   ses_bth_type
//   u16  ses_hdr_len + ses_hdr_bytes (phase 1 uses Standard_Header only)
//   u32  payload_len + payload_bytes
//
// Backward compatibility:
// If magic != "UET1", we parse the legacy layout (src/dst/type + raw PDS header only)
// and treat SES/payload as empty.
constexpr uint32_t kUETWireMagic = 0x55455431; // "UET1"
constexpr uint8_t kUETWireVersion = 1;

template <typename T>
inline void copy_packed_object_if_present(T& dst, const uint8_t* src, size_t available_bytes)
{
    if (available_bytes >= sizeof(T)) {
        std::memcpy(&dst, src, sizeof(T));
    }
}

inline void append_u8(std::vector<uint8_t>& buffer, uint8_t value)
{
    buffer.push_back(value);
}

inline void append_u16(std::vector<uint8_t>& buffer, uint16_t value)
{
    const uint16_t be = htons(value);
    const auto* bytes = reinterpret_cast<const uint8_t*>(&be);
    buffer.insert(buffer.end(), bytes, bytes + sizeof(be));
}

inline void append_u32(std::vector<uint8_t>& buffer, uint32_t value)
{
    const uint32_t be = htonl(value);
    const auto* bytes = reinterpret_cast<const uint8_t*>(&be);
    buffer.insert(buffer.end(), bytes, bytes + sizeof(be));
}

inline bool read_u8(const uint8_t* data, size_t size, size_t& offset, uint8_t& out)
{
    if (offset + 1 > size) return false;
    out = data[offset];
    offset += 1;
    return true;
}

inline bool read_u16(const uint8_t* data, size_t size, size_t& offset, uint16_t& out)
{
    if (offset + sizeof(uint16_t) > size) return false;
    uint16_t be{};
    std::memcpy(&be, data + offset, sizeof(be));
    offset += sizeof(be);
    out = ntohs(be);
    return true;
}

inline bool read_u32(const uint8_t* data, size_t size, size_t& offset, uint32_t& out)
{
    if (offset + sizeof(uint32_t) > size) return false;
    uint32_t be{};
    std::memcpy(&be, data + offset, sizeof(be));
    offset += sizeof(be);
    out = ntohl(be);
    return true;
}

inline uint16_t ack_ctrl_ext_len(const PDS_RUOD_ack_ctrl_ext& ext)
{
    uint16_t len = sizeof(PDS_RUOD_ack_ctrl_prefix);
    if ((ext.prefix.section_mask & ACK_CTRL_SECTION_SACK) != 0) {
        len = static_cast<uint16_t>(len + sizeof(PDS_RUOD_ack_ctrl_sack_section));
    }
    if ((ext.prefix.section_mask & ACK_CTRL_SECTION_CREDIT) != 0) {
        len = static_cast<uint16_t>(len + sizeof(PDS_RUOD_ack_ctrl_credit_section));
    }
    if ((ext.prefix.section_mask & ACK_CTRL_SECTION_ACKREQ_HINT) != 0) {
        len = static_cast<uint16_t>(len + sizeof(PDS_RUOD_ack_ctrl_ackreq_hint_section));
    }
    if ((ext.prefix.section_mask & ACK_CTRL_SECTION_RECEIVER_PRESSURE) != 0) {
        len = static_cast<uint16_t>(len + sizeof(PDS_RUOD_ack_ctrl_receiver_pressure_section));
    }
    return len;
}

inline void append_ack_ctrl_ext(std::vector<uint8_t>& buffer, const PDS_RUOD_ack_ctrl_ext& ext)
{
    const auto* prefix_ptr = reinterpret_cast<const uint8_t*>(&ext.prefix);
    buffer.insert(buffer.end(), prefix_ptr, prefix_ptr + sizeof(ext.prefix));
    if ((ext.prefix.section_mask & ACK_CTRL_SECTION_SACK) != 0) {
        const auto* ptr = reinterpret_cast<const uint8_t*>(&ext.sack);
        buffer.insert(buffer.end(), ptr, ptr + sizeof(ext.sack));
    }
    if ((ext.prefix.section_mask & ACK_CTRL_SECTION_CREDIT) != 0) {
        const auto* ptr = reinterpret_cast<const uint8_t*>(&ext.credit);
        buffer.insert(buffer.end(), ptr, ptr + sizeof(ext.credit));
    }
    if ((ext.prefix.section_mask & ACK_CTRL_SECTION_ACKREQ_HINT) != 0) {
        const auto* ptr = reinterpret_cast<const uint8_t*>(&ext.ackreq_hint);
        buffer.insert(buffer.end(), ptr, ptr + sizeof(ext.ackreq_hint));
    }
    if ((ext.prefix.section_mask & ACK_CTRL_SECTION_RECEIVER_PRESSURE) != 0) {
        const auto* ptr = reinterpret_cast<const uint8_t*>(&ext.receiver_pressure);
        buffer.insert(buffer.end(), ptr, ptr + sizeof(ext.receiver_pressure));
    }
}

inline void copy_ack_ctrl_ext(PDS_RUOD_ack_ctrl_ext& dst, const uint8_t* src, uint16_t available_len)
{
    dst = {};
    if (available_len < sizeof(PDS_RUOD_ack_ctrl_prefix)) {
        return;
    }
    std::memcpy(&dst.prefix, src, sizeof(dst.prefix));
    if (dst.prefix.total_len == 0 || dst.prefix.total_len > available_len) {
        dst = {};
        return;
    }

    size_t offset = sizeof(PDS_RUOD_ack_ctrl_prefix);
    const size_t total_len = dst.prefix.total_len;
    if ((dst.prefix.section_mask & ACK_CTRL_SECTION_SACK) != 0) {
        if (offset + sizeof(dst.sack) > total_len) {
            dst = {};
            return;
        }
        std::memcpy(&dst.sack, src + offset, sizeof(dst.sack));
        offset += sizeof(dst.sack);
    }
    if ((dst.prefix.section_mask & ACK_CTRL_SECTION_CREDIT) != 0) {
        if (offset + sizeof(dst.credit) > total_len) {
            dst = {};
            return;
        }
        std::memcpy(&dst.credit, src + offset, sizeof(dst.credit));
        offset += sizeof(dst.credit);
    }
    if ((dst.prefix.section_mask & ACK_CTRL_SECTION_ACKREQ_HINT) != 0) {
        if (offset + sizeof(dst.ackreq_hint) > total_len) {
            dst = {};
            return;
        }
        std::memcpy(&dst.ackreq_hint, src + offset, sizeof(dst.ackreq_hint));
        offset += sizeof(dst.ackreq_hint);
    }
    if ((dst.prefix.section_mask & ACK_CTRL_SECTION_RECEIVER_PRESSURE) != 0) {
        if (offset + sizeof(dst.receiver_pressure) > total_len) {
            dst = {};
            return;
        }
        std::memcpy(&dst.receiver_pressure, src + offset, sizeof(dst.receiver_pressure));
    }
}

inline void set_receive_timeout(int socket_fd, int timeout_ms)
{
    if (timeout_ms <= 0) {
        return;
    }
#ifdef _WIN32
    DWORD timeout = timeout_ms;
    setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
#else
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
}

template <typename Deserializer>
bool receive_packet_impl(int socket_fd,
                         bool initialized,
                         const UDPNetworkLayer::PacketCallback& callback,
                         int timeout_ms,
                         PDStoNET_pkt* packet_out,
                         Deserializer&& deserialize)
{
    if (!initialized || socket_fd < 0) {
        std::cerr << "UDP network layer not initialized" << std::endl;
        return false;
    }

    set_receive_timeout(socket_fd, timeout_ms);

    std::vector<uint8_t> buffer(65535);
    sockaddr_in sender_addr{};
    socklen_t sender_addr_len = sizeof(sender_addr);

    const int recv_bytes = recvfrom(socket_fd,
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
        char sender_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sender_addr.sin_addr, sender_ip, INET_ADDRSTRLEN);
        const uint16_t sender_port = ntohs(sender_addr.sin_port);

        std::cout << "Received packet: " << recv_bytes << " bytes <- "
                  << sender_ip << ":" << sender_port << std::endl;

        PDStoNET_pkt packet = deserialize(buffer.data(), static_cast<size_t>(recv_bytes));
        if (packet_out != nullptr) {
            *packet_out = packet;
        }
        if (callback) {
            callback(packet, std::string(sender_ip), sender_port);
        }
        return true;
    }

    if (recv_bytes < 0) {
#ifdef _WIN32
        const int error = WSAGetLastError();
        if (error != WSAETIMEDOUT && error != WSAEWOULDBLOCK) {
            std::cerr << "Failed to receive packet, error code: " << error << std::endl;
        }
#else
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            std::cerr << "Failed to receive packet: " << std::strerror(errno) << std::endl;
        }
#endif
    }

    return false;
}
} // namespace

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
        std::cerr << "Failed to create socket: " << std::strerror(errno) << std::endl;
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
        std::cerr << "Failed to set SO_REUSEADDR: " << std::strerror(errno) << std::endl;
    }

    // Bind to local port
    sockaddr_in local_addr{};
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = INADDR_ANY;
    local_addr.sin_port = htons(local_port_);

    if (bind(socket_fd_, reinterpret_cast<sockaddr*>(&local_addr), sizeof(local_addr)) < 0) {
        std::cerr << "Failed to bind port " << local_port_ << ": " << std::strerror(errno) << std::endl;
#ifdef _WIN32
        closesocket(socket_fd_);
        WSACleanup();
#else
        ::close(socket_fd_);
#endif
        socket_fd_ = -1;
        return false;
    }

    if (local_port_ == 0) {
        sockaddr_in bound_addr{};
        socklen_t bound_addr_len = sizeof(bound_addr);
        if (getsockname(socket_fd_, reinterpret_cast<sockaddr*>(&bound_addr), &bound_addr_len) == 0) {
            local_port_ = ntohs(bound_addr.sin_port);
        }
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
        std::cerr << "Failed to send packet: " << std::strerror(errno) << std::endl;
    } else {
        std::cout << "Packet sent successfully: " << sent_bytes << " bytes -> "
                  << dest_ip << ":" << dest_port << std::endl;
    }

    return sent_bytes;
}

bool UDPNetworkLayer::receivePacket(int timeout_ms)
{
    return receive_packet_impl(
        socket_fd_,
        initialized_,
        packet_callback_,
        timeout_ms,
        nullptr,
        [this](const uint8_t* data, size_t size) { return deserializePacket(data, size); });
}

bool UDPNetworkLayer::receivePDStoNETPacket(int timeout_ms , PDStoNET_pkt& packet)
{
    return receive_packet_impl(
        socket_fd_,
        initialized_,
        packet_callback_,
        timeout_ms,
        &packet,
        [this](const uint8_t* data, size_t size) { return deserializePacket(data, size); });
}

void UDPNetworkLayer::setPacketCallback(PacketCallback callback)
{
    packet_callback_ = std::move(callback);
}

void UDPNetworkLayer::close()
{
    if (socket_fd_ != -1) {
#ifndef _WIN32
        // Ensure any blocking recvfrom/sendto in other threads wakes up promptly.
        // 中文说明：单纯 close(fd) 在多线程下不一定能立刻打断阻塞中的 recvfrom；
        // shutdown(SHUT_RDWR) 可以更可靠地唤醒并让其返回错误，从而加速退出。
        ::shutdown(socket_fd_, SHUT_RDWR);
#endif
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

    // Serialize PDStoNET_pkt into a self-describing byte stream.
    // This allows the network layer to carry both PDS header and SES payload bytes end-to-end.
    append_u32(buffer, kUETWireMagic);
    append_u8(buffer, kUETWireVersion);
    append_u8(buffer, 0);      // flags
    append_u16(buffer, 0);     // reserved

    // Source/Destination FEP
    append_u32(buffer, packet.src_fep);
    append_u32(buffer, packet.dst_fep);

    // PDS header type and header bytes
    append_u8(buffer, static_cast<uint8_t>(packet.PDS_type));

    const uint8_t* pds_hdr_ptr = nullptr;
    uint16_t pds_hdr_len = 0;
    switch (packet.PDS_type) {
        case PDS_header_type::RUOD_req_header:
            pds_hdr_ptr = reinterpret_cast<const uint8_t*>(&packet.PDS_header.RUOD_req_header);
            pds_hdr_len = static_cast<uint16_t>(sizeof(packet.PDS_header.RUOD_req_header));
            break;
        case PDS_header_type::RUOD_ack_header:
            pds_hdr_ptr = reinterpret_cast<const uint8_t*>(&packet.PDS_header.RUOD_ack_header);
            pds_hdr_len = static_cast<uint16_t>(sizeof(packet.PDS_header.RUOD_ack_header));
            if (packet.PDS_header.RUOD_ack_header.flags.x) {
                pds_hdr_len = static_cast<uint16_t>(pds_hdr_len + ack_ctrl_ext_len(packet.ack_ctrl_ext));
            }
            break;
        case PDS_header_type::RUOD_cp_header:
            pds_hdr_ptr = reinterpret_cast<const uint8_t*>(&packet.PDS_header.RUOD_cp_header);
            pds_hdr_len = static_cast<uint16_t>(sizeof(packet.PDS_header.RUOD_cp_header));
            break;
        case PDS_header_type::nack_header:
            pds_hdr_ptr = reinterpret_cast<const uint8_t*>(&packet.PDS_header.nack_header);
            pds_hdr_len = static_cast<uint16_t>(sizeof(packet.PDS_header.nack_header));
            break;
        default:
            pds_hdr_ptr = nullptr;
            pds_hdr_len = 0;
            break;
    }

    append_u16(buffer, pds_hdr_len);
    if (pds_hdr_ptr && pds_hdr_len) {
        const uint16_t base_hdr_len =
            (packet.PDS_type == PDS_header_type::RUOD_ack_header)
                ? static_cast<uint16_t>(sizeof(packet.PDS_header.RUOD_ack_header))
                : pds_hdr_len;
        buffer.insert(buffer.end(), pds_hdr_ptr, pds_hdr_ptr + base_hdr_len);
        if (packet.PDS_type == PDS_header_type::RUOD_ack_header &&
            packet.PDS_header.RUOD_ack_header.flags.x) {
            append_ack_ctrl_ext(buffer, packet.ack_ctrl_ext);
        }
    }

    // SES BTH header
    append_u8(buffer, static_cast<uint8_t>(packet.SESpkt.bth_type));
    const uint8_t* ses_hdr_ptr = nullptr;
    uint16_t ses_hdr_len = 0;
    if (packet.SESpkt.bth_type == Standard_Header) {
        ses_hdr_ptr = reinterpret_cast<const uint8_t*>(&packet.SESpkt.bth_header.Standard_Header);
        ses_hdr_len = static_cast<uint16_t>(sizeof(packet.SESpkt.bth_header.Standard_Header));
    } else if (packet.SESpkt.bth_type == Semantic_Response_Header) {
        ses_hdr_ptr = reinterpret_cast<const uint8_t*>(&packet.SESpkt.bth_header.Semantic_Response_Header);
        ses_hdr_len = static_cast<uint16_t>(sizeof(packet.SESpkt.bth_header.Semantic_Response_Header));
    } else if (packet.SESpkt.bth_type == Semantic_Response_with_Data_Header) {
        ses_hdr_ptr = reinterpret_cast<const uint8_t*>(&packet.SESpkt.bth_header.Semantic_Response_with_Data_Header);
        ses_hdr_len = static_cast<uint16_t>(sizeof(packet.SESpkt.bth_header.Semantic_Response_with_Data_Header));
    } else if (packet.SESpkt.bth_type == Optimized_Response_with_Data_Header) {
        ses_hdr_ptr = reinterpret_cast<const uint8_t*>(&packet.SESpkt.bth_header.Optimized_Response_with_Data_Header);
        ses_hdr_len = static_cast<uint16_t>(sizeof(packet.SESpkt.bth_header.Optimized_Response_with_Data_Header));
    }
    append_u16(buffer, ses_hdr_len);
    if (ses_hdr_ptr && ses_hdr_len) {
        buffer.insert(buffer.end(), ses_hdr_ptr, ses_hdr_ptr + ses_hdr_len);
    }

    // Payload bytes
    const uint32_t payload_len = static_cast<uint32_t>(packet.SESpkt.payload.size());
    append_u32(buffer, payload_len);
    if (payload_len) {
        const uint8_t* payload_data = packet.SESpkt.payload.data();
        if (payload_data) {
            buffer.insert(buffer.end(), payload_data, payload_data + payload_len);
        }
    }

    return buffer;
}

PDStoNET_pkt UDPNetworkLayer::deserializePacket(const uint8_t* data, size_t size)
{
    PDStoNET_pkt packet{};
    size_t offset = 0;

    uint32_t magic = 0;
    if (!read_u32(data, size, offset, magic)) {
        return packet;
    }

    if (magic != kUETWireMagic) {
        // Backward-compatible parsing for legacy format (no framing, no SES/payload).
        // This keeps old tests/tools working while we bring up FI_MSG-based providers.
        offset = 0;
        if (size >= offset + sizeof(packet.src_fep)) {
            std::memcpy(&packet.src_fep, data + offset, sizeof(packet.src_fep));
            offset += sizeof(packet.src_fep);
        }
        if (size >= offset + sizeof(packet.dst_fep)) {
            std::memcpy(&packet.dst_fep, data + offset, sizeof(packet.dst_fep));
            offset += sizeof(packet.dst_fep);
        }
        if (size >= offset + 1) {
            packet.PDS_type = static_cast<PDS_header_type>(data[offset]);
            offset += 1;
        }
        switch (packet.PDS_type) {
            case PDS_header_type::RUOD_req_header:
                copy_packed_object_if_present(packet.PDS_header.RUOD_req_header, data + offset, size - offset);
                break;
            case PDS_header_type::RUOD_ack_header:
                copy_packed_object_if_present(packet.PDS_header.RUOD_ack_header, data + offset, size - offset);
                break;
            case PDS_header_type::RUOD_cp_header:
                copy_packed_object_if_present(packet.PDS_header.RUOD_cp_header, data + offset, size - offset);
                break;
            case PDS_header_type::nack_header:
                copy_packed_object_if_present(packet.PDS_header.nack_header, data + offset, size - offset);
                break;
            default:
                break;
        }
        packet.SESpkt.payload.clear();
        return packet;
    }

    uint8_t wire_ver = 0;
    uint8_t flags = 0;
    uint16_t rsvd = 0;
    if (!read_u8(data, size, offset, wire_ver) ||
        !read_u8(data, size, offset, flags) ||
        !read_u16(data, size, offset, rsvd)) {
        return packet;
    }
    (void)flags;
    (void)rsvd;
    if (wire_ver != kUETWireVersion) {
        return packet;
    }

    uint32_t src_fep = 0;
    uint32_t dst_fep = 0;
    if (!read_u32(data, size, offset, src_fep) || !read_u32(data, size, offset, dst_fep)) {
        return packet;
    }
    packet.src_fep = src_fep;
    packet.dst_fep = dst_fep;

    uint8_t pds_type = 0;
    if (!read_u8(data, size, offset, pds_type)) {
        return packet;
    }
    packet.PDS_type = static_cast<PDS_header_type>(pds_type);

    uint16_t pds_hdr_len = 0;
    if (!read_u16(data, size, offset, pds_hdr_len)) {
        return packet;
    }
    if (offset + pds_hdr_len > size) {
        return packet;
    }
    switch (packet.PDS_type) {
        case PDS_header_type::RUOD_req_header:
            copy_packed_object_if_present(packet.PDS_header.RUOD_req_header, data + offset, pds_hdr_len);
            break;
        case PDS_header_type::RUOD_ack_header:
            copy_packed_object_if_present(packet.PDS_header.RUOD_ack_header, data + offset, pds_hdr_len);
            if (pds_hdr_len > sizeof(packet.PDS_header.RUOD_ack_header) &&
                packet.PDS_header.RUOD_ack_header.flags.x) {
                const uint16_t ext_len = static_cast<uint16_t>(
                    pds_hdr_len - sizeof(packet.PDS_header.RUOD_ack_header));
                copy_ack_ctrl_ext(packet.ack_ctrl_ext,
                                  data + offset + sizeof(packet.PDS_header.RUOD_ack_header),
                                  ext_len);
            }
            break;
        case PDS_header_type::RUOD_cp_header:
            copy_packed_object_if_present(packet.PDS_header.RUOD_cp_header, data + offset, pds_hdr_len);
            break;
        case PDS_header_type::nack_header:
            copy_packed_object_if_present(packet.PDS_header.nack_header, data + offset, pds_hdr_len);
            break;
        default:
            break;
    }
    offset += pds_hdr_len;

    uint8_t ses_bth_type = 0;
    if (!read_u8(data, size, offset, ses_bth_type)) {
        return packet;
    }
    packet.SESpkt.bth_type = static_cast<SES_BTH_header_type>(ses_bth_type);

    uint16_t ses_hdr_len = 0;
    if (!read_u16(data, size, offset, ses_hdr_len)) {
        return packet;
    }
    if (offset + ses_hdr_len > size) {
        return packet;
    }
    if (packet.SESpkt.bth_type == Standard_Header && ses_hdr_len >= sizeof(packet.SESpkt.bth_header.Standard_Header)) {
        copy_packed_object_if_present(packet.SESpkt.bth_header.Standard_Header, data + offset, ses_hdr_len);
    } else if (packet.SESpkt.bth_type == Semantic_Response_Header &&
               ses_hdr_len >= sizeof(packet.SESpkt.bth_header.Semantic_Response_Header)) {
        copy_packed_object_if_present(packet.SESpkt.bth_header.Semantic_Response_Header, data + offset, ses_hdr_len);
    } else if (packet.SESpkt.bth_type == Semantic_Response_with_Data_Header &&
               ses_hdr_len >= sizeof(packet.SESpkt.bth_header.Semantic_Response_with_Data_Header)) {
        copy_packed_object_if_present(packet.SESpkt.bth_header.Semantic_Response_with_Data_Header,
                                      data + offset,
                                      ses_hdr_len);
    } else if (packet.SESpkt.bth_type == Optimized_Response_with_Data_Header &&
               ses_hdr_len >= sizeof(packet.SESpkt.bth_header.Optimized_Response_with_Data_Header)) {
        copy_packed_object_if_present(packet.SESpkt.bth_header.Optimized_Response_with_Data_Header,
                                      data + offset,
                                      ses_hdr_len);
    }
    offset += ses_hdr_len;

    uint32_t payload_len = 0;
    if (!read_u32(data, size, offset, payload_len)) {
        return packet;
    }
    if (offset + payload_len > size) {
        return packet;
    }
    packet.SESpkt.payload.clear();
    if (payload_len) {
        packet.SESpkt.payload.allocate(payload_len);
        uint8_t* dst = packet.SESpkt.payload.data();
        if (dst) {
            std::memcpy(dst, data + offset, payload_len);
        } else {
            packet.SESpkt.payload.clear();
        }
    }
    offset += payload_len;

    return packet;
}

} // namespace NetworkLayer
} // namespace UET
