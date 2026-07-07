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

#include "../Network_Layer/UDP_Network_Layer.hpp"
#include "../PDS/PDS_Manager/PDSManagerInternal.hpp"
#include "../SES/SES.hpp"
#include "../SES/SESInternal.hpp"
#include "../logger/Logger.hpp"

#include <cstring>
#include <iostream>
#include <string>

using namespace UET::NetworkLayer;

namespace {

bool require(bool condition, const std::string& message)
{
    if (!condition) {
        std::cerr << "FAIL: " << message << std::endl;
        return false;
    }
    return true;
}

PDStoNET_pkt makePacket()
{
    PDStoNET_pkt packet{};
    packet.src_fep = 0x12345678;
    packet.dst_fep = 0x87654321;
    packet.PDS_type = RUOD_req_header;
    packet.PDS_header.RUOD_req_header.type = ROD_REQ;
    packet.PDS_header.RUOD_req_header.next_hdr = UET_HDR_REQUEST_STD;
    packet.PDS_header.RUOD_req_header.flags.syn = 1;
    packet.PDS_header.RUOD_req_header.psn = 1001;
    packet.PDS_header.RUOD_req_header.spdcid = 7;
    packet.PDS_header.RUOD_req_header.dpdcid = 9;
    packet.SESpkt.bth_type = Standard_Header;
    packet.SESpkt.bth_header.Standard_Header.version = 2;
    packet.SESpkt.bth_header.Standard_Header.som = 1;
    packet.SESpkt.bth_header.Standard_Header.eom = 1;
    packet.SESpkt.bth_header.Standard_Header.msg_id = 0x33;
    packet.SESpkt.payload = UET::PayloadHandle::alloc(4);
    uint8_t* payload = packet.SESpkt.payload.data();
    if (payload != nullptr) {
        payload[0] = 1;
        payload[1] = 2;
        payload[2] = 3;
        payload[3] = 4;
    }
    return packet;
}

bool samePacketShape(const PDStoNET_pkt& lhs, const PDStoNET_pkt& rhs)
{
    if (lhs.src_fep != rhs.src_fep || lhs.dst_fep != rhs.dst_fep || lhs.PDS_type != rhs.PDS_type) {
        return false;
    }
    if (lhs.PDS_header.RUOD_req_header.spdcid != rhs.PDS_header.RUOD_req_header.spdcid ||
        lhs.PDS_header.RUOD_req_header.dpdcid != rhs.PDS_header.RUOD_req_header.dpdcid ||
        lhs.PDS_header.RUOD_req_header.psn != rhs.PDS_header.RUOD_req_header.psn) {
        return false;
    }
    if (lhs.SESpkt.payload.size() != rhs.SESpkt.payload.size()) {
        return false;
    }
    return lhs.SESpkt.payload.size() == 0 ||
           std::memcmp(lhs.SESpkt.payload.data(), rhs.SESpkt.payload.data(), lhs.SESpkt.payload.size()) == 0;
}

bool testPdsRouteHelper()
{
    PDStoNET_pkt req{};
    req.PDS_type = RUOD_req_header;
    req.PDS_header.RUOD_req_header.dpdcid = 11;
    req.PDS_header.RUOD_req_header.spdcid = 22;
    req.PDS_header.RUOD_req_header.flags.syn = 1;
    auto req_route = UET::PDSInternal::inspectRxPacketRoute(req);
    if (!require(req_route.recognized && req_route.is_request, "req route should be recognized as request")) return false;
    if (!require(req_route.syn && req_route.dpdcid == 11 && req_route.spdcid == 22, "req route fields mismatch")) return false;

    PDStoNET_pkt cp{};
    cp.PDS_type = RUOD_cp_header;
    cp.PDS_header.RUOD_cp_header.dpdcid = 12;
    cp.PDS_header.RUOD_cp_header.spdcid = 23;
    cp.PDS_header.RUOD_cp_header.flags.syn = 0;
    auto cp_route = UET::PDSInternal::inspectRxPacketRoute(cp);
    if (!require(cp_route.recognized && cp_route.is_request, "cp route should be recognized as request")) return false;
    if (!require(!cp_route.syn && cp_route.dpdcid == 12 && cp_route.spdcid == 23, "cp route fields mismatch")) return false;

    PDStoNET_pkt ack{};
    ack.PDS_type = RUOD_ack_header;
    ack.PDS_header.RUOD_ack_header.dpdcid = 13;
    ack.PDS_header.RUOD_ack_header.spdcid = 24;
    auto ack_route = UET::PDSInternal::inspectRxPacketRoute(ack);
    if (!require(ack_route.recognized && !ack_route.is_request, "ack route should be recognized as non-request")) return false;
    return require(ack_route.dpdcid == 13 && ack_route.spdcid == 24, "ack route fields mismatch");
}

bool testSesValidationProbe()
{
    SESManager manager;
    if (!require(SESValidationProbe::validateVersion(manager, 2), "validateVersion(2) should stay true")) return false;
    if (!require(!SESValidationProbe::validateVersion(manager, 1), "validateVersion(1) should stay false")) return false;
    if (!require(SESValidationProbe::validateJobId(manager, 0), "validateJobId should preserve permissive stub")) return false;
    if (!require(SESValidationProbe::validateNeedAck(manager, 1, true), "validateNeedAck(1,true) should stay true")) return false;
    if (!require(!SESValidationProbe::validateNeedAck(manager, 2, true), "validateNeedAck(2,true) should stay false")) return false;
    return require(!SESValidationProbe::validateNeedAck(manager, 1, false), "validateNeedAck(1,false) should stay false");
}

bool testUdpReceivePaths()
{
    const PDStoNET_pkt sent = makePacket();

    {
        UDPNetworkLayer rx(0);
        UDPNetworkLayer tx(0);
        PDStoNET_pkt callback_pkt{};
        bool callback_seen = false;
        rx.setPacketCallback([&](const PDStoNET_pkt& packet, const std::string&, uint16_t) {
            callback_pkt = packet;
            callback_seen = true;
        });
        if (!require(rx.initialize() && tx.initialize(), "udp initialize for callback path")) return false;
        if (!require(tx.sendPacket(sent, "127.0.0.1", rx.getLocalPort()) > 0, "udp send for callback path")) return false;
        if (!require(rx.receivePacket(500), "receivePacket should succeed")) return false;
        if (!require(callback_seen, "receivePacket callback should fire")) return false;
        if (!require(samePacketShape(sent, callback_pkt), "receivePacket callback packet should match")) return false;
    }

    {
        UDPNetworkLayer rx(0);
        UDPNetworkLayer tx(0);
        PDStoNET_pkt callback_pkt{};
        PDStoNET_pkt received_pkt{};
        bool callback_seen = false;
        rx.setPacketCallback([&](const PDStoNET_pkt& packet, const std::string&, uint16_t) {
            callback_pkt = packet;
            callback_seen = true;
        });
        if (!require(rx.initialize() && tx.initialize(), "udp initialize for direct path")) return false;
        if (!require(tx.sendPacket(sent, "127.0.0.1", rx.getLocalPort()) > 0, "udp send for direct path")) return false;
        if (!require(rx.receivePDStoNETPacket(500, received_pkt), "receivePDStoNETPacket should succeed")) return false;
        if (!require(callback_seen, "receivePDStoNETPacket callback should still fire")) return false;
        if (!require(samePacketShape(sent, received_pkt), "receivePDStoNETPacket output should match")) return false;
        if (!require(samePacketShape(sent, callback_pkt), "receivePDStoNETPacket callback packet should match")) return false;
    }

    return true;
}

} // namespace

int main()
{
    Logger::initialize("RefactorGuardTest.log", LogLevel::DEBUG, 1, 1);

    const bool ok = testPdsRouteHelper() && testSesValidationProbe() && testUdpReceivePaths();
    std::cout << (ok ? "RefactorGuardTest PASS" : "RefactorGuardTest FAIL") << std::endl;
    return ok ? 0 : 1;
}
