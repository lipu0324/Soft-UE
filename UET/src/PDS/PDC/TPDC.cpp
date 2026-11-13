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
 * @file             TPDC.cpp
 * @brief            TPDC.cpp
 * @author           softuegroup@gmail.com
 * @version          1.0.0
 * @date             2025-10-29
 * @copyright        Apache License Version 2.0
 *
 * @details
 * This file implements the Target PDC (T_PDC) class for reliable ordered data delivery.
 */


#include "TPDC.hpp"
#include "../DefaultSemanticResponse.hpp"

bool T_PDC::initPDC(uint16_t id)
{
    if (!beginTransmitIncarnation()) return false;
    resetCloseSafety();
    resetProbe();
    clearAllPacketTimers();
    acknowledged_tx_.clear();
    semantic_completed_tx_.clear();
    peer_clear_requests_.clear();
    ordered_recovery_.acknowledged();
    received_rx_psns_.clear();
    completed_rx_psns_.clear();
    uncached_read_responses_.clear();
    resetAcknowledgmentOrdering();
    // FUNCTION_LOG_ENTRY();

    // Record input parameters
    std::stringstream params;
    params << "Initialize PDC - ID: " << id;
    LOG_INFO(__FUNCTION__, formatLogMessage(params.str()));

    // ==================== Basic Parameter Initialization
    SPDCID = id;       // Set source PDC ID
    DPDCID = 0;        // Initialize destination PDC ID to 0
    initializePsnRanges();
    mode = ROD;        // Set to reliable ordered delivery mode
    state = CLOSED;    // Initial state is closed

    // ==================== PSN Related Initialization
    start_psn = 1000;   // Set starting PSN, actually not used
    resetPeerSequenceWindow();
    tx_cur_psn = 0;     // Initialize transmit PSN
    clear_psn = 0;      // Initialize clear PSN
    rx_cur_psn = 0;     // Initialize receive PSN
    cack_psn = 0;       // Initialize cumulative acknowledgment PSN

    // ==================== Counter and Flag Initialization
    unack_cnt = 0;     // Reset unacknowledged packet counter
    allACK = true;     // Initialize all ACK flag to true
    open_msg = 0;      // Reset open message counter
    ACK_GEN_COUNT = 0; // Reset ACK generation counter

    // ==================== Status Flag Initialization
    SYN = false;         // Synchronization flag
    secure_psn = false;  // Secure PSN flag
    bad_psn = false;     // Bad PSN flag
    pause_pdc = false;   // Pause PDC transmission flag
    trim = false;        // Trim flag
    rx_error = false;    // Receive error flag
    close_error = false; // Close error flag
    closing = false;     // Closing flag
    close_cmd = false;   // Close command flag
    req_closing = false; // Request closing flag

    // ==================== Control Message and Error Type Initialization
    gen_cm = NONE;       // Control message type to be generated
    error_chk = OPEN;    // Error check type

    // ==================== Clear Static Queues and Containers
    // Clear all static queues
    while (!tx_req_q.empty()) tx_req_q.pop();
    while (!tx_rsp_q.empty()) tx_rsp_q.pop();
    rx_pkt_q.clear();
    while (!tx_pkt_q.empty()) tx_pkt_q.pop();
    while (!rx_req_pkt_q.empty()) rx_req_pkt_q.pop();
    while (!rx_rsp_pkt_q.empty()) rx_rsp_pkt_q.pop();
    while (!rto_pkt_q.empty()) rto_pkt_q.pop();

    // Clear all static maps
    tx_pkt_map.clear();
    rx_pkt_map.clear();
    tx_pkt_buffer.clear();
    tx_ack_buffer.clear();

    // Record initialization status
    std::stringstream init_state;
    init_state << "PDC initialization complete - SPDCID: " << SPDCID
                << ", DPDCID: " << DPDCID
                << ", local_packet_capacity: " << local_packet_capacity
                << ", mode: " << MODE_STR(mode)
                << ", state: " << STATE_STR(state)
                << ", tx_cur_psn: " << tx_cur_psn
                << ", clear_psn: " << clear_psn
                << ", rx_cur_psn: " << rx_cur_psn
                << ", cack_psn: " << cack_psn
                << ", unack_cnt: " << unack_cnt
                << ", allACK: " << (allACK ? "true" : "false")
                << ", open_msg: " << open_msg;
    LOG_INFO(__FUNCTION__, formatLogMessage(init_state.str()));

    diagnostics() << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] Establish T_PDC:" << id << " - Complete initialization" << std::endl;

    FUNCTION_LOG_EXIT();
    return true;
}

void T_PDC::processOpen1(PDStoNET_pkt *pkt)
{
    diagnostics() << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] process open1" << std::endl;
    if (chkTrim())
    { // Check if packet is trimmed
        trim = true;
    }
    else
        trim = false;

    if (trim)
    { // If packet is trimmed, close connection
        processClose();
    }
    else
    {
        if (secure_psn)
            processSecurePsn1(pkt); // Enable secure PSN verification
        else if (!secure_psn)
            processOpen2(pkt); // Directly enter establishment phase 2
    }
}

void T_PDC::establishContext(uint16_t remote_pdc,uint32_t initial_sequence,pdc_mode delivery_mode)
{
    DPDCID=remote_pdc; start_psn=initial_sequence; mode=delivery_mode;
    resetAcknowledgmentOrdering();
    resetPeerSequenceWindow();
    rx_cur_psn=start_psn-1; cack_psn=rx_cur_psn; rx_clear_psn=rx_cur_psn;
    tx_cur_psn=start_psn; clear_psn=start_psn-1;
    bad_psn=false; state=ESTABLISHED;
    bindCongestionContext(delivery_mode);
}

void T_PDC::processOpen2(PDStoNET_pkt *pkt)
{
    diagnostics() << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] process open2" << std::endl;
    if (!secure_psn)
    {
        const auto& header=pkt->PDS_header.RUOD_req_header;
        establishContext(header.spdcid,header.psn-header.psn_off,header.type==RUD_REQ?RUD:ROD);
        if (mode==ROD && header.psn_off) {
            // §3.5.8.2 step 3.e: the first ROD arrival may be any later
            // SYN packet. Retain the new context and request Start_PSN,
            // before applying checks for an already established SYN.
            sendNack(header.flags.retx,header.psn,UET_ROD_OOO,start_psn,nullptr,pkt);
            return;
        }
        LOG_INFO(__FUNCTION__, formatLogMessage("process2 running - SPDCID: " + std::to_string(SPDCID) + ", DPDCID: " + std::to_string(DPDCID) + ", cack_psn: " + std::to_string(cack_psn)));
    }
    else
        state = PENDING; // Waiting for secure PSN verification

    chkRxError(pkt); // Check receive packet error
    observeCongestionDuplicate(*pkt);
    if (!trim && error_chk==ACK_ERROR && reissueReceivedRead(pkt)) return;
    if (error_chk==INV_SYN) {
        const auto& header=pkt->PDS_header.RUOD_req_header;
        sendNack(header.flags.retx,header.psn,
            ((header.type==RUD_REQ)!=(mode==RUD))?UET_PDC_MODE_MISMATCH:UET_INVALID_SYN,0,nullptr,pkt);
        return;
    }
    if (error_chk == OPEN)
    { // Packet is normal, process receive request
        if (!admitSemanticRequest(*pkt)) return;
        uint16_t handle = processRxReq(pkt);
        RX_pkt_meta meta = rx_pkt_map.at(handle);
        std::stringstream forward_info;
        forward_info << "Forward to SES layer - handle: " << handle << ", PSN: " << meta.psn;
        LOG_DEBUG(__FUNCTION__, formatLogMessage(forward_info.str()));
        fwdReq2SES(handle, meta, &pkt->SESpkt); // Forward to SES layer
        updateRxPsnTracker(&meta);
        // Any packet may produce a guaranteed SES error (§3.4.6). Wait for
        // SES even on an intermediate SYN request: a separate plain ACK would
        // release its packet-to-message association before the error arrives.
        // The explicit legacy path retains its historical handshake behavior.
        if (!runtime_ || pkt->SESpkt.bth_type!=Standard_Header ||
            pkt->SESpkt.bth_header.Standard_Header.version!=0)
            sendAck(PDS_next_hdr::UET_HDR_NONE, 0, 0, meta.psn, nullptr, false,pkt);
        LOG_INFO(__FUNCTION__, formatLogMessage("Send ACK - SPDCID: " + std::to_string(SPDCID) + ", DPDCID: " + std::to_string(DPDCID) + ", PSN: " + std::to_string(meta.psn)));
    }
    else if (error_chk==OOO)
    {
        sendNack(0, pkt->PDS_header.RUOD_req_header.psn, UET_ROD_OOO, rx_cur_psn + 1,nullptr,pkt);
        // A later SYN packet may arrive before the starting packet. Keep the
        // newly allocated context so the missing PSN can establish it (§3.5.8.1).
    }
    // DROP is a receive-window refusal, including a locally reduced MPR.
    // It must not be mislabeled as ROD_OOO on a newly created RUD PDC.
}

void T_PDC::openChk()
{
    //FUNCTION_LOG_ENTRY();

    // Record current PDC status
    // std::stringstream entry_state;
    // entry_state << "Entry status - state: " << STATE_STR(state)
    //             << ", gen_cm: " << CM_TYPE_STR(gen_cm)
    //             << ", close_error: " << close_error
    //             << ", closing: " << closing
    //             << ", unack_cnt: " << unack_cnt
    //             << ", allACK: " << allACK;
    // LOG_DEBUG(__FUNCTION__, formatLogMessage(entry_state.str()));

    // // Record queue status
    // std::stringstream queue_state;
    // queue_state << "Queue status - rx_pkt_q: " << rx_pkt_q.size()
    //             << ", tx_rsp_q: " << tx_rsp_q.size()
    //             << ", tx_req_q: " << tx_req_q.size();
    // LOG_DEBUG(__FUNCTION__, formatLogMessage(queue_state.str()));

    //diagnostics() << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] open_chk state: " << STATE_STR(state) << std::endl;

    if (state != CLOSED)
    {
        //diagnostics() << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] unack_cnt:" << unack_cnt << ",allACK:" << allACK << std::endl;
        if (gen_cm != NONE)
        { // Prioritize control message generation
            diagnostics() << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] gen_cm:" << CM_TYPE_STR(gen_cm) << std::endl;
            LOG_INFO(__FUNCTION__, formatLogMessage("Process control message generation"));
            txCtrl();
        }
        else if (close_error)
        {
            // §3.5.8.3 permits terminal close in error after fatal replies or
            // retry exhaustion. Repeating Close Requests here would otherwise
            // keep an event-driven host runnable forever at one timestamp.
            emitPdcEvent(UET::Runtime::PdcEventKind::ConnectionClosed,rx_cur_psn);
            freePDC();
            state=CLOSED;
            if (public_close_queue) public_close_queue->push(SPDCID);
        }
        else if (closing && unack_cnt == 0 && allACK)
        { // Check if close can be completed
            diagnostics() << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] closing && unack_cnt == 0 && allACK" << std::endl;
            LOG_INFO(__FUNCTION__, formatLogMessage("Close conditions met, execute close"));
            close();
        }
        else if (!rx_pkt_q.empty())
        { // Handle received packets
            LOG_DEBUG(__FUNCTION__, formatLogMessage("Process data packets in receive queue"));
            diagnostics() << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] rx_pkt_q size:" << rx_pkt_q.size() << std::endl;
            PDStoNET_pkt p;
            if (!rx_pkt_q.pop(p)) return;
            if (p.PDS_type == nack_header)
            {
                LOG_DEBUG(__FUNCTION__, formatLogMessage("Process negative acknowledgment packet"));
                netRxNack(&p); // Handle negative acknowledgment packet / Process negative acknowledgment packet
            }
            else if (p.PDS_type == RUOD_req_header)
            {
                LOG_DEBUG(__FUNCTION__, formatLogMessage("Process request packet"));
                netRxReq(&p); // Handle request packet / Process request packet
            }
            else if (p.PDS_type == RUOD_ack_header)
            {
                LOG_DEBUG(__FUNCTION__, formatLogMessage("Process acknowledgment packet"));
                netRxAck(&p); // Handle acknowledgment packet / Process acknowledgment packet
            }
            else if (p.PDS_type == RUOD_cp_header)
            {
                LOG_DEBUG(__FUNCTION__, formatLogMessage("Process control packet"));
                netRxCm(&p); // Handle control packet / Process control packet
            }
        }
        else if(probe_due_ || needsWindowProbe()) { progressProbe(); }
    else if(admissionRetryReady()) { retryAdmissionDeferred(); }
        else if(!rto_pkt_q.empty()){
            uint32_t psn = rto_pkt_q.front();
            rto_pkt_q.pop();
            LOG_DEBUG(__FUNCTION__, formatLogMessage("Process timeout retransmission packet,psn:"+std::to_string(psn)));
            txRto(psn); // Handle timeout retransmission packet / Process timeout retransmission packet
        }
        else if (!tx_rsp_q.empty())
        { // Handle SES layer response transmission
            diagnostics() << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] tx_rsp_q size:" << tx_rsp_q.size() << std::endl;
            LOG_DEBUG(__FUNCTION__, formatLogMessage("Process SES layer response transmission"));
            sesTxRsp(&tx_rsp_q.front());
            tx_rsp_q.pop();
        }
        else if (state == ESTABLISHED && pause_pdc == false && newDataAllowed() && !tx_req_q.empty() && peerWindowAllows(tx_cur_psn) && congestionReady())
        { // Packet transmission can only be done in established state
            //diagnostics() << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] state == ESTABLISHED && pause_pdc == false" << std::endl;
            if (!tx_req_q.empty())
            { // Handle PDS layer request transmission
                LOG_DEBUG(__FUNCTION__, formatLogMessage("Process PDS layer request transmission"));
                sesTxReq(&tx_req_q.front());
                tx_req_q.pop();
            }
        }
        else
            diagnostics() << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] error" << std::endl;
    }
    else
    {
        LOG_DEBUG(__FUNCTION__, formatLogMessage("Connection closed state, only process receive packets"));
        diagnostics() << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] Connection closed state, only process receive packets" << rx_pkt_q.size() << std::endl;
        if (!rx_pkt_q.empty())
        { // Handle received packets
            PDStoNET_pkt p;
            if (!rx_pkt_q.pop(p)) return;
            if (p.PDS_type == RUOD_req_header)
            {
                LOG_DEBUG(__FUNCTION__, formatLogMessage("Process request packet in closed state"));
                netRxReq(&p); // Handle request packet / Process request packet
            }
            else if (p.PDS_type==RUOD_cp_header) netRxCm(&p);
        }
    }

    // FUNCTION_LOG_EXIT();
}

void T_PDC::reqClose()
{
    if (req_closing || state!=ESTABLISHED) return;
    req_closing=true;
    sendCloseReq(); // Schedule once; ordinary PDS timers own its retransmits.
}

void T_PDC::beginClose()
{
    diagnostics() << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] begin close" << std::endl;
    closing = true;        // Set closing flag
    state = ACK_WAIT;      // Wait for ACK state
}

void T_PDC::close()
{
    emitPdcEvent(UET::Runtime::PdcEventKind::ConnectionClosed,rx_cur_psn);
    diagnostics() << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] close" << std::endl;
    sendCloseAck();  // Send close acknowledgment
    saveExpectedPSN(); // Save expected PSN
    // Delay 50ms
    if (!runtime_) std::this_thread::sleep_for(std::chrono::milliseconds(50));
    // Release PDC resources
    freePDC();
    state = CLOSED;    // Set to closed state

    // Add own PDCID to PDC close queue
    if (public_close_queue) {
        public_close_queue->push(SPDCID);
        LOG_INFO(__FUNCTION__, formatLogMessage("[PDCID:" + std::to_string(SPDCID) + "] T_PDC closure complete, PDCID added to close queue"));
    }
    else{
        LOG_ERROR(__FUNCTION__, formatLogMessage("[PDCID:" + std::to_string(SPDCID) + "] Close queue not initialized"));
    }
    // TODO: Send close message to PDS
}

void T_PDC::processClose()
{
    closing = false;
    req_closing = false;
    diagnostics() << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] process close" << std::endl;
}

void T_PDC::processSecurePsn1(PDStoNET_pkt *pkt)
{
    diagnostics() << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] process secure psn" << std::endl;
    DPDCID = pkt->PDS_header.RUOD_req_header.spdcid;     // Set destination PDC ID
    processRxReq(pkt);                                 // Process receive request
    chkSecurePsn(pkt->PDS_header.RUOD_req_header.psn); // Check PSN security
    if (bad_psn)
    {
        diagnostics() << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] psn is bad" << std::endl;
        // TODO: Complete PSN verification failure handling process
    }
    else
    {
        diagnostics() << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] psn not bad" << std::endl;
        processOpen2(pkt); // PSN verification passed, continue establishment process
    }
}

void T_PDC::processSecurePsn2(PDStoNET_pkt *pkt)
{
    chkSecurePsn(pkt->PDS_header.RUOD_req_header.psn);
    if (bad_psn)
    {
        // PSN verification failed, wait for re-verification
    }
    else
        rxReq(pkt); // PSN verification passed, normal request processing
}

void T_PDC::chkSecurePsn(uint32_t psn)
{
    LOG_DEBUG(__FUNCTION__, formatLogMessage("Check PSN security - PSN: " + std::to_string(psn)));
    bool invalid_psn = false; // TODO: Implement PSN validity check logic
    if (invalid_psn)
    {
        // TODO: Send NACK and use new PSN
        bad_psn = true;
        state = PENDING;
    }
    else
        bad_psn = false;
}

void T_PDC::saveExpectedPSN()
{
    // TODO: Implement PSN save logic
    diagnostics() << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] Save expected PSN: " << rx_cur_psn + 1 << std::endl;
}

void T_PDC::netRxReq(PDStoNET_pkt *pkt)
{
    // FUNCTION_LOG_ENTRY();
    diagnostics() << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] net rx req" << std::endl;
    // Parameter check
    if (!pkt)
    {
        LOG_ERROR(__FUNCTION__, formatLogMessage("Input packet pointer is null"));
        // FUNCTION_LOG_EXIT();
        return;
    }
    if (pkt->trimmed) { rejectTrimmed(*pkt); return; }

    // Record packet information
    std::stringstream pkt_info;
    pkt_info << "Receive request packet - PSN: " << pkt->PDS_header.RUOD_req_header.psn
                << ", SPDCID: " << pkt->PDS_header.RUOD_req_header.spdcid
                << ", DPDCID: " << pkt->PDS_header.RUOD_req_header.dpdcid
                << ", SYN: " << (pkt->PDS_header.RUOD_req_header.flags.syn ? "1" : "0")
                << ", AR: " << (pkt->PDS_header.RUOD_req_header.flags.ar ? "1" : "0")
                << ", RETX: " << (pkt->PDS_header.RUOD_req_header.flags.retx ? "1" : "0");
    LOG_INFO(__FUNCTION__, formatLogMessage(pkt_info.str()));

    // Record current status
    std::stringstream state_info;
    state_info << "Current status - state: " << STATE_STR(state) << ", bad_psn: " << (bad_psn ? "true" : "false");
    LOG_DEBUG(__FUNCTION__, formatLogMessage(state_info.str()));

    if (state == CLOSED)
    { // Connection closed state, start establishing connection
        LOG_INFO(__FUNCTION__, formatLogMessage("Connection closed state, start establishing connection"));
        processOpen1(pkt);
    }
    else if (bad_psn)
    { // PSN has problems, perform secure PSN processing
        LOG_WARN(__FUNCTION__, formatLogMessage("PSN has problems, perform secure PSN processing"));
        processSecurePsn2(pkt);
    }
    else if (!bad_psn)
    { // PSN is normal, process request
        LOG_DEBUG(__FUNCTION__, formatLogMessage("PSN is normal, process request"));
        rxReq(pkt);
    }

    // FUNCTION_LOG_EXIT();
}

void T_PDC::netRxAck(PDStoNET_pkt *pkt)
{
    // FUNCTION_LOG_ENTRY();
    diagnostics() << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] net rx ack" << std::endl;
    if (!pkt)
    {
        LOG_ERROR(__FUNCTION__, formatLogMessage("Input packet pointer is null"));
        // FUNCTION_LOG_EXIT();
        return;
    }

    // Record ACK packet information
    std::stringstream ack_info;
    ack_info << "Receive ACK packet - ack_psn_off: " << pkt->PDS_header.RUOD_ack_header.ack_psn_off
                << ", cack_psn: " << pkt->PDS_header.RUOD_ack_header.cack_psn
                << ", SPDCID: " << pkt->PDS_header.RUOD_ack_header.spdcid
                << ", DPDCID: " << pkt->PDS_header.RUOD_ack_header.dpdcid;
    LOG_INFO(__FUNCTION__, formatLogMessage(ack_info.str()));

    if (bad_psn == false)
    { // Process ACK when PSN is normal
        LOG_DEBUG(__FUNCTION__, formatLogMessage("PSN is normal, process ACK"));
        rxAck(pkt);
    }
    else
    {
        LOG_WARN(__FUNCTION__, formatLogMessage("PSN abnormal, skip ACK processing"));
    }

    // FUNCTION_LOG_EXIT();
}

void T_PDC::netRxNack(PDStoNET_pkt* packet)
{
    rxNack(packet);
}

void T_PDC::netRxCm(PDStoNET_pkt *pkt)
{
    const auto& header=pkt->PDS_header.RUOD_cp_header;
    if (state==CLOSED) {
        // §3.5.16: NOOP and Negotiation are the only CPs that can establish
        // a PDC. No semantic request or application completion is fabricated.
        if (!header.flags.syn || (header.ctl_type!=Noop && header.ctl_type!=Negotiation) || header.flags.pdc_type>1) return;
        establishContext(header.spdcid,header.psn-header.psn_off,header.flags.pdc_type==1?ROD:RUD);
        if (mode==ROD && header.psn_off) {
            sendNack(header.flags.retx,header.psn,UET_ROD_OOO,start_psn,nullptr,pkt);
            return;
        }
    }
    if (pkt->PDS_header.RUOD_cp_header.ctl_type == 4){
        LOG_INFO(__FUNCTION__, formatLogMessage("TPDC received close command, PSN:" + std::to_string(pkt->PDS_header.RUOD_cp_header.psn)));
        if(pkt->PDS_header.RUOD_cp_header.psn == rx_cur_psn + 1){
            rx_cur_psn = pkt->PDS_header.RUOD_cp_header.psn;
            LOG_INFO(__FUNCTION__, formatLogMessage("TPDC received close command packet with correct PSN, update rx_cur_psn:" + std::to_string(rx_cur_psn)));
        }
        // §3.5.8.3: Close Command is an implicit clear of forward PSNs and
        // an ACK for all return PSNs. A lost Clear CP must not deadlock close.
        tx_ack_buffer.clear(); tx_pkt_buffer.clear(); tx_pkt_map.clear();
        clearAllPacketTimers();
        cack_psn=rx_cur_psn; rx_clear_psn=rx_cur_psn;
        unack_cnt=0; allACK=true;
        close_network_trigger_=*pkt;
        beginClose(); // Close command
    }
    else if (!bad_psn)
        rxCtrl(pkt); // Other control messages
}

void T_PDC::rxReq(PDStoNET_pkt *pkt)
{
    // FUNCTION_LOG_ENTRY();
    diagnostics() << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] rx req" << std::endl;
    if (!pkt)
    {
        LOG_ERROR(__FUNCTION__, formatLogMessage("Input packet pointer is null"));
        // FUNCTION_LOG_EXIT();
        return;
    }

    // Record packet information
    std::stringstream pkt_info;
    pkt_info << "Process request packet - PSN: " << pkt->PDS_header.RUOD_req_header.psn
                << ", rx_cur_psn: " << rx_cur_psn
                << ", clear_psn: " << pkt->PDS_header.RUOD_req_header.psn + pkt->PDS_header.RUOD_req_header.clear_psn_off;
    LOG_DEBUG(__FUNCTION__, formatLogMessage(pkt_info.str()));

    chkRxError(pkt); // Check receive packet error
    observeCongestionDuplicate(*pkt);
    if (!trim && error_chk==ACK_ERROR && reissueReceivedRead(pkt)) return;
    if (error_chk==INV_SYN) {
        const auto& header=pkt->PDS_header.RUOD_req_header;
        sendNack(header.flags.retx,header.psn,
            ((header.type==RUD_REQ)!=(mode==RUD))?UET_PDC_MODE_MISMATCH:UET_INVALID_SYN,0,nullptr,pkt);
        return;
    }

    // Record error check results
    std::stringstream error_info;
    error_info << "Error check results - trim: " << (trim ? "true" : "false")
                << ", error_chk: " << ERROR_TYPE_STR(error_chk);
    LOG_DEBUG(__FUNCTION__, formatLogMessage(error_info.str()));

    if (trim || error_chk != OPEN)
    {
        if (trim)
        {
            diagnostics() << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] trim is true" << std::endl;
            LOG_WARN(__FUNCTION__, formatLogMessage("Packet trimmed, send NACK"));
            sendNack(0, pkt->PDS_header.RUOD_req_header.psn, UET_TRIMMED, rx_cur_psn + 1,nullptr,pkt);
        }
        else if (error_chk == ACK_ERROR)
        {
            diagnostics() << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] error_chk is ACK_ERROR" << std::endl;
            LOG_INFO(__FUNCTION__, formatLogMessage("Duplicate packet, respond with ACK immediately"));
            if (!replaySemanticAck(pkt->PDS_header.RUOD_req_header.psn,pkt)) {
                const auto sequence=pkt->PDS_header.RUOD_req_header.psn;
                const bool processing=std::any_of(rx_pkt_map.begin(),rx_pkt_map.end(),
                    [sequence](const auto& request) { return request.second.psn==sequence; });
                if (processing) sendNack(pkt->PDS_header.RUOD_req_header.flags.retx,sequence,UET_RCVD_SES_PROCG,0,nullptr,pkt);
                else if (runtime_ && runtime_->standard_wire && pkt->SESpkt.bth_type==Standard_Header) {
                    auto response=UET::PDS::default_semantic_response(pkt->SESpkt);
                    sendAck(UET_HDR_RESPONSE,pkt->PDS_header.RUOD_req_header.flags.retx,0,sequence,&response,false,pkt);
                } else sendAck(UET_HDR_NONE,0,0,sequence,nullptr,false,pkt);
            }
        }
        else if (error_chk == DROP)
        {
            diagnostics() << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] error_chk is DROP" << std::endl;
            LOG_WARN(__FUNCTION__, formatLogMessage("Drop packet"));
        } // Drop packet / Drop packet
        else if (error_chk == OOO)
        {
            diagnostics() << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] error_chk is OOO" << std::endl;
            LOG_WARN(__FUNCTION__, formatLogMessage("Out of order packet, send NACK"));
            sendNack(pkt->PDS_header.RUOD_req_header.flags.retx, pkt->PDS_header.RUOD_req_header.psn, UET_ROD_OOO, rx_cur_psn + 1,nullptr,pkt); // Out of order packet / 乱序包
        }
    }
    else
    { // Packet is normal, process request / Packet normal, process request
        if (!admitSemanticRequest(*pkt)) return;
        LOG_INFO(__FUNCTION__, formatLogMessage("Packet normal, process request"));
        diagnostics() << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] rx req ok" << std::endl;
        uint16_t handle = processRxReq(pkt);
        RX_pkt_meta meta = rx_pkt_map.at(handle);
        updateRxPsnTracker(&meta);

        std::stringstream forward_info;
        forward_info << "Forward to SES layer - handle: " << handle << ", PSN: " << meta.psn;
        LOG_DEBUG(__FUNCTION__, formatLogMessage(forward_info.str()));

        fwdReq2SES(handle, meta, &pkt->SESpkt); // Forward to SES layer
    }
    chkClear(); // Check if buffer needs to be cleared / 检查是否需要清除缓冲区

    // FUNCTION_LOG_EXIT();
}

void T_PDC::rxAck(PDStoNET_pkt *pkt)
{
    // FUNCTION_LOG_ENTRY();

    if (pkt->PDS_header.RUOD_ack_header.flags.p) { receiveProbeAcknowledgment(*pkt); return; }
    if (runtime_ && runtime_->standard_wire && pkt->PDS_header.RUOD_ack_header.flags.req==3) return;
    uint32_t ack_psn = pkt->PDS_header.RUOD_ack_header.ack_psn_off + pkt->PDS_header.RUOD_ack_header.cack_psn;
    uint32_t cack_psn = pkt->PDS_header.RUOD_ack_header.cack_psn;
    if (runtime_ && runtime_->standard_wire) {
        if (tx_cur_psn==start_psn) return;
        const uint32_t lowest=peer_sequence_window_?peer_sequence_window_->cumulative_ack():start_psn-1;
        const uint32_t span=(tx_cur_psn-1)-lowest;
        if (span>=0x80000000u || ack_psn-lowest>span || (tx_cur_psn-1)-cack_psn>=0x80000000u) return;
    }
    processPeerAcknowledgment(*pkt);
    processCongestionAck(*pkt);
    processDeliveryAcknowledgment(*pkt);
    processSemanticAcknowledgment(*pkt);
    diagnostics() << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] rx ack,ack_psn:" << ack_psn << ",cack_psn:" << cack_psn << std::endl;
    // Record ACK processing information
    std::stringstream ack_process_info;
    ack_process_info << "Process ACK - ack_psn: " << ack_psn
                        << ", cack_psn: " << cack_psn
                        << ", current clear_psn: " << clear_psn
                        << ", unack_cnt: " << unack_cnt;
    LOG_INFO(__FUNCTION__, formatLogMessage(ack_process_info.str()));

    const auto acknowledged = pkt->PDS_header.RUOD_ack_header.next_hdr == UET_HDR_NONE && awaitsSemantic(ack_psn)
        ? clear_psn : ack_psn;
    updateTxPsnTracker(acknowledged, pkt->PDS_header.RUOD_ack_header.flags.req,cack_psn);
    LOG_DEBUG(__FUNCTION__, formatLogMessage("Transmit PSN tracker updated"));

    if (pkt->PDS_header.RUOD_ack_header.next_hdr != UET_HDR_NONE)
    {
        diagnostics() << getCurrentTimestamp() << "ack has rsp" << std::endl;
        LOG_DEBUG(__FUNCTION__, formatLogMessage("Forward response to SES layer"));
        if ((!runtime_ || !runtime_->standard_wire) &&
            (pkt->PDS_header.RUOD_ack_header.next_hdr==UET_HDR_RESPONSE ||
             pkt->PDS_header.RUOD_ack_header.next_hdr==UET_HDR_RESPONSE_DATA))
            fwdRsp2SES(&pkt->SESpkt,ack_psn);
    }
    // FUNCTION_LOG_EXIT();
}

void T_PDC::sesTxReq(PDS_PDC_req *req)
{
    diagnostics() << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] ses tx req" << std::endl;
    if (!bad_psn)
        txReq(req); // Process request transmission when PSN is normal
}

void T_PDC::sesTxRsp(SES_PDC_rsp *rsp)
{
    if (!bad_psn)
    {
        if (rsp->ses_nack)
        {
            txNack(rsp);
        }
        else
        {
            diagnostics() << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] ses tx rsp" << std::endl;
            txRsp(rsp);
        }
    } // Process response transmission when PSN is normal
}

void T_PDC::rxCtrl(PDStoNET_pkt *pkt)
{
    // TODO: Implement control message processing logic
    if (!pkt)
    {
        LOG_ERROR(__FUNCTION__, formatLogMessage("Input packet pointer is null"));
        return;
    }
    else
    {
        switch (pkt->PDS_header.RUOD_cp_header.ctl_type)
        {
        case Noop:
            rxCtrlNoop(pkt);
            break;
        case Negotiation:
            // Optional negotiation is disabled; acknowledge the numbered CP
            // without enabling features or transferring SYN safety tracking.
            rxCtrlNoop(pkt);
            break;
        case Probe:
            receiveProbe(*pkt);
            break;
        case ACK_req:
            rxCtrlAckReq(pkt);
            break;
        case Clear_cmd:
            rxCtrlClearCmd(pkt);
            break;
        case Clear_req:
            rxCtrlClearReq(pkt);
            break;
            // case
        }
    }
}



