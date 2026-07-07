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
 * @file             IPDC.cpp
 * @brief            IPDC.cpp
 * @author           softuegroup@gmail.com
 * @version          1.0.0
 * @date             2025-10-29
 * @copyright        Apache License Version 2.0
 *
 * @details
 * This file implements the Initiator PDC (I_PDC) class for reliable ordered data delivery.
 */

#include "IPDC.hpp"


/**
 * @brief Initialize PDC instance
 * @param id PDC identifier
 * @return Initialization success status
 */
bool I_PDC::initPDC(uint16_t id, pdc_mode init_mode){
    //FUNCTION_LOG_ENTRY();

    // Record input parameters
    std::stringstream params;
    params << "Initialize PDC - ID: " << id;
    LOG_INFO(__FUNCTION__, params.str());

    // ==================== Basic Parameter Initialization ====================
    SPDCID = id;                    // Set source PDC ID
    DPDCID = 0;                     // Initialize destination PDC ID to 0
    MPR = Default_MPR;              // Set maximum unacknowledged packets
    mode = init_mode;               // Set delivery mode for this PDC instance
    state = CLOSED;                 // Initial state is closed

    // ==================== PSN Related Initialization ====================
    start_psn = 1000;               // Set starting PSN
    tx_cur_psn = start_psn;         // Initialize transmit PSN
    clear_psn = start_psn - 1;      // Initialize clear PSN
    rx_cur_psn = start_psn - 1;     // Initialize receive PSN
    cack_psn = start_psn - 1;       // Initialize cumulative acknowledgment PSN
    close_psn = 0;                  // Initialize close PSN

    // ==================== Counter and Flag Initialization ====================
    unack_cnt = 0;                  // Reset unacknowledged packet counter
    allACK = true;     // Initialize all ACK flag to true
    open_msg = 0;                   // Reset open message counter
    ACK_GEN_COUNT = 0;              // Reset ACK generation counter

    // ==================== Status Flag Initialization ====================
    SYN = false;                    // Synchronization flag
    pause_pdc = false;              // Pause PDC transmission flag
    trim = false;                   // Trim flag
    rx_error = false;               // Receive error flag
    close_triger = false;           // Trigger close flag
    close_req = false;              // Close request flag
    close_error = false;            // Close error flag
    closing = false;                // Closing flag
    clr_cm = false;                 // Clear control message flag

    // ==================== Control Message and Error Type Initialization ====================
    gen_cm = NONE;                  // Control message type to be generated
    error_chk = OPEN;               // Error check type

    // ==================== Clear Static Queues and Containers ====================
    // Clear all static queues
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        while (!tx_req_q.empty()) tx_req_q.pop();
        while (!tx_rsp_q.empty()) tx_rsp_q.pop();
        while (!rx_pkt_q.empty()) rx_pkt_q.pop();
        while (!tx_pkt_q.empty()) tx_pkt_q.pop();
        while (!rx_req_pkt_q.empty()) rx_req_pkt_q.pop();
        while (!rx_rsp_pkt_q.empty()) rx_rsp_pkt_q.pop();
        while (!rto_pkt_q.empty()) rto_pkt_q.pop();
    }

    // Clear all static maps
    tx_pkt_map.clear();
    rx_pkt_map.clear();
    tx_pkt_buffer.clear();
    tx_ack_buffer.clear();
    resetRudState();

    // Record initialization status
    std::stringstream init_state;
    init_state << "PDC initialization complete - SPDCID: " << SPDCID
                << ", DPDCID: " << DPDCID
                << ", MPR: " << MPR
                << ", mode: " << MODE_STR(mode)
                << ", state: " << STATE_STR(state)
                << ", start_psn: " << start_psn
                << ", tx_cur_psn: " << tx_cur_psn
                << ", clear_psn: " << clear_psn
                << ", rx_cur_psn: " << rx_cur_psn
                << ", cack_psn: " << cack_psn
                << ", close_psn: " << close_psn
                << ", unack_cnt: " << unack_cnt
                << ", open_msg: " << open_msg;
    LOG_INFO(__FUNCTION__, init_state.str());

    std::cout << getCurrentTimestamp() << "Establish I_PDC:" << id << " - Complete initialization" << std::endl;

    //FUNCTION_LOG_EXIT();
    return true;
}
/**
 * @brief Main event loop, processes various events by priority: control messages, close requests, packet reception, response transmission, etc.
 */
/**
 * @brief Request PDC connection closure
 */
    

/**
 * @brief Process SES layer send request
 * @param req Request packet
 */
void I_PDC::sesTxReq(PDS_PDC_req *req){
    if (req && req->pkt.bth_type == Standard_Header) {
        std::cout << "[uet-ipdc] sesTxReq msg_id="
                  << req->pkt.bth_header.Standard_Header.msg_id
                  << " job_id=" << req->pkt.bth_header.Standard_Header.job_id
                  << " som=" << static_cast<unsigned>(req->pkt.bth_header.Standard_Header.som)
                  << " eom=" << static_cast<unsigned>(req->pkt.bth_header.Standard_Header.eom)
                  << " state=" << state
                  << std::endl;
    }
    if(state == CLOSED){
        unack_cnt = 0;
        open_msg = 0;
        SYN = 1;
        state = CREATING;
        //TODO: Establish connection
        std::cout << "First packet sent, establishing connection" << std::endl;
    }
    txReq(req);
}
/**
 * @brief Process SES layer send response
 * @param rsp Response packet
 */
void I_PDC::sesTxRsp(SES_PDC_rsp *rsp){
    if(rsp->ses_nack){
        txNack(rsp);
    }else{
        txRsp(rsp);
    }
}



/**
 * @brief Process received request packet
 * @param pkt Request packet
 */
void I_PDC::rxReq(PDStoNET_pkt *pkt){
    //FUNCTION_LOG_ENTRY();

    if(!pkt) {
        LOG_ERROR(__FUNCTION__, "Input packet pointer is null");
        //FUNCTION_LOG_EXIT();
        return;
    }

    // Record packet information
    std::stringstream pkt_info;
    pkt_info << "Receive request packet - PSN: " << pkt->PDS_header.RUOD_req_header.psn
                << ", SPDCID: " << pkt->PDS_header.RUOD_req_header.spdcid
                << ", DPDCID: " << pkt->PDS_header.RUOD_req_header.dpdcid
                << ", SYN: " << (pkt->PDS_header.RUOD_req_header.flags.syn ? "1" : "0")
                << ", RETX: " << (pkt->PDS_header.RUOD_req_header.flags.retx ? "1" : "0");
    LOG_INFO(__FUNCTION__, pkt_info.str());

    std::cout << getCurrentTimestamp() << "I_PDC receive request packet - PSN: " << pkt->PDS_header.RUOD_req_header.psn << std::endl;

    if (handleRudRxRequest(pkt)) {
        return;
    }
    if (!packetModeMatches(pkt)) {
        sendNack(pkt->PDS_header.RUOD_req_header.flags.retx,
                 pkt->PDS_header.RUOD_req_header.psn,
                 UET_PDC_MODE_MISMATCH,
                 0,
                 nullptr);
        return;
    }

    chkRxError(pkt);

    // Record error check results
    std::stringstream error_info;
    error_info << "Error check results - trim: " << (trim ? "true" : "false")
                << ", error_chk: " << ERROR_TYPE_STR(error_chk);
    LOG_DEBUG(__FUNCTION__, error_info.str());

    if(trim || error_chk != OPEN){
        if(trim) {
            std::cout << getCurrentTimestamp() << "I_PDC packet trimmed, sending NACK" << std::endl;
            LOG_WARN(__FUNCTION__, "Packet trimmed, sending NACK");
            sendNack(pkt->PDS_header.RUOD_req_header.flags.retx,pkt->PDS_header.RUOD_req_header.psn,UET_TRIMMED,rx_cur_psn + 1,nullptr);
        }
        else if(error_chk == ACK_ERROR) {
            std::cout << getCurrentTimestamp() << "I_PDC duplicate packet received, sending ACK" << std::endl;
            LOG_INFO(__FUNCTION__, "Duplicate packet, respond with ACK immediately");
            sendAck(PDS_next_hdr::UET_HDR_NONE,0,0,pkt->PDS_header.RUOD_req_header.psn,nullptr,false,
                    pkt->SESpkt.bth_header.Standard_Header.job_id);//Immediately respond to duplicate packet
        }
        else if(error_chk == DROP) {
            std::cout << getCurrentTimestamp() << "I_PDC drop packet" << std::endl;
            LOG_WARN(__FUNCTION__, "Drop packet");
        }//Drop packet
        else if(error_chk == OOO) {
            std::cout << getCurrentTimestamp() << "I_PDC out-of-order packet, sending NACK" << std::endl;
            LOG_WARN(__FUNCTION__, "Out-of-order packet, sending NACK");
            sendNack(pkt->PDS_header.RUOD_req_header.flags.retx,pkt->PDS_header.RUOD_req_header.psn,UET_ROD_OOO,rx_cur_psn + 1,nullptr);
        }
    }
    else{
        LOG_INFO(__FUNCTION__, "Packet normal, processing request");
        std::cout << getCurrentTimestamp() << "I_PDC packet received normally, start processing" << std::endl;
    
        uint16_t handle = processRxReq(pkt);
        RX_pkt_meta meta = rx_pkt_map.at(handle);
        updateRxPsnTracker(&meta);
    
        if(SYN){
            std::cout << getCurrentTimestamp() << "I_PDC connection established,DPDCID:" << pkt->PDS_header.RUOD_req_header.spdcid << std::endl;
            LOG_INFO(__FUNCTION__, "SYN packet processing, establishing connection");

            DPDCID = pkt->PDS_header.RUOD_req_header.spdcid; //Why is this dpdcid here? //I think this should be spdcid
            state = ESTABLISHED;
            SYN = 0;

            std::stringstream conn_info;
            conn_info << "Connection establishment complete - DPDCID: " << DPDCID << ", state: " << STATE_STR(state);
            LOG_INFO(__FUNCTION__, conn_info.str());
        }

        // ACK-per-packet mode: if sender requested an ACK (ar flag), respond immediately
        // after the request has been accepted into the RX window (i.e., after updateRxPsnTracker).
        // This matches the intent of the spec's per-packet ACK behavior and prevents ACK_REQ storms.
        if (pkt->PDS_header.RUOD_req_header.flags.ar) {
            if (DPDCID == 0) {
                DPDCID = pkt->PDS_header.RUOD_req_header.spdcid;
            }
            sendAck(PDS_next_hdr::UET_HDR_NONE, 0, 0, meta.psn, nullptr, false,
                    pkt->SESpkt.bth_header.Standard_Header.job_id);
        }

        std::cout << getCurrentTimestamp() << "I_PDC forward to SES - PSN:" << pkt->PDS_header.RUOD_req_header.psn << ", handle:" << handle << std::endl;

        std::stringstream forward_info;
        forward_info << "Forward to SES layer - handle: " << handle << ", PSN: " << meta.psn;
        LOG_DEBUG(__FUNCTION__, forward_info.str());
    
        fwdReq2SES(handle,meta,&pkt->SESpkt);
    }

    //FUNCTION_LOG_EXIT();
}

/**
 * @brief Process received ACK packet
 * @param pkt ACK packet
 */
void I_PDC::rxAck(PDStoNET_pkt *pkt){
    //FUNCTION_LOG_ENTRY();

    if(!pkt) {
        LOG_ERROR(__FUNCTION__, "Input packet pointer is null");
        //FUNCTION_LOG_EXIT();
        return;
    }

    uint32_t ack_psn = pkt->PDS_header.RUOD_ack_header.ack_psn_off + pkt->PDS_header.RUOD_ack_header.cack_psn;
    uint32_t cack_psn = pkt->PDS_header.RUOD_ack_header.cack_psn;

    // Record ACK packet information
    std::stringstream ack_info;
    ack_info << "Receive ACK packet - ack_psn: " << ack_psn
                << ", cack_psn: " << cack_psn
                << ", SPDCID: " << pkt->PDS_header.RUOD_ack_header.spdcid
                << ", DPDCID: " << pkt->PDS_header.RUOD_ack_header.dpdcid
                << ", req_flag: " << (int)pkt->PDS_header.RUOD_ack_header.flags.req;
    LOG_INFO(__FUNCTION__, ack_info.str());

    std::cout << getCurrentTimestamp() << "I_PDC receive ACK packet - ack_psn: " << ack_psn
                << ", cack_psn: " << cack_psn << std::endl;

    if(closing && ack_psn == close_psn){
        LOG_INFO(__FUNCTION__, "Close confirmation ACK received, execute closure");
        close();
    }
    else{
        LOG_INFO(__FUNCTION__, "Close process not executed, closing status:" + std::to_string(closing) + ", ack_psn: " + std::to_string(ack_psn) + ", close_psn: " + std::to_string(close_psn));
        if(SYN){
            std::cout << getCurrentTimestamp() << "I_PDC connection established,DPDCID:" << pkt->PDS_header.RUOD_ack_header.spdcid << std::endl;
            LOG_INFO(__FUNCTION__, "SYN ACK processing, establishing connection");

            DPDCID = pkt->PDS_header.RUOD_ack_header.spdcid;
            state = ESTABLISHED;
            SYN = 0;

            std::stringstream conn_info;
            conn_info << "Connection establishment complete - DPDCID: " << DPDCID << ", state: " << STATE_STR(state);
            LOG_INFO(__FUNCTION__, conn_info.str());
        }

        // Pass req flag from ACK packet to update_tx_psn_tracker
        LOG_DEBUG(__FUNCTION__, "Update transmit PSN tracker");
        updateTxPsnTracker(ack_psn, pkt->PDS_header.RUOD_ack_header.flags.req, cack_psn);
        rxAckControlExt(pkt);

        //update_ccc();
        if(pkt->PDS_header.RUOD_ack_header.flags.req == 0x10){//CLOSE_REQ
            std::cout << getCurrentTimestamp() << "I_PDC close request received - PSN: " << ack_psn << std::endl;
            LOG_WARN(__FUNCTION__, "Close request flag received, trigger close process");
            closeReq();
        }

        if (pkt->PDS_header.RUOD_ack_header.next_hdr != UET_HDR_NONE) {
            if (!handleRudRxResponse(pkt)) {
                LOG_DEBUG(__FUNCTION__, "Forward response to SES layer");
                fwdRsp2SES(pkt);
            }
        }
    }

    //FUNCTION_LOG_EXIT();
}


/**
 * @brief Process received control message
 * @param pkt Control message packet
 */
void I_PDC::rxCtrl(PDStoNET_pkt *pkt){
            if (!pkt)
    {
        LOG_ERROR(__FUNCTION__, "Input packet pointer is null");
        return;
    }
    else if (!packetModeMatches(pkt))
    {
        sendNack(pkt->PDS_header.RUOD_cp_header.flags.retx,
                 pkt->PDS_header.RUOD_cp_header.psn,
                 UET_PDC_MODE_MISMATCH,
                 0,
                 nullptr);
    }
    else
    {
        switch (pkt->PDS_header.RUOD_cp_header.ctl_type)
        {
        case Noop:
            rxCtrlNoop(pkt);
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
        case SACK:
            rxCtrlSack(pkt);
            break;
        case Credit:
            rxCtrlCredit(pkt);
            break;
        case Credit_req:
            rxCtrlCreditReq(pkt);
            break;
            // case
        }
    }
}
