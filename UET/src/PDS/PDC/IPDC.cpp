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
bool I_PDC::initPDC(uint16_t id){
    //FUNCTION_LOG_ENTRY();

    // Record input parameters
    std::stringstream params;
    params << "Initialize PDC - ID: " << id;
    LOG_INFO(__FUNCTION__, params.str());

    // ==================== Basic Parameter Initialization ====================
    SPDCID = id;                    // Set source PDC ID
    DPDCID = 0;                     // Initialize destination PDC ID to 0
    MPR = Default_MPR;              // Set maximum unacknowledged packets
    mode = ROD;                     // Set to reliable ordered delivery mode
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
    while (!tx_req_q.empty()) tx_req_q.pop();
    while (!tx_rsp_q.empty()) tx_rsp_q.pop();
    while (!rx_pkt_q.empty()) rx_pkt_q.pop();
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
void I_PDC::openChk(){
    ////FUNCTION_LOG_ENTRY();

    // Record current PDC status
    // std::stringstream entry_state;
    // entry_state << "Entry status - state: " << STATE_STR(state)
    //             << ", gen_cm: " << CM_TYPE_STR(gen_cm)
    //             << ", close_req: " << (close_req ? "true" : "false")
    //             << ", close_error: " << (close_error ? "true" : "false")
    //             << ", closing: " << (closing ? "true" : "false")
    //             << ", open_msg: " << open_msg
    //             << ", unack_cnt: " << unack_cnt;
    // LOG_DEBUG(__FUNCTION__, entry_state.str());

    // Record queue status
    // std::stringstream queue_state;
    // queue_state << "Queue status - rx_pkt_q: " << rx_pkt_q.size()
    //             << ", tx_rsp_q: " << tx_rsp_q.size()
    //             << ", tx_req_q: " << tx_req_q.size()
    //             << ", tx_pkt_q: " << tx_pkt_q.size();
    // LOG_DEBUG(__FUNCTION__, queue_state.str());

    //std::cout << getCurrentTimestamp() << "I_PDC open_chk state: " << STATE_STR(state) << std::endl;

    if(gen_cm != NONE) {
        std::cout << getCurrentTimestamp() << "I_PDC tx_control processing - gen_cm: " << CM_TYPE_STR(gen_cm) << std::endl;
        LOG_INFO(__FUNCTION__, "Process control message generation");
        txCtrl();
        gen_cm = NONE;  // Reset flag
        LOG_DEBUG(__FUNCTION__, "Control message flag reset");
    }
    else if((close_req || close_error) && open_msg == 0){
        std::cout << getCurrentTimestamp() << "I_PDC start close process" << std::endl;
        LOG_INFO(__FUNCTION__, "Close conditions met, start close process");
        beginClose();
    }
    else if(closing && open_msg == 0 && unack_cnt == 0 && state != CLOSE_ACK_WAIT){
        std::cout << getCurrentTimestamp() << "I_PDC target close" << std::endl;
        LOG_INFO(__FUNCTION__, "Target close conditions met, execute target close");
        targetClose();
    }
    else if(!rx_pkt_q.empty()){
        PDStoNET_pkt p = rx_pkt_q.front();
        std::cout << getCurrentTimestamp() << "I_PDC process receive queue packet - Type: " << p.PDS_type << std::endl;

        if(p.PDS_type == RUOD_req_header) {
            LOG_DEBUG(__FUNCTION__, "Process request packet");
            rxReq(&p);        // Process request packet
        }
        else if(p.PDS_type == RUOD_ack_header) {
            LOG_DEBUG(__FUNCTION__, "Process acknowledgment packet");
            rxAck(&p);   // Process acknowledgment packet
        }
        else if(p.PDS_type == RUOD_cp_header) {
            LOG_DEBUG(__FUNCTION__, "Process control packet");
            rxCtrl(&p);     // Process control packet
        }
        else if(p.PDS_type == nack_header) {
        LOG_DEBUG(__FUNCTION__, "Process negative acknowledgment packet");
        rxNack(&p);      // Process negative acknowledgment packet
        }
        rx_pkt_q.pop();
    }
    else if(!rto_pkt_q.empty()){
        uint32_t psn = rto_pkt_q.front();
        rto_pkt_q.pop();
        LOG_DEBUG(__FUNCTION__, "Process timeout retransmission packet,psn:"+std::to_string(psn));
        txRto(psn); // Process timeout retransmission packet
    }
    else if(!tx_rsp_q.empty()){                 // Process SES layer response transmission
        std::cout << getCurrentTimestamp() << "I_PDC process SES layer response transmission - tx_rsp_q size: " << tx_rsp_q.size() << std::endl;
        LOG_DEBUG(__FUNCTION__, "Process SES layer response transmission");
        sesTxRsp(&tx_rsp_q.front());
        tx_rsp_q.pop();
    }
    else if(!tx_req_q.empty()){                 // Process SES layer request transmission
        std::cout << getCurrentTimestamp() << "I_PDC process SES layer request transmission - tx_req_q size: " << tx_req_q.size() << std::endl;
        LOG_DEBUG(__FUNCTION__, "Process SES layer request transmission");
        sesTxReq(&tx_req_q.front());
        tx_req_q.pop();
    }

    ////FUNCTION_LOG_EXIT();
}
/**
 * @brief Request PDC connection closure
 */
void I_PDC::closeReq(){
    //FUNCTION_LOG_ENTRY();

    // Record close request
    LOG_INFO(__FUNCTION__, "Close request received, setting close flag");
    std::cout << getCurrentTimestamp() << "I_PDC close request received, state switched to QUIESCE" << std::endl;

    close_req = true;
    state = QUIESCE;

    // Record state change
    std::stringstream state_info;
    state_info << "State change - close_req: " << (close_req ? "true" : "false")
                << ", state: " << STATE_STR(state);
    LOG_INFO(__FUNCTION__, state_info.str());
    
    //FUNCTION_LOG_EXIT();
}
    

/**
 * @brief Process SES layer send request
 * @param req Request packet
 */
void I_PDC::sesTxReq(PDS_PDC_req *req){
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
            sendAck(PDS_next_hdr::UET_HDR_NONE,0,0,pkt->PDS_header.RUOD_req_header.psn,nullptr,false);//Immediately respond to duplicate packet
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

        //update_ccc();
        if(pkt->PDS_header.RUOD_ack_header.flags.req == 0x10){//CLOSE_REQ
            std::cout << getCurrentTimestamp() << "I_PDC close request received - PSN: " << ack_psn << std::endl;
            LOG_WARN(__FUNCTION__, "Close request flag received, trigger close process");
            closeReq();
        }

        LOG_DEBUG(__FUNCTION__, "Forward response to SES layer");
        fwdRsp2SES(&pkt->SESpkt);
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
            // case
        }
    }
}


/**
 * @brief Start PDC closure
 */
void I_PDC::beginClose(){
    //FUNCTION_LOG_ENTRY();

    LOG_INFO(__FUNCTION__, "Start PDC closure process");
    std::cout << getCurrentTimestamp() << "I_PDC start close process" << std::endl;

    closing = true;
    state = ACK_WAIT;

    // Record state change
    std::stringstream state_info;
    state_info << "Close process state change - closing: " << (closing ? "true" : "false")
                << ", state: " << STATE_STR(state);
    LOG_INFO(__FUNCTION__, state_info.str());
    close_error = false;
    close_req = false;
    //Display PDC internal parameters
    std::stringstream pdc_info;
    pdc_info << "PDC close process - closing: " << (closing ? "true" : "false")
                << ", state: " << STATE_STR(state)
                << ", close_error: " << (close_error ? "true" : "false")
                << ", close_req: " << (close_req ? "true" : "false") << ",unack_cnt: " << unack_cnt;
    LOG_INFO(__FUNCTION__, pdc_info.str());
    //FUNCTION_LOG_EXIT();
}

/**
 * @brief Target side close handling
 */
void I_PDC::targetClose(){
    std::cout << "Trigger close" << std::endl;
    if(DPDCID==0){
        std::cout << getCurrentTimestamp() << "I_PDC target side close with DPDCID 0, cannot send close packet" << std::endl;
        LOG_ERROR(__FUNCTION__, "Target side close with DPDCID 0, cannot send close packet");
        close();
        return;
    }
    state = CLOSE_ACK_WAIT;
    sendClose();
}



/**
 * @brief Complete close operation
 */
void I_PDC::close(){
    //saveExpectedPSN();
    freePDC();
    state = CLOSED;
    
    // Add own PDCID to PDC close queue
    if (public_close_queue) {
        public_close_queue->push(SPDCID);
        LOG_INFO(__FUNCTION__, "I_PDC closure complete, PDCID " + std::to_string(SPDCID) + " added to close queue");
    }
    //Transmit close information to PDS
}
    
/**
 * @brief Send close packet
 */
void I_PDC::sendClose(){
    //FUNCTION_LOG_ENTRY();

    LOG_INFO(__FUNCTION__, "Construct and send close control packet");

    PDStoNET_pkt ctrl_pkt;
    ctrl_pkt.dst_fep = dst_fep;
    ctrl_pkt.src_fep = src_fep;

    // Set control packet basic properties
    ctrl_pkt.PDS_type = RUOD_cp_header;

    // Set SES layer header information
    ctrl_pkt.SESpkt.bth_type = Standard_Header;
    ctrl_pkt.SESpkt.bth_header.Standard_Header.som = false;
    ctrl_pkt.SESpkt.bth_header.Standard_Header.eom = false;

    // Set CP header information
    ctrl_pkt.PDS_header.RUOD_cp_header.type = CP;
    ctrl_pkt.PDS_header.RUOD_cp_header.ctl_type = Close_cmd;
    ctrl_pkt.PDS_header.RUOD_cp_header.psn = setPsn();
    ctrl_pkt.PDS_header.RUOD_cp_header.spdcid = SPDCID;
    ctrl_pkt.PDS_header.RUOD_cp_header.dpdcid = DPDCID;
    ctrl_pkt.PDS_header.RUOD_cp_header.flags.syn = 0;
    ctrl_pkt.PDS_header.RUOD_cp_header.flags.ar = 1;        // Request ACK
    ctrl_pkt.PDS_header.RUOD_cp_header.flags.retx = 0;      // Not retransmission
    ctrl_pkt.PDS_header.RUOD_cp_header.flags.isrod = 0;     // rsvd
    ctrl_pkt.PDS_header.RUOD_cp_header.payload = 0;  // The CP pds.payload field is set to 0x0

    // Record close packet information
    std::stringstream close_info;
    close_info << "Construct close packet - PSN: " << ctrl_pkt.PDS_header.RUOD_cp_header.psn
                << ", SPDCID: " << SPDCID
                << ", DPDCID: " << DPDCID
                << ", ctl_type: Close_cmd";
    LOG_INFO(__FUNCTION__, close_info.str());

    // Update transmit PSN tracker
    LOG_DEBUG(__FUNCTION__, "Update transmit PSN tracker");

    TX_pkt_meta meta;
    meta.tx_pkt_handle = 0;
    meta.rto = Base_RTO;
    meta.retry_cnt = 0;
    tx_pkt_map.insert(std::make_pair(tx_cur_psn, meta));

    tx_pkt_buffer.insert(std::make_pair(tx_cur_psn, ctrl_pkt));

    if(USE_RTO){
        startPacketTimer(tx_cur_psn, 0); 
    }

    updateTxPsnTracker();

    // Add control packet to send queue
    if (public_net_queue) {
        public_net_queue->push(ctrl_pkt);
    } else {
        tx_pkt_q.push(ctrl_pkt);
    }
    LOG_INFO(__FUNCTION__, "Close packet added to send queue");

    close_psn = ctrl_pkt.PDS_header.RUOD_cp_header.psn;

    std::stringstream final_info;
    final_info << "Close packet send complete - close_psn: " << close_psn;
    LOG_INFO(__FUNCTION__, final_info.str());

    std::cout << getCurrentTimestamp() << "I_PDC send close packet - PSN: " << ctrl_pkt.PDS_header.RUOD_cp_header.psn << std::endl;

    //FUNCTION_LOG_EXIT();
}

