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
 * @file             PDC.cpp
 * @brief            PDC.cpp
 * @author           softuegroup@gmail.com
 * @version          1.0.0
 * @date             2025-10-29
 * @copyright        Apache License Version 2.0
 *
 * @details
 * This file implements the base PDC class providing core functionality for reliable data delivery.
 */


#include "PDC.hpp"
#include <functional>

/**
 * @brief PDC constructor 
 * @details Initializes PDC with default parameters and sets up timer callback
 */
PDC::PDC()
    : rto_timer_([this](uint32_t psn) {
          
          rto_pkt_q.push(psn);

          LOG_WARN("RTOTimer::timeout_callback",
                   formatLogMessage("Packet timeout - PSN: " + std::to_string(psn)));

          std::cout << getCurrentTimestamp() << formatLogMessage("Packet timeout, added to retransmission queue - PSN: ")
                    << psn << std::endl;
      }),
      mode(RUD),                    
      SPDCID(0),                    
      DPDCID(0),                    
      unack_cnt(0),                 
      allACK(true),                 
      open_msg(0),                  
      SYN(false),                   
      MPR(Default_MPR),             
      ACK_GEN_COUNT(0),             
      start_psn(1000),              
      tx_cur_psn(start_psn),        
      clear_psn(start_psn - 1),     
      rx_cur_psn(start_psn - 1),    
      cack_psn(start_psn - 1),      
      rx_clear_psn(start_psn - 1),  
      pause_pdc(false),             
      gen_cm(NONE),                 
      gen_ack(false),               
      trim(false),                  
      rx_error(false),              
      error_chk(OPEN),              
      close_error(false),           
      closing(false),               
      pdc_close_timer(0),           
      state(CLOSED),                
      public_net_queue(nullptr),    
      public_ses_req_queue(nullptr),
      public_ses_rsp_queue(nullptr),
      public_close_queue(nullptr)  
{
    LOG_INFO("PDC::PDC", formatLogMessage("PDC constructor called - initialization completed"));
    std::cout << getCurrentTimestamp() << formatLogMessage("PDC constructor completed initialization") << std::endl;
}

/**
 * @brief PDC destructor 
 * @details Cleans up all resources including timers, maps, and queues
 */
PDC::~PDC()
{
    LOG_INFO("PDC::~PDC", formatLogMessage("PDC destructor called - starting resource cleanup"));
    std::cout << getCurrentTimestamp() << formatLogMessage("PDC destructor starting resource cleanup") << std::endl;

    
    rto_timer_.stop();

    // Clean up all timer resources
    clearAllPacketTimers();

    // Clean up all maps
    tx_pkt_map.clear();
    rx_pkt_map.clear();
    tx_pkt_buffer.clear();
    tx_ack_buffer.clear();

    
    while (!tx_pkt_q.empty()) tx_pkt_q.pop();
    while (!rx_req_pkt_q.empty()) rx_req_pkt_q.pop();
    while (!rx_rsp_pkt_q.empty()) rx_rsp_pkt_q.pop();
    while (!tx_req_q.empty()) tx_req_q.pop();
    while (!tx_rsp_q.empty()) tx_rsp_q.pop();
    while (!rx_pkt_q.empty()) rx_pkt_q.pop();
    while (!rto_pkt_q.empty()) rto_pkt_q.pop();

    
    public_net_queue = nullptr;
    public_ses_req_queue = nullptr;
    public_ses_rsp_queue = nullptr;
    public_close_queue = nullptr;

    LOG_INFO("PDC::~PDC", formatLogMessage("PDC destructor completed - all resources cleaned up"));
}

/**
 * @brief Process received request
 * @param pkt Received network packet
 * @return Processing result handle
 */
uint16_t PDC::processRxReq(PDStoNET_pkt *pkt)
{
    RX_pkt_meta meta = {};
    meta.type = pkt->PDS_header.RUOD_req_header.type;
    meta.next_hdr = pkt->PDS_header.RUOD_req_header.next_hdr;
    meta.spdcid = pkt->PDS_header.RUOD_req_header.spdcid;
    meta.psn = pkt->PDS_header.RUOD_req_header.psn;
    meta.clear_psn = meta.psn - pkt->PDS_header.RUOD_req_header.clear_psn_off;
    meta.syn = pkt->PDS_header.RUOD_req_header.flags.syn;
    meta.retx = pkt->PDS_header.RUOD_req_header.flags.retx;
    meta.ar = pkt->PDS_header.RUOD_req_header.flags.ar;
    meta.som = pkt->SESpkt.bth_header.Standard_Header.som;
    if (meta.som == false) {
        meta.payload_len = pkt->SESpkt.bth_header.Standard_Header.diff.som_false.payload_length;
    }
    else {
        meta.payload_len = 0;
    }

    uint16_t handle = setRXhandle(meta.psn, meta.spdcid);
    rx_pkt_map.insert({handle, meta});
    return handle;
}

/**
 * @brief Update TX PSN tracker 
 * @details Updates current transmission PSN and handles flow control
 */
void PDC::updateTxPsnTracker(){
    ////FUNCTION_LOG_ENTRY();

    
    std::stringstream before_state;
    before_state << "Before update state - tx_cur_psn: " << tx_cur_psn
                << ", unack_cnt: " << unack_cnt
                << ", MPR: " << MPR
                << ", pause_pdc: " << (pause_pdc ? "true" : "false");
    LOG_DEBUG(__FUNCTION__, before_state.str());

    
    tx_cur_psn = tx_cur_psn + 1;
    
    unack_cnt++;

    std::cout << getCurrentTimestamp() << "I_PDC update TX PSN - tx_cur_psn: " << tx_cur_psn
            << ", unack_cnt: " << unack_cnt << std::endl;

    if ((tx_cur_psn - clear_psn) >= (unsigned)(MPR / 2) && state == ESTABLISHED)
    {
        gen_cm = ACK_REQ; 
        std::cout << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] Need to send ACK Request, current psn: " << tx_cur_psn << ", clear_psn: " << clear_psn << std::endl;
    }
    else if ((unack_cnt >= MPR))
    {
        gen_cm = ACK_REQ;
        pause_pdc = true;
    }

    
    std::stringstream after_state;
    after_state << "Updated state - tx_cur_psn: " << tx_cur_psn
                << ", unack_cnt: " << unack_cnt
                << ", pause_pdc: " << (pause_pdc ? "true" : "false");
    LOG_INFO(__FUNCTION__, after_state.str());

    ////FUNCTION_LOG_EXIT();
}

/**
 * @brief Update TX PSN tracker with parameters
 * @param psn Packet sequence number
 * @param ack_req_flag ACK request flag
 * @param cack_psn Cumulative ACK PSN
 */
void PDC::updateTxPsnTracker(uint32_t psn, uint8_t ack_req_flag, uint32_t cack_psn){
    //FUNCTION_LOG_ENTRY();

    
    std::stringstream params;
    params << "Update TX PSN tracker - psn: " << psn
            << ", ack_req_flag: " << (int)ack_req_flag
            << ", cack_psn: " << cack_psn
            << ", Current clear_psn: " << clear_psn
            << ", Current unack_cnt: " << unack_cnt;
    LOG_INFO(__FUNCTION__, params.str());

    std::cout << getCurrentTimestamp() << "I_PDCUpdate TX PSN tracker - psn: " << psn
            << ", clear_psn: " << clear_psn << ", unack_cnt: " << unack_cnt << std::endl;

    if(psn > clear_psn + 1 && psn > cack_psn + 1) { 
        gen_cm = ACK_REQ;  
        std::cout << getCurrentTimestamp() << "Need to send ACK Request, tx_cur_psn: " << tx_cur_psn << ", clear_psn: " << clear_psn << std::endl;
        LOG_WARN(__FUNCTION__, "Detected ACK loss, set generate ACK Request");
    }
    else if(psn > clear_psn){
        uint32_t old_unack_cnt = unack_cnt;
        unack_cnt -= psn - clear_psn;
        
        for (uint32_t i = clear_psn; i < psn; i++)
        {
            if (tx_pkt_map.count(i))
            {
                if(USE_RTO) stopPacketTimer(i);  
                tx_pkt_map.erase(i);
                tx_pkt_buffer.erase(i);
            }
        }   
        clear_psn = psn;
        pause_pdc = false;
        
        std::stringstream update_info;
        update_info << "PSN acknowledgment update - old unack_cnt: " << old_unack_cnt
                    << ", New unack_cnt: " << unack_cnt
                    << ", New clear_psn: " << clear_psn
                    << ", pause_pdc: false";
        LOG_INFO(__FUNCTION__, update_info.str());
    
        
        
        // 条件：
        if(tx_pkt_q.empty() && unack_cnt == 0 && (ack_req_flag == 0x01)) {
            gen_cm = CLR_CMD;  
            std::cout << getCurrentTimestamp() << ", clear_psn: " << clear_psn << ", ack_req_flag: " << (int)ack_req_flag << std::endl;
            LOG_INFO(__FUNCTION__, "Clear Command conditions met, set generate Clear Command");
        }
    }

    //FUNCTION_LOG_EXIT();
}

/**
 * @brief Update RX PSN tracker
 * @param meta Received packet metadata
 */
void PDC::updateRxPsnTracker(RX_pkt_meta *meta){
    //FUNCTION_LOG_ENTRY();

    if(!meta) {
        LOG_ERROR(__FUNCTION__, "接收包元数据指针为空");
        //FUNCTION_LOG_EXIT();
        return;
    }

    uint32_t psn = meta->psn;
    uint32_t cpsn = meta->clear_psn;
    rx_clear_psn = std::max(rx_clear_psn, meta->clear_psn); 
    
    std::stringstream before_state;
    before_state << "Before update state - rx_cur_psn: " << rx_cur_psn
                    << ", cack_psn: " << cack_psn
                    << ", Received psn: " << psn
                    << ", Received clear_psn: " << cpsn;
    LOG_DEBUG(__FUNCTION__, before_state.str());

    if(psn == rx_cur_psn + 1){
        rx_cur_psn = psn;
        std::cout << getCurrentTimestamp() << "I_PDC update RX PSN - rx_cur_psn: " << rx_cur_psn << std::endl;
        LOG_INFO(__FUNCTION__, "Receive PSN sequential update");
    }

    if(cpsn > cack_psn){
        uint32_t old_cack = cack_psn;
        
        for (uint32_t i = cack_psn; i < cpsn; i++)
        {
            if (tx_ack_buffer.count(i))
            {
                tx_pkt_map.erase(i);
                tx_ack_buffer.erase(i);
            }
        }
        cack_psn = cpsn;    
        std::stringstream cack_update;
        cack_update << "Cumulative ACK PSN update - old cack_psn: " << old_cack << ", New cack_psn: " << cack_psn;
        LOG_INFO(__FUNCTION__, cack_update.str());
        std::cout << getCurrentTimestamp() << "I_PDC update cumulative ACK PSN - cack_psn: " << cack_psn << std::endl;
    }

    if(Enb_ACK_Per_Pkt && meta->som == false){
        uint16_t pl = meta->payload_len;
        if(pl >= ACK_Gen_Min_Pkt_Add) ACK_GEN_COUNT += pl;
        else ACK_GEN_COUNT += ACK_Gen_Min_Pkt_Add;
        
        if(ACK_GEN_COUNT >= ACK_Gen_Trigger){
            gen_ack = true;
            ACK_GEN_COUNT = 0;
            LOG_INFO(__FUNCTION__, "ACK generation threshold reached, set generate ACK flag");
        std::cout << getCurrentTimestamp() << "I_PDC reached ACK generation threshold, preparing to generate ACK" << std::endl;
        }
    }

//FUNCTION_LOG_EXIT();
}

/**
 * @brief Update RX PSN tracker with guaranteed delivery
 * @param meta Received packet metadata
 * @param gtd_del Guaranteed delivery flag
 */
void PDC::updateRxPsnTracker(RX_pkt_meta *meta, bool gtd_del)
{
    if (!gtd_del)
    {
        cack_psn = meta->psn;
    }
    std::cout << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] update_rx_psn_tracker,rx_cur_psn:" << rx_cur_psn << "cack_psn:" << cack_psn << std::endl;
    if (rx_cur_psn == cack_psn)
        allACK = true;
    else
        allACK = false;
}


/**
 * @brief Retransmit specified PSN packet
 * @param psn Packet sequence number
 */
void PDC::reTx(uint32_t psn){
    PDStoNET_pkt p = tx_pkt_buffer.at(psn);
    p.PDS_header.RUOD_req_header.flags.retx = 1; 
    if (public_net_queue) {
        public_net_queue->push(p);
    } else {
        tx_pkt_q.push(p);
    }
}

/**
 * @brief Handle transmission timeout
 * @param psn Timeout packet sequence number
 */
void PDC::txRto(uint32_t psn){
    TX_pkt_meta meta = tx_pkt_map.at(psn);
    if(meta.retry_cnt < Max_RTO_Retx_Cnt){
        meta.retry_cnt++;
        meta.rto = Base_RTO * (1 << meta.retry_cnt);
        tx_pkt_map[psn] = meta; 
        std::cout << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] Packet retransmission - PSN: " << psn
                << ", retry_cnt: " << meta.retry_cnt
                << ", new_rto22: " << meta.rto << std::endl;
        
        startPacketTimer(psn, meta.retry_cnt);

        std::stringstream retry_info;
        retry_info << "Retransmit packet - PSN: " << psn
                    << ", retry_cnt: " << meta.retry_cnt
                    << ", new_rto: " << meta.rto;
        LOG_INFO(__FUNCTION__, retry_info.str());

        PDStoNET_pkt p = tx_pkt_buffer.at(psn);
        p.PDS_header.RUOD_req_header.flags.retx = 1; 
        if (public_net_queue) {
            public_net_queue->push(p);
        } else {
            tx_pkt_q.push(p);
        }
    } else {
        LOG_ERROR(__FUNCTION__, "重传次数超限,设置关闭错误标志");
        close_error = true;
        
        open_msg = 0;
        unack_cnt = 0;
    } 
}


/**
 * @brief Free PDC resources 
 * @details Clears all buffers and queues
 */
void PDC::freePDC()
{
    
    tx_pkt_map.clear();
    rx_pkt_map.clear();
    tx_pkt_buffer.clear();
    tx_ack_buffer.clear();

    
    while (!tx_pkt_q.empty()) tx_pkt_q.pop();
    while (!tx_req_q.empty()) tx_req_q.pop();
    while (!tx_rsp_q.empty()) tx_rsp_q.pop();
    while (!rx_pkt_q.empty()) rx_pkt_q.pop();
    while (!rx_req_pkt_q.empty()) rx_req_pkt_q.pop();
    while (!rx_rsp_pkt_q.empty()) rx_rsp_pkt_q.pop();
    while (!rto_pkt_q.empty()) rto_pkt_q.pop();

    std::cout << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] PDC resources released" << std::endl;
}

/**
 * @brief Send NACK response
 * @param rsp Response packet
 */
void PDC::txNack(SES_PDC_rsp *rsp)
{
    if(!rsp) {
        LOG_ERROR(__FUNCTION__, formatLogMessage("输入响应指针为空"));
        return;
    }

    
    if(rx_pkt_map.find(rsp->rx_pkt_handle) == rx_pkt_map.end()) {
        LOG_ERROR(__FUNCTION__, formatLogMessage("未找到对应句柄的接收包元数据"));
        return;
    }

    RX_pkt_meta meta = rx_pkt_map.at(rsp->rx_pkt_handle);

    
    std::stringstream nack_info;
    nack_info << "SES layer requests to send NACK - handle: " << rsp->rx_pkt_handle
                << ", PSN: " << meta.psn
                << ", ses_nack: " << (rsp->ses_nack ? "true" : "false");
    LOG_WARN(__FUNCTION__, formatLogMessage(nack_info.str()));

    std::cout << getCurrentTimestamp() << formatLogMessage("Send SES NACK - PSN: ") << meta.psn << std::endl;

    
    sendNack(0, meta.psn, static_cast<PDS_Nack_Codes>(rsp->nack_payload.nack_code), 0, &rsp->pkt);

    
    rx_pkt_map.erase(rsp->rx_pkt_handle);
}
/**
 * @brief Handle control packet generation and transmission
 * @details Processes and sends various control message types
 */
void PDC::txCtrl(){
    if(state != ESTABLISHED && state != CREATING) {
        std::cout << "PDC state does not allow processing control packet, current state: " << state << std::endl;
        return;
    }
    else{
        PDStoNET_pkt p = {};
        // Set basic control packet properties
        p.PDS_type = RUOD_cp_header;
        p.dst_fep = dst_fep;
        p.src_fep = src_fep;
        p.PDS_header.RUOD_cp_header.type = CP;
        p.PDS_header.RUOD_cp_header.flags.syn = 0;
        p.PDS_header.RUOD_cp_header.flags.retx = 0;         
        p.PDS_header.RUOD_cp_header.flags.isrod = 0;        // rsvd
        switch (gen_cm)
        {
        case NOOP:
            sendCtrlNoop(&p);
            break;
        case ACK_req:
            sendCtrlAckReq(&p);
            break;
        case Clear_cmd:
            sendCtrlClearCmd(&p);
            break;
        case Clear_req:
            sendCtrlClearReq(&p);
            break;
        case Close_req:
            sendCtrlCloseReq(&p);
            break;
        case Credit:
            sendCtrlCredit(&p);
            break;
        case Negotiation:
            sendCtrlNegotiation(&p);
            break;
        default:
            LOG_ERROR(__FUNCTION__, formatLogMessage("未知控制消息类型"));
        }
        if(p.PDS_header.RUOD_cp_header.psn!=0){
            tx_pkt_buffer.insert(std::make_pair(tx_cur_psn,p)); 
            if(USE_RTO){
                startPacketTimer(p.PDS_header.RUOD_cp_header.psn, 0); 
            }
        }
        if (public_net_queue) {
            public_net_queue->push(p);
        } else {
            tx_pkt_q.push(p);
        }
    }
}
/**
 * @brief Forward request to SES layer
 * @param handle Request handle
 * @param meta Packet metadata
 * @param pkt Packet data
 */
void PDC::fwdReq2SES(uint16_t handle, RX_pkt_meta meta, SEStoPDS_pkt *pkt)
{
    if(!pkt) {
        LOG_ERROR(__FUNCTION__, formatLogMessage("SES packet pointer is null"));
        return;
    }

    
    std::stringstream fwd_info;
    fwd_info << "Forward request to SES layer - handle: " << handle
                << ", PSN: " << meta.psn
                << ", SPDCID: " << meta.spdcid
                << ", next_hdr: " << meta.next_hdr
                << ", payload_len: " << meta.payload_len;
    LOG_INFO(__FUNCTION__, formatLogMessage(fwd_info.str()));

    PDC_SES_req req;
    req.PDCID = SPDCID;                     
    req.rx_pkt_handle = handle;
    req.pkt = *pkt;
    req.pkt_len = meta.payload_len;
    req.next_hdr = meta.next_hdr;
    req.orig_psn = meta.psn;
    req.orig_pdcid = meta.spdcid;

    if (public_ses_req_queue) {
        public_ses_req_queue->push(req);
    } else {
        rx_req_pkt_q.push(req);
    }
    LOG_DEBUG(__FUNCTION__, formatLogMessage("Request added to SES layer receive queue"));

    std::cout << getCurrentTimestamp() << formatLogMessage("Forward to SES - handle: ") << handle
                << ", PSN: " << meta.psn << std::endl;
}

/**
 * @brief Forward response to SES layer
 * @param pkt Response packet pointer
 */
void PDC::fwdRsp2SES(SEStoPDS_pkt *pkt)
{
    LOG_DEBUG(__FUNCTION__, formatLogMessage("Forward response to SES layer"));
    PDC_SES_rsp rsp;
    rsp.PDCID = SPDCID;                     
    rsp.rx_pkt_handle = pkt->bth_header.Semantic_Response_Header.job_id;
    rsp.pkt = *pkt;                         // 响应包内容
    rsp.pkt_len = sizeof(SEStoPDS_pkt);     // 获取结构体大小
    if (public_ses_rsp_queue) {
        LOG_DEBUG(__FUNCTION__, formatLogMessage("加入公共队列"));
        public_ses_rsp_queue->push(rsp);
        LOG_DEBUG(__FUNCTION__, formatLogMessage("响应已加入公共队列"));
    } else {
        LOG_DEBUG(__FUNCTION__, formatLogMessage("加入本地队列"));
        rx_rsp_pkt_q.push(rsp);
        LOG_DEBUG(__FUNCTION__, formatLogMessage("响应已加入本地队列"));
    }
}

/**
 * @brief Check reception error
 * @param pkt Received packet
 */
void PDC::chkRxError(PDStoNET_pkt *pkt)
{
    uint32_t psn = pkt->PDS_header.RUOD_req_header.psn;

    if (psn > rx_cur_psn + 1) {
        std::cout << getCurrentTimestamp() << formatLogMessage("收到预期外的psn") << std::endl;
        if (pkt->PDS_header.RUOD_req_header.flags.syn == 1)
            error_chk = INV_SYN;
        else
            error_chk = OOO;
    } else if (psn < rx_clear_psn) {
        std::cout << getCurrentTimestamp() << formatLogMessage("PSN less than clear_psn, discard") << std::endl;
        error_chk = DROP;
    } else if (psn >= rx_clear_psn && psn <= rx_cur_psn) {
        std::cout << getCurrentTimestamp() << formatLogMessage("重复包") << std::endl;
        error_chk = ACK_ERROR;
    } else {
        std::cout << getCurrentTimestamp() << formatLogMessage("包正常") << std::endl;
        error_chk = OPEN;
    }
}

/**
 * @brief Process NOOP control message 
 * @param p Data packet to process // 需要处理的数据包
 */
void PDC::rxCtrlNoop(PDStoNET_pkt *p)
{
    if (!p) {
        LOG_ERROR(__FUNCTION__, formatLogMessage("输入数据包指针为空"));
        return;
    } else if (p->PDS_header.RUOD_cp_header.flags.ar) {
        sendAck(PDS_next_hdr::UET_HDR_NONE, 0, 0, p->PDS_header.RUOD_cp_header.psn, nullptr, false);
        return;
    } else {
        return;
    }
}

/**
 * @brief Process ACK_req control message 
 * @param p Data packet to process // 需要处理的数据包
 */
void PDC::rxCtrlAckReq(PDStoNET_pkt *p)
{
    if (!p) {
        LOG_ERROR(__FUNCTION__, formatLogMessage("输入数据包指针为空"));
        return;
    }

    uint32_t req_psn = p->PDS_header.RUOD_cp_header.psn;

    std::stringstream req_info;
    req_info << "Receive ACK Request - Request PSN: " << req_psn
                << ", SPDCID: " << p->PDS_header.RUOD_cp_header.spdcid
                << ", DPDCID: " << p->PDS_header.RUOD_cp_header.dpdcid;
    LOG_INFO(__FUNCTION__, formatLogMessage(req_info.str()));

    std::cout << getCurrentTimestamp() << formatLogMessage("rx_ctrl_ack_req - Request PSN: ") << req_psn << std::endl;

    auto ack_it = tx_ack_buffer.find(req_psn);
    if (ack_it != tx_ack_buffer.end()) {
        LOG_INFO(__FUNCTION__, formatLogMessage("Found corresponding ACK packet in ACK buffer, retransmit"));
        std::cout << getCurrentTimestamp() << formatLogMessage("Retransmit cached ACK packet, PSN: ") << req_psn << std::endl;
        PDStoNET_pkt ack_pkt = ack_it->second;
        tx_pkt_q.push(ack_pkt);
    } else {
        LOG_WARN(__FUNCTION__, formatLogMessage("ACK缓冲区中未找到对应PSN,构造新ACK包"));
        std::cout << getCurrentTimestamp() << formatLogMessage("Construct new ACK packet, PSN: ") << req_psn << std::endl;

        if (req_psn > rx_cur_psn) {
            LOG_ERROR(__FUNCTION__, formatLogMessage("Requested PSN exceeds current receive PSN range"));
            sendNack(0, req_psn, UET_PKT_NOT_RCVD, rx_cur_psn + 1, nullptr);
            return;
        }

        if (req_psn < cack_psn) {
            LOG_INFO(__FUNCTION__, formatLogMessage("Requested PSN has been cumulatively acknowledged, send current acknowledgment status"));
            sendAck(PDS_next_hdr::UET_HDR_NONE, 0, 0, req_psn, nullptr, false);
        } else {
            LOG_INFO(__FUNCTION__, formatLogMessage("Construct normal ACK response"));
            sendAck(PDS_next_hdr::UET_HDR_NONE, 0, 0, req_psn, nullptr, false);
        }
    }
}

/**
 * @brief Process Clear_cmd control message 
 * @param p Data packet to process // 需要处理的数据包
 */
void PDC::rxCtrlClearCmd(PDStoNET_pkt *p)
{
    if (!p) {
        LOG_ERROR(__FUNCTION__, formatLogMessage("输入数据包指针为空"));
        return;
    }

    uint32_t clear_psn_cmd = p->PDS_header.RUOD_cp_header.payload;

    std::stringstream cmd_info;
    cmd_info << "Receive Clear Command - CLEAR_PSN: " << clear_psn_cmd
                << ", SPDCID: " << p->PDS_header.RUOD_cp_header.spdcid
                << ", DPDCID: " << p->PDS_header.RUOD_cp_header.dpdcid;
    LOG_INFO(__FUNCTION__, formatLogMessage(cmd_info.str()));

    std::cout << getCurrentTimestamp() << formatLogMessage("rx_ctrl_clear_cmd - CLEAR_PSN: ") << clear_psn_cmd << std::endl;

    if (clear_psn_cmd > cack_psn) {
        LOG_ERROR(__FUNCTION__, formatLogMessage("PSN in Clear Command exceeds current cumulative acknowledgment PSN"));
        std::cout << getCurrentTimestamp() << formatLogMessage("Invalid CLEAR_PSN: ") << clear_psn_cmd
                    << ", Current cack_psn: " << cack_psn << std::endl;
        return;
    }

    std::cout << getCurrentTimestamp() << formatLogMessage("Clear ACK buffer, range: ") << cack_psn
                << " 到 " << clear_psn_cmd << std::endl;

    auto it = tx_ack_buffer.begin();
    while (it != tx_ack_buffer.end()) {
        if (it->first <= clear_psn_cmd) {
            std::cout << getCurrentTimestamp() << formatLogMessage("Delete PSN from ACK buffer: ") << it->first << std::endl;
            LOG_DEBUG(__FUNCTION__, formatLogMessage("Delete PSN from ACK buffer: " + std::to_string(it->first)));
            tx_pkt_map.erase(it->first);
            it = tx_ack_buffer.erase(it);
        } else {
            ++it;
        }
    }

    std::stringstream state_info;
    state_info << "Clear Command processing complete - Clear range: 0 到 " << clear_psn_cmd
                << ", Remaining ACK buffer size: " << tx_ack_buffer.size();
    LOG_INFO(__FUNCTION__, formatLogMessage(state_info.str()));

    std::cout << getCurrentTimestamp() << formatLogMessage("Clear Command处理完成，Remaining ACK buffer size: ")
                << tx_ack_buffer.size() << std::endl;

    if (p->PDS_header.RUOD_cp_header.flags.ar) {
        LOG_WARN(__FUNCTION__, formatLogMessage("Clear Command包含AR标志，这可能是协议违规"));
        std::cout << getCurrentTimestamp() << formatLogMessage("Warning: Clear Command set AR flag") << std::endl;
    }
}

/**
 * @brief Process Clear_req control message 
 * @param p Data packet to process // 需要处理的数据包
 */
void PDC::rxCtrlClearReq(PDStoNET_pkt *p)
{
    if (!p) {
        LOG_ERROR(__FUNCTION__, formatLogMessage("输入数据包指针为空"));
        return;
    }

    uint32_t req_clear_psn = p->PDS_header.RUOD_cp_header.payload;

    std::stringstream req_info;
    req_info << "Receive Clear Request - Request clear PSN: " << req_clear_psn
                << ", SPDCID: " << p->PDS_header.RUOD_cp_header.spdcid
                << ", DPDCID: " << p->PDS_header.RUOD_cp_header.dpdcid;
    LOG_INFO(__FUNCTION__, formatLogMessage(req_info.str()));

    std::cout << getCurrentTimestamp() << formatLogMessage("rx_ctrl_clear_req - Request clear PSN: ") << req_clear_psn << std::endl;

    if (req_clear_psn > clear_psn) {
        LOG_WARN(__FUNCTION__, formatLogMessage("Requested clear PSN exceeds current clear_psn range"));
        std::cout << getCurrentTimestamp() << formatLogMessage("Request clear PSN ") << req_clear_psn
                    << " exceeds current clear_psn " << clear_psn << std::endl;
    }

    bool has_resources_to_clear = false;

    for (auto it = tx_pkt_buffer.begin(); it != tx_pkt_buffer.end(); ++it) {
        if (it->first <= req_clear_psn) {
            has_resources_to_clear = true;
            break;
        }
    }

    if (!has_resources_to_clear) {
        for (auto it = tx_pkt_map.begin(); it != tx_pkt_map.end(); ++it) {
            if (it->first <= req_clear_psn) {
                has_resources_to_clear = true;
                break;
            }
        }
    }

    if (has_resources_to_clear) {
        std::cout << getCurrentTimestamp() << formatLogMessage("Clear send buffer, range: 0 到 ") << req_clear_psn << std::endl;
        LOG_INFO(__FUNCTION__, formatLogMessage("清除发送缓冲区中的过期包"));

        auto buf_it = tx_pkt_buffer.begin();
        while (buf_it != tx_pkt_buffer.end()) {
            if (buf_it->first <= req_clear_psn) {
                std::cout << getCurrentTimestamp() << formatLogMessage("清除发送包PSN: ") << buf_it->first << std::endl;
                if(USE_RTO) stopPacketTimer(buf_it->first);  // 停止计时器
                buf_it = tx_pkt_buffer.erase(buf_it);
            } else {
                ++buf_it;
            }
        }

        auto meta_it = tx_pkt_map.begin();
        while (meta_it != tx_pkt_map.end()) {
            if (meta_it->first <= req_clear_psn) {
                meta_it = tx_pkt_map.erase(meta_it);
            } else {
                ++meta_it;
            }
        }

        if (req_clear_psn > clear_psn) {
            clear_psn = req_clear_psn;
            std::cout << getCurrentTimestamp() << formatLogMessage("Update clear_psn to: ") << clear_psn << std::endl;
            LOG_INFO(__FUNCTION__, formatLogMessage("Update clear_psn to: " + std::to_string(clear_psn)));
        }
    }

    std::cout << getCurrentTimestamp() << formatLogMessage("Generate Clear Command response") << std::endl;
    LOG_INFO(__FUNCTION__, formatLogMessage("生成Clear Command作为清除请求的响应"));

    gen_cm = CLR_CMD;

    std::stringstream completion_info;
    completion_info << "Clear Request processing complete - Clear PSN: " << req_clear_psn
                    << ", Current clear_psn: " << clear_psn
                    << ", Remaining send buffer size: " << tx_pkt_buffer.size()
                    << ", Remaining metadata size: " << tx_pkt_map.size();
    LOG_INFO(__FUNCTION__, formatLogMessage(completion_info.str()));

    std::cout << getCurrentTimestamp() << formatLogMessage("Clear Request processing complete, remaining send buffer: ")
                << tx_pkt_buffer.size() << ", 元数据: " << tx_pkt_map.size() << std::endl;
}
/**
 * @brief Send close request packet // Send close request包
 */
void PDC::sendCloseReq()
{
    PDStoNET_pkt pkt = {};  
    pkt.PDS_type = RUOD_cp_header;
    pkt.PDS_header.RUOD_cp_header.type = CP;
    pkt.PDS_header.RUOD_cp_header.ctl_type = 0x3;
    pkt.PDS_header.RUOD_cp_header.flags.isrod = 1;
    pkt.PDS_header.RUOD_cp_header.flags.retx = 0;
    pkt.PDS_header.RUOD_cp_header.psn = tx_cur_psn;
    pkt.PDS_header.RUOD_cp_header.spdcid = SPDCID;
    pkt.PDS_header.RUOD_cp_header.dpdcid = DPDCID;

    TX_pkt_meta meta;
    meta.tx_pkt_handle = 0;
    meta.rto = Base_RTO;
    meta.retry_cnt = 0;

    tx_ack_buffer.insert(std::make_pair(tx_cur_psn, pkt));
    tx_pkt_map.insert(std::make_pair(tx_cur_psn, meta));

    if(USE_RTO){
       startPacketTimer(tx_cur_psn, 0);
    }

    updateTxPsnTracker();
    

    if (public_net_queue) {
        public_net_queue->push(pkt);
    } else {
        tx_pkt_q.push(pkt);
    }
    std::cout << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] Send close request" << std::endl;
}    
/**
 * @brief Send close acknowledgment packet // 发送关闭确认包
 */
void PDC::sendCloseAck()
{
    PDStoNET_pkt pkt = {};  
    pkt.dst_fep = dst_fep;
    pkt.src_fep = src_fep;
    pkt.PDS_type = RUOD_ack_header;
    pkt.PDS_header.RUOD_ack_header.type = ACK;
    pkt.PDS_header.RUOD_ack_header.next_hdr = UET_HDR_NONE;
    pkt.PDS_header.RUOD_ack_header.cack_psn = cack_psn + 1;
    pkt.PDS_header.RUOD_ack_header.ack_psn_off = rx_cur_psn - cack_psn - 1;
    pkt.PDS_header.RUOD_ack_header.dpdcid = DPDCID;
    pkt.PDS_header.RUOD_ack_header.spdcid = SPDCID;


    if (public_net_queue) {
        public_net_queue->push(pkt);
        LOG_INFO(__FUNCTION__, formatLogMessage("发送关闭确认到公共队列"));
    } else {
        tx_pkt_q.push(pkt);
        LOG_INFO(__FUNCTION__, formatLogMessage("发送关闭确认到本地队列"));
    }
}    
/**
 * @brief Send Noop control packet 
 * @param p Control packet pointer // 控制包指针
 */
void PDC::sendCtrlNoop(PDStoNET_pkt *p){
    LOG_INFO(__FUNCTION__, formatLogMessage("Send Noop control packet"));
    p->PDS_header.RUOD_cp_header.ctl_type = Noop;
    p->PDS_header.RUOD_cp_header.psn = setPsn();         
    p->PDS_header.RUOD_cp_header.spdcid = SPDCID;
    p->PDS_header.RUOD_cp_header.flags.ar = 1;           
    p->PDS_header.RUOD_cp_header.flags.isrod = 1;        //ROD
    p->PDS_header.RUOD_cp_header.flags.syn = SYN;        
    p->PDS_header.RUOD_cp_header.payload = 0;            
    if(!SYN)p->PDS_header.RUOD_cp_header.dpdcid = DPDCID;
    else{
        p->PDS_header.RUOD_cp_header.pdc_info = 0;      
        p->PDS_header.RUOD_req_header.psn_off = p->PDS_header.RUOD_cp_header.psn - start_psn;
    }

    updateTxPsnTracker();
}
/**
 * @brief Send ACK Request control packet 
 * @param p Control packet pointer // 控制包指针
 */
void PDC::sendCtrlAckReq(PDStoNET_pkt *p){
    LOG_INFO(__FUNCTION__, formatLogMessage("Send ACK Request control packet"));
    LOG_INFO(__FUNCTION__, formatLogMessage("ACK Request control packet DPDCID: " + std::to_string(DPDCID)));
    
    p->PDS_header.RUOD_cp_header.ctl_type = ACK_req;
    p->PDS_header.RUOD_cp_header.psn = clear_psn + 1;   
    p->PDS_header.RUOD_cp_header.spdcid = SPDCID;
    p->PDS_header.RUOD_cp_header.dpdcid = DPDCID;
    p->PDS_header.RUOD_cp_header.flags.ar = 1;        
    p->PDS_header.RUOD_cp_header.payload = tx_pkt_buffer.at(clear_psn + 1).SESpkt.bth_header.Standard_Header.msg_id;  //{message_id}
}

/**
 * @brief Send Clear Command control packet 
 * @param p Control packet pointer // 控制包指针
 */
void PDC::sendCtrlClearCmd(PDStoNET_pkt *p){
    LOG_INFO(__FUNCTION__, formatLogMessage("Send Clear Command control packet"));
    p->PDS_header.RUOD_cp_header.ctl_type = Clear_cmd;
    p->PDS_header.RUOD_cp_header.psn = 0;                
    p->PDS_header.RUOD_cp_header.spdcid = SPDCID;
    p->PDS_header.RUOD_cp_header.dpdcid = DPDCID;
    p->PDS_header.RUOD_cp_header.flags.ar = 0;           
    p->PDS_header.RUOD_cp_header.payload = clear_psn;    
}

/**
 * @brief Send Clear Request control packet 
 * @param p Control packet pointer // 控制包指针
 */
void PDC::sendCtrlClearReq(PDStoNET_pkt *p){
    LOG_INFO(__FUNCTION__, formatLogMessage("Send Clear Request control packet"));
    p->PDS_header.RUOD_cp_header.ctl_type = Clear_req;
    p->PDS_header.RUOD_cp_header.psn = 0;                
    p->PDS_header.RUOD_cp_header.spdcid = SPDCID;
    p->PDS_header.RUOD_cp_header.dpdcid = DPDCID;
    p->PDS_header.RUOD_cp_header.flags.ar = 0;           
    p->PDS_header.RUOD_cp_header.payload = cack_psn + 1;    
}
/**
 * @brief Send Close_req control message 
 * @param p Data packet to process // 需要处理的数据包
 */
void PDC::sendCtrlCloseReq(PDStoNET_pkt *p)
{
    LOG_INFO(__FUNCTION__, formatLogMessage("Send Close_req control packet"));
    p->PDS_header.RUOD_cp_header.ctl_type = Close_req;
    p->PDS_header.RUOD_cp_header.flags.ar = 1;
    p->PDS_header.RUOD_cp_header.psn = tx_cur_psn; 
    p->PDS_header.RUOD_cp_header.spdcid = SPDCID;
    p->PDS_header.RUOD_cp_header.dpdcid = DPDCID;
    p->PDS_header.RUOD_cp_header.pdc_info = 0;
    p->PDS_header.RUOD_cp_header.payload = 0x0;
    updateTxPsnTracker();
}

/**
 * @brief Send Credit control message 
 * @param p Data packet to process // 需要处理的数据包
 * @warning TODO: We need to study credit-based flow control 
 */
void PDC::sendCtrlCredit(PDStoNET_pkt *p)
{
    LOG_INFO(__FUNCTION__, formatLogMessage("Send Credit control packet"));
    
    if(!p) {
        LOG_ERROR(__FUNCTION__, formatLogMessage("输入数据包指针为空"));
        return;
    }
    
    p->PDS_header.RUOD_cp_header.flags.isrod = 0;   // rsvd
    p->PDS_header.RUOD_cp_header.ctl_type = gen_cm; 
    p->PDS_header.RUOD_cp_header.flags.ar = 0;
    p->PDS_header.RUOD_cp_header.flags.syn = 0;
    p->PDS_header.RUOD_cp_header.psn = 0x0; 
    p->PDS_header.RUOD_cp_header.spdcid = SPDCID;
    p->PDS_header.RUOD_cp_header.dpdcid = DPDCID;
    p->PDS_header.RUOD_cp_header.pdc_info = 0;
    p->PDS_header.RUOD_cp_header.payload = 0x0; 

    std::stringstream credit_info;
    credit_info << "Credit control packet parameters - gen_cm: " << CM_TYPE_STR(gen_cm)
                << ", SPDCID: " << SPDCID
                << ", DPDCID: " << DPDCID;
    LOG_DEBUG(__FUNCTION__, formatLogMessage(credit_info.str()));
    
    LOG_INFO(__FUNCTION__, formatLogMessage("Credit control packet construction complete"));
}

/**
 * @brief Send Negotiation control message 
 * @param p Data packet to process // 需要处理的数据包
 */
void PDC::sendCtrlNegotiation(PDStoNET_pkt *p)
{
    LOG_INFO(__FUNCTION__, formatLogMessage("Send Negotiation control packet"));
    
    if(!p) {
        LOG_ERROR(__FUNCTION__, formatLogMessage("输入数据包指针为空"));
        return;
    }
    
    p->PDS_header.RUOD_cp_header.flags.isrod = 1;   
    p->PDS_header.RUOD_cp_header.ctl_type = gen_cm; 
    p->PDS_header.RUOD_cp_header.flags.ar = 1;
    p->PDS_header.RUOD_cp_header.flags.syn = 0;
    p->PDS_header.RUOD_cp_header.psn = tx_cur_psn;
    p->PDS_header.RUOD_cp_header.spdcid = SPDCID;
    p->PDS_header.RUOD_cp_header.dpdcid = DPDCID;
    p->PDS_header.RUOD_cp_header.pdc_info = 0;
    p->PDS_header.RUOD_cp_header.payload = 0x0; 

    std::stringstream negotiation_info;
    negotiation_info << "Negotiation control packet parameters - gen_cm: " << CM_TYPE_STR(gen_cm)
                        << ", PSN: " << tx_cur_psn
                        << ", SPDCID: " << SPDCID
                        << ", DPDCID: " << DPDCID;
    LOG_DEBUG(__FUNCTION__, formatLogMessage(negotiation_info.str()));
    
    LOG_INFO(__FUNCTION__, formatLogMessage("Negotiation control packet construction complete"));
}

/**
 * @brief Get unacknowledged packet count // 获取未确认包计数
 * @return Number of unacknowledged packets // 未确认包数量
 */
int PDC::getUnackCount() const
{
    LOG_DEBUG(__FUNCTION__, formatLogMessage("Get unacknowledged packet count: " + std::to_string(unack_cnt)));
    return unack_cnt;
}

/**
 * @brief Get all acknowledgment status (I_PDC judges through unack_cnt) 
 * @return Whether all are acknowledged // 是否全部已确认
 */
bool PDC::getAllACKStatus() const {
    bool all_ack = (unack_cnt == 0);
    LOG_DEBUG(__FUNCTION__, formatLogMessage("获取全部确认状态 - unack_cnt: " + std::to_string(unack_cnt) + ", allACK: " + std::string(all_ack ? "true" : "false")));
    return all_ack;
}

/**
 * @brief Get open message count // 获取打开消息计数
 * @return Number of open messages // 打开消息数量
 */
int PDC::getOpenMsgCount() const
{
    LOG_DEBUG(__FUNCTION__, formatLogMessage("获取打开消息计数: " + std::to_string(open_msg)));
    return open_msg;
}

/**
 * @brief 获取PDC是否可以安全关闭的状态
 * @param unack_cnt_out 输出未确认包计数
 * @param allACK_out 输出全部确认状态
 * @param open_msg_out 输出打开消息计数
 */
void PDC::getCloseStatus(int& unack_cnt_out, bool& allACK_out, int& open_msg_out) const
{
    LOG_INFO(__FUNCTION__, formatLogMessage("获取关闭状态信息"));
    
    unack_cnt_out = unack_cnt;
    allACK_out = allACK;
    open_msg_out = open_msg;
    
    std::stringstream status_info;
    status_info << "关闭状态 - unack_cnt: " << unack_cnt
                << ", allACK: " << (allACK ? "true" : "false")
                << ", open_msg: " << open_msg;
    LOG_DEBUG(__FUNCTION__, formatLogMessage(status_info.str()));
}

/**
 * @brief 处理接收到的NACK包
 * @param pkt NACK包
 */
void PDC::rxNack(PDStoNET_pkt *pkt){
    //FUNCTION_LOG_ENTRY();

    if(!pkt) {
        LOG_ERROR(__FUNCTION__, "输入数据包指针为空");
        //FUNCTION_LOG_EXIT();
        return;
    }

    uint32_t psn = pkt->PDS_header.nack_header.nack_psn;

    
    std::stringstream nack_info;
    nack_info << "接收NACK - PSN: " << psn
                << ", nack_code: " << pkt->PDS_header.nack_header.nack_code;
    LOG_WARN(__FUNCTION__, nack_info.str());
    std::cout << getCurrentTimestamp() << "PDC接收NACK - PSN: " << psn << std::endl;

    if(isClose(pkt->PDS_header.nack_header.nack_code)){
        LOG_INFO(__FUNCTION__, "收到关闭NACK，设置关闭错误标志");
        std::cout << getCurrentTimestamp() << "PDC收到关闭NACK，触发关闭错误" << std::endl;
        close_error = true;
    }else{
        if(tx_pkt_map.find(psn) == tx_pkt_map.end()) {
            LOG_ERROR(__FUNCTION__, "未找到对应PSN的发送包元数据");
            //FUNCTION_LOG_EXIT();
            return;
        }

        TX_pkt_meta meta = tx_pkt_map.at(psn);

        if(meta.retry_cnt < Max_RTO_Retx_Cnt){
            meta.retry_cnt ++;
            meta.rto = Base_RTO * (1 << meta.retry_cnt) ;
        
            std::stringstream retry_info;
            retry_info << "Retransmit packet - PSN: " << psn
                        << ", retry_cnt: " << meta.retry_cnt
                        << ", new_rto: " << meta.rto;
            LOG_INFO(__FUNCTION__, retry_info.str());
            std::cout << getCurrentTimestamp() << "I_PDCRetransmit packet - PSN: " << psn
                        << ", retry_cnt: " << meta.retry_cnt << std::endl;
        
            reTx(psn);
        }else{
            LOG_ERROR(__FUNCTION__, "重传次数超限，设置关闭错误标志");
            std::cout << getCurrentTimestamp() << "I_PDC重传次数超限，触发关闭错误" << std::endl;
            close_error = true;
        }
    }
    //FUNCTION_LOG_EXIT();
}

/**
 * @brief 发送请求包
 * @param next_hdr 下一个头部类型
 * @param retx 重传标志
 * @param ar ACK请求标志
 * @param psn 包序列号
 * @param syn SYN标志
 * @param pkt 包数据
 */
void PDC::sendReq(PDS_next_hdr next_hdr,uint8_t retx,uint8_t ar,uint32_t psn,uint8_t syn,const SEStoPDS_pkt *pkt){
    // Perform packet header encapsulation here // 这里进行包头封装
    PDStoNET_pkt p = {};
    p.dst_fep = dst_fep;
    p.src_fep = src_fep;
    p.PDS_type = RUOD_req_header;
    p.PDS_header.RUOD_req_header.type = ROD_REQ;
    p.PDS_header.RUOD_req_header.next_hdr = next_hdr;
    p.PDS_header.RUOD_req_header.flags.syn = syn;
    p.PDS_header.RUOD_req_header.flags.retx = retx;
    p.PDS_header.RUOD_req_header.flags.ar = ar;
    p.PDS_header.RUOD_req_header.clear_psn_off =psn - clear_psn ;
    p.PDS_header.RUOD_req_header.psn = psn;
    p.PDS_header.RUOD_req_header.spdcid = SPDCID;
    if(syn == 0)p.PDS_header.RUOD_req_header.dpdcid = DPDCID;
    else {
        
        p.PDS_header.RUOD_req_header.pdc_info = 0;      
        p.PDS_header.RUOD_req_header.psn_off = psn - start_psn;
    }
    p.SESpkt = *pkt;
    tx_pkt_buffer.insert(std::make_pair(psn,p)); 

    TX_pkt_meta meta;
    meta.rto = Base_RTO;
    meta.tx_pkt_handle = 0;
    meta.retry_cnt = 0;
    tx_pkt_map.insert(std::make_pair(psn, meta));

    if(USE_RTO){
        startPacketTimer(psn, 0); 
    }

    if (public_net_queue) {
        public_net_queue->push(p);
        LOG_INFO(__FUNCTION__, formatLogMessage("将请求包压入公共网络队列"));
    } else {
        tx_pkt_q.push(p);
        LOG_INFO(__FUNCTION__, formatLogMessage("将请求包压入本地网络队列"));
    }
}
/**
 * @brief 发送ACK包
 * @param next_hdr 下一个头部类型
 * @param retx 重传标志
 * @param req 请求标志
 * @param psn 包序列号
 * @param pkt 包数据
 * @param gtd_del 保证传递标志
 */
void PDC::sendAck(PDS_next_hdr next_hdr,uint8_t retx,uint8_t req,uint32_t psn,SEStoPDS_pkt *pkt,bool gtd_del){
    //FUNCTION_LOG_ENTRY();

    
    std::stringstream params;
    params << "发送ACK参数 - next_hdr: " << next_hdr
            << ", retx: " << (int)retx
            << ", req: " << (int)req
            << ", psn: " << psn
            << ", gtd_del: " << (gtd_del ? "true" : "false")
            << ", pkt: " << (pkt ? "非空" : "空");
    LOG_INFO(__FUNCTION__, params.str());

    
    std::stringstream state_info;
    state_info << "PDC状态 - SPDCID: " << SPDCID
                << ", DPDCID: " << DPDCID
                << ", cack_psn: " << cack_psn;
    LOG_DEBUG(__FUNCTION__, state_info.str());

    PDStoNET_pkt p = {};
    p.dst_fep = dst_fep;
    p.src_fep = src_fep;
    p.PDS_type = RUOD_ack_header;
    p.PDS_header.RUOD_ack_header.type = PDS_type::ACK;
    p.PDS_header.RUOD_ack_header.next_hdr = next_hdr;
    p.PDS_header.RUOD_ack_header.flags.retx = retx;
    p.PDS_header.RUOD_ack_header.flags.req = req;
    p.PDS_header.RUOD_ack_header.ack_psn_off = psn - cack_psn;
    p.PDS_header.RUOD_ack_header.cack_psn = cack_psn;
    p.PDS_header.RUOD_ack_header.spdcid = SPDCID;
    p.PDS_header.RUOD_ack_header.dpdcid = DPDCID;

    if (pkt != nullptr)
    {
        p.SESpkt = *pkt;
        LOG_DEBUG(__FUNCTION__, formatLogMessage("包含SES层数据"));
    }

    
    std::stringstream ack_info;
    ack_info << "构造ACK包 - PSN: " << psn
            << ", CACK_PSN: " << cack_psn
            << ", ACK_PSN_OFF: " << (psn - cack_psn);
    LOG_INFO(__FUNCTION__, formatLogMessage(ack_info.str()));

    if (public_net_queue) {
        public_net_queue->push(p);
    } else {
        tx_pkt_q.push(p);
    }
    LOG_DEBUG(__FUNCTION__, formatLogMessage("ACK包已加入发送队列"));

    if (gtd_del)
    { 
        LOG_INFO(__FUNCTION__, formatLogMessage("保证交付模式,保存到ACK缓冲区"));
        TX_pkt_meta meta;
        meta.tx_pkt_handle = 0;
        meta.retry_cnt = 0;
        meta.rto = Base_RTO;
        tx_pkt_map.insert(std::make_pair(psn, meta));
        tx_ack_buffer.insert(std::make_pair(psn, p)); 
    }

    std::cout << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] tx_ack包发送,psn : " << psn << "cack_psn :" << cack_psn << std::endl;

    //FUNCTION_LOG_EXIT();
}
/**
 * @brief 发送NACK包
 * @param retx 重传标志
 * @param nack_psn NACK的PSN
 * @param nack_code NACK错误码
 * @param payload 载荷数据
 * @param pkt 包数据
 */
void PDC::sendNack(uint8_t retx, uint32_t nack_psn, PDS_Nack_Codes nack_code, uint32_t payload,SEStoPDS_pkt *pkt){
    //FUNCTION_LOG_ENTRY();

    
    std::stringstream nack_params;
    nack_params << "发送NACK参数 - retx: " << (int)retx
                << ", nack_psn: " << nack_psn
                << ", nack_code: " << NACK_CODE_STR(nack_code)
                << ", payload: " << payload;
    LOG_WARN(__FUNCTION__, nack_params.str());

    std::cout << getCurrentTimestamp() << "I_PDC发送NACK包 - PSN: " << nack_psn
                << ", code: " << NACK_CODE_STR(nack_code) << std::endl;

    // Currently parameters are set this way, need to add more // 目前参数先定成这样，需要再加
    PDStoNET_pkt p = {};
    p.dst_fep = dst_fep;
    p.src_fep = src_fep;
    p.PDS_type = nack_header;
    p.PDS_header.nack_header.type = NACK;
    p.PDS_header.nack_header.next_hdr = UET_HDR_NONE;//todo 根据需要设置
    p.PDS_header.nack_header.flags.m = 0x0;
    p.PDS_header.nack_header.flags.retx = retx;
    p.PDS_header.nack_header.flags.nt = 0x0;    
    p.PDS_header.nack_header.nack_psn = nack_psn;
    p.PDS_header.nack_header.nack_code = nack_code;

    
    if(nack_code == UET_NO_PDC_AVAIL || nack_code == UET_NO_CCC_AVAIL || nack_code == UET_NO_BITMAP || nack_code == UET_INV_DPDCID || nack_code == UET_PDC_HDR_MISMATCH || nack_code == UET_NO_RESOURCE){
        p.PDS_header.nack_header.spdcid = 0x0;
        LOG_DEBUG(__FUNCTION__, "特殊NACK码，设置SPDCID为0");
    }
    else {
        p.PDS_header.nack_header.spdcid = SPDCID;
    }
    p.PDS_header.nack_header.dpdcid = DPDCID;
    p.PDS_header.nack_header.payload = payload;

    if(pkt) {
        p.SESpkt = *pkt;
        LOG_DEBUG(__FUNCTION__, "NACK包包含SES层数据");
    }
    else {
        p.SESpkt = {};
        LOG_DEBUG(__FUNCTION__, "NACK包不包含SES层数据");
    }

    if (public_net_queue) {
        public_net_queue->push(p);
    } else {
        tx_pkt_q.push(p);
    }
    LOG_INFO(__FUNCTION__, "NACK包已加入发送队列");

    std::cout << getCurrentTimestamp() << "I_PDC NACK包已发送 - PSN: " << p.PDS_header.nack_header.nack_psn
                << ", code: " << NACK_CODE_STR(nack_code) << std::endl;

    //FUNCTION_LOG_EXIT();
}
/**
 * @brief 发送请求给网络层
 * @param req 请求包
 */
void PDC::txReq(PDS_PDC_req *req){

    if(!req) {
        LOG_ERROR(__FUNCTION__, "输入请求指针为空");
        //FUNCTION_LOG_EXIT();
        return;
    }

    uint32_t psn = setPsn();

    
    std::stringstream req_info;
    req_info << "发送请求包 - tx_pkt_handle: " << req->tx_pkt_handle
                << ", next_hdr: " << req->next_hdr
                << ", som: " << (req->som ? "true" : "false")
                << ", eom: " << (req->eom ? "true" : "false")
                << ", psn: " << psn
                << ", SYN: " << (SYN ? "true" : "false");
    LOG_INFO(__FUNCTION__, req_info.str());

    std::cout << getCurrentTimestamp() << "I_PDC发送请求包 - PSN: " << psn
                << ", handle: " << req->tx_pkt_handle << std::endl;

    updateTxPsnTracker();

    TX_pkt_meta meta;
    meta.retry_cnt = 0;                         
    meta.tx_pkt_handle = req->tx_pkt_handle;
    meta.rto = Base_RTO;                        
    tx_pkt_map.insert(std::make_pair(psn, meta));
    
    LOG_DEBUG(__FUNCTION__, "包元数据已保存");

    
    if(req->som) {
        open_msg += 1;
        LOG_DEBUG(__FUNCTION__, "消息开始标记，open_msg增加");
        std::cout << getCurrentTimestamp() << "I_PDC消息开始，open_msg: " << open_msg << std::endl;
    }
    if(req->eom) {
        open_msg -= 1;
        LOG_DEBUG(__FUNCTION__, "消息结束标记，open_msg减少");
        std::cout << getCurrentTimestamp() << "I_PDC消息结束，open_msg: " << open_msg << std::endl;
    }

    std::stringstream msg_info;
    msg_info << "当前open_msg计数: " << open_msg;
    LOG_DEBUG(__FUNCTION__, msg_info.str());

    if(req->eom == 1 || Enb_ACK_Per_Pkt) sendReq(req->next_hdr,0,1,psn,SYN,&req->pkt);
    else sendReq(req->next_hdr,0,0,psn,SYN,&req->pkt);
    
    LOG_INFO(__FUNCTION__, "请求包已发送");
}

/**
 * @brief 发送响应给网络层
 * @param rsp 响应包
 */
void PDC::txRsp(SES_PDC_rsp *rsp){
    //FUNCTION_LOG_ENTRY();

    
    std::stringstream debug_info;
    debug_info << "tx_rsp调用 - 查找句柄: " << rsp->rx_pkt_handle
                << ", rx_pkt_map大小: " << rx_pkt_map.size();
    LOG_INFO(__FUNCTION__, debug_info.str());

    
    if (!rx_pkt_map.empty()) {
        std::stringstream map_keys;
        map_keys << "rx_pkt_map中的所有句柄: ";
        for (const auto& pair : rx_pkt_map) {
            map_keys << pair.first << " ";
        }
        LOG_DEBUG(__FUNCTION__, map_keys.str());
    }

    
    if (rx_pkt_map.find(rsp->rx_pkt_handle) == rx_pkt_map.end()) {
        std::stringstream error_info;
        error_info << "错误：未找到句柄 " << rsp->rx_pkt_handle << " 在rx_pkt_map中";
        LOG_ERROR(__FUNCTION__, error_info.str());
        //FUNCTION_LOG_EXIT();
        return;
    }

    RX_pkt_meta meta = rx_pkt_map.at(rsp->rx_pkt_handle);

    std::stringstream meta_info;
    meta_info << "找到元数据 - PSN: " << meta.psn
                << ", SPDCID: " << meta.spdcid;
    LOG_INFO(__FUNCTION__, meta_info.str());

    updateRxPsnTracker(&meta,rsp->gtd_del);
    //SES response does not contain payload packet //SES回应不包含负载包
    if(rsp->rep_len == 0){
        LOG_DEBUG(__FUNCTION__, formatLogMessage("响应不包含SES层数据"));
        sendAck(PDS_next_hdr::UET_HDR_NONE,0,0,meta.psn,&rsp->pkt,rsp->gtd_del);
    }
    else sendAck(PDS_next_hdr::UET_HDR_RESPONSE,0,0,meta.psn,&rsp->pkt,rsp->gtd_del);
    rx_pkt_map.erase(rsp->rx_pkt_handle);//Delete metadata //删除元数据

    //FUNCTION_LOG_EXIT();
}
/**
 * @brief 设置公共队列
 * @param net_q 网络队列
 * @param ses_req_q SES请求队列
 * @param ses_rsp_q SES响应队列
 * @param close_q 关闭队列
 */
void PDC::setPublicQueues(ThreadSafeQueue<PDStoNET_pkt>* net_q,
                    ThreadSafeQueue<PDC_SES_req>* ses_req_q,
                    ThreadSafeQueue<PDC_SES_rsp>* ses_rsp_q,
                    ThreadSafeQueue<uint16_t>* close_q)
{
    public_net_queue = net_q;
    public_ses_req_queue = ses_req_q;
    public_ses_rsp_queue = ses_rsp_q;
    public_close_queue = close_q;
}

/**
 * @brief 判断PDC是否可以安全关闭
 * @return 是否可以关闭
 */
bool PDC::canSafelyClose(){
    bool canClose = (unack_cnt == 0) && allACK && (open_msg == 0);
    
    std::stringstream status_info;
    status_info << "PDC关闭状态检查 - SPDCID: " << SPDCID
                << ", unack_cnt: " << unack_cnt
                << ", allACK: " << (allACK ? "true" : "false")
                << ", open_msg: " << open_msg
                << ", 可以关闭: " << (canClose ? "是" : "否");
    LOG_INFO(__FUNCTION__, formatLogMessage(status_info.str()));
    
    return canClose;
}

/**
 * @brief 启动包的计时器
 * @param psn 包序列号
 * @param retry_count 当前重试次数
 */
void PDC::startPacketTimer(uint32_t psn, uint16_t retry_count)
{
    if (!rto_timer_.startTimer(psn, Base_RTO, retry_count)) {
        LOG_ERROR("PDC::startPacketTimer", 
                 formatLogMessage("启动计时器失败 - PSN: " + std::to_string(psn)));
    }
}

/**
 * @brief 停止包的计时器
 * @param psn 包序列号
 */
void PDC::stopPacketTimer(uint32_t psn)
{
    if (!rto_timer_.stopTimer(psn)) {
        LOG_DEBUG("PDC::stopPacketTimer", 
                 formatLogMessage("停止计时器失败或不存在 - PSN: " + std::to_string(psn)));
    }
}

/**
 * @brief 更新包的RTO时间
 * @param psn 包序列号
 * @param new_rto 新的RTO时间
 */
void PDC::updatePacketRTO(uint32_t psn, uint16_t new_rto)
{
    if (!rto_timer_.updateRTO(psn, new_rto)) {
        LOG_WARN("PDC::updatePacketRTO", 
                 formatLogMessage("更新RTO失败 - PSN: " + std::to_string(psn)));
    }
}

/**
 * @brief 清理所有包的计时器
 */
void PDC::clearAllPacketTimers()
{
    rto_timer_.clearAllTimers();
    LOG_INFO("PDC::clearAllPacketTimers", 
             formatLogMessage("清理所有包计时器"));
}

/**
 * @brief 获取计时器状态信息
 * @param psn 包序列号
 * @return 计时器状态信息
 */
RTOTimer::TimerItem PDC::getTimerInfo(uint32_t psn) const
{
    return rto_timer_.getTimerInfo(psn);
}

/**
 * @brief 检查计时器是否活跃
 * @param psn 包序列号
 * @return 是否活跃
 */
bool PDC::isTimerActive(uint32_t psn) const
{
    return rto_timer_.isTimerActive(psn);
}

/**
 * @brief 获取活跃计时器数量
 * @return 活跃计时器数量
 */
size_t PDC::getActiveTimerCount() const
{
    return rto_timer_.getActiveTimerCount();
}

/**
 * @brief 检查清理状态
 */

void PDC::chkClear()
{ 
    if (tx_ack_buffer.size() + 5 >= tx_ack_buffer_capa)
        gen_cm = CLR_REQ;
}

/**
 * @brief 检查裁剪状态
 * @return 裁剪状态检查结果
 */
bool PDC::chkTrim()
{
    return false;
    
}

/**
 * @brief 设置FEP地址
 * @param dst 目标IP地址
 * @param src 源IP地址
 */
void PDC::setFep(uint32_t dst, uint32_t src)
{
    dst_fep = dst;
    src_fep = src;
}