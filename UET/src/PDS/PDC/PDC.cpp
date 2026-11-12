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
#include "../TrimmedPacket.hpp"
#include <algorithm>
#include <functional>

/**
 * @brief PDC constructor 
 * @details Initializes PDC with default parameters and sets up timer callback
 */
PDC::PDC(UET::Runtime::Services* services)
    : rto_timer_([this](uint32_t psn) {
          
          rto_pkt_q.push(psn);

          LOG_WARN("RTOTimer::timeout_callback",
                   formatLogMessage("Packet timeout - PSN: " + std::to_string(psn)));

          diagnostics() << getCurrentTimestamp() << formatLogMessage("Packet timeout, added to retransmission queue - PSN: ")
                    << psn << std::endl;
      }, services),
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
    runtime_ = services;
    LOG_INFO("PDC::PDC", formatLogMessage("PDC constructor called - initialization completed"));
    diagnostics() << getCurrentTimestamp() << formatLogMessage("PDC constructor completed initialization") << std::endl;
}

/**
 * @brief PDC destructor 
 * @details Cleans up all resources including timers, maps, and queues
 */
PDC::~PDC()
{
    releaseCongestionState();
    resetCloseSafety();
    resetNackPause();
    lifetime_guard_.reset();
    LOG_INFO("PDC::~PDC", formatLogMessage("PDC destructor called - starting resource cleanup"));
    diagnostics() << getCurrentTimestamp() << formatLogMessage("PDC destructor starting resource cleanup") << std::endl;

    
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
    rx_pkt_q.clear();
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
    meta.clear_psn = meta.psn + pkt->PDS_header.RUOD_req_header.clear_psn_off;
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
    if (runtime_ && runtime_->congestion_control) {
        congestion_engaged_=true;
        runtime_->congestion_control->received(congestionConnection(),*pkt);
    }
    return handle;
}

void PDC::releaseCongestionState() {
    if (congestion_engaged_ && runtime_ && runtime_->congestion_control)
        runtime_->congestion_control->closed(congestionConnection());
    congestion_engaged_=false;
    congestion_connection_.reset();
    admission_deferred_retries_.clear();
}

void PDC::rejectTrimmed(const PDStoNET_pkt& packet) {
    auto reply=UET::PDS::trimmed_negative_ack(packet,SPDCID,rx_cur_psn+1);
    if (public_net_queue) public_net_queue->push(reply); else tx_pkt_q.push(std::move(reply));
}

void PDC::processCongestionAck(const PDStoNET_pkt& packet) {
    if (!runtime_ || !runtime_->congestion_control) return;
    const auto& ack=packet.PDS_header.RUOD_ack_header;
    const uint32_t sequence=ack.cack_psn+ack.ack_psn_off;
    std::optional<UET::CMS::NsccTransmitSample> sample;
    const auto found=tx_pkt_map.find(sequence);
    if (found!=tx_pkt_map.end() && found->second.congestion_nominal_bytes && !found->second.congestion_data_received)
        sample=UET::CMS::NsccTransmitSample{found->second.last_transmit_time,found->second.retry_cnt};
    runtime_->congestion_control->acknowledged(congestionConnection(),packet,sample);
    if (ack.type==ACK_CC) {
        const auto span=tx_cur_psn-clear_psn;
        for (auto& item:tx_pkt_map) {
            const uint32_t distance=item.first-clear_psn;
            const uint32_t sack_base=ack.cack_psn+packet.congestion_ack.sack_psn_offset;
            const uint32_t sack_bit=item.first-sack_base;
            if (distance && distance<span && (item.first==sequence ||
                (ack.cack_psn-clear_psn<span && distance<=ack.cack_psn-clear_psn) ||
                (sack_bit<64 && (packet.congestion_ack.sack_bitmap&(uint64_t{1}<<sack_bit))))) {
                item.second.congestion_data_received=true;
                item.second.congestion_inflight=false;
            }
        }
    }
}

void PDC::processPeerAcknowledgment(const PDStoNET_pkt& packet) {
    const auto& ack=packet.PDS_header.RUOD_ack_header;
    if (ack.flags.p) return; // Probe's base CACK is not delivery state.
    if ((tx_cur_psn-1)-ack.cack_psn>=0x80000000u) return; // Never anchor a peer window on unsent future PSNs.
    if (!peer_sequence_window_) {
        if (ack.cack_psn-(start_psn-1)>tx_cur_psn-start_psn) return;
        peer_sequence_window_.emplace(start_psn,runtime_?runtime_->mpr_zero_override:0);
    }
    const auto encoding=ack.type==ACK_CC?std::optional<uint8_t>{packet.congestion_ack.mpr}:std::nullopt;
    peer_sequence_window_->observe(ack.cack_psn,encoding);
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

    diagnostics() << getCurrentTimestamp() << "I_PDC update TX PSN - tx_cur_psn: " << tx_cur_psn
            << ", unack_cnt: " << unack_cnt << std::endl;

    if ((tx_cur_psn - clear_psn) >= (unsigned)(MPR / 2) && state == ESTABLISHED)
    {
        gen_cm = ACK_REQ; 
        diagnostics() << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] Need to send ACK Request, current psn: " << tx_cur_psn << ", clear_psn: " << clear_psn << std::endl;
    }
    else if ((unack_cnt >= MPR) && !SYN)
    {
        gen_cm = ACK_REQ;
        pause_pdc = true;
    }
    // Window backpressure is independent of ACK-request heuristics.
    // §3.5.12.6: selective ACKs free packet buffers, but cannot authorize a
    // new PSN beyond the still-open sequence window at the receiver.
    pause_pdc = nack_traffic_paused_ || unack_cnt >= MPR || tx_cur_psn-clear_psn > MPR;

    
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
void PDC::updateTxPsnTracker(uint32_t psn, uint8_t ack_req_flag, uint32_t cumulative) {
    const uint32_t outstanding_span = tx_cur_psn - clear_psn;
    if (outstanding_span >= 0x80000000u) {
        close_error = true;
        return;
    }
    const uint32_t explicit_distance = psn - clear_psn;
    const uint32_t cumulative_distance = cumulative - clear_psn;
    const bool valid_explicit = explicit_distance && explicit_distance < outstanding_span;
    const bool valid_cumulative = cumulative_distance < outstanding_span;
    if (valid_explicit || valid_cumulative) resumeNackTraffic();
    if (valid_cumulative) emitPdcEvent(UET::Runtime::PdcEventKind::PeerCumulativeAcknowledged,cumulative);
    for (auto it = tx_pkt_buffer.begin(); it != tx_pkt_buffer.end();) {
        const uint32_t distance = it->first - clear_psn;
        if (distance && distance < outstanding_span &&
            ((valid_explicit && it->first == psn) ||
             (valid_cumulative && distance <= cumulative_distance))) {
            const auto sequence = it->first;
            stopPacketTimer(sequence);
            admission_deferred_retries_.erase(sequence);
            tx_pkt_map.erase(sequence);
            acknowledged_tx_.insert(sequence);
            it = tx_pkt_buffer.erase(it);
            if (unack_cnt > 0) --unack_cnt;
        } else ++it;
    }
    if (fast_retransmit_psn_ && !tx_pkt_buffer.count(*fast_retransmit_psn_))
        fast_retransmit_psn_.reset();
    while (acknowledged_tx_.erase(clear_psn + 1)) ++clear_psn;
    pause_pdc = nack_traffic_paused_ || unack_cnt >= MPR || tx_cur_psn-clear_psn > MPR;
    if ((ack_req_flag & 1u) && (valid_explicit || valid_cumulative)) gen_cm = CLR_CMD;
    // Selective ACKs are remembered, so a repeated ACK cannot decrement the
    // count twice or cause an endless ACK_REQ/cache-reply exchange.
}

/**
 * @brief Update RX PSN tracker
 * @param meta Received packet metadata
 */
void PDC::advanceCumulativeAck()
{
    // §3.5.12.5: CACK cannot skip either a missing packet or a guaranteed
    // semantic response that the peer has not yet cleared.
    while (completed_rx_psns_.erase(cack_psn+1)) ++cack_psn;
    allACK = cack_psn == rx_cur_psn;
}

void PDC::clearReceivedPacketsThrough(uint32_t clear_through)
{
    const uint32_t advance = clear_through-rx_clear_psn;
    if (advance>=0x80000000u) return;
    // A clear may cover only already received contiguous PSNs. Otherwise a
    // malformed peer could silently discard a hole in the RUD receive window.
    if (clear_through-rx_cur_psn && clear_through-rx_cur_psn<0x80000000u) return;
    rx_clear_psn=clear_through;
    if (congestion_engaged_ && runtime_ && runtime_->congestion_control)
        runtime_->congestion_control->receive_cleared(congestionConnection(),clear_through);
    if (advance) emitPdcEvent(UET::Runtime::PdcEventKind::ReceiveCleared,clear_through);
    for (auto entry=tx_ack_buffer.begin();entry!=tx_ack_buffer.end();) {
        if (clear_through-entry->first<0x80000000u) {
            completed_rx_psns_.insert(entry->first);
            entry=tx_ack_buffer.erase(entry);
        } else ++entry;
    }
    for (auto sequence=received_rx_psns_.begin();sequence!=received_rx_psns_.end();) {
        if (clear_through-*sequence<0x80000000u) sequence=received_rx_psns_.erase(sequence);
        else ++sequence;
    }
    advanceCumulativeAck();
}

void PDC::updateRxPsnTracker(RX_pkt_meta* metadata)
{
    if (!metadata) return;
    received_rx_psns_.insert(metadata->psn);
    while (received_rx_psns_.count(rx_cur_psn+1)) ++rx_cur_psn;
    clearReceivedPacketsThrough(metadata->clear_psn);
}

void PDC::updateRxPsnTracker(RX_pkt_meta* metadata, bool guaranteed_delivery)
{
    if (!metadata) return;
    if (!guaranteed_delivery) completed_rx_psns_.insert(metadata->psn);
    advanceCumulativeAck();
}

/**
 * @brief Retransmit specified PSN packet
 * @param psn Packet sequence number
 */
void PDC::reTx(uint32_t psn){
    const auto found = tx_pkt_buffer.find(psn);
    if (found == tx_pkt_buffer.end()) return;
    PDStoNET_pkt p = found->second;
    if (runtime_ && runtime_->congestion_control && p.PDS_type==RUOD_req_header &&
        tx_pkt_map.at(psn).congestion_data_received) {
        // Data receipt has already clocked NSCC. Re-sending that data would
        // charge another attempt that duplicate suppression can never count
        // as new bytes. Ask for the retained SES response (§3.5.16.2).
        PDStoNET_pkt query{}; query.src_fep=src_fep; query.dst_fep=dst_fep;
        query.PDS_type=RUOD_cp_header;
        auto& control=query.PDS_header.RUOD_cp_header;
        control.type=CP; control.ctl_type=ACK_req; control.flags.ar=1;
        control.psn=psn; control.spdcid=SPDCID; control.dpdcid=DPDCID;
        control.payload=uint32_t{p.SESpkt.bth_header.Standard_Header.msg_id}<<16;
        if (public_net_queue) public_net_queue->push(query); else tx_pkt_q.push(query);
        return;
    }
    if (p.PDS_type == RUOD_cp_header) {
        auto& control=p.PDS_header.RUOD_cp_header;
        control.flags.retx=1;
        if (!SYN && (control.ctl_type==Noop || control.ctl_type==Negotiation)) {
            control.flags.syn=0; control.dpdcid=DPDCID;
        }
    }
    else if (p.PDS_type == RUOD_req_header) {
        p.PDS_header.RUOD_req_header.flags.retx = 1;
        if (!SYN) {
            // §3.5.8.2: after learning the peer PDCID, retransmissions of
            // packets originally sent with SYN use the established tuple.
            p.PDS_header.RUOD_req_header.flags.syn=0;
            p.PDS_header.RUOD_req_header.dpdcid=DPDCID;
        }
    }
    else return;
    if (runtime_ && runtime_->congestion_control && p.PDS_type==RUOD_req_header) {
        auto& metadata=tx_pkt_map.at(psn);
        metadata.congestion_nominal_bytes=runtime_->congestion_control->transmitted(congestionConnection(),p);
        metadata.congestion_inflight=true;
    }
    found->second=p;
    if (runtime_ && tx_pkt_map.count(psn)) tx_pkt_map.at(psn).last_transmit_time=runtime_->clock.now();
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
    if (!tx_pkt_map.count(psn) || !tx_pkt_buffer.count(psn)) return;
    if (nack_traffic_paused_ && tx_pkt_buffer.at(psn).PDS_type!=RUOD_cp_header) {
        deferred_nack_retransmits_.insert(psn);
        return;
    }
    if (runtime_ && runtime_->congestion_control && tx_pkt_buffer.at(psn).PDS_type==RUOD_req_header &&
        !tx_pkt_map.at(psn).congestion_data_received) {
        auto& metadata=tx_pkt_map.at(psn);
        if (metadata.congestion_inflight) {
            runtime_->congestion_control->inferred_loss(congestionConnection(),metadata.congestion_nominal_bytes);
            metadata.congestion_inflight=false;
        }
        // Infer loss once, but do not consume a retry or arm a new RTO until
        // CMS admits the actual retransmission (§3.6.8 / §3.6.13.5).
        stopPacketTimer(psn);
    }
    const bool data=tx_pkt_buffer.at(psn).PDS_type==RUOD_req_header;
    const bool semantic_query=data && runtime_ && runtime_->congestion_control && tx_pkt_map.at(psn).congestion_data_received;
    if (data && !semantic_query && (!peerWindowAllows(psn) || !congestionReady())) {
        stopPacketTimer(psn); admission_deferred_retries_.insert(psn); return;
    }
    TX_pkt_meta meta = tx_pkt_map.at(psn);
    const auto& lost_packet=tx_pkt_buffer.at(psn);
    const bool lost_syn=lost_packet.PDS_type==RUOD_req_header?
        lost_packet.PDS_header.RUOD_req_header.flags.syn:
        lost_packet.PDS_type==RUOD_cp_header && lost_packet.PDS_header.RUOD_cp_header.flags.syn;
    if (runtime_ && lost_syn) {
        syn_safety_deadline_=std::max(syn_safety_deadline_,
            UET::Runtime::add_time(meta.last_transmit_time,runtime_->syn_retransmission_safety_time));
        if (closing) armCloseSafetyWake();
    }
    if(meta.retry_cnt < Max_RTO_Retx_Cnt){
        meta.retry_cnt++;
        meta.rto = static_cast<uint16_t>(std::min<uint64_t>(10000, static_cast<uint64_t>(runtime_ ? runtime_->rto_ms : Base_RTO) << std::min<uint16_t>(meta.retry_cnt,16)));
        tx_pkt_map[psn] = meta; 
        diagnostics() << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] Packet retransmission - PSN: " << psn
                << ", retry_cnt: " << meta.retry_cnt
                << ", new_rto22: " << meta.rto << std::endl;
        
        startPacketTimer(psn, meta.retry_cnt);

        std::stringstream retry_info;
        retry_info << "Retransmit packet - PSN: " << psn
                    << ", retry_cnt: " << meta.retry_cnt
                    << ", new_rto: " << meta.rto;
        LOG_INFO(__FUNCTION__, retry_info.str());

        reTx(psn);
    } else {
        LOG_ERROR(__FUNCTION__, "重传次数超限,设置关闭错误标志");
        close_error = true;
        failure_reason_=UET::Runtime::PdcFailureReason::RetryExhausted;
        
        open_msg = 0;
        unack_cnt = 0;
    } 
}


/**
 * @brief Free PDC resources 
 * @details Clears all buffers and queues
 */
void PDC::resetCloseSafety()
{
    if (runtime_ && close_safety_wake_) runtime_->timers.cancel(close_safety_wake_);
    close_safety_wake_=0;
    syn_safety_deadline_=0;
}

void PDC::armCloseSafetyWake()
{
    if (!runtime_) return;
    if (close_safety_wake_) runtime_->timers.cancel(close_safety_wake_);
    close_safety_wake_=0;
    if (closeSafetyReady()) return;
    const std::weak_ptr<int> lifetime=lifetime_guard_;
    close_safety_wake_=runtime_->timers.at(syn_safety_deadline_,[this,lifetime] {
        if (lifetime.expired()) return;
        close_safety_wake_=0;
        if (runtime_->wake) runtime_->wake();
    });
}

void PDC::resetNackPause() {
    if (runtime_ && nack_retry_wake_) runtime_->timers.cancel(nack_retry_wake_);
    nack_retry_wake_=0;
    nack_traffic_paused_=false;
    deferred_nack_retransmits_.clear();
}

void PDC::resumeNackTraffic() {
    if (!nack_traffic_paused_) return;
    if (runtime_ && nack_retry_wake_) runtime_->timers.cancel(nack_retry_wake_);
    nack_retry_wake_=0;
    nack_traffic_paused_=false;
    pause_pdc=unack_cnt>=MPR || tx_cur_psn-clear_psn>MPR;
    for (const auto sequence:deferred_nack_retransmits_)
        if (tx_pkt_buffer.count(sequence)) rto_pkt_q.push(sequence);
    deferred_nack_retransmits_.clear();
    if (runtime_ && runtime_->wake) runtime_->wake();
}

void PDC::pauseForResourceNack(uint32_t sequence) {
    deferred_nack_retransmits_.insert(sequence);
    stopPacketTimer(sequence);
    if (nack_traffic_paused_) return; // A burst of NACKs must not restart the delay.
    nack_traffic_paused_=true;
    pause_pdc=true;
    const auto delay=std::max<UET::Runtime::Time>(1,runtime_->resource_nack_retry_delay);
    const std::weak_ptr<int> lifetime=lifetime_guard_;
    nack_retry_wake_=runtime_->timers.at(UET::Runtime::add_time(runtime_->clock.now(),delay),[this,lifetime] {
        if (lifetime.expired()) return;
        nack_retry_wake_=0;
        resumeNackTraffic();
    });
}

void PDC::freePDC()
{
    releaseCongestionState();
    peer_sequence_window_.reset();
    resetCloseSafety();
    resetNackPause();
    clearAllPacketTimers();
    acknowledged_tx_.clear();
    fast_retransmit_psn_.reset();
    received_rx_psns_.clear();
    completed_rx_psns_.clear();
    closing = false;
    close_error = false;
    failure_reason_=UET::Runtime::PdcFailureReason::None;
    gen_cm = NONE;
    
    tx_pkt_map.clear();
    rx_pkt_map.clear();
    tx_pkt_buffer.clear();
    tx_ack_buffer.clear();

    
    while (!tx_pkt_q.empty()) tx_pkt_q.pop();
    while (!tx_req_q.empty()) tx_req_q.pop();
    while (!tx_rsp_q.empty()) tx_rsp_q.pop();
    rx_pkt_q.clear();
    while (!rx_req_pkt_q.empty()) rx_req_pkt_q.pop();
    while (!rx_rsp_pkt_q.empty()) rx_rsp_pkt_q.pop();
    while (!rto_pkt_q.empty()) rto_pkt_q.pop();

    diagnostics() << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] PDC resources released" << std::endl;
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

    diagnostics() << getCurrentTimestamp() << formatLogMessage("Send SES NACK - PSN: ") << meta.psn << std::endl;

    
    sendNack(0, meta.psn, static_cast<PDS_Nack_Codes>(rsp->nack_payload.nack_code), 0, &rsp->pkt);

    
    rx_pkt_map.erase(rsp->rx_pkt_handle);
}
/**
 * @brief Handle control packet generation and transmission
 * @details Processes and sends various control message types
 */
void PDC::txCtrl(){
    // Consume a scheduled control action exactly once for both PDC roles.
    // Leaving it set makes a target emit the same CP forever at one timestamp.
    const auto requested_control=gen_cm;
    gen_cm=NONE;
    if(state != ESTABLISHED && state != CREATING && state != QUIESCE && state != ACK_WAIT) {
        diagnostics() << "PDC state does not allow processing control packet, current state: " << state << std::endl;
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
        switch (requested_control)
        {
        case NOOP:
            sendCtrlNoop(&p);
            break;
        case ACK_REQ:
            sendCtrlAckReq(&p);
            break;
        case CLR_CMD:
            sendCtrlClearCmd(&p);
            break;
        case CLR_REQ:
            sendCtrlClearReq(&p);
            break;
        case CLOSE_REQ:
            sendCtrlCloseReq(&p);
            break;
        case CREDIT:
            sendCtrlCredit(&p);
            break;
        case NEGOTIATION:
            sendCtrlNegotiation(&p);
            break;
        default:
            LOG_ERROR(__FUNCTION__, formatLogMessage("未知控制消息类型"));
        }
        if(p.PDS_header.RUOD_cp_header.ctl_type == Noop ||
           p.PDS_header.RUOD_cp_header.ctl_type == Close_cmd ||
           p.PDS_header.RUOD_cp_header.ctl_type == Close_req ||
           p.PDS_header.RUOD_cp_header.ctl_type == Negotiation){
            const auto sequence = p.PDS_header.RUOD_cp_header.psn;
            tx_pkt_buffer.insert(std::make_pair(sequence,p));
            TX_pkt_meta meta{};
            meta.rto = runtime_ ? runtime_->rto_ms : Base_RTO;
            if (runtime_) meta.last_transmit_time=runtime_->clock.now();
            tx_pkt_map.emplace(sequence,meta);
            if(rtoEnabled()){
                startPacketTimer(sequence, 0);
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
    req.source_fep = dst_fep;
    req.delivery_mode = mode;
    req.connection_start_psn = start_psn;

    if (public_ses_req_queue) {
        public_ses_req_queue->push(req);
    } else {
        rx_req_pkt_q.push(req);
    }
    LOG_DEBUG(__FUNCTION__, formatLogMessage("Request added to SES layer receive queue"));

    diagnostics() << getCurrentTimestamp() << formatLogMessage("Forward to SES - handle: ") << handle
                << ", PSN: " << meta.psn << std::endl;
}

/**
 * @brief Forward response to SES layer
 * @param pkt Response packet pointer
 */
void PDC::fwdRsp2SES(SEStoPDS_pkt *pkt,uint32_t original_sequence)
{
    LOG_DEBUG(__FUNCTION__, formatLogMessage("Forward response to SES layer"));
    PDC_SES_rsp rsp;
    rsp.original_sequence=original_sequence; rsp.connection_start_psn=start_psn;
    rsp.PDCID = SPDCID;                     
    rsp.rx_pkt_handle = pkt->bth_header.Semantic_Response_Header.job_id;
    rsp.pkt = *pkt;                         // 响应包内容
    rsp.pkt_len = sizeof(SEStoPDS_pkt);     // 获取结构体大小
    rsp.source_fep = dst_fep;
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
void PDC::chkRxError(PDStoNET_pkt* packet)
{
    const auto& header=packet->PDS_header.RUOD_req_header;
    const uint32_t sequence=header.psn;
    const uint32_t distance_from_clear=sequence-rx_clear_psn;
    const uint32_t distance_from_contiguous=sequence-rx_cur_psn;
    if ((header.type==RUD_REQ)!=(mode==RUD)) {
        error_chk=INV_SYN;
    } else if (header.flags.syn && sequence-header.psn_off!=start_psn) {
        error_chk=INV_SYN;
    } else if (!distance_from_clear || distance_from_clear>=0x80000000u) {
        error_chk=DROP;
    } else if (received_rx_psns_.count(sequence) || !distance_from_contiguous ||
               distance_from_contiguous>=0x80000000u) {
        error_chk=header.flags.retx?ACK_ERROR:DROP; // §3.5.8.2: unmarked network duplicates are discarded.
    } else if (mode==ROD && distance_from_contiguous>1) {
        error_chk=OOO;
    } else if (mode==RUD && distance_from_contiguous>MPR) {
        // Bounded receive state is the simulator's configured packet window.
        error_chk=DROP;
    } else error_chk=OPEN;
}

/**
 * @brief Process NOOP control message 
 * @param p Data packet to process // 需要处理的数据包
 */
bool PDC::acknowledgeNumberedControl(PDStoNET_pkt* packet)
{
    if (!packet) return false;
    const auto& header=packet->PDS_header.RUOD_cp_header;
    const bool carries_mode=header.ctl_type==Noop || header.ctl_type==Negotiation;
    if (carries_mode && bool(header.flags.isrod)!=(mode==ROD)) {
        sendNack(header.flags.retx,header.psn,UET_PDC_MODE_MISMATCH,0,nullptr); return false;
    }
    if (header.flags.syn && header.psn-header.psn_off!=start_psn) {
        sendNack(header.flags.retx,header.psn,UET_INVALID_SYN,0,nullptr); return false;
    }
    // Unique CP PSNs share the receive window with semantic requests. A NOOP
    // cannot leave a hole that would stall the following request's CACK.
    const auto distance=header.psn-rx_cur_psn;
    const auto since_clear=header.psn-rx_clear_psn;
    if (!since_clear || since_clear>=0x80000000u) return false;
    const bool duplicate=!distance || distance>=0x80000000u || received_rx_psns_.count(header.psn);
    if (duplicate) {
        if (header.flags.retx) sendAck(UET_HDR_NONE,0,0,header.psn,nullptr,false);
        return false;
    }
    if (mode==ROD && distance!=1) {
        sendNack(header.flags.retx,header.psn,UET_ROD_OOO,rx_cur_psn+1,nullptr); return false;
    }
    if (mode==RUD && distance>MPR) return false;
    received_rx_psns_.insert(header.psn); completed_rx_psns_.insert(header.psn);
    while (received_rx_psns_.count(rx_cur_psn+1)) ++rx_cur_psn;
    advanceCumulativeAck();
    sendAck(UET_HDR_NONE,0,0,header.psn,nullptr,false);
    return true;
}

void PDC::rxCtrlNoop(PDStoNET_pkt* packet)
{
    acknowledgeNumberedControl(packet);
}
/**
 * @brief Process ACK_req control message 
 * @param p Data packet to process // 需要处理的数据包
 */
void PDC::rxCtrlAckReq(PDStoNET_pkt* packet)
{
    if (!packet) return;
    const auto requested_sequence=packet->PDS_header.RUOD_cp_header.psn;
    // §3.5.16.2: a delayed request below Clear is silently discarded. Use
    // modular distance so this decision also works across the 32-bit wrap.
    if (requested_sequence-rx_clear_psn>=0x80000000u) return;
    if (replaySemanticAck(requested_sequence)) return;
    const bool processing=std::any_of(rx_pkt_map.begin(),rx_pkt_map.end(),
        [requested_sequence](const auto& request) { return request.second.psn==requested_sequence; });
    if (processing) {
        sendNack(0,requested_sequence,UET_RCVD_SES_PROCG,0,nullptr); return;
    }
    const auto since_cumulative=requested_sequence-cack_psn;
    if (received_rx_psns_.count(requested_sequence) || !since_cumulative || since_cumulative>=0x80000000u) {
        sendAck(UET_HDR_NONE,0,0,requested_sequence,nullptr,false); return;
    }
    sendNack(0,requested_sequence,UET_PKT_NOT_RCVD,rx_cur_psn+1,nullptr);
}
/**
 * @brief Process Clear_cmd control message 
 * @param p Data packet to process // 需要处理的数据包
 */
void PDC::rxCtrlClearCmd(PDStoNET_pkt* packet)
{
    if (!packet) return;
    const auto previous_cumulative_ack=cack_psn;
    clearReceivedPacketsThrough(packet->PDS_header.RUOD_cp_header.payload);
    // §3.5.11.4: publish a newly advanced CACK even when no SES traffic is
    // pending. In RUD, clearing one response can release later packets that
    // were processed out of order, including the end-of-message packet.
    if (cack_psn!=previous_cumulative_ack)
        sendAck(UET_HDR_NONE,0,0,cack_psn,nullptr,false);
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

    diagnostics() << getCurrentTimestamp() << formatLogMessage("rx_ctrl_clear_req - Request clear PSN: ") << req_clear_psn << std::endl;

    if (req_clear_psn > clear_psn) {
        LOG_WARN(__FUNCTION__, formatLogMessage("Requested clear PSN exceeds current clear_psn range"));
        diagnostics() << getCurrentTimestamp() << formatLogMessage("Request clear PSN ") << req_clear_psn
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
        diagnostics() << getCurrentTimestamp() << formatLogMessage("Clear send buffer, range: 0 到 ") << req_clear_psn << std::endl;
        LOG_INFO(__FUNCTION__, formatLogMessage("清除发送缓冲区中的过期包"));

        auto buf_it = tx_pkt_buffer.begin();
        while (buf_it != tx_pkt_buffer.end()) {
            if (buf_it->first <= req_clear_psn) {
                diagnostics() << getCurrentTimestamp() << formatLogMessage("清除发送包PSN: ") << buf_it->first << std::endl;
                if(rtoEnabled()) stopPacketTimer(buf_it->first);  // 停止计时器
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
            diagnostics() << getCurrentTimestamp() << formatLogMessage("Update clear_psn to: ") << clear_psn << std::endl;
            LOG_INFO(__FUNCTION__, formatLogMessage("Update clear_psn to: " + std::to_string(clear_psn)));
        }
    }

    diagnostics() << getCurrentTimestamp() << formatLogMessage("Generate Clear Command response") << std::endl;
    LOG_INFO(__FUNCTION__, formatLogMessage("生成Clear Command作为清除请求的响应"));

    gen_cm = CLR_CMD;

    std::stringstream completion_info;
    completion_info << "Clear Request processing complete - Clear PSN: " << req_clear_psn
                    << ", Current clear_psn: " << clear_psn
                    << ", Remaining send buffer size: " << tx_pkt_buffer.size()
                    << ", Remaining metadata size: " << tx_pkt_map.size();
    LOG_INFO(__FUNCTION__, formatLogMessage(completion_info.str()));

    diagnostics() << getCurrentTimestamp() << formatLogMessage("Clear Request processing complete, remaining send buffer: ")
                << tx_pkt_buffer.size() << ", 元数据: " << tx_pkt_map.size() << std::endl;
}
/**
 * @brief Send close request packet // Send close request包
 */
void PDC::sendCloseReq()
{
    // Use the common control builder and TX cache, never the semantic ACK
    // cache. §3.5.16.4 requires a fresh PSN, AR=1 and reliable retry.
    gen_cm=CLOSE_REQ;
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
    pkt.PDS_header.RUOD_ack_header.next_hdr = runtime_ && runtime_->standard_wire?UET_HDR_CP_ACK:UET_HDR_NONE;
    pkt.control_ack.cp_ack_type=Close_cmd;
    pkt.PDS_header.RUOD_ack_header.cack_psn = rx_cur_psn;
    pkt.PDS_header.RUOD_ack_header.ack_psn_off = 0;
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
    p->PDS_header.RUOD_cp_header.flags.isrod = mode==ROD;
    p->PDS_header.RUOD_cp_header.flags.syn = SYN;        
    p->PDS_header.RUOD_cp_header.payload = 0;            
    if(!SYN)p->PDS_header.RUOD_cp_header.dpdcid = DPDCID;
    else{
        p->PDS_header.RUOD_cp_header.pdc_info = 0;      
        p->PDS_header.RUOD_cp_header.psn_off = p->PDS_header.RUOD_cp_header.psn - start_psn;
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
    const auto original = tx_pkt_buffer.find(clear_psn + 1);
    p->PDS_header.RUOD_cp_header.payload = original == tx_pkt_buffer.end() ? 0 :
        static_cast<uint32_t>(original->second.SESpkt.bth_header.Standard_Header.msg_id) << 16;
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
    p->PDS_header.RUOD_cp_header.psn = setPsn();
    p->PDS_header.RUOD_cp_header.flags.isrod = 0; // Reserved in a CP.
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
void PDC::sendCtrlNegotiation(PDStoNET_pkt* packet)
{
    auto& header=packet->PDS_header.RUOD_cp_header;
    header.ctl_type=Negotiation; header.flags.ar=1; header.flags.syn=SYN;
    header.flags.isrod=mode==ROD; header.psn=setPsn(); header.spdcid=SPDCID;
    if (SYN) { header.pdc_info=0; header.psn_off=header.psn-start_psn; }
    else header.dpdcid=DPDCID;
    // NO_NEG: no optional feature is requested or enabled. The standard keeps
    // this payload at 32 zero bytes for compatibility (§3.5.16.7).
    header.payload=0; packet->control_extension.assign(28,0);
    updateTxPsnTracker();
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
void PDC::rxNack(PDStoNET_pkt* packet)
{
    if (!packet) return;
    const auto& negative_ack = packet->PDS_header.nack_header;
    // A late reply from an earlier incarnation of this local PDCID cannot
    // affect the current context, even when its peer tuple is otherwise equal.
    if (!tx_pkt_buffer.count(negative_ack.nack_psn)) return;
    if (runtime_ && runtime_->congestion_control) {
        auto& metadata=tx_pkt_map.at(negative_ack.nack_psn);
        if (metadata.congestion_inflight) {
            runtime_->congestion_control->negative_acknowledged(congestionConnection(),metadata.congestion_nominal_bytes,
                *packet,UET::CMS::NsccTransmitSample{metadata.last_transmit_time,metadata.retry_cnt});
            metadata.congestion_inflight=false;
        }
    }
    if (isClose(negative_ack.nack_code)) {
        close_error = true;
        failure_reason_=UET::Runtime::PdcFailureReason::FatalNegativeAcknowledgement;
        return;
    }
    if (!negative_ack.spdcid && runtime_) {
        pauseForResourceNack(negative_ack.nack_psn);
        return;
    }
    if (negative_ack.spdcid) resumeNackTraffic();

    if (negative_ack.nack_code == UET_ROD_OOO) {
        // §3.5.12.7: the payload is the receiver's next expected PSN.
        // Retransmitting only nack_psn would repeatedly send the packet that
        // arrived too early, leaving the actual gap to wait for its RTO.
        const uint32_t expected_psn = negative_ack.payload;
        const uint32_t outstanding_span = tx_cur_psn - clear_psn;
        const uint32_t expected_distance = expected_psn - clear_psn;
        if (!expected_distance || expected_distance >= outstanding_span ||
            !tx_pkt_buffer.count(expected_psn) || fast_retransmit_psn_ == expected_psn) return;
        fast_retransmit_psn_ = expected_psn;
        std::vector<uint32_t> recovery_sequences;
        for (const auto& outstanding : tx_pkt_buffer)
            if (outstanding.first - expected_psn < tx_cur_psn - expected_psn)
                recovery_sequences.push_back(outstanding.first);
        // Unsigned distance preserves transmit order across the 32-bit wrap.
        std::sort(recovery_sequences.begin(),recovery_sequences.end(),[expected_psn](uint32_t left,uint32_t right) {
            return left - expected_psn < right - expected_psn;
        });
        for (const auto sequence : recovery_sequences) txRto(sequence);
        return;
    }

    switch (negative_ack.nack_code) {
    case UET_TRIMMED: case UET_TRIMMED_LASTHOP: case UET_TRIMMED_ACK:
    case UET_NO_PKT_BUFFER: case UET_NO_GTD_DEL_AVAIL: case UET_NO_SES_MSG_AVAIL:
    case UET_PSN_OOR_WINDOW: case UET_PKT_NOT_RCVD: case UET_ACK_WITH_DATA:
    case UET_RCVR_INFER_LOSS:
        txRto(negative_ack.nack_psn);
        break;
    default:
        // Resource/SES-processing notifications retain the existing RTO.
        // Immediate resend here can make two zero-time endpoints livelock.
        break;
    }
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
    p.PDS_header.RUOD_req_header.type = mode==RUD?RUD_REQ:ROD_REQ;
    p.PDS_header.RUOD_req_header.next_hdr = next_hdr;
    p.PDS_header.RUOD_req_header.flags.syn = syn;
    p.PDS_header.RUOD_req_header.flags.retx = retx;
    p.PDS_header.RUOD_req_header.flags.ar = ar;
    p.PDS_header.RUOD_req_header.clear_psn_off = static_cast<int16_t>(clear_psn-psn);
    p.PDS_header.RUOD_req_header.psn = psn;
    p.PDS_header.RUOD_req_header.spdcid = SPDCID;
    if(syn == 0)p.PDS_header.RUOD_req_header.dpdcid = DPDCID;
    else {
        
        p.PDS_header.RUOD_req_header.pdc_info = 0;      
        p.PDS_header.RUOD_req_header.psn_off = psn - start_psn;
    }
    p.SESpkt = *pkt;
    if (runtime_ && runtime_->congestion_control) {
        congestion_engaged_=true;
        auto& metadata=tx_pkt_map[psn];
        metadata.congestion_nominal_bytes=runtime_->congestion_control->transmitted(congestionConnection(),p);
        metadata.congestion_inflight=true;
        metadata.last_transmit_time=runtime_->clock.now();
    }
    if (pkt->bth_type==Standard_Header)
        emitPdcEvent(UET::Runtime::PdcEventKind::RequestTransmitted,psn,
            pkt->bth_header.Standard_Header.job_id,pkt->bth_header.Standard_Header.msg_id,
            pkt->bth_header.Standard_Header.eom);
    tx_pkt_buffer.insert(std::make_pair(psn,p)); 

    TX_pkt_meta meta;
    meta.rto = Base_RTO;
    meta.tx_pkt_handle = 0;
    meta.retry_cnt = 0;
    tx_pkt_map.insert(std::make_pair(psn, meta));

    if(rtoEnabled()){
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
    p.PDS_header.RUOD_ack_header.flags.req = gtd_del ? (req | 1u) : req;
    p.PDS_header.RUOD_ack_header.ack_psn_off = psn - cack_psn;
    p.PDS_header.RUOD_ack_header.cack_psn = cack_psn;
    p.PDS_header.RUOD_ack_header.spdcid = SPDCID;
    p.PDS_header.RUOD_ack_header.dpdcid = DPDCID;

    if (pkt != nullptr)
    {
        p.SESpkt = *pkt;
        LOG_DEBUG(__FUNCTION__, formatLogMessage("包含SES层数据"));
    }
    if (runtime_ && runtime_->congestion_control)
        runtime_->congestion_control->decorate_ack(congestionConnection(),psn,p);

    
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

    diagnostics() << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] tx_ack包发送,psn : " << psn << "cack_psn :" << cack_psn << std::endl;

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

    diagnostics() << getCurrentTimestamp() << "I_PDC发送NACK包 - PSN: " << nack_psn
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

    diagnostics() << getCurrentTimestamp() << "I_PDC NACK包已发送 - PSN: " << p.PDS_header.nack_header.nack_psn
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

    if (tx_cur_psn==start_psn) mode=req->delivery_mode;
    uint32_t psn = setPsn();

    
    std::stringstream req_info;
    req_info << "发送请求包 - tx_pkt_handle: " << req->tx_pkt_handle
                << ", next_hdr: " << req->next_hdr
                << ", som: " << (req->som ? "true" : "false")
                << ", eom: " << (req->eom ? "true" : "false")
                << ", psn: " << psn
                << ", SYN: " << (SYN ? "true" : "false");
    LOG_INFO(__FUNCTION__, req_info.str());

    diagnostics() << getCurrentTimestamp() << "I_PDC发送请求包 - PSN: " << psn
                << ", handle: " << req->tx_pkt_handle << std::endl;

    updateTxPsnTracker();

    TX_pkt_meta meta;
    meta.retry_cnt = 0;                         
    meta.tx_pkt_handle = req->tx_pkt_handle;
    meta.rto = Base_RTO;                        
    if (runtime_) meta.last_transmit_time=runtime_->clock.now();
    tx_pkt_map.insert(std::make_pair(psn, meta));
    
    LOG_DEBUG(__FUNCTION__, "包元数据已保存");

    
    if(req->som) {
        open_msg += 1;
        LOG_DEBUG(__FUNCTION__, "消息开始标记，open_msg增加");
        diagnostics() << getCurrentTimestamp() << "I_PDC消息开始，open_msg: " << open_msg << std::endl;
    }
    if(req->eom) {
        open_msg -= 1;
        LOG_DEBUG(__FUNCTION__, "消息结束标记，open_msg减少");
        diagnostics() << getCurrentTimestamp() << "I_PDC消息结束，open_msg: " << open_msg << std::endl;
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
    bool canClose = (unack_cnt == 0) && allACK && (open_msg == 0) && tx_req_q.empty() && tx_rsp_q.empty();
    
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
    if (!rto_timer_.startTimer(psn, runtime_ ? runtime_->rto_ms : Base_RTO, retry_count)) {
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
