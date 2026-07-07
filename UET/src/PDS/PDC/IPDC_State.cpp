#include "IPDC.hpp"

void I_PDC::openChk(){
    maybeTriggerRudControl();

    if(gen_cm != NONE && !consumeSkipCtrlEmitOnce()) {
        std::cout << getCurrentTimestamp() << "I_PDC tx_control processing - gen_cm: " << CM_TYPE_STR(gen_cm) << std::endl;
        LOG_INFO(__FUNCTION__, "Process control message generation");
        txCtrl();
        LOG_DEBUG(__FUNCTION__, "Control message processing complete");
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
    else {
        PDStoNET_pkt rx_pkt;
        bool have_rx = false;
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            if (!rx_pkt_q.empty()) {
                rx_pkt = rx_pkt_q.front();
                rx_pkt_q.pop();
                have_rx = true;
            }
        }
        if (have_rx) {
            std::cout << getCurrentTimestamp() << "I_PDC process receive queue packet - Type: " << rx_pkt.PDS_type << std::endl;

            if(rx_pkt.PDS_type == RUOD_req_header) {
                LOG_DEBUG(__FUNCTION__, "Process request packet");
                rxReq(&rx_pkt);
            }
            else if(rx_pkt.PDS_type == RUOD_ack_header) {
                LOG_DEBUG(__FUNCTION__, "Process acknowledgment packet");
                rxAck(&rx_pkt);
            }
            else if(rx_pkt.PDS_type == RUOD_cp_header) {
                LOG_DEBUG(__FUNCTION__, "Process control packet");
                rxCtrl(&rx_pkt);
            }
            else if(rx_pkt.PDS_type == nack_header) {
                LOG_DEBUG(__FUNCTION__, "Process negative acknowledgment packet");
                rxNack(&rx_pkt);
            }
            return;
        }

        uint32_t psn = 0;
        bool have_rto = false;
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            if (!rto_pkt_q.empty()) {
                psn = rto_pkt_q.front();
                rto_pkt_q.pop();
                have_rto = true;
            }
        }
        if (have_rto) {
            LOG_DEBUG(__FUNCTION__, "Process timeout retransmission packet,psn:"+std::to_string(psn));
            txRto(psn);
            return;
        }

        SES_PDC_rsp rsp;
        bool have_rsp = false;
        size_t tx_rsp_q_size = 0;
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            if (!tx_rsp_q.empty()) {
                rsp = tx_rsp_q.front();
                tx_rsp_q.pop();
                have_rsp = true;
                tx_rsp_q_size = tx_rsp_q.size();
            }
        }
        if (have_rsp) {
            std::cout << getCurrentTimestamp() << "I_PDC process SES layer response transmission - tx_rsp_q size: " << tx_rsp_q_size << std::endl;
            LOG_DEBUG(__FUNCTION__, "Process SES layer response transmission");
            sesTxRsp(&rsp);
            return;
        }

        PDS_PDC_req req;
        bool have_req = false;
        size_t tx_req_q_size = 0;
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            if (!tx_req_q.empty() && canDispatchFrontReq(tx_req_q.front(), nowMs())) {
                req = tx_req_q.front();
                tx_req_q.pop();
                have_req = true;
                tx_req_q_size = tx_req_q.size();
            }
        }
        if (have_req) {
            std::cout << getCurrentTimestamp() << "I_PDC process SES layer request transmission - tx_req_q size: " << tx_req_q_size << std::endl;
            LOG_DEBUG(__FUNCTION__, "Process SES layer request transmission");
            sesTxReq(&req);
            return;
        }
    }
}

void I_PDC::closeReq(){
    LOG_INFO(__FUNCTION__, "Close request received, setting close flag");
    std::cout << getCurrentTimestamp() << "I_PDC close request received, state switched to QUIESCE" << std::endl;

    close_req = true;
    state = QUIESCE;

    std::stringstream state_info;
    state_info << "State change - close_req: " << (close_req ? "true" : "false")
                << ", state: " << STATE_STR(state);
    LOG_INFO(__FUNCTION__, state_info.str());
}

void I_PDC::beginClose(){
    LOG_INFO(__FUNCTION__, "Start PDC closure process");
    std::cout << getCurrentTimestamp() << "I_PDC start close process" << std::endl;

    closing = true;
    state = ACK_WAIT;
    gen_cm = NONE;
    ctrl_tx_deferred_ = false;

    std::stringstream state_info;
    state_info << "Close process state change - closing: " << (closing ? "true" : "false")
                << ", state: " << STATE_STR(state);
    LOG_INFO(__FUNCTION__, state_info.str());
    close_error = false;
    close_req = false;
    std::stringstream pdc_info;
    pdc_info << "PDC close process - closing: " << (closing ? "true" : "false")
                << ", state: " << STATE_STR(state)
                << ", close_error: " << (close_error ? "true" : "false")
                << ", close_req: " << (close_req ? "true" : "false") << ",unack_cnt: " << unack_cnt;
    LOG_INFO(__FUNCTION__, pdc_info.str());
}

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

void I_PDC::close(){
    freePDC();
    state = CLOSED;
    
    if (public_close_queue) {
        public_close_queue->push(SPDCID);
        LOG_INFO(__FUNCTION__, "I_PDC closure complete, PDCID " + std::to_string(SPDCID) + " added to close queue");
    }
}
    
void I_PDC::sendClose(){
    LOG_INFO(__FUNCTION__, "Construct and send close control packet");

    PDStoNET_pkt ctrl_pkt;
    ctrl_pkt.dst_fep = dst_fep;
    ctrl_pkt.src_fep = src_fep;
    ctrl_pkt.PDS_type = RUOD_cp_header;
    ctrl_pkt.SESpkt.bth_type = Standard_Header;
    ctrl_pkt.SESpkt.bth_header.Standard_Header.som = false;
    ctrl_pkt.SESpkt.bth_header.Standard_Header.eom = false;
    ctrl_pkt.PDS_header.RUOD_cp_header.type = CP;
    ctrl_pkt.PDS_header.RUOD_cp_header.ctl_type = Close_cmd;
    ctrl_pkt.PDS_header.RUOD_cp_header.psn = setPsn();
    ctrl_pkt.PDS_header.RUOD_cp_header.spdcid = SPDCID;
    ctrl_pkt.PDS_header.RUOD_cp_header.dpdcid = DPDCID;
    ctrl_pkt.PDS_header.RUOD_cp_header.flags.syn = 0;
    ctrl_pkt.PDS_header.RUOD_cp_header.flags.ar = 1;
    ctrl_pkt.PDS_header.RUOD_cp_header.flags.retx = 0;
    ctrl_pkt.PDS_header.RUOD_cp_header.flags.isrod = 0;
    ctrl_pkt.PDS_header.RUOD_cp_header.payload = 0;

    std::stringstream close_info;
    close_info << "Construct close packet - PSN: " << ctrl_pkt.PDS_header.RUOD_cp_header.psn
                << ", SPDCID: " << SPDCID
                << ", DPDCID: " << DPDCID
                << ", ctl_type: Close_cmd";
    LOG_INFO(__FUNCTION__, close_info.str());

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

    if (public_net_queue) {
        public_net_queue->push(ctrl_pkt);
    } else {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        tx_pkt_q.push(ctrl_pkt);
    }
    LOG_INFO(__FUNCTION__, "Close packet added to send queue");

    close_psn = ctrl_pkt.PDS_header.RUOD_cp_header.psn;

    std::stringstream final_info;
    final_info << "Close packet send complete - close_psn: " << close_psn;
    LOG_INFO(__FUNCTION__, final_info.str());

    std::cout << getCurrentTimestamp() << "I_PDC send close packet - PSN: " << ctrl_pkt.PDS_header.RUOD_cp_header.psn << std::endl;
}
