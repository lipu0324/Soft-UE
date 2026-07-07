#include "TPDC.hpp"

void T_PDC::openChk()
{
    maybeTriggerRudControl();

    if (state != CLOSED)
    {
        if (gen_cm != NONE && !consumeSkipCtrlEmitOnce())
        {
            std::cout << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] gen_cm:" << CM_TYPE_STR(gen_cm) << std::endl;
            LOG_INFO(__FUNCTION__, formatLogMessage("Process control message generation"));
            txCtrl();
        }
        else if (close_error)
        {
            std::cout << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] close_error" << std::endl;
            LOG_WARN(__FUNCTION__, formatLogMessage("Close error detected, request close"));
            reqClose();
        }
        else if (closing && unack_cnt == 0 && (allACK || state == ACK_WAIT))
        {
            std::cout << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] closing && unack_cnt == 0 && allACK" << std::endl;
            LOG_INFO(__FUNCTION__, formatLogMessage("Close conditions met, execute close"));
            close();
        }
        else
        {
            PDStoNET_pkt rx_pkt;
            bool have_rx = false;
            size_t rx_pkt_q_size = 0;
            {
                std::lock_guard<std::mutex> lock(queue_mutex_);
                if (!rx_pkt_q.empty()) {
                    rx_pkt_q_size = rx_pkt_q.size();
                    rx_pkt = rx_pkt_q.front();
                    rx_pkt_q.pop();
                    have_rx = true;
                }
            }
            if (have_rx)
            {
                LOG_DEBUG(__FUNCTION__, formatLogMessage("Process data packets in receive queue"));
                std::cout << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] rx_pkt_q size:" << rx_pkt_q_size << std::endl;
                if (rx_pkt.PDS_type == nack_header)
                {
                    LOG_DEBUG(__FUNCTION__, formatLogMessage("Process negative acknowledgment packet"));
                    netRxNack(&rx_pkt);
                }
                else if (rx_pkt.PDS_type == RUOD_req_header)
                {
                    LOG_DEBUG(__FUNCTION__, formatLogMessage("Process request packet"));
                    netRxReq(&rx_pkt);
                }
                else if (rx_pkt.PDS_type == RUOD_ack_header)
                {
                    LOG_DEBUG(__FUNCTION__, formatLogMessage("Process acknowledgment packet"));
                    netRxAck(&rx_pkt);
                }
                else if (rx_pkt.PDS_type == RUOD_cp_header)
                {
                    LOG_DEBUG(__FUNCTION__, formatLogMessage("Process control packet"));
                    netRxCm(&rx_pkt);
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
                LOG_DEBUG(__FUNCTION__, formatLogMessage("Process timeout retransmission packet,psn:"+std::to_string(psn)));
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
            if (have_rsp)
            {
                std::cout << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] tx_rsp_q size:" << tx_rsp_q_size << std::endl;
                LOG_DEBUG(__FUNCTION__, formatLogMessage("Process SES layer response transmission"));
                sesTxRsp(&rsp);
                return;
            }

            if (state == ESTABLISHED && pause_pdc == false)
            {
                PDS_PDC_req req;
                bool have_req = false;
                {
                    std::lock_guard<std::mutex> lock(queue_mutex_);
                    if (!tx_req_q.empty() && canDispatchFrontReq(tx_req_q.front(), nowMs())) {
                        req = tx_req_q.front();
                        tx_req_q.pop();
                        have_req = true;
                    }
                }
                if (have_req)
                {
                    LOG_DEBUG(__FUNCTION__, formatLogMessage("Process PDS layer request transmission"));
                    sesTxReq(&req);
                }
                return;
            }

            if (closing || state == ACK_WAIT) {
                LOG_DEBUG(__FUNCTION__, formatLogMessage("Waiting for close completion"));
                return;
            }

            std::cout << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] error" << std::endl;
        }
    }
    else
    {
        LOG_DEBUG(__FUNCTION__, formatLogMessage("Connection closed state, only process receive packets"));
        PDStoNET_pkt rx_pkt;
        bool have_rx = false;
        size_t rx_pkt_q_size = 0;
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            if (!rx_pkt_q.empty()) {
                rx_pkt_q_size = rx_pkt_q.size();
                rx_pkt = rx_pkt_q.front();
                rx_pkt_q.pop();
                have_rx = true;
            }
        }
        if (have_rx) {
            std::cout << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] Connection closed state, only process receive packets" << rx_pkt_q_size
                      << std::endl;
            if (rx_pkt.PDS_type == RUOD_req_header)
            {
                LOG_DEBUG(__FUNCTION__, formatLogMessage("Process request packet in closed state"));
                netRxReq(&rx_pkt);
            }
        }
    }
}

void T_PDC::reqClose()
{
    std::cout << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] req close" << std::endl;
    sendCloseReq();
}

void T_PDC::beginClose()
{
    std::cout << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] begin close" << std::endl;
    closing = true;
    state = ACK_WAIT;
    gen_cm = NONE;
    ctrl_tx_deferred_ = false;
}

void T_PDC::close()
{
    std::cout << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] close" << std::endl;
    sendCloseAck();
    saveExpectedPSN();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    freePDC();
    state = CLOSED;

    if (public_close_queue) {
        public_close_queue->push(SPDCID);
        LOG_INFO(__FUNCTION__, formatLogMessage("[PDCID:" + std::to_string(SPDCID) + "] T_PDC closure complete, PDCID added to close queue"));
    }
    else{
        LOG_ERROR(__FUNCTION__, formatLogMessage("[PDCID:" + std::to_string(SPDCID) + "] Close queue not initialized"));
    }
}

void T_PDC::processClose()
{
    if (state == CLOSED) {
        freePDC();
    }
    closing = false;
    req_closing = false;
    std::cout << getCurrentTimestamp() << "[PDCID:" << SPDCID << "] process close" << std::endl;
}
