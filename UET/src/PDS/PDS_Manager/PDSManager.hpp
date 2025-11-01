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
 * @file             PDSManager.hpp
 * @brief            PDSManager.hpp
 * @author           softuegroup@gmail.com
 * @version          1.0.0
 * @date             2025-10-29
 * @copyright        Apache License Version 2.0
 *
 * @details
 * PDSManager.hpp
 */
#ifndef PDSMANAGER_HPP
#define PDSMANAGER_HPP

#include "../../Transport_Layer.hpp"
#include "../../logger/Logger.hpp"
#include "../PDC/process/TPDCProcessManager.hpp"
#include "../PDC/process/IPDCProcessManager.hpp"
#include "../PDC/process/ThreadSafeQueue.hpp"

class PDS_Manager
{
    
private:

public:
    TPDCProcessManager TPDC_Processmanager;
    IPDCProcessManager IPDC_Processmanager;
    pdc pdc_list[MAX_PDC * 2];             // PDC list
    std::queue<SES_PDS_req> SES_tx_req_q;  // SES layer send request queue
    std::queue<SES_PDS_rsp> SES_tx_rsp_q;  // SES layer send response queue
    std::queue<PDStoNET_pkt> Net_rx_pkt_q; // Network layer receive request queue

    std::queue<SES_PDS_eager> SES_eager_req_q; // Eager request queue
    std::queue<PDS_SES_error> PDS_error_q;     // Error event queue

    // Public queues for inter-module communication integration
    ThreadSafeQueue<PDStoNET_pkt> PDStoNet;    // Queue for all PDC to NET layer packets
    ThreadSafeQueue<PDC_SES_req> PDCtoSES_req; // Queue for all PDC to SES layer request events
    ThreadSafeQueue<PDC_SES_rsp> PDCtoSES_rsp; // Queue for all PDC to SES layer response events
    ThreadSafeQueue<uint16_t> PDC_close_q;     // Close request queue, PDC will add its ID to queue after closing
    int open_cnt = 0;                          // Current number of open PDCs
    int pend_cnt = 0;                          // Number of pending tasks
    int closing_cnt = 0;                       // Number of PDCs currently closing
    bool pause_ses;                            // SES layer pause flag
    int event_cnt = 0;                         // Event counter
    // PDC queue depth tracking
    int8_t pdc_qdepth[NUM_BANKS][PDCs_PER_BANK] = {0}; // Queue depth counter for each PDC
    uint8_t BitMap[MAX_PDC] = {0};           // PDC bitmap, each variable represents the number of tasks stored in that PDC
    std::map<uint16_t, uint16_t> msg_map;                     // msgid mapping table
    std::queue<pend_node> pend_q;                             // Pending task queue
    bool initPDSM()
    {
        LOG_INFO(__FUNCTION__, "=====================PDS Manager State Machine Initialization=====================");
        LOG_INFO(__FUNCTION__, "Creating PDC process managers");

        if (!TPDC_Processmanager.start() || !IPDC_Processmanager.start())
            LOG_ERROR(__FUNCTION__, "PDC process manager initialization failed");
        else
            LOG_INFO(__FUNCTION__, "PDC process manager initialization successful");

        // Initialize public queues
        PDStoNet.set_max_size(1024); // Set maximum capacity, can be adjusted as needed
        PDCtoSES_req.set_max_size(512);
        PDCtoSES_rsp.set_max_size(512);
        LOG_INFO(__FUNCTION__, "Public queue initialization completed");

        // Pass public queue references to process managers
        TPDC_Processmanager.setPublicQueues(&PDStoNet, &PDCtoSES_req, &PDCtoSES_rsp, &PDC_close_q);
        IPDC_Processmanager.setPublicQueues(&PDStoNet, &PDCtoSES_req, &PDCtoSES_rsp, &PDC_close_q);
        LOG_INFO(__FUNCTION__, "Public queue references passed to process managers");
        // Wait 50ms
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        open_cnt = 0;
        pend_cnt = 0;
        closing_cnt = 0;
        event_cnt = 0;     // Event counter initialization
        pause_ses = false; // Initialize pause state to false

        LOG_INFO(__FUNCTION__, "=====================PDS Manager State Machine Initialization Completed=====================");

        return true;
    }

    // IDLE, TX_READY, TX_PROCESSING, PDC and ERROR -> idle
    void mainChk()
    {
        if (!SES_eager_req_q.empty())
        {
            // State machine not written, leave it for now
        }
        else if (!SES_tx_rsp_q.empty())
        {
            LOG_INFO(__FUNCTION__, "Processing SES load response");
            sesTxRsp();
        }
        else if (!Net_rx_pkt_q.empty())
        {
            LOG_INFO(__FUNCTION__, "Processing network layer packet reception");
            rxPkt();
        }
        else if (!SES_tx_req_q.empty())
        {
            LOG_INFO(__FUNCTION__, "Processing SES load request");
            SESTxReq();
        }
        else if (!PDC_close_q.empty())
        {
            LOG_INFO(__FUNCTION__, "Processing PDC close request");
            PDCClose();
        } /* I feel this part is not needed
         else if(!PDS_error_q.empty()){
             LOG_INFO(__FUNCTION__,"PDS error event processing");
             pdsError();
         }*/
    }

    void sesTxRsp()
    {
        LOG_INFO("ses_tx_rsp", "=====================Processing SES TX Response=====================");
        SES_PDS_rsp tx = SES_tx_rsp_q.front(); // Get queue head element
        SES_tx_rsp_q.pop();                      // Pop queue head element
        uint16_t pdc_id = tx.PDCID;
        // Process send response logic
        if (assignPDC(tx.rsp.bth_header.Standard_Header.msg_id, pdc_id))
        {
            // For tx_rsp messages, PDC is already opened so can be used directly
            LOG_INFO("ses_tx_rsp", "Allocated PDC for TX_RSP, ID: " + std::to_string(pdc_id));
            fwdPkt2PDC(&tx, pdc_id); // Send request to PDC
        }
        else
        {
            // Report error directly, drop packet
            LOG_ERROR("ses_tx_rsp", "Cannot allocate PDC, dropping packet");
            // dropPkt(); // Placeholder
            event_cnt++;
            PDS_SES_error err_event = {PDS_SES_Error_Unknown, tx.rx_pkt_handle}; // Create error event
            PDS_error_q.push(err_event);                                          // Add to error event queue
            // free(tx);                                                             // Release resources
            LOG_WARN("ses_tx_rsp", "Created error event, type: " + std::to_string(err_event.pds_error) + ", event count: " + std::to_string(event_cnt));
        }
    }

    void rxPkt()
    {
        LOG_INFO("rx_pkt", "=====================Processing Network Layer Packet=====================");
        bool is_fwd_pkt = false; // Default: cannot forward
        uint16_t pdc_id = 0;
        // Process receive request logic
        PDStoNET_pkt *rx = &Net_rx_pkt_q.front(); // Get queue head element
        Net_rx_pkt_q.pop();                       // Pop queue head element

        if (checkRxPkt(rx))
        {
            LOG_INFO("rx_pkt", "RX packet valid, starting processing...");
            if (rx->PDS_type == RUOD_req_header || rx->PDS_type == RUOD_cp_header)
            { // If request
                if (rx->PDS_type == RUOD_req_header)
                    pdc_id = rx->PDS_header.RUOD_req_header.dpdcid;
                else if (rx->PDS_type == RUOD_cp_header)
                    pdc_id = rx->PDS_header.RUOD_cp_header.dpdcid;

                if ((rx->PDS_type == RUOD_req_header && rx->PDS_header.RUOD_req_header.flags.syn == 0) ||
                    (rx->PDS_type == RUOD_cp_header && rx->PDS_header.RUOD_cp_header.flags.syn == 0))
                {
                    LOG_INFO("rx_pkt", "RX packet type: RUOD request, PDCID: " + std::to_string(pdc_id));
                }
                else
                    LOG_INFO("rx_pkt", "RX packet type: RUOD establishment request ");

                if (rx->PDS_header.RUOD_req_header.flags.syn == 0 && pdc_list[pdc_id].is_open)
                { // If PDC is already open
                    LOG_INFO("rx_pkt", "RX packet target PDC is open");
                    is_fwd_pkt = true; // If packet is valid, can forward
                }
                else // if(rx->PDS_header.RUOD_req_header.flags.syn == 1)
                {    // PDC not open
                    LOG_INFO("rx_pkt", "RX packet target PDC is not open");
                    if (rx->PDS_header.RUOD_req_header.flags.syn == 1)
                    { // Connection initiation packet
                        if (isOOR())
                        {
                            is_fwd_pkt = false; // PDC full, cannot establish new PDC
                            LOG_WARN("rx_pkt", "PDC full, cannot establish new connection, dropping");
                        }
                        else
                        {
                            uint16_t new_pdcid = muxRx2PDCID(rx->src_fep, rx->dst_fep, rx->PDS_header.RUOD_req_header.spdcid);
                            allocPDC(new_pdcid, rx->src_fep, rx->dst_fep); // Allocate PDC
                            pdc_id = new_pdcid;
                            LOG_INFO("rx_pkt", "Allocate PDC, ID: " + std::to_string(pdc_id));
                            is_fwd_pkt = true;
                        }
                    }
                    else
                    {
                        LOG_INFO("rx_pkt", "Non-connection initiation packet, illegal, dropping");
                    }
                }
            }
            else if (rx->PDS_type == RUOD_ack_header)
            { // ACK NACK
                if (pdc_list[rx->PDS_header.RUOD_ack_header.dpdcid].is_open)
                { // If PDC is already open
                    LOG_INFO("rx_pkt", "RX packet type: RUOD request, PDCID: " + std::to_string(rx->PDS_header.RUOD_ack_header.dpdcid));
                    pdc_id = rx->PDS_header.RUOD_ack_header.dpdcid;
                    is_fwd_pkt = true; // If packet is valid, can forward
                }
            }
        }
        else
        {
            is_fwd_pkt = false; // If packet is invalid, cannot forward
            LOG_ERROR("rx_pkt", "RX packet invalid");
        }

        if (is_fwd_pkt)
        {
            LOG_INFO("rx_pkt", "RX packet type: RUOD request, PDCID: " + std::to_string(pdc_id));
            fwdPkt2PDC(rx, pdc_id); // Send request to PDC
        }
        else
        {
            // Invalid packet enters UNEXPECTED RX OOR
            LOG_WARN("rx_pkt", "Unexpected RX packet, entering RX OOR processing");
            unexpectedOrRxOOR(rx); // Enter RX OOR queue
        }
    }

    /**
     * @brief Check if received packet is valid
     * @param rx Pointer to received PDStoNET_pkt structure, containing received packet information
     * @return true if packet is valid, false otherwise
     */
    bool checkRxPkt(PDStoNET_pkt *rx)
    {
        // Check if received packet is valid, don't know how to handle, assume valid for now
        if (rx != nullptr)
        {
            return true; // Valid packet
        }
        else
        {
            return false; // Invalid packet
        }
    }

    /**
     * @brief Check if NACK transmission is needed
     * @param rx Pointer to received PDStoNET_pkt structure, containing received packet information
     * @return true if NACK transmission needed, false otherwise
     */
    PDS_Nack_Codes checkUnexpectEvent(PDStoNET_pkt *rx)
    {
        if (rx != nullptr)
            return UET_TRIMMED; // This will return different NACK types based on packet content, temporarily return an example value
        else
            return reserved;
    }

    /**
     * @brief Handle unexpected RX packets or RX OOR state
     * @param rx Pointer to received PDStoNET_pkt structure, containing received packet information
     */
    void unexpectedOrRxOOR(PDStoNET_pkt *rx)
    {
        // Enter RX OOR queue
        LOG_INFO("unexpected_or_rx_oor", "=====================Entering RX OOR Queue=====================");
        // Error handling logic can be implemented here based on actual requirements
        // Such as logging, sending error responses, etc.
        if (isOOR())
        {
            sendNack(rx, UET_NO_PDC_AVAIL); // Insufficient resources
            LOG_WARN("unexpected_or_rx_oor", "Currently in OOR state, sending resource insufficient NACK");
        }
        bool enable_nack = rx->PDS_type == RUOD_req_header; // Determine whether to transmit NACK.
        if (enable_nack)
        {
            // Directly output NACK packet downward, no need to go through PDC
            LOG_WARN("unexpected_or_rx_oor", "Unexpected RX packet, sending NACK");
            sendNack(rx, checkUnexpectEvent(rx)); // Send NACK packet
        }
        // Processing completed
        event_cnt++; // Event counter increment by 1
        // drop_packet
        // free(rx); // Release memory
        LOG_INFO("unexpected_or_rx_oor", "Error event processing completed: RX OOR, event count: " + std::to_string(event_cnt));
        // Enter resource check
        resourceCheck();
    }

    /**
     * @brief Send NACK packet
     * @param rx Pointer to received PDStoNET_pkt structure, containing received packet information
     * @param nack_type NACK type to send
     */
    void sendNack(PDStoNET_pkt *rx, PDS_Nack_Codes nack_type)
    {
        // Send NACK packet
        PDStoNET_pkt nack_pkt;
        nack_pkt.src_fep = rx->dst_fep;
        nack_pkt.dst_fep = rx->src_fep;
        nack_pkt.PDS_type = PDS_header_type::nack_header;
        nack_pkt.SESpkt = {}; // NACK packet does not carry SES data
        nack_pkt.PDS_header.nack_header.type = PDS_type::NACK;
        nack_pkt.PDS_header.nack_header.next_hdr = PDS_next_hdr::UET_HDR_NONE;
        nack_pkt.PDS_header.nack_header.flags.m = 0;
        nack_pkt.PDS_header.nack_header.flags.retx = 0;
        nack_pkt.PDS_header.nack_header.flags.nt = 0;
        nack_pkt.PDS_header.nack_header.nack_code = nack_type;
        nack_pkt.PDS_header.nack_header.vendor_code = 0; // Unknown purpose
        nack_pkt.PDS_header.nack_header.nack_psn = rx->PDS_header.RUOD_req_header.psn;
        // TODO: If PDC establishment error, set spdcid to 0 here
        nack_pkt.PDS_header.nack_header.spdcid = rx->PDS_header.RUOD_req_header.dpdcid;
        nack_pkt.PDS_header.nack_header.dpdcid = rx->PDS_header.RUOD_req_header.spdcid;
        nack_pkt.PDS_header.nack_header.payload = 0;
        // Temporarily put in send queue like this?
        PDStoNet.push(nack_pkt);
        LOG_INFO("send_nack", "Sending NACK packet, NACK type: " + std::to_string(nack_type));
    }

    /**
     * @brief Process SES to PDS request
     * @param tx Pointer to SES to PDS request processing structure, containing request information to forward
     */
    void SESTxReq()
    {
        LOG_INFO("ses_tx_req", "=====================Processing SES TX Request=====================");
        // Process send request logic
        // Get request from queue
        SES_PDS_req tx = SES_tx_req_q.front(); // Get queue
        SES_tx_req_q.pop();                      // Pop queue head element
        // Select PDC based on tx to execute task, first check if PDC is available or can be allocated
        // Try to allocate PDC based on tx
        uint16_t pdc_id;
        if (assignPDC(tx.pkt.bth_header.Standard_Header.job_id, tx.dst_fep, tx.tc, tx.mode, tx.pkt.bth_header.Standard_Header.msg_id, &pdc_id))
        { // Allocate PDC
            if (!PDCOpen(pdc_id) && !isOOR())
            {
                // If PDC is not open and not in OOR state
                // Try to allocate PDC
                if (allocPDC(pdc_id, tx.dst_fep, tx.src_fep))
                {
                    LOG_INFO("ses_tx_req", "PDC allocation successful, ID: " + std::to_string(pdc_id) + ", current open count: " + std::to_string(open_cnt));
                }
                else
                {
                    LOG_ERROR("ses_tx_req", "Unexpected error: PDC allocation failed");
                }
            }
            if (isOOR())
            {
                // If in OOR state, enter wait queue
                txOORPendEnqueue(&tx);
            }
            else
            {
                // if (tx->pkt.bth_header.Standard_Header.som == 1)
                //     msgmap(tx->pkt.bth_header.Standard_Header.msg_id, pdc_id); // Associate each message ID with PDC of message start (som), unclear how to associate for now
                // LOG_INFO("ses_tx_req", "PDC is open and not in OOR state, adding to PDC processing");
                fwdPkt2PDC(&tx, pdc_id); // Send request to PDC
            }
        }
        else
        {
            LOG_WARN("ses_tx_req", "PDC cannot be allocated, entering TX OOR & PEND queue");
            // If PDC is unavailable or cannot be allocated, enter wait queue
            txOORPendEnqueue(&tx);
        }
    }

    /**
     * @brief Associate message ID with PDC
     * @param msgid Message ID
     * @param pdc_id PDC ID
     */
    // void msgmap(uint16_t msgid, int pdc_id)
    // {
    //     // Associate message ID with PDC
    //     msg_map[pdc_id] = msgid;
    //     LOG_INFO("msgmap", "Message mapping - PDC ID: " + std::to_string(pdc_id) + " -> Message ID: " + std::to_string(msgid));
    // }

    /**
     * @brief Apply for PDC
     * @param pdc_id PDC ID to apply for
     * @return true if application successful, false otherwise
     */
    bool allocPDC(uint16_t pdc_id, uint32_t dst_fep, uint32_t src_fep)
    {
        // PDC application logic
        // Simple simulation here, actual logic needs implementation based on specific requirements
        if (!pdc_list[pdc_id].is_open)
        {
            if (pdc_id >= MAX_PDC)
            { // TPDC
                if (TPDC_Processmanager.createTPDCProcess(pdc_id, dst_fep, src_fep))
                {
                    pdc_list[pdc_id].is_open = true;
                    open_cnt++;
                }
                else
                {
                    LOG_ERROR("alloc_pdc", "Failed to create TPDC");
                    return false;
                }
            }
            else
            {
                if (IPDC_Processmanager.createIPDCProcess(pdc_id, dst_fep, src_fep))
                {
                    pdc_list[pdc_id].is_open = true;
                    open_cnt++;
                }
                else
                {
                    LOG_ERROR("alloc_pdc", "Failed to create IPDC");
                    return false;
                }
            }
            LOG_INFO("alloc_pdc", "PDC allocation successful, ID: " + std::to_string(pdc_id));
            return true; // Application successful
        }
        return false; // Application failed, PDC already open
    }

    /**
     * @brief Check if in OOR (Out Of Resources) state
     * @return true if in OOR state, false otherwise
     */
    bool isOOR()
    {
        // Check if there are available PDCs
        // Simple simulation here, actual logic needs implementation based on specific requirements
        return open_cnt >= MAX_PDC; // If number of open PDCs exceeds maximum, considered OOR state
    }

    /**
     * @brief Check if PDC is open
     * @param pdc_id PDC ID to check
     * @return true if PDC is open, false otherwise
     */
    bool PDCOpen(int pdc_id)
    {
        // Check if PDC is open, i.e., already in use
        // Simple simulation here, actual logic needs implementation based on specific requirements
        if (pdc_id < 0 || pdc_id >= MAX_PDC)
        {
            LOG_ERROR("pdc_open", "PDC ID " + std::to_string(pdc_id) + " out of range");
            return false; // PDC not available
        }
        if (!pdc_list[pdc_id].is_open)
        {
            LOG_ERROR("pdc_open", "PDC ID " + std::to_string(pdc_id) + " not open");
            return false; // PDC not open
        }
        return true; // PDC open
    }

    /**
     * @brief Add TX request to OOR & PEND wait queue
     * @param tx Pointer to SES to PDS request processing structure, containing request information to add to wait queue
     */
    void txOORPendEnqueue(SES_PDS_req *tx)
    {
        // Enter wait queue
        LOG_INFO("tx_oor_pend_enqueue", "=====================TX OOR & PEND Request Enqueue=====================");
        // Calculate maximum wait end_time
        pend_node node = createPendNode(*tx); // Create pend_node
        pend_q.push(node);
        pend_cnt++; // Pending counter increment by 1
        if (pendQFull())
        {
            pause_ses = true; // If pending queue is full, pause SES, haven't figured out how to notify SES yet
            LOG_WARN("tx_oor_pend_enqueue", "Wait queue is full, SES paused");
        }
        // Enter resource checking
        resourceCheck(); // Check if resources are available, whether need to close some PDCs to release pending data packets
    }

    /**
     * @brief Check if pending queue is full
     * @return true if pending queue is full, false otherwise
     */
    bool pendQFull()
    {
        return pend_cnt >= MAX_PEND; // If pending queue is full, return true
    }

    /**
     * @brief Create a waiting node
     * @param tx SES to PDS request to create waiting node for
     * @return Returns created waiting node
     */
    pend_node createPendNode(SES_PDS_req tx)
    {
        // Create pend_node
        LOG_INFO("create_pend_node", "=====================Creating Wait Node=====================");
        auto pend_start = std::chrono::steady_clock::now();
        uint32_t pend_start_ms = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::milliseconds>(pend_start.time_since_epoch()).count());
        uint32_t pend_time = Pend_Time;
        auto pend_end = pend_start + std::chrono::milliseconds(pend_time);
        uint32_t pend_end_ms = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::milliseconds>(pend_end.time_since_epoch()).count());
        LOG_INFO("create_pend_node", "Wait start time: " + std::to_string(pend_start_ms));
        LOG_INFO("create_pend_node", "Wait end time: " + std::to_string(pend_end_ms));
        pend_node node = {tx, pend_time, pend_start_ms, pend_end_ms}; // Create pend_node
        return node;                                                  // Return pend_node
    }

    /**
     * @brief Forward SES to PDS request to specified PDC
     * @param pkt Pointer to SES_PDS_req structure, containing request information to forward
     * @param pdc_id Target PDC ID
     */
    // For REQ use
    void fwdPkt2PDC(struct SES_PDS_req *pkt, int pdc_id)
    {
        // Display pkt information
        LOG_INFO("fwd_pkt_to_pdc", "Forward packet type: SES_PDS_req");
        // Process receive response
        LOG_INFO("fwd_pkt_to_pdc", "Forwarding packet to PDC ID: " + std::to_string(pdc_id));
        // Package as PDS_PDC_req
        PDS_PDC_req req = {}; // value-initialize to ensure nack_payload is default-initialized
        req.next_hdr = pkt->next_hdr;
        req.tx_pkt_handle = pkt->tx_pkt_handle;
        req.pkt = pkt->pkt;
        req.pkt_len = pkt->pkt_len;
        req.som = (pkt->pkt.bth_header.Standard_Header.som != 0);
        req.eom = (pkt->pkt.bth_header.Standard_Header.eom != 0);
        // Send request to PDC
        if (pdc_id < MAX_PDC)
        {
            // Send to IPDC
            IPDC_Processmanager.pushTxRequest(pdc_id, req);
        }
        else
        {
            // Send to TPDC
            TPDC_Processmanager.pushTxRequest(pdc_id, req);
        }
        // External transmission here, need to interface with actual PDC below
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        resourceCheck();
        return;
    }
    // For RSP use
    void fwdPkt2PDC(struct SES_PDS_rsp *pkt, int pdc_id)
    {
        // Display pkt information
        LOG_INFO("fwd_pkt_to_pdc", "Forward packet type: SES_PDS_rsp");
        // Process receive response
        LOG_INFO("fwd_pkt_to_pdc", "Forwarding packet to PDC ID: " + std::to_string(pdc_id));
        // Package as PDS_PDC_rsp
        SES_PDC_rsp rsp = {}; // value-initialize to ensure nack_payload is default-initialized
        rsp.rx_pkt_handle = pkt->rx_pkt_handle;
        rsp.gtd_del = true;   // Response with payload, guarantee delivery;
        rsp.ses_nack = false; // Not NACK
        rsp.pkt = pkt->rsp;
        rsp.rep_len = pkt->rsp_len;
        // TODO: nack_payload

        // Send request to PDC
        if (pdc_id < MAX_PDC)
        {
            // Send to IPDC
            IPDC_Processmanager.pushTxResponse(pdc_id, rsp);
        }
        else
        {
            // Send to TPDC
            TPDC_Processmanager.pushTxResponse(pdc_id, rsp);
        }
        // External transmission here, need to interface with actual PDC below
        resourceCheck();
        return;
    }

    /**
     * @brief Forward network layer to PDS packet to specified PDC
     * @param pkt Pointer to PDStoNET_pkt structure, containing packet information to forward
     * @param pdc_id Target PDC ID
     */
    void fwdPkt2PDC(struct PDStoNET_pkt *pkt, int pdc_id)
    {
        // Display pkt information
        LOG_INFO("fwd_pkt_to_pdc", "Forward packet type: PDStoNET_pkt");
        // Process receive response
        LOG_INFO("fwd_pkt_to_pdc", "Forwarding packet to PDC ID: " + std::to_string(pdc_id));
        // Send response to PDC
        if (pdc_id < MAX_PDC)
        {
            // Send to IPDC
            IPDC_Processmanager.pushRxPacket(pdc_id, *pkt);
        }
        else
        {
            // Send to TPDC
            TPDC_Processmanager.pushRxPacket(pdc_id, *pkt);
        }
        // External transmission here, need to interface with actual PDC below
        resourceCheck();
        return;
    } /**
       * @brief Resource check, decide whether to close PDC to release resources
       */
    void resourceCheck()
    {
        // Check if resources are available
        LOG_INFO("resource_check", "=====================Resource Check=====================");

        if (pend_cnt > 0 || (open_cnt - closing_cnt > Close_Thresh))
        {
            // Add timeout check logic, first confirm if queued tasks have timed out, drop them if timed out
            while (!pend_q.empty())
            {
                if (isPendNodeOverTime(pend_q.front()))
                {
                    // Directly pop if timed out, drop it
                    LOG_WARN("resource_check", "First wait node timed out, removed, remaining wait count: " + std::to_string(pend_cnt));
                    pend_node node = pend_q.front();
                    pend_q.pop();
                    pendTimeOut(node);
                }
            }
            uint16_t sPDCID = selectPDC2Close(); // Select PDC to close
            if (sPDCID == -1)
            {
                LOG_WARN("resource_check", "No PDC available to close, not closing for now");
            }
            else
            {
                IPDC_Processmanager.sendCloseReq(sPDCID); // Send close request to IPDC
                // Enter main request processing
                closing_cnt++; // Counter increment by 1

                LOG_INFO("resource_check", "Resource check: closing PDC, closing count: " + std::to_string(closing_cnt));
            }
        }
        else
        {
            // If no PDC needs to be closed, do nothing
            LOG_INFO("resource_check", "Resource check: no need to close PDC");
        }
    }

    /**
     * @brief Check if head node has timed out
     * @param node Waiting node to check
     */
    void pendTimeOut(pend_node node)
    {
        // Process timed out pend_node
        LOG_WARN("pend_timeout", "Processing timed out wait node");
        pend_cnt--;
        event_cnt++;
        // dropPkt(); // Placeholder, temporarily empty
        dropPkt(node);

        // ses -> pkt fail event
        sendError2SES(); // Send error report to SES, this function is empty for now
    }

    /**
     * @brief Send error report to SES
     */
    void sendError2SES()
    {
        // Send error to SES, will be improved based on actual requirements later
        LOG_INFO("send_error_to_ses", "Sending error message to SES");
    }

    /**
     * @brief Drop error packet
     * @return Send error packet
     */
    void dropPkt(pend_node node)
    {
        // Placeholder, temporarily empty
        LOG_DEBUG("drop_packet", "node :" + std::to_string(node.tx_req.pkt.bth_header.Standard_Header.msg_id) + " dropped");
        // Note: Do not call free on stack objects, nodes will be automatically destroyed when scope ends
    }

    /**
     * @brief Check if timeout occurred
     * @return true or false
     */
    bool isPendNodeOverTime(pend_node node)
    {
        // Check if exceeds expected time limit
        auto pend_end = std::chrono::steady_clock::now();
        uint32_t time_now_ms = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::milliseconds>(pend_end.time_since_epoch()).count());
        return time_now_ms > node.end_time; // Correct logic: current time exceeds end time to be considered timeout
    }

    /**
     * @brief Allocate PDC when receiving SES response packet
     * @return true if allocation successful, false otherwise
     */
    bool assignPDC(uint16_t msgid, uint16_t pdc_id)
    {
        // if (msg_map.find(msgid) == msg_map.end() || msg_map[msgid] != pdc_id) // First is to check existence, second is to check equality
        // {
        //     LOG_ERROR("assign_pdc", "Message ID " + std::to_string(msgid) + " not mapped to PDC");
        //     LOG_ERROR(__FUNCTION__, "Message ID " + std::to_string(msgid) + " mapped to PDC ID: " + std::to_string(pdc_id));
        //     return false; // allocation failed
        // }
        LOG_INFO("assign_pdc", "Allocated PDC ID: " + std::to_string(pdc_id));
        if (pdc_list[pdc_id].is_open)
        {
            // If PDC is already open
            // Check if msgid and pdc match
            LOG_INFO("assign_pdc", "PDC already open, no need to reallocate, msgid: " + std::to_string(msgid));
            BitMap[pdc_id]++;
            return true; // Allocation successful
        }
        else
        {
            // If PDC is not open, try to apply for PDC
            LOG_INFO("assign_pdc", "PDC ID: " + std::to_string(pdc_id) + " not open");
            return false; // is rsp request, cannot allocate
        }
    }

    /**
     * @brief Allocate PDC when receiving SES request packet
     * @return true if allocation successful, false otherwise
     */
    bool assignPDC(uint32_t job_id, uint32_t dest_fa, uint8_t trafficclass, uint8_t deliverymode, uint16_t msgid, uint16_t *pdc_id)
    {
        // Allocate PDC algorithm
        // Simple allocation here for now
        *pdc_id = muxTx2PDCID(job_id, dest_fa, trafficclass, deliverymode); // Calculate tx corresponding pdc_id
        LOG_INFO("assign_pdc", "Allocated PDC ID: " + std::to_string(*pdc_id));
        if (pdc_list[*pdc_id].is_open)
        {
            // If PDC is already open
            // Check if msgid and pdc match, why??? This logic doesn't work for new messages
            LOG_INFO("assign_pdc", "PDC already open, no need to reallocate, msgid: " + std::to_string(msgid));
            BitMap[*pdc_id]++;
            return true; // Allocation successful
        }
        else
        {
            // If PDC is not open, try to apply for PDC
            LOG_INFO("assign_pdc", "Applying for PDC ID: " + std::to_string(*pdc_id));
            return true; // Not rsp request, can allocate
        }
        LOG_ERROR("assign_pdc", "Unknown error");
        return false;
    }

    /**
     * @brief Check if msgid matches PDC
     * @param pdc_id PDC ID to check
     * @param msgid Message ID to check
     * @return true if matches, false otherwise
     */
    // bool pdc_msg_chk(int pdc_id, int msgid)
    // {
    //     // Check if current msgid is allocated to current pdc
    //     if (msg_map.find(msgid) != msg_map.end())
    //     {
    //         if (msg_map[msgid] == pdc_id)
    //         {
    //             return true;
    //         }
    //     }
    //     return false;
    // }

    // PDC queue depth tracking

    // 4-tuple to PDCID mapping algorithm
    int muxTx2PDCID(uint32_t job_id, uint32_t dest_fa, uint8_t trafficclass, uint8_t deliverymode)
    {
        LOG_INFO("mux_tx_to_pdc_id", "PDC allocation algorithm - input parameters: " + std::to_string(job_id) +
                                         ", " + std::to_string(dest_fa) +
                                         ", " + std::to_string(trafficclass) +
                                         ", " + std::to_string(deliverymode));

        // 1. Partition by destination FA (banking)
        uint32_t bank = hash_fa(dest_fa) & BANK_MASK;
        job_id *= 10;
        // 2. Construct key and calculate hash once
        uint64_t key = ((uint64_t)job_id << JOBID_SHIFT) |
                       ((uint64_t)dest_fa << DEST_FA_SHIFT) |
                       ((uint64_t)trafficclass << TC_SHIFT) |
                       ((uint64_t)deliverymode << DM_SHIFT);

        uint16_t h1 = crc16_hash(key, CRC16_POLY1, HASH_SEED1);

        // 3. Map to bank index (use mask, ensure PDCs_PER_BANK is power of 2)
        uint32_t pick = h1 & (PDCs_PER_BANK - 1);

        // 4. Check selected PDC's queue depth
        uint8_t q1 = pdc_qdepth[bank][pick];
        // 5. Check if queue depth exceeds limit
        if (q1 >= MAX_PDC_QUEUE)
        {
            LOG_ERROR("mux_tx_to_pdc_id", "Selected PDC queue depth exceeds limit: " + std::to_string(q1));
            return -1; // Queue depth out of range
        }

        // 6. Generate global PDCID
        uint32_t pdcid = (bank << BANK_SHIFT) | pick;

        // Verify PDCID range
        if (pdcid >= MAX_PDC)
        {
            LOG_ERROR("mux_tx_to_pdc_id", "Generated PDCID out of range: " + std::to_string(pdcid));
            return -1;
        }

        // Update selected PDC's queue depth counter (simplified version, should decrement after PDC processing completes)
        pdc_qdepth[bank][pick]++;

        LOG_INFO("mux_tx_to_pdc_id", "PDC allocation algorithm - Bank: " + std::to_string(bank) +
                                         ", Selected index: " + std::to_string(pick) + "(depth:" + std::to_string(q1) + ")" +
                                         ", Final PDCID: " + std::to_string(pdcid));
        return static_cast<int>(pdcid);
    }

    uint16_t muxRx2PDCID(uint32_t src_addr, uint32_t dest_addr, uint16_t spdcid)
    {
        LOG_INFO("mux_rx_to_pdc_id", "PDC allocation algorithm - input parameters: " + std::to_string(src_addr) +
                                         ", " + std::to_string(dest_addr) +
                                         ", " + std::to_string(spdcid));

        // 1. Partition by destination address (banking)
        uint32_t bank = hash_fa(dest_addr) & BANK_MASK;
        spdcid *= 10;
        // 2. Construct key and calculate hash once
        uint64_t key = ((uint64_t)src_addr << JOBID_SHIFT) |
                       ((uint64_t)dest_addr << DEST_FA_SHIFT) |
                       ((uint64_t)spdcid << TC_SHIFT) |
                       ((uint64_t)0 << DM_SHIFT); // deliverymode fixed as 0

        uint16_t h1 = crc16_hash(key, CRC16_POLY1, HASH_SEED1);

        // 3. Map to bank index (use mask, ensure PDCs_PER_BANK is power of 2)
        uint32_t pick = h1 & (PDCs_PER_BANK - 1);

        // 4. Check selected PDC's queue depth
        uint8_t q1 = pdc_qdepth[bank][pick];
        // 5. Check if queue depth exceeds limit
        if (q1 >= MAX_PDC_QUEUE)
        {
            LOG_ERROR("mux_rx_to_pdc_id", "Selected PDC queue depth exceeds limit: " + std::to_string(q1));
            return -1; // Queue depth out of range
        }

        // 6. Generate global PDCID
        uint32_t pdcid = (bank << BANK_SHIFT) | pick;

        // Verify PDCID range
        if (pdcid >= MAX_PDC + MAX_PDC)
        {
            LOG_ERROR("mux_rx_to_pdc_id", "Generated PDCID out of range: " + std::to_string(pdcid));
            return -1;
        }

        // Update selected PDC's queue depth counter (simplified version, should decrement after PDC processing completes)
        pdc_qdepth[bank][pick]++;

        LOG_INFO("mux_rx_to_pdc_id", "PDC allocation algorithm - Bank: " + std::to_string(bank) +
                                         ", Selected index: " + std::to_string(pick) + "(depth:" + std::to_string(q1) + ")" +
                                         ", Final PDCID: " + std::to_string(pdcid));
        return static_cast<int>(pdcid + MAX_PDC);
    }

    int selectPDC2Close()
    {
        // Select PDC to close
        // Selection logic can be implemented based on actual requirements, here simply return first open PDC
        for (int i = 0; i < MAX_PDC; i++)
        {

            if (pdc_list[i].is_open)
            {
                if (i < MAX_PDC)
                { // Prioritize closing IPDC?
                    if (IPDC_Processmanager.canIPDCCloseInternal(i))
                    {
                        return i;
                        LOG_INFO("select_pdc_2close", "Selecting PDC to close, ID: " + std::to_string(i));
                    }
                }
                // else
                // {
                //     if (TPDC_Processmanager.canTPDCCloseInternal(i))
                //     {
                //         return i;
                //         LOG_INFO("select_pdc_2close", "Selecting PDC to close, ID: " + std::to_string(i));
                //     }
                // }
            }
        }
        LOG_WARN("select_pdc_2close", "No PDC available to close");
        return -1;
    }

    bool PDCClose()
    {
        // Get request
        LOG_INFO("pdc_close", "=====================PDC Close Request=====================");
        uint16_t pdc_id = MAX_PDC * 2; // Initialize to invalid value
        PDC_close_q.pop(pdc_id);
        LOG_INFO("pdc_close", "Popped PDC ID from close queue: " + std::to_string(pdc_id));
        if (pdc_id >= MAX_PDC * 2)
        {
            LOG_ERROR("pdc_close", "PDC ID out of range: " + std::to_string(pdc_id));
            return false;
        }
        if (pdc_list[pdc_id].is_open)
        {
            pdc_list[pdc_id].is_open = false;
            switch (getPDCType(pdc_id))
            {
            case PDC_TYPE::IPDC:
                LOG_INFO("pdc_close", "Closing IPDC ID: " + std::to_string(pdc_id));
                IPDC_Processmanager.stopIPDCProcess(pdc_id);
                pdc_list[pdc_id].is_open = false;
                open_cnt--;
                closing_cnt--;
                break;
            case PDC_TYPE::TPDC:
                LOG_INFO("pdc_close", "Closing TPDC ID: " + std::to_string(pdc_id));
                TPDC_Processmanager.stopTPDCProcess(pdc_id);
                pdc_list[pdc_id].is_open = false;
                open_cnt--;
                closing_cnt--;
                break;
            default:
                LOG_ERROR("pdc_close", "Unknown PDC type: " + std::to_string(pdc_id));
                return false;
            }

            LOG_INFO("pdc_close", "PDC ID: " + std::to_string(pdc_id) + " close successful");
            return true;
        }
        else
        {
            LOG_WARN("pdc_close", "PDC ID: " + std::to_string(pdc_id) + " already closed");
            return false;
        }
    }

    //=========================Internal Basic Functions===========================//
private:
    enum PDC_TYPE
    {
        IPDC = 0,
        TPDC = 1,
    };

    /*
     * @brief: Get PDC type
     * @param pdc_id: PDC ID
     * @return: PDC type
     */
    PDC_TYPE getPDCType(int pdc_id)
    {
        if (pdc_id <= MAX_PDC)
        {
            return PDC_TYPE::IPDC;
        }
        else
        {
            return PDC_TYPE::TPDC;
        }
    }

    bool pdsError()
    {
        LOG_DEBUG("pds_error", "PDC error");
        return true;
    }
};

#endif