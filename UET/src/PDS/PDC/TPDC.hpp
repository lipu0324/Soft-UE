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
 * @file             TPDC.hpp
 * @brief            TPDC.hpp
 * @author           softuegroup@gmail.com
 * @version          1.0.0
 * @date             2025-10-29
 * @copyright        Apache License Version 2.0
 *
 * @details
 * TPDC.hpp
 */




#ifndef T_PDC_HPP
#define T_PDC_HPP

#include "process/ThreadSafeQueue.hpp"

#include "./PDC.hpp"
#include "../../logger/Logger.hpp"
#include <iostream>
#include <queue>
#include <sstream>
#include <chrono>
#include <iomanip>
/**
 * @class T_PDC
 * @brief Target PDC class, responsible for managing PDC functionality on the connection receiving side 
 *
 * T_PDC handles connection requests from the initiator, maintains connection state,
 * implements reliable data transmission, and processes control messages 
 */
class T_PDC : public PDC
{
private:
    bool secure_psn; /**< Enable secure PSN flag  */
    bool bad_psn;    /**< Bad PSN flag  */
    bool close_cmd;   /**< Close command flag  */
    bool req_closing; /**< Request closing flag  */

public:
    

    // ==========================================
    // 1. Initialization and lifecycle management functions 
    // ==========================================
    /**
     * @brief Initialize target PDC 
     * @param id PDC identifier 
     * @return Whether initialization was successful 
     */
    bool initPDC(uint16_t id);


    // ==========================================
    // 2. Connection establishment and closure management functions 
    // ==========================================
    /**
     * @brief Process connection establishment phase 1 
     * @param pkt Connection request packet 
     */
    void processOpen1(PDStoNET_pkt *pkt);

    /**
     * @brief Process connection establishment phase 2 
     * @param pkt Connection request packet 
     */
    void processOpen2(PDStoNET_pkt *pkt);
    /**
     * @brief Main event loop, handles various events by priority: control messages, close requests, packet reception, response sending, etc. 
     */
    void openChk();
    /**
     * @brief Request PDC closure 
     */
    // Request PDC connection closure
    void reqClose();

    /**
     * @brief Start PDC closure 
     */
    void beginClose();

    /**
     * @brief Complete PDC closure 
     */
    void close();
    /**
     * @brief Handle closure process 
     */
    void processClose();

    // ==========================================
    // 3. PSN management and security functions 
    // ==========================================


    /**
     * @brief Secure PSN processing phase 1 
     * @param pkt Packet to be verified 
     */
    void processSecurePsn1(PDStoNET_pkt *pkt);
    /**
     * @brief Secure PSN processing phase 2 
     * @param pkt Packet to be verified 
     */
    void processSecurePsn2(PDStoNET_pkt *pkt);
    /**
     * @brief Check PSN security 
     * @param psn PSN to be checked 
     */
    void chkSecurePsn(uint32_t psn);
    /**
     * @brief Save expected PSN value 
     */
    void saveExpectedPSN();
    // ==========================================
    // 4. Packet reception processing functions 
    // ==========================================
    /**
     * @brief Process request packets received from network 
     * @param pkt Request packet 
     */
    void netRxReq(PDStoNET_pkt *pkt);

    /**
     * @brief Process ACK packets received from network 
     * @param pkt ACK packet 
     */
    void netRxAck(PDStoNET_pkt *pkt);

    /**
     * @brief Process NACK packets received from network 
     * @param pkt NACK packet 
     */
    void netRxNack(PDStoNET_pkt *pkt);

    /**
     * @brief Process control messages received from network 
     * @param pkt Control message packet 
     */
    void netRxCm(PDStoNET_pkt *pkt);

    /**
     * @brief Process received request packets 
     * @param pkt Request packet 
     */
    void rxReq(PDStoNET_pkt *pkt);

    /**
     * @brief Process received ACK packets 
     * @param pkt ACK packet 
     */
    void rxAck(PDStoNET_pkt *pkt);
    // ==========================================
    // 5. Packet transmission processing functions 
    // ==========================================
    /**
     * @brief Handle SES layer transmission requests 
     * @param req Request packet 
     */
    void sesTxReq(PDS_PDC_req *req);

    /**
     * @brief Handle SES layer transmission responses 
     * @param rsp Response packet 
     */
    void sesTxRsp(SES_PDC_rsp *rsp);

    // ==========================================
    // 6. Specific transmission functionality functions 
    // ==========================================

    /**
     * @brief Process received control messages 
     * @param pkt Control message packet 
     */
    void rxCtrl(PDStoNET_pkt *pkt);

};

#endif // T_PDC_HPP
