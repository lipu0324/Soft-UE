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
 * @file             IPDC.hpp
 * @brief            IPDC.hpp
 * @author           softuegroup@gmail.com
 * @version          1.0.0
 * @date             2025-10-29
 * @copyright        Apache License Version 2.0
 *
 * @details
 * This header defines the Initiator PDC (I_PDC) class for managing connection initiation and data transmission.
 */




#ifndef I_PDC_HPP
#define I_PDC_HPP

#include "process/ThreadSafeQueue.hpp"

#include "./PDC.hpp"
#include <iostream>
#include <queue>
#include <sstream>
#include <chrono>
#include <iomanip>
/**
 * @class I_PDC
 * @brief Initiator PDC class, responsible for managing PDC functionality on the connection initiating side
 *
 * I_PDC is responsible for handling connection establishment, reliable packet transmission,
 * flow control, error recovery, and connection closure
 */
class I_PDC : public PDC
{
private:
    bool clr_cm;         /**< Clear control message flag */
    bool close_triger;   /**< Close trigger flag */
    uint32_t close_psn;  /**< Close packet sequence number */
   
public:
    bool close_req;      /**< Close request flag */

    /**
     * @brief Initialize PDC instance
     * @param id PDC identifier
     * @return Initialization success status
     */
    bool initPDC(uint16_t id);
    
    /**
     * @brief Main event loop, handles various events by priority: control messages, close requests, packet reception, response sending, etc.
     */
    void openChk();

    /**
     * @brief Request to close PDC connection
     */
    void closeReq();
     

    /**
     * @brief Handle SES layer transmission request
     * @param req Request packet
     */
    void sesTxReq(PDS_PDC_req *req);

    /**
     * @brief Handle SES layer transmission response
     * @param rsp Response packet
     */
    void sesTxRsp(SES_PDC_rsp *rsp);



    /**
     * @brief Handle received request packet
     * @param pkt Request packet
     */
    void rxReq(PDStoNET_pkt *pkt);
    
    /**
     * @brief Handle received ACK packet
     * @param pkt ACK packet
     */
    void rxAck(PDStoNET_pkt *pkt);
    
    /**
     * @brief Handle received control message
     * @param pkt Control message packet
     */
    void rxCtrl(PDStoNET_pkt *pkt);


    /**
     * @brief Start PDC closing process
     */
    void beginClose();
    
    /**
     * @brief Handle target side closing
     */
    void targetClose();



    /**
     * @brief Complete closing operation
     */
    void close();
     
    /**
     * @brief Send close packet
     */
    void sendClose();
};

#endif // I_PDC_HPP