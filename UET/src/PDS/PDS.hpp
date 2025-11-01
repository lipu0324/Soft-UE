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
 * @file             PDS.hpp
 * @brief            PDS.hpp
 * @author           softuegroup@gmail.com
 * @version          1.0.0
 * @date             2025-10-29
 * @copyright        Apache License Version 2.0
 *
 * @details
 * PDS.hpp
 */




#ifndef PDS_HPP
#define PDS_HPP
#include "../Transport_Layer.hpp"
#include <cstdint>

// Define constants
const int MAX_PDC_QUEUE = 8; // Maximum depth of each PDC queue (maximum pending tasks a PDC can handle)
const int MAX_PEND = 16384;  // Maximum number of pending tasks
// Base_RTO macro definition moved to Transport_Layer.hpp, commented out here to avoid redefinition
// #define Base_RTO 10000       // Base RTO
#define Pend_Time 100        // Default pend time
#define BITMAP_WORD_SIZE 64


// PDC allocation algorithm configuration parameters
#define NUM_BANKS 4                       // Number of banks, must be power of 2
#define PDCs_PER_BANK MAX_PDC / NUM_BANKS // Number of PDCs per bank, must be power of 2
#define BANK_SHIFT 7                      // log2(PDCs_PER_BANK) = 8
#define BANK_MASK (NUM_BANKS - 1)         // Bank mask = 15

// Hash parameter configuration
#define CRC16_POLY1 0x1021 // CRC16 CCITT polynomial
#define CRC16_POLY2 0x8005 // CRC16 IBM polynomial
#define HASH_SEED1 0x1234  // Seed for first hash
#define HASH_SEED2 0x5678  // Seed for second hash

// 4-tuple concatenation shift configuration
#define JOBID_SHIFT 0
#define DEST_FA_SHIFT 16
#define TC_SHIFT 24
#define DM_SHIFT 40


// pend_node definition
struct pend_node
{
    SES_PDS_req tx_req;  // Send request
    uint32_t pend_time;  // Pend time
    uint32_t start_time; // Start time
    uint32_t end_time;   // End time
};

// pdc structure definition
struct pdc
{
    bool is_open;             // PDC status
    pdc() : is_open(false) {} // Initialize to closed state
};

enum pdc_type
{
    IPDC,
    TPDC
};

//=============================================================================
// 辅助函数定义
//=============================================================================


/**
 * @brief Get source PDCID of PDS packet
 * @param pkt PDS packet to query
 * @return Source PDCID, returns 0 if packet type does not match
 * @details Extract source PDCID from corresponding header structure based on different PDS header types
 *          Supports RUOD_ack_header, RUOD_req_header, RUOD_cp_header and nack_header types
 */
inline uint16_t getSPDCID(PDStoNET_pkt pkt){
    if(pkt.PDS_type == RUOD_ack_header) return pkt.PDS_header.RUOD_ack_header.spdcid;
    else if(pkt.PDS_type == RUOD_req_header) return pkt.PDS_header.RUOD_req_header.spdcid;
    else if(pkt.PDS_type == RUOD_cp_header) return pkt.PDS_header.RUOD_cp_header.spdcid;
    else if(pkt.PDS_type == nack_header) return pkt.PDS_header.nack_header.spdcid;
    else return 0;
}

/**
 * @brief Check if NACK code indicates fatal PDC error requiring connection closure
 * @param code NACK error code
 * @return true if fatal error requiring PDC closure, false otherwise
 * @details Check if NACK code belongs to PDC_FATAL type, these errors require PDC connection closure
 *          Included fatal error codes:
 *          - 0x0E (UET_INV_DPDCID): Unrecognized destination PDCID
 *          - 0x0F (UET_PDC_HDR_MISMATCH): PDC header mismatch
 *          - 0x11 (UET_CLOSING_IN_ERR): Error during closure
 *          - 0x13 (UET_GTD_RESP_UNAVAIL): Guaranteed transmission response unavailable
 *          - 0x15 (UET_INVALID_SYN): Invalid SYN flag
 *          - 0x16 (UET_PDC_MODE_MISMATCH): PDC mode mismatch
 *          - 0x19 (UET_UNEXP_EVENT): Unexpected event
 */
inline bool isClose(uint8_t code){
    if(code == 0x0E || code == 0x0F || code == 0x11 || code == 0x13 || code == 0x15 ||
       code == 0x16 || code == 0x19) return true;
    else return false;
}

/**
 * @brief Calculate receive PSN based on packet sequence number and PDC offset
 * @param psn Packet sequence number
 * @param pdc_off PDC offset (12-bit complement)
 * @return Calculated receive PSN
 * @details Add 12-bit PDC offset value to PSN to get actual receive PSN
 *          Note: Current implementation does not properly handle sign extension of 12-bit complement, may need correction
 */
inline uint32_t getRxpsn(uint32_t psn, uint16_t pdc_off) {
    // Sign extend 12-bit complement to 32-bit (current implementation may need correction)
    int16_t offset = (int16_t)(pdc_off << 4) >> 4;  // Sign extend 12-bit to 16-bit
    return psn + offset;
}

/**
 * @brief Generate receive handle based on PSN and source PDCID
 * @param psn Packet sequence number
 * @param spdcid Source PDCID
 * @return Generated 16-bit handle
 * @details Generate handle using simple concatenation:
 *          - Low 8 bits: Low 8 bits of source PDCID
 *          - High 8 bits: Low 8 bits of PSN
 *          This method may have conflicts, may need more complex algorithm in actual use
 */
inline uint16_t setRXhandle(uint32_t psn,uint16_t spdcid){
    uint16_t handle = (spdcid & 0xFF) | ((psn & 0xFF) << 8); // Simple concatenation method
    return handle;
}


// Utility function to determine PDC type
inline pdc_type getPDCType(int pdc_id)
{
    if (pdc_id < MAX_PDC)
    {
        return IPDC; // 1-16 are IPDC
    }
    else
    {
        return TPDC; // 17-32 are TPDC
    }
}

// Check if PDC ID is IPDC
inline bool is_ipdc(int pdc_id)
{
    return pdc_id < MAX_PDC;
}

// Check if PDC ID is TPDC
inline bool is_tpdc(int pdc_id)
{
    return pdc_id >= MAX_PDC;
}

// CRC16 hash function implementation
inline uint16_t crc16_hash(uint64_t data, uint16_t poly, uint16_t seed)
{
    uint16_t crc = seed;
    for (int i = 0; i < 64; i++)
    {
        if ((crc ^ (data >> (63 - i))) & 1)
        {
            crc = (crc >> 1) ^ poly;
        }
        else
        {
            crc = crc >> 1;
        }
    }
    return crc;
}

// Destination FA hash function
inline uint32_t hash_fa(uint32_t dest_fa)
{
    // Simple hash function, can be optimized
    return (dest_fa * 0x9E3779B9) >> 16; // Golden ratio hash
}

// Check if NACK code is close type
inline bool isClose(PDS_Nack_Codes nack_code){
    return (nack_code == UET_INV_DPDCID || 
            nack_code == UET_PDC_HDR_MISMATCH || 
            nack_code == UET_CLOSING_IN_ERR || 
            nack_code == UET_GTD_RESP_UNAVAIL || 
            nack_code == UET_PDC_HDR_MISMATCH || 
            nack_code == UET_INVALID_SYN ||
            nack_code == UET_PDC_MODE_MISMATCH ||
            nack_code == UET_UNEXP_EVENT 
        );
}

#endif 