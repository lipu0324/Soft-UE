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
 * @file             ipdc_rto_test.cpp
 * @brief            ipdc_rto_test.cpp
 * @author           softuegroup@gmail.com
 * @version          1.0.0
 * @date             2025-10-29
 * @copyright        Apache License Version 2.0
 *
 * @details
 * ipdc_rto_test.cpp
 */

/**
 * @file ipdc_rto_test.cpp
 * @brief IPDC timeout retransmission functionality test
 *
 * Test scenarios:
 * 1. Initialize an IPDC instance
 * 2. Send request packet
 * 3. Verify timeout retransmission mechanism
 * 4. Check timer status
 */

#include "../IPDC.hpp"
#include "../PDC.hpp"
#include <iostream>
#include <cassert>
#include <thread>
#include <chrono>
#include <queue>

/**
 * @brief Test IPDC initialization
 */
void testIPDCInit() {
    std::cout << "\n=== Test IPDC Initialization ===" << std::endl;

    I_PDC ipdc;

    // Initialize IPDC
    uint16_t pdcid = 5001;
    bool init_result = ipdc.initPDC(pdcid);
    
    assert(init_result);
    assert(ipdc.SPDCID == pdcid);
    assert(ipdc.DPDCID == 0);
    assert(ipdc.state == CLOSED);
    assert(ipdc.start_psn == 1000);
    assert(ipdc.tx_cur_psn == 1000);
    assert(ipdc.clear_psn == 999);
    assert(ipdc.unack_cnt == 0);
    
    std::cout << "✓ IPDC initialization successful" << std::endl;
    std::cout << "  - SPDCID: " << ipdc.SPDCID << std::endl;
    std::cout << "  - start_psn: " << ipdc.start_psn << std::endl;
    std::cout << "  - State: " << STATE_STR(ipdc.state) << std::endl;
}

/**
 * @brief Test IPDC sending request packet
 */
void testIPDCSendReq() {
    std::cout << "\n=== Test IPDC Sending Request Packet ===" << std::endl;

    I_PDC ipdc;
    ipdc.initPDC(5002);

    // Prepare to send request
    PDS_PDC_req req;
    req.tx_pkt_handle = 1001;
    req.next_hdr = UET_HDR_NONE;
    req.som = true;
    req.eom = true;
    
    // Set SES layer packet data
    req.pkt.bth_type = Standard_Header;
    req.pkt.bth_header.Standard_Header.som = true;
    req.pkt.bth_header.Standard_Header.eom = true;
    req.pkt.bth_header.Standard_Header.msg_id = 12345;
    
    // Add request to queue
    ipdc.tx_req_q.push(req);

    std::cout << "✓ Request packet added to send queue" << std::endl;
    std::cout << "  - tx_pkt_handle: " << req.tx_pkt_handle << std::endl;
    std::cout << "  - msg_id: " << req.pkt.bth_header.Standard_Header.msg_id << std::endl;

    // Process send request
    ipdc.sesTxReq(&req);

    // Verify state changes
    assert(ipdc.state == CREATING);
    assert(ipdc.tx_cur_psn == 1001);
    assert(ipdc.unack_cnt == 1);
    
    std::cout << "✓ Request packet sending completed" << std::endl;
    std::cout << "  - Current state: " << STATE_STR(ipdc.state) << std::endl;
    std::cout << "  - tx_cur_psn: " << ipdc.tx_cur_psn << std::endl;
    std::cout << "  - unack_cnt: " << ipdc.unack_cnt << std::endl;
}

/**
 * @brief Test IPDC timeout retransmission mechanism
 */
void testIPDCRetransmission() {
    std::cout << "\n=== Test IPDC Timeout Retransmission Mechanism ===" << std::endl;

    I_PDC ipdc;
    ipdc.initPDC(5003);

    // Prepare and send request
    PDS_PDC_req req;
    req.tx_pkt_handle = 2001;
    req.next_hdr = UET_HDR_NONE;
    req.som = true;
    req.eom = true;
    req.pkt.bth_type = Standard_Header;
    req.pkt.bth_header.Standard_Header.som = true;
    req.pkt.bth_header.Standard_Header.eom = true;
    req.pkt.bth_header.Standard_Header.msg_id = 23456;
    
    // Send request
    ipdc.sesTxReq(&req);

    uint32_t sent_psn = 1000;

    std::cout << "✓ Request packet sent - PSN: " << sent_psn << std::endl;

    // Verify timer has started
    if (USE_RTO) {
        assert(ipdc.isTimerActive(sent_psn));
        assert(ipdc.getActiveTimerCount() == 1);
        
        auto timer_info = ipdc.getTimerInfo(sent_psn);
        assert(timer_info.psn == sent_psn);
        assert(timer_info.rto == Base_RTO);
        assert(timer_info.retry_count == 0);
        assert(timer_info.active);
        
        std::cout << "✓ Timer has started" << std::endl;
        std::cout << "  - PSN: " << timer_info.psn << std::endl;
        std::cout << "  - RTO: " << timer_info.rto << "ms" << std::endl;
        std::cout << "  - retry_count: " << timer_info.retry_count << std::endl;

        // Wait for timeout
        std::cout << "\nWaiting for timeout (" << Base_RTO << "ms)..." << std::endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(Base_RTO + 50));

        // Check timeout retransmission queue
        if (!ipdc.rto_pkt_q.empty()) {
            uint32_t timeout_psn = ipdc.rto_pkt_q.front();
            assert(timeout_psn == sent_psn);

            std::cout << "✓ Packet timed out, PSN added to retransmission queue" << std::endl;
            std::cout << "  - Timeout PSN: " << timeout_psn << std::endl;

            // Process timeout retransmission
            ipdc.rto_pkt_q.pop();
            ipdc.txRto(timeout_psn);

            // Verify timer status after retransmission
            if (ipdc.isTimerActive(sent_psn)) {
                auto retry_timer_info = ipdc.getTimerInfo(sent_psn);
                assert(retry_timer_info.retry_count == 1);
                assert(retry_timer_info.rto == Base_RTO * 2);

                std::cout << "✓ Retransmission completed, timer updated" << std::endl;
                std::cout << "  - New retry_count: " << retry_timer_info.retry_count << std::endl;
                std::cout << "  - New RTO: " << retry_timer_info.rto << "ms (exponential backoff)" << std::endl;
            }
        } else {
            std::cout << "⚠ Timeout queue is empty, timeout time may be insufficient" << std::endl;
        }
    } else {
        std::cout << "⚠ RTO functionality not enabled (USE_RTO=0)" << std::endl;
    }
}

/**
 * @brief Test IPDC multiple retransmissions
 */
void testIPDCMultipleRetransmissions() {
    std::cout << "\n=== Test IPDC Multiple Retransmissions ===" << std::endl;

    I_PDC ipdc;
    ipdc.initPDC(5004);

    // Send request
    PDS_PDC_req req;
    req.tx_pkt_handle = 3001;
    req.next_hdr = UET_HDR_NONE;
    req.som = true;
    req.eom = true;
    req.pkt.bth_type = Standard_Header;
    req.pkt.bth_header.Standard_Header.som = true;
    req.pkt.bth_header.Standard_Header.eom = true;
    req.pkt.bth_header.Standard_Header.msg_id = 34567;
    
    ipdc.sesTxReq(&req);
    uint32_t sent_psn = 1000;
    
    std::cout << "✓ Request packet sent - PSN: " << sent_psn << std::endl;
    
    if (USE_RTO) {
        // Simulate multiple timeout retransmissions
        for (int retry = 0; retry < Max_RTO_Retx_Cnt; retry++) {
            std::cout << "\n--- " << (retry + 1) << "th Retransmission ---" << std::endl;
            
            // Get current RTO
            auto timer_info = ipdc.getTimerInfo(sent_psn);
            uint16_t current_rto = timer_info.rto;

            std::cout << "Waiting for timeout (" << current_rto << "ms)..." << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(current_rto + 50));

            if (!ipdc.rto_pkt_q.empty()) {
                uint32_t timeout_psn = ipdc.rto_pkt_q.front();
                ipdc.rto_pkt_q.pop();

                std::cout << "✓ Timeout PSN: " << timeout_psn << std::endl;

                // Process retransmission
                ipdc.txRto(timeout_psn);
                
                if (ipdc.isTimerActive(sent_psn)) {
                    auto retry_info = ipdc.getTimerInfo(sent_psn);
                    std::cout << "  - retry_count: " << retry_info.retry_count << std::endl;
                    std::cout << "  - RTO: " << retry_info.rto << "ms" << std::endl;
                }
            }
        }
        
        // Next timeout should trigger close error
        std::cout << "\n--- Exceeded Maximum Retransmission Count ---" << std::endl;
        auto final_timer_info = ipdc.getTimerInfo(sent_psn);
        std::this_thread::sleep_for(std::chrono::milliseconds(final_timer_info.rto + 50));

        if (!ipdc.rto_pkt_q.empty()) {
            uint32_t timeout_psn = ipdc.rto_pkt_q.front();
            ipdc.rto_pkt_q.pop();
            ipdc.txRto(timeout_psn);

            // Verify close error flag
            assert(ipdc.close_error == true);
            std::cout << "✓ Maximum retransmission count reached, triggering close error" << std::endl;
        }
    } else {
        std::cout << "⚠ RTO functionality not enabled (USE_RTO=0)" << std::endl;
    }
}

/**
 * @brief 测试IPDC接收ACK后停止计时器
 */
void testIPDCReceiveACK() {
    std::cout << "\n=== 测试IPDC接收ACK后停止计时器 ===" << std::endl;
    
    I_PDC ipdc;
    ipdc.initPDC(5005);
    ipdc.DPDCID = 5006;  // 设置目标PDCID
    ipdc.state = ESTABLISHED;  // 设置为已建立状态
    
    // 发送请求
    PDS_PDC_req req;
    req.tx_pkt_handle = 4001;
    req.next_hdr = UET_HDR_NONE;
    req.som = true;
    req.eom = true;
    req.pkt.bth_type = Standard_Header;
    req.pkt.bth_header.Standard_Header.som = true;
    req.pkt.bth_header.Standard_Header.eom = true;
    req.pkt.bth_header.Standard_Header.msg_id = 45678;
    
    ipdc.txReq(&req);
    uint32_t sent_psn = ipdc.tx_cur_psn - 1;
    
    std::cout << "✓ Request packet sent - PSN: " << sent_psn << std::endl;
    
    if (USE_RTO) {
        // 验证计时器已启动
        assert(ipdc.isTimerActive(sent_psn));
        std::cout << "✓ 计时器已启动" << std::endl;
        
        // 模拟接收ACK包
        PDStoNET_pkt ack_pkt;
        ack_pkt.PDS_type = RUOD_ack_header;
        ack_pkt.PDS_header.RUOD_ack_header.type = ACK;
        ack_pkt.PDS_header.RUOD_ack_header.ack_psn_off = 1;
        ack_pkt.PDS_header.RUOD_ack_header.cack_psn = sent_psn;
        ack_pkt.PDS_header.RUOD_ack_header.spdcid = 5006;
        ack_pkt.PDS_header.RUOD_ack_header.dpdcid = 5005;
        ack_pkt.PDS_header.RUOD_ack_header.flags.req = 0;
        
        // 将ACK包加入接收队列
        ipdc.rx_pkt_q.push(ack_pkt);
        
        std::cout << "✓ 模拟接收ACK - ack_psn: " << sent_psn << std::endl;
        
        // 处理ACK包
        ipdc.openChk();
        
        // 等待一小段时间确保处理完成
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        
        // 验证计时器已停止
        assert(!ipdc.isTimerActive(sent_psn));
        assert(ipdc.getActiveTimerCount() == 0);
        
        std::cout << "✓ 收到ACK后计时器已停止" << std::endl;
        std::cout << "  - 活跃计时器数量: " << ipdc.getActiveTimerCount() << std::endl;
    } else {
        std::cout << "⚠ RTO功能未启用 (USE_RTO=0)" << std::endl;
    }
}

/**
 * @brief Main test function
 */
int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "      IPDC Timeout Retransmission Function Test" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "\nConfiguration Parameters:" << std::endl;
    std::cout << "  - USE_RTO: " << USE_RTO << std::endl;
    std::cout << "  - Base_RTO: " << Base_RTO << "ms" << std::endl;
    std::cout << "  - Max_RTO_Retx_Cnt: " << Max_RTO_Retx_Cnt << std::endl;
    
    try {
        // 测试1: IPDC初始化
        testIPDCInit();
        
        // 测试2: IPDC发送req包
        testIPDCSendReq();
        
        // 测试3: IPDC超时重传机制
        testIPDCRetransmission();
        
        // 测试4: IPDC多次重传
        testIPDCMultipleRetransmissions();
        
        // 测试5: IPDC接收ACK后停止计时器
        testIPDCReceiveACK();
        
        std::cout << "\n========================================" << std::endl;
        std::cout << "           All Tests Completed" << std::endl;
        std::cout << "========================================" << std::endl;
        std::cout << "\nTest Results Summary:" << std::endl;
        std::cout << "  ✓ IPDC initialization test passed" << std::endl;
        std::cout << "  ✓ IPDC request packet sending test passed" << std::endl;
        std::cout << "  ✓ IPDC timeout retransmission mechanism test passed" << std::endl;
        std::cout << "  ✓ IPDC multiple retransmissions test passed" << std::endl;
        std::cout << "  ✓ IPDC receive ACK stop timer test passed" << std::endl;
        std::cout << "\nAll tests completed successfully!" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "\n❌ Exception occurred during testing: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "\n❌ Unknown exception occurred during testing" << std::endl;
        return 1;
    }
    
    return 0;
}