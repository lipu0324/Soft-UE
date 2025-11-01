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
 * @file             SES.cpp
 * @brief            SES.cpp
 * @author           softuegroup@gmail.com
 * @version          1.0.0
 * @date             2025-10-29
 * @copyright        Apache License Version 2.0
 *
 * @details
 * SES.cpp
 */
#include "SES.hpp"
//#include "../PDS/PDS.hpp"
//#include "../PDS/PDC/PDC.hpp"
#include <cstdint>
#include <unordered_map>
#include <set>
#include <mutex>
#include <algorithm>
#include <iostream>
#include <vector>
#include<queue>
using namespace std;


// Conduct testing
void test_send_packet(){
    // To be completed later
    printf("test buffer manager\n");
    // Test sending a standard single packet
    SESManager ses_manager;
    std::cout<<"Testing single packet send"<<endl;
    OperationMetadata metadata;
    metadata.op_type = SEND;
    metadata.job_id = 1;
    metadata.res_index = 0;
    metadata.t_pid_on_fep = 1;
    metadata.has_imm_data = true;
    metadata.memory.rkey = 0x1234567890123456;
    metadata.payload.start_addr = 0x1000;
    metadata.payload.length = 1024; // Less than MTU
    metadata.payload.imm_data = 0xdeadbeef;
    metadata.has_imm_data = true;
    ses_manager.process_send_packet(metadata);

    // Test sending a multi-packet larger than MTU
    std::cout<<"Testing multi-packet send"<<endl;
    metadata.payload.length = 8192; // Greater than MTU
    metadata.has_imm_data = false;
    ses_manager.process_send_packet(metadata);
    


    // Send an error packet
    std::cout<<"Testing error packet send"<<endl;
    metadata.payload.start_addr = 0xFFFFFFFFFFFF; // Exceeds MR range
    metadata.payload.length = 1024; // Less than MTU
    metadata.has_imm_data = false;
    ses_manager.process_send_packet(metadata);

    std::cout<<"Buffer manager test completed"<<endl;
    
}

void test_recv_packet(){
    // To be completed later
    printf("test buffer manager\n");
    // Test receiving a standard single packet
    SESManager ses_manager;
    std::cout<<"Testing single packet receive"<<endl;
    PDC_SES_req req;
    req.rx_pkt_handle = 1234;
    req.orig_pdcid = 125;
    req.orig_psn = 1;
    
    req.pkt_len = 1024; // Less than MTU
    req.pkt.bth_type = Standard_Header;
    req.pkt.bth_header.Standard_Header.version = 2;
    req.pkt.bth_header.Standard_Header.msg_id = 1;
    req.pkt.bth_header.Standard_Header.opcode = SEND;
    req.pkt.bth_header.Standard_Header.buffer_offset = 0;
    req.pkt.bth_header.Standard_Header.ie = 0;
    req.pkt.bth_header.Standard_Header.request_length = 1024;
    req.pkt.bth_header.Standard_Header.job_id= 1;
    req.pkt.bth_header.Standard_Header.som = 1;
    req.pkt.bth_header.Standard_Header.eom = 1;
    req.pkt.bth_header.Standard_Header.hd = 1;
    req.pkt.bth_header.Standard_Header.match_bits = 0x1234567890123456;
    req.pkt.bth_header.Standard_Header.diff.som_true.header_data = 0xdeadbeef;
    req.pkt.bth_header.Standard_Header.diff.som_false.message_offset = 0;
    req.pkt.bth_header.Standard_Header.diff.som_false.payload_length = 1024;

    ses_manager.process_recv_req_packet(req);
    cout<<"Single packet receive test completed"<<endl<<endl;
    // Test a message divided into 5 packets, starting from the first packet
    std::cout<<"Testing multi-packet receive"<<endl;
    
    req.rx_pkt_handle = 1235;
    req.orig_pdcid = 126;
    req.orig_psn = 3;
    req.pkt_len = 2048; // Less than MTU  
    req.pkt.bth_header.Standard_Header.job_id= 2;
    req.pkt.bth_header.Standard_Header.msg_id = 1;
    req.pkt.bth_header.Standard_Header.request_length = 8192; // Greater than MTU
    req.pkt.bth_header.Standard_Header.som = 1; // Is the first packet
    req.pkt.bth_header.Standard_Header.eom = 0; // Is not the last packet
    req.pkt.bth_header.Standard_Header.hd = 0; // Is not the middle packet    
    req.pkt.bth_header.Standard_Header.diff.som_false.message_offset = 0;
    req.pkt.bth_header.Standard_Header.diff.som_false.payload_length = 2048; // Greater than MTU
    ses_manager.process_recv_req_packet(req);
    
    req.rx_pkt_handle = 1236;
    req.orig_psn = 4;
    req.pkt.bth_header.Standard_Header.msg_id = 1;
    req.pkt.bth_header.Standard_Header.request_length = 8192; // Greater than MTU
    req.pkt.bth_header.Standard_Header.som = 0; // Is not the first packet
    req.pkt.bth_header.Standard_Header.eom = 0; // Is not the last packet
    req.pkt.bth_header.Standard_Header.hd = 0; // Is not the middle packet    
    req.pkt.bth_header.Standard_Header.diff.som_false.message_offset = 2048;
    req.pkt.bth_header.Standard_Header.diff.som_false.payload_length = 2048; // Greater than MTU
    ses_manager.process_recv_req_packet(req);
    
    req.rx_pkt_handle = 1237;
    req.orig_psn = 5;
    req.pkt.bth_header.Standard_Header.msg_id = 1;
    req.pkt.bth_header.Standard_Header.request_length = 8192; // Greater than MTU
    req.pkt.bth_header.Standard_Header.som = 0; // Is not the first packet
    req.pkt.bth_header.Standard_Header.eom = 0; // Is not the last packet
    req.pkt.bth_header.Standard_Header.hd = 1; // Is the middle packet    
    req.pkt.bth_header.Standard_Header.diff.som_false.message_offset = 4096;
    req.pkt.bth_header.Standard_Header.diff.som_false.payload_length = 2048; // Greater than MTU
    ses_manager.process_recv_req_packet(req);
    
    req.rx_pkt_handle = 1238;
    req.orig_psn = 6;
    req.pkt.bth_header.Standard_Header.msg_id = 1;
    req.pkt.bth_header.Standard_Header.request_length = 8192; // Greater than MTU
    req.pkt.bth_header.Standard_Header.som = 0; // Is not the first packet
    req.pkt.bth_header.Standard_Header.eom = 1; // Is the last packet
    req.pkt.bth_header.Standard_Header.hd = 0; // Is not the middle packet    
    req.pkt.bth_header.Standard_Header.diff.som_false.message_offset = 6144;
    req.pkt.bth_header.Standard_Header.diff.som_false.payload_length = 2048; // Greater than MTU
    ses_manager.process_recv_req_packet(req);

    cout<<"Multi-packet receive test completed"<<endl;
    
}

int main()
{
    //test_send_packet();
    test_recv_packet();

}