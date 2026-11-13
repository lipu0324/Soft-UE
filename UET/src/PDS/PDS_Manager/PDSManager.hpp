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
#include "../TrimmedPacket.hpp"
#include "../ReceiveAdmission.hpp"
#include "../RudiInitiator.hpp"
#include "../../logger/Logger.hpp"
#include "../PDC/process/TPDCProcessManager.hpp"
#include "../PDC/process/IPDCProcessManager.hpp"
#include "../PDC/process/ThreadSafeQueue.hpp"
#include "../../Network_Layer/PdsQueueTransport.hpp"

#include <chrono>
#include <cstddef>
#include <memory>
#include <tuple>
#include <limits>
#include <deque>
#include <set>

class PDS_Manager
{

private:

public:

    bool pushReturnData(const PDC_SES_req& original,const SEStoPDS_pkt& data) {
        return original.PDCID>=MAX_PDC && original.PDCID<MAX_PDC*2 && PDCOpen(original.PDCID) &&
            TPDC_Processmanager.pushReturnData(original,data);
    }

    uint16_t openWithControl(uint32_t local_node,uint32_t peer,uint32_t job,pdc_mode mode,bool negotiation,
                             UET::PDS::PdcMappingIdentity identity={}) {
        if (!local_node || !peer || (mode!=ROD && mode!=RUD)) return UINT16_MAX;
        uint16_t local_pdc=UINT16_MAX;
        if (!identity.valid() || !assignPDC(job,peer,0,mode,0,&local_pdc,local_node,identity)) return UINT16_MAX;
        if (!PDCOpen(local_pdc) && !allocPDC(local_pdc,peer,local_node,mode)) return UINT16_MAX;
        return IPDC_Processmanager.openWithControl(local_pdc,mode,negotiation)?local_pdc:UINT16_MAX;
    }

    // Remove unsent fragments after the owning PDC terminates. They must not
    // accidentally establish a replacement context under a retired message ID.
    void cancelQueuedMessage(uint32_t peer,uint32_t job,uint16_t message_id) {
        if (rudi_initiator_) rudi_initiator_->cancel_message(peer,job,message_id);
        const auto matches=[&](const SES_PDS_req& request) {
            const auto& header=request.pkt.bth_header.Standard_Header;
            return request.dst_fep==peer && header.job_id==job && header.msg_id==message_id;
        };
        std::queue<SES_PDS_req> remaining;
        while (!SES_tx_req_q.empty()) {
            auto request=std::move(SES_tx_req_q.front()); SES_tx_req_q.pop();
            if (!matches(request)) remaining.push(std::move(request));
        }
        SES_tx_req_q=std::move(remaining);
        std::queue<pend_node> retained;
        while (!pend_q.empty()) {
            auto node=std::move(pend_q.front()); pend_q.pop();
            if (!matches(node.tx_req)) retained.push(std::move(node));
        }
        pend_q=std::move(retained); pend_cnt=static_cast<int>(pend_q.size()); pause_ses=pendQFull();
        for (auto& deferred:deferred_close_requests_)
            deferred.second.erase(std::remove_if(deferred.second.begin(),deferred.second.end(),matches),deferred.second.end());
        for (auto entry=quiesced_messages_.begin();entry!=quiesced_messages_.end();)
            if (std::get<0>(*entry)==job && std::get<1>(*entry)==peer && std::get<4>(*entry)==message_id)
                entry=quiesced_messages_.erase(entry); else ++entry;
        armPendingDeadline();
    }
    explicit PDS_Manager(UET::Runtime::Services* runtime = nullptr)
        : TPDC_Processmanager(runtime), IPDC_Processmanager(runtime), runtime_(runtime) {
        if (runtime_) rudi_initiator_=std::make_unique<UET::PDS::RudiInitiator>(*runtime_,
            [this](const PDStoNET_pkt& packet) { return PDStoNet.push(packet); },
            [this](UET::PDS::RudiInitiator::Result result) {
                PDC_SES_rsp response{}; response.PDCID=UINT16_MAX; response.delivery_mode=RUDI;
                response.source_fep=result.peer; response.rudi_packet_id=result.packet_id;
                response.rudi_request_offset=result.request_offset; response.rudi_message_id=result.message_id;
                response.rudi_timed_out=result.timed_out; response.pkt=std::move(result.semantic_response);
                // At most the initiator packet budget can complete at once.
                // SES response delivery must not silently lose a terminal fact.
                rudi_results_.push_back(std::move(response));
            });
    }
    std::optional<uint32_t> submitRudi(const SES_PDS_req& request) {
        if (runtime_ && rudi_initiator_ && rudi_results_.size()+rudi_initiator_->outstanding_packets()>=runtime_->rudi_packet_limit) return {};
        return rudi_initiator_?rudi_initiator_->submit(request):std::optional<uint32_t>{};
    }
    bool notifyRudiTransmit(const UET::Runtime::TransmitNotification& notification) {
        return rudi_initiator_ && rudi_initiator_->notify_transmit(notification);
    }
    bool activeRudiAttempt(const UET::Runtime::TransmitIdentity& identity) const {
        return rudi_initiator_ && rudi_initiator_->active_attempt(identity);
    }
    bool popRudiResult(PDC_SES_rsp& response) {
        if (rudi_results_.empty()) return false;
        response=std::move(rudi_results_.front()); rudi_results_.pop_front(); return true;
    }
    bool respondRudi(const PDC_SES_req& request,uint32_t local_fep,const SEStoPDS_pkt& semantic_response) {
        if (request.delivery_mode!=RUDI) return false;
        PDStoNET_pkt response{}; response.src_fep=local_fep; response.dst_fep=request.source_fep;
        response.PDS_type=RUDI_header; response.SESpkt=semantic_response;
        response.PDS_header.RUDI_header={RUDI_RESP,
            semantic_response.bth_type==Semantic_Response_with_Data_Header?UET_HDR_RESPONSE_DATA:UET_HDR_RESPONSE,
            {static_cast<uint8_t>(request.rudi_congestion_marked),static_cast<uint8_t>(request.rudi_retransmission)},request.rudi_packet_id};
        return PDStoNet.push(response); // No retained response; source recovers a lost reply.
    }
    ~PDS_Manager() {
        lifetime_.reset();
        if (runtime_ && pending_deadline_timer_) runtime_->timers.cancel(pending_deadline_timer_);
    }
    TPDCProcessManager TPDC_Processmanager;
    IPDCProcessManager IPDC_Processmanager;
    pdc pdc_list[MAX_PDC * 2];             // PDC list
    std::queue<SES_PDS_req> SES_tx_req_q;  // SES layer send request queue
    std::queue<SES_PDS_rsp> SES_tx_rsp_q;  // SES layer send response queue
    ThreadSafeQueue<PDStoNET_pkt> Net_rx_pkt_q; // Network layer receive request queue

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
    uint64_t BitMap[MAX_PDC * 2] = {0}; // Task counters cover both initiator and target ID spaces.
    std::map<uint16_t, uint16_t> msg_map;                     // msgid mapping table
    std::queue<pend_node> pend_q;                             // Pending task queue

    // Optional network bridge driven by the owning PDS process loop. The
    // bridge is attached after a PacketChannel has been configured.
    void attachNetworkChannel(UET::NetworkLayer::PacketChannel& channel)
    {
        network_transport_ = std::make_unique<UET::NetworkLayer::PdsQueueTransport>(
            PDStoNet, Net_rx_pkt_q, channel);
    }

    size_t progressNetwork(std::chrono::milliseconds timeout)
    {
        return network_transport_ ? network_transport_->progress(timeout) : 0;
    }

    bool hasNetworkChannel() const { return network_transport_ != nullptr; }

    // Report whether at least one PDC has completed the protocol handshake.
    // This is used by integration code to distinguish allocation from a
    // completed network connection.
    bool hasEstablishedPDC()
    {
        for (uint16_t pdc_id = 0; pdc_id < MAX_PDC; ++pdc_id)
        {
            if (pdc_list[pdc_id].is_open.load() &&
                IPDC_Processmanager.isPDCEstablished(pdc_id))
                return true;
        }
        for (uint16_t pdc_id = MAX_PDC; pdc_id < MAX_PDC * 2; ++pdc_id)
        {
            if (pdc_list[pdc_id].is_open.load() &&
                TPDC_Processmanager.isPDCEstablished(pdc_id))
                return true;
        }
        return false;
    }

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
        Net_rx_pkt_q.set_max_size(1024);
        PDCtoSES_req.set_max_size(512);
        PDCtoSES_rsp.set_max_size(512);
        LOG_INFO(__FUNCTION__, "Public queue initialization completed");

        // Pass public queue references to process managers
        TPDC_Processmanager.setPublicQueues(&PDStoNet, &PDCtoSES_req, &PDCtoSES_rsp, &PDC_close_q);
        IPDC_Processmanager.setPublicQueues(&PDStoNet, &PDCtoSES_req, &PDCtoSES_rsp, &PDC_close_q);
        LOG_INFO(__FUNCTION__, "Public queue references passed to process managers");
        // Wait 50ms
        if (!runtime_) std::this_thread::sleep_for(std::chrono::milliseconds(50));

        open_cnt = 0;
        pend_cnt = 0;
        closing_cnt = 0;
        event_cnt = 0;     // Event counter initialization
        pause_ses = false; // Initialize pause state to false

        LOG_INFO(__FUNCTION__, "=====================PDS Manager State Machine Initialization Completed=====================");

        return true;
    }

private:
    UET::Runtime::Services* runtime_ = nullptr;
    std::unique_ptr<UET::PDS::RudiInitiator> rudi_initiator_;
    std::deque<PDC_SES_rsp> rudi_results_;
    // A PDC ID is meaningful only within its peer endpoint tuple (§3.5.8).
    // IDs can collide across peers; validating just dpdcid would deliver a
    // forged or delayed packet into an unrelated connection.
    struct ConnectionIdentity {
        uint32_t local_endpoint = 0;
        uint32_t remote_endpoint = 0;
        uint16_t remote_pdc_id = 0;
        bool remote_pdc_known = false;
    };
    ConnectionIdentity connection_identities_[MAX_PDC * 2];
    std::map<UET::PDS::InitiatorPdcKey,uint16_t> tx_contexts_;
    std::map<std::tuple<uint32_t,uint32_t,uint16_t>,uint16_t> rx_contexts_;
    using OutgoingMessage=std::tuple<uint32_t,uint32_t,uint8_t,uint8_t,uint16_t>;
    std::set<OutgoingMessage> quiesced_messages_;
    std::map<uint16_t,std::deque<SES_PDS_req>> deferred_close_requests_;
    std::unique_ptr<UET::NetworkLayer::PdsQueueTransport> network_transport_;
    std::shared_ptr<int> lifetime_=std::make_shared<int>(0);
    UET::Runtime::TimerId pending_deadline_timer_=0;
    bool resource_check_due_=false, checking_resources_=false;

    uint16_t initiatorCapacity() const {
        return runtime_?std::min<uint16_t>(runtime_->initiator_context_limit,MAX_PDC-1):MAX_PDC-1;
    }
    uint16_t targetCapacity() const {
        return runtime_?std::min<uint16_t>(runtime_->target_context_limit,MAX_PDC):MAX_PDC;
    }
    void armPendingDeadline() {
        if (!runtime_) return;
        if (pending_deadline_timer_) runtime_->timers.cancel(pending_deadline_timer_);
        pending_deadline_timer_=0;
        if (pend_q.empty()) return;
        std::weak_ptr<int> life=lifetime_;
        pending_deadline_timer_=runtime_->timers.at(pend_q.front().deadline_ns,[this,life] {
            if (life.expired()) return;
            pending_deadline_timer_=0;
            resource_check_due_=true;
            if (runtime_->wake) runtime_->wake();
        });
    }
    void rejectPendingMessage(const SES_PDS_req& request) {
        const auto& header=request.pkt.bth_header.Standard_Header;
        if (runtime_ && runtime_->pdc_event)
            runtime_->pdc_event({UET::Runtime::PdcEventKind::RequestRejected,UINT16_MAX,
                request.dst_fep,0,0,header.job_id,header.msg_id,UET::Runtime::PdcFailureReason::ResourcesUnavailable});
        // A fragmented operation is one application request. Remove all of its
        // unsent fragments before SES is allowed to release its message ID.
        const auto same_message=[&](const SES_PDS_req& queued) {
            const auto& other=queued.pkt.bth_header.Standard_Header;
            return queued.dst_fep==request.dst_fep && other.job_id==header.job_id && other.msg_id==header.msg_id;
        };
        std::queue<pend_node> retained;
        while (!pend_q.empty()) {
            auto node=std::move(pend_q.front()); pend_q.pop();
            if (!same_message(node.tx_req)) retained.push(std::move(node));
        }
        pend_q=std::move(retained); pend_cnt=static_cast<int>(pend_q.size());
        std::queue<SES_PDS_req> retained_requests;
        while (!SES_tx_req_q.empty()) {
            auto queued=std::move(SES_tx_req_q.front()); SES_tx_req_q.pop();
            if (!same_message(queued)) retained_requests.push(std::move(queued));
        }
        SES_tx_req_q=std::move(retained_requests);
    }

public:

    bool progressOne() {
        if (!runtime_) throw std::logic_error("manual progress requires injected runtime");
        const bool queued = !SES_tx_rsp_q.empty() || !Net_rx_pkt_q.empty() ||
                            !SES_tx_req_q.empty() || !PDC_close_q.empty() || resource_check_due_;
        if (queued) mainChk();
        const bool initiator = IPDC_Processmanager.progressOne();
        const bool target = TPDC_Processmanager.progressOne();
        const bool rudi=rudi_initiator_ && rudi_initiator_->progress();
        return queued || initiator || target || rudi;
    }

    // IDLE, TX_READY, TX_PROCESSING, PDC and ERROR -> idle
    void mainChk()
    {
        resource_check_due_=false;
        if (!SES_tx_rsp_q.empty()) sesTxRsp();
        // A terminated instance must be retired before another queued message
        // can select its ID. Otherwise CLOSED could be mistaken for a fresh SYN
        // on an instance whose generation has not yet been advanced.
        else if (!PDC_close_q.empty()) PDCClose();
        else if (!Net_rx_pkt_q.empty()) rxPkt();
        else if (!SES_tx_req_q.empty()) SESTxReq();
        resourceCheck();
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
        PDStoNET_pkt received_packet{};
        if (!Net_rx_pkt_q.pop(received_packet)) return;
        // Optimized wire decoding is available to parsers/oracles before its
        // PSN-based SES association is enabled. Do not reinterpret that union
        // as Standard_Header, allocate a PDC, or acknowledge an unsupported
        // semantic request/response. Native capability discovery stays false.
        if (!received_packet.trimmed && (received_packet.SESpkt.bth_type==Optimized_Header ||
            received_packet.SESpkt.bth_type==Small_Message_RMA_Header ||
            received_packet.SESpkt.bth_type==Optimized_Response_with_Data_Header)) { ++event_cnt; return; }

        if (received_packet.PDS_type==RUDI_header) {
            const auto& transport=received_packet.PDS_header.RUDI_header;
            if (transport.type==RUDI_RESP) {
                if (rudi_initiator_) rudi_initiator_->receive(received_packet);
            } else if (transport.type==RUDI_REQ) {
                if (received_packet.trimmed) { sendRudiNack(received_packet,
                    received_packet.trimmed_last_hop?UET_TRIMMED_LASTHOP:UET_TRIMMED); return; }
                PDC_SES_req request{}; request.PDCID=UINT16_MAX; request.delivery_mode=RUDI;
                request.source_fep=received_packet.src_fep; request.next_hdr=transport.next_hdr;
                request.rudi_packet_id=transport.pkt_id; request.rudi_retransmission=transport.flags.retx;
                request.rudi_congestion_marked=received_packet.network_ecn==3;
                request.pkt=std::move(received_packet.SESpkt);
                if (!PDCtoSES_req.push(request)) sendRudiNack(received_packet,UET_NO_PKT_BUFFER);
            }
            return; // Never allocate a PDC, even for duplicates or malformed SES.
        }
        if (received_packet.PDS_type==nack_header && received_packet.PDS_header.nack_header.flags.nt) {
            if (rudi_initiator_) rudi_initiator_->receive(received_packet);
            return; // RUDI NACK IDs are not PDC sequence numbers.
        }
        if (!received_packet.trimmed && received_packet.PDS_type==RUOD_cp_header &&
            received_packet.PDS_header.RUOD_cp_header.ctl_type>=10) {
            // Protect direct protocol-queue adapters as well as wire ingress.
            // Unknown CPs may have PSN=0; sending a NACK or learning a peer
            // from them would violate §3.5.11.3 and corrupt connection state.
            if (runtime_) runtime_->pds_error_counters.record_invalid_control_type();
            ++event_cnt; return;
        }
        if (received_packet.trimmed) {
            // Trimmed headers are not authenticated by the missing CRC. Resolve
            // only an already-bound tuple for NACK generation; never allocate
            // a PDC or learn a new peer ID from this packet (§3.5.15.1).
            if (received_packet.PDS_type!=RUOD_req_header) { ++event_cnt; return; }
            const auto& request=received_packet.PDS_header.RUOD_req_header;
            uint16_t existing=UINT16_MAX;
            if (request.flags.syn) {
                const auto found=rx_contexts_.find({received_packet.src_fep,received_packet.dst_fep,request.spdcid});
                if (found!=rx_contexts_.end()) existing=found->second;
            } else existing=request.dpdcid;
            if (existing<MAX_PDC*2 && pdc_list[existing].is_open) {
                const auto& identity=connection_identities_[existing];
                if (identity.remote_pdc_known && identity.remote_pdc_id==request.spdcid &&
                    identity.remote_endpoint==received_packet.src_fep && identity.local_endpoint==received_packet.dst_fep) {
                    fwdPkt2PDC(&received_packet,existing); return;
                }
            }
            PDStoNet.push(UET::PDS::trimmed_negative_ack(received_packet));
            return;
        }
        if (received_packet.PDS_type == UUD_req_header) {
            // §3.5.7.5: datagrams bypass connection allocation, sequence
            // tracking and acknowledgements. SES validates the operation.
            if (received_packet.PDS_header.UUD_req_header.type != UUD_REQ) return;
            PDC_SES_req datagram{};
            datagram.PDCID=UINT16_MAX; datagram.delivery_mode=UUD;
            datagram.source_fep=received_packet.src_fep;
            datagram.next_hdr=received_packet.PDS_header.UUD_req_header.next_hdr;
            datagram.pkt=std::move(received_packet.SESpkt);
            PDCtoSES_req.push(datagram);
            return;
        }
        if (!checkRxPkt(&received_packet)) { ++event_cnt; return; }

        const bool is_request = received_packet.PDS_type == RUOD_req_header;
        const bool is_control = received_packet.PDS_type == RUOD_cp_header;
        const bool is_acknowledgement = received_packet.PDS_type == RUOD_ack_header;
        const bool is_negative_acknowledgement = received_packet.PDS_type == nack_header;
        const bool starts_connection = is_request
            ? received_packet.PDS_header.RUOD_req_header.flags.syn
            : is_control && received_packet.PDS_header.RUOD_cp_header.flags.syn;
        const auto remote_pdc_id = getSPDCID(received_packet);
        uint16_t local_pdc_id = UINT16_MAX;
        if (is_request) local_pdc_id = received_packet.PDS_header.RUOD_req_header.dpdcid;
        else if (is_control) local_pdc_id = received_packet.PDS_header.RUOD_cp_header.dpdcid;
        else if (is_acknowledgement) local_pdc_id = received_packet.PDS_header.RUOD_ack_header.dpdcid;
        else if (is_negative_acknowledgement) local_pdc_id = received_packet.PDS_header.nack_header.dpdcid;

        if (is_request && starts_connection && runtime_ && runtime_->standard_wire) {
            // §3.5.12.1: outside RODL, SES requests use only the forward
            // direction; READ/atomic response data uses only the return
            // direction. Drop an illegal combination before allocation or
            // peer-ID learning (local malformed-direction policy).
            if (received_packet.SESpkt.bth_type!=Standard_Header) {
                ++event_cnt; return;
            }
        }

        if (starts_connection) {
            if (is_control && received_packet.PDS_header.RUOD_cp_header.ctl_type!=Noop &&
                received_packet.PDS_header.RUOD_cp_header.ctl_type!=Negotiation) {
                sendNack(&received_packet,UET_PDC_HDR_MISMATCH); return;
            }
            if (!remote_pdc_id) {
                // §3.5.8.2 reserves ID zero for replies without a valid PDC.
                // A SYN must never create a context under that identity.
                ++event_cnt; sendNack(&received_packet,UET_PDC_HDR_MISMATCH); return;
            }
            // §3.5.8.2 step 3.d.i: plaintext startup does not validate the
            // new Start_PSN against a retired peer's sequence floor. Random
            // local-ID reuse across other peers can cross half the space.
            // Live-context SYN/identity/window checks still apply below;
            // authenticated anti-replay belongs to the TSS start methods.
            // SYN carries pdc_info/psn_off in place of dpdcid. Resolve it by
            // {source FEP, destination FEP, source PDCID}, never by that union.
            local_pdc_id = muxRx2PDCID(received_packet.src_fep,
                                     received_packet.dst_fep, remote_pdc_id);
            if (local_pdc_id >= MAX_PDC * 2) {
                sendNack(&received_packet,UET_NO_PDC_AVAIL);
                return;
            }
            if (!pdc_list[local_pdc_id].is_open) {
                const bool ordered=is_request?received_packet.PDS_header.RUOD_req_header.type==ROD_REQ:
                    received_packet.PDS_header.RUOD_cp_header.flags.pdc_type==1;
                const auto initial_offset=is_request?received_packet.PDS_header.RUOD_req_header.psn_off:
                    received_packet.PDS_header.RUOD_cp_header.psn_off;
                const auto initial_range=runtime_ && runtime_->standard_wire?runtime_->psn_ranges.initial_range():Default_MPR;
                // A new RUD receive window starts at Start_PSN-1. Reject a
                // packet beyond that window before allocating a PDC: ordinary
                // NACKs cannot create one (§3.5.8.2). ROD gaps are the explicit
                // exception and are handled by the newly allocated T_PDC.
                if (!ordered && initial_offset>=initial_range) {
                    ++event_cnt; sendNack(&received_packet,UET_PSN_OOR_WINDOW); return;
                }
                std::optional<PDC_SES_req> reserved_message;
                if (is_request && runtime_ && runtime_->semantic_admission) {
                    const auto& header=received_packet.PDS_header.RUOD_req_header;
                    const auto mode=header.type==RUD_REQ?RUD:ROD;
                    // A ROD gap may allocate a PDC and return ROD_OOO, but it
                    // does not deliver a message. Reserve SES state only for
                    // a first packet that can enter the new receive window.
                    const bool can_deliver=mode==RUD?header.psn_off<initial_range:header.psn_off==0;
                    if (can_deliver) {
                        const auto request=UET::PDS::semantic_admission_request(received_packet,local_pdc_id,
                            received_packet.src_fep,mode,header.psn-header.psn_off);
                        const auto admission=runtime_->semantic_admission(request);
                        if (admission==UET::Runtime::SemanticAdmission::Rejected ||
                            admission==UET::Runtime::SemanticAdmission::NoSynchronizationState) {
                            // §3.5.8.2 step 3.c: resource refusal does not
                            // create a PDC, so this NACK carries SPDCID=0.
                            const auto reason=admission==UET::Runtime::SemanticAdmission::NoSynchronizationState?UET_NO_SES_SYNC_AVAIL:UET_NO_SES_MSG_AVAIL;
                            ++event_cnt; sendNack(&received_packet,reason); return;
                        }
                        if (admission==UET::Runtime::SemanticAdmission::ReservedMessage ||
                            admission==UET::Runtime::SemanticAdmission::ReservedPacket) reserved_message=request;
                    }
                }
                if (!allocPDC(local_pdc_id,received_packet.src_fep,received_packet.dst_fep)) {
                    if (reserved_message && runtime_->cancel_semantic_reservation)
                        runtime_->cancel_semantic_reservation(*reserved_message);
                    sendNack(&received_packet,UET_NO_PDC_AVAIL); return;
                }
            }
        }

        if (local_pdc_id >= MAX_PDC * 2 || !pdc_list[local_pdc_id].is_open) {
            // Never answer an unexpected ACK/NACK with another NACK. Only
            // requests and controls can elicit this response (§3.5.12.7).
            const bool unbound_probe=is_control && received_packet.PDS_header.RUOD_cp_header.ctl_type==Probe;
            if (!unbound_probe && (is_request || is_control)) sendNack(&received_packet,UET_INV_DPDCID);
            return;
        }
        auto& identity = connection_identities_[local_pdc_id];
        if (!identity.remote_pdc_known && local_pdc_id<MAX_PDC && (is_acknowledgement || is_negative_acknowledgement)) {
            const uint32_t sequence=is_acknowledgement
                ? received_packet.PDS_header.RUOD_ack_header.cack_psn+received_packet.PDS_header.RUOD_ack_header.ack_psn_off
                : received_packet.PDS_header.nack_header.nack_psn;
            if (!IPDC_Processmanager.hasOutstandingPacket(local_pdc_id,sequence)) return;
        }
        const bool establishment_failure = is_negative_acknowledgement && remote_pdc_id == 0;
        if (identity.local_endpoint != received_packet.dst_fep ||
            identity.remote_endpoint != received_packet.src_fep ||
            (identity.remote_pdc_known && identity.remote_pdc_id != remote_pdc_id && !establishment_failure)) {
            const bool unbound_probe=is_control && received_packet.PDS_header.RUOD_cp_header.ctl_type==Probe;
            if (!unbound_probe && (is_request || is_control)) sendNack(&received_packet,UET_PDC_HDR_MISMATCH);
            return;
        }
        if (is_request && runtime_ && runtime_->standard_wire) {
            // An unknown DPDCID or mismatched FA must get its mandated NACK
            // first (§3.5.8.2). Only an existing, correctly addressed PDC tells
            // us which local direction this request would use.
            const bool forward=local_pdc_id>=MAX_PDC;
            if ((forward && received_packet.SESpkt.bth_type!=Standard_Header) ||
                (!forward && received_packet.SESpkt.bth_type!=Semantic_Response_with_Data_Header)) {
                ++event_cnt; return;
            }
        }
        if (!establishment_failure && !identity.remote_pdc_known) {
            identity.remote_pdc_id = remote_pdc_id;
            identity.remote_pdc_known = true;
        }
        fwdPkt2PDC(&received_packet,local_pdc_id);
    }

    /**
     * @brief Check if received packet is valid
     * @param rx Pointer to received PDStoNET_pkt structure, containing received packet information
     * @return true if packet is valid, false otherwise
     */
    bool checkRxPkt(PDStoNET_pkt* packet)
    {
        if (!packet) return false;
        switch (packet->PDS_type) {
        case RUOD_req_header:
            return packet->PDS_header.RUOD_req_header.type == ROD_REQ ||
                   packet->PDS_header.RUOD_req_header.type == RUD_REQ;
        case RUOD_cp_header: {
            const auto& control=packet->PDS_header.RUOD_cp_header;
            const bool carries_mode=control.ctl_type==Noop || control.ctl_type==Negotiation;
            // RODL is not enabled yet. Check the full two-bit field before
            // allocating a context; never reinterpret 10/11 as RUD or ROD.
            return control.type==CP && (!carries_mode || control.flags.pdc_type<=1);
        }
        case RUOD_ack_header:
            return (packet->PDS_header.RUOD_ack_header.type==ACK || packet->PDS_header.RUOD_ack_header.type==ACK_CC) &&
                packet->PDS_header.RUOD_ack_header.flags.req!=3;
        case nack_header:
            return packet->PDS_header.nack_header.type == NACK &&
                   !packet->PDS_header.nack_header.flags.nt &&
                   UET::PDS::negative_acknowledgment_policy(packet->PDS_header.nack_header.nack_code).has_value();
        default: return false;
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
            return UET_INV_DPDCID; // An unknown connection is not evidence of trimming.
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
        PDStoNET_pkt nack_pkt{};
        nack_pkt.src_fep = rx->dst_fep;
        nack_pkt.dst_fep = rx->src_fep;
        nack_pkt.PDS_type = PDS_header_type::nack_header;
        nack_pkt.SESpkt = {}; // NACK packet does not carry SES data
        nack_pkt.PDS_header.nack_header.type = PDS_type::NACK;
        nack_pkt.PDS_header.nack_header.next_hdr = PDS_next_hdr::UET_HDR_NONE;
        nack_pkt.wire_entropy=rx->wire_entropy;
        nack_pkt.PDS_header.nack_header.flags.m = rx->network_ecn==3;
        nack_pkt.PDS_header.nack_header.flags.retx = rx->PDS_type==RUOD_cp_header?
            rx->PDS_header.RUOD_cp_header.flags.retx:rx->PDS_header.RUOD_req_header.flags.retx;
        nack_pkt.PDS_header.nack_header.flags.nt = 0;
        nack_pkt.PDS_header.nack_header.nack_code = nack_type;
        nack_pkt.PDS_header.nack_header.vendor_code = 0; // Unknown purpose
        nack_pkt.PDS_header.nack_header.nack_psn = rx->PDS_type == RUOD_cp_header
            ? rx->PDS_header.RUOD_cp_header.psn : rx->PDS_header.RUOD_req_header.psn;
        // TODO: If PDC establishment error, set spdcid to 0 here
        nack_pkt.PDS_header.nack_header.spdcid = 0; // No matching local PDC exists.
        nack_pkt.PDS_header.nack_header.dpdcid = getSPDCID(*rx);
        nack_pkt.PDS_header.nack_header.payload = 0;
        // Temporarily put in send queue like this?
        PDStoNet.push(nack_pkt);
        LOG_INFO("send_nack", "Sending NACK packet, NACK type: " + std::to_string(nack_type));
    }

    void sendRudiNack(const PDStoNET_pkt& received,PDS_Nack_Codes code) {
        PDStoNET_pkt response{}; response.PDS_type=nack_header;
        response.src_fep=received.dst_fep; response.dst_fep=received.src_fep;
        auto& nack=response.PDS_header.nack_header;
        nack.type=NACK; nack.next_hdr=UET_HDR_NONE; nack.flags.nt=1;
        nack.flags.m=received.network_ecn==3; nack.flags.retx=received.PDS_header.RUDI_header.flags.retx;
        nack.nack_code=code; nack.nack_pkt_id=received.PDS_header.RUDI_header.pkt_id;
        PDStoNet.push(response); // Reserved PDC IDs/payload remain zero (Table3-49).
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
        if (tx.mode==RUDI) {
            if (!submitRudi(tx)) rejectPendingMessage(tx);
            return; // Generic queue adapters must never allocate a RUDI PDC either.
        }
        if (tx.mode == UUD) {
            PDStoNET_pkt datagram{};
            datagram.src_fep=tx.src_fep; datagram.dst_fep=tx.dst_fep;
            datagram.PDS_type=UUD_req_header;
            datagram.PDS_header.UUD_req_header={UUD_REQ,tx.next_hdr};
            datagram.SESpkt=std::move(tx.pkt); datagram.local_tx_handle=tx.tx_pkt_handle;
            PDStoNet.push(datagram);
            return;
        }
        if (!tryForwardRequest(tx)) txOORPendEnqueue(&tx);
    }

    // Allocation and resource retry use exactly the same path. An established
    // context remains usable even when every other ID in its pool is occupied.
    bool tryForwardRequest(SES_PDS_req& request) {
        const auto& semantic=request.pkt.bth_header.Standard_Header;
        uint16_t local_pdc;
        const UET::PDS::PdcMappingIdentity identity{request.source_pid,
            static_cast<uint16_t>(semantic.PIDonFEP),static_cast<uint16_t>(semantic.resource_index)};
        if (!assignPDC(semantic.job_id,request.dst_fep,request.tc,request.mode,semantic.msg_id,
                       &local_pdc,request.src_fep,identity)) return false;
        const OutgoingMessage message{semantic.job_id,request.dst_fep,request.tc,request.mode,semantic.msg_id};
        if (quiesced_messages_.count(message) ||
            (semantic.som && IPDC_Processmanager.isConnectionClosing(local_pdc))) {
            // §3.5.8.3: finish existing messages before starting a new context.
            quiesced_messages_.insert(message);
            deferred_close_requests_[local_pdc].push_back(std::move(request));
            return true;
        }
        if (!PDCOpen(local_pdc) && !allocPDC(local_pdc,request.dst_fep,request.src_fep,static_cast<pdc_mode>(request.mode))) return false;
        if (semantic.som && request.establish_with_control &&
            !IPDC_Processmanager.openWithControl(local_pdc,static_cast<pdc_mode>(request.mode),false)) return false;
        fwdPkt2PDC(&request,local_pdc);
        return true;
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
    bool allocPDC(uint16_t pdc_id, uint32_t dst_fep, uint32_t src_fep,pdc_mode delivery_mode=ROD)
    {
        // PDC application logic
        // Simple simulation here, actual logic needs implementation based on specific requirements
        if (!pdc_id || pdc_id >= MAX_PDC * 2) return false;
        if (pdc_id<MAX_PDC && IPDC_Processmanager.getActiveProcessCount()>=initiatorCapacity()) return false;
        if (pdc_id>=MAX_PDC && TPDC_Processmanager.getActiveProcessCount()>=targetCapacity()) return false;
        if (!pdc_list[pdc_id].is_open)
        {
            connection_identities_[pdc_id] = {src_fep,dst_fep,0,false};
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
                if (IPDC_Processmanager.createIPDCProcess(pdc_id, dst_fep, src_fep,delivery_mode))
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
        // Both ID pools belong to this host: initiators occupy [0,MAX_PDC),
        // targets [MAX_PDC,2*MAX_PDC). Return data uses the latter pool.
        if (pdc_id < 0 || pdc_id >= MAX_PDC*2)
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
        const size_t limit=runtime_?runtime_->pending_request_limit:MAX_PEND;
        if (pend_q.size()>=limit) {
            rejectPendingMessage(*tx);
            armPendingDeadline();
            return;
        }
        pend_q.push(createPendNode(*tx));
        pend_cnt=static_cast<int>(pend_q.size());
        pause_ses=pendQFull();
        resourceCheck();
    }

    /**
     * @brief Check if pending queue is full
     * @return true if pending queue is full, false otherwise
     */
    bool pendQFull()
    {
        return pend_q.size() >= (runtime_?runtime_->pending_request_limit:MAX_PEND); // If pending queue is full, return true
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
        auto pend_start = runtime_
            ? std::chrono::steady_clock::time_point(std::chrono::nanoseconds(runtime_->clock.now()))
            : std::chrono::steady_clock::now();
        uint32_t pend_start_ms = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::milliseconds>(pend_start.time_since_epoch()).count());
        uint32_t pend_time = Pend_Time;
        auto pend_end = pend_start + std::chrono::milliseconds(pend_time);
        uint32_t pend_end_ms = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::milliseconds>(pend_end.time_since_epoch()).count());
        LOG_INFO("create_pend_node", "Wait start time: " + std::to_string(pend_start_ms));
        LOG_INFO("create_pend_node", "Wait end time: " + std::to_string(pend_end_ms));
        pend_node node = {tx, pend_time, pend_start_ms, pend_end_ms};
        if (runtime_) node.deadline_ns=UET::Runtime::add_time(runtime_->clock.now(),runtime_->pending_request_timeout); // Create pend_node
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
        req.delivery_mode=static_cast<pdc_mode>(pkt->mode);
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
        if (!runtime_) std::this_thread::sleep_for(std::chrono::milliseconds(100));
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
        rsp.gtd_del = pkt->gtd_del;
        rsp.ses_nack = pkt->ses_nack;
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
        if (checking_resources_) return;
        checking_resources_=true;
        while (!pend_q.empty() && isPendNodeOverTime(pend_q.front())) {
            const auto expired=pend_q.front(); pend_q.pop();
            ++event_cnt;
            rejectPendingMessage(expired.tx_req);
        }
        while (!pend_q.empty()) {
            // Copy until accepted: a failed allocation leaves the original
            // deadline and queue order intact instead of restarting the timer.
            auto request=pend_q.front().tx_req;
            if (!tryForwardRequest(request)) break;
            pend_q.pop();
        }
        pend_cnt=static_cast<int>(pend_q.size());
        pause_ses=pendQFull();
        if (!pend_q.empty()) {
            // Simulator policy: reclaim one idle initiator context under
            // pressure. Targets are reclaimed only by their owning initiator.
            const int candidate=selectPDC2Close();
            if (candidate>=0 && IPDC_Processmanager.sendCloseReq(static_cast<uint16_t>(candidate))) ++closing_cnt;
        }
        armPendingDeadline();
        checking_resources_=false;
    }

    /**
     * @brief Check if head node has timed out
     * @param node Waiting node to check
     */
    void pendTimeOut(pend_node node)
    {
        ++event_cnt;
        rejectPendingMessage(node.tx_req);
        armPendingDeadline();
    }

    // Runtime nanoseconds avoid the legacy millisecond counter's wraparound.
    bool isPendNodeOverTime(pend_node node)
    {
        if (runtime_) return runtime_->clock.now()>=node.deadline_ns;
        auto pend_end = runtime_
            ? std::chrono::steady_clock::time_point(std::chrono::nanoseconds(runtime_->clock.now()))
            : std::chrono::steady_clock::now();
        uint32_t time_now_ms = static_cast<uint32_t>(std::chrono::duration_cast<std::chrono::milliseconds>(pend_end.time_since_epoch()).count());
        return static_cast<int32_t>(time_now_ms - node.end_time) >= 0;
    }

    /**
     * @brief Allocate PDC when receiving SES response packet
     * @return true if allocation successful, false otherwise
     */
    bool assignPDC(uint16_t msgid, uint16_t pdc_id)
    {
        if (pdc_id >= MAX_PDC * 2) return false;
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
    bool assignPDC(uint32_t job_id, uint32_t dest_fa, uint8_t trafficclass, uint8_t deliverymode,
                   uint16_t msgid, uint16_t *pdc_id,uint32_t source_fa=0,UET::PDS::PdcMappingIdentity identity={})
    {
        // Allocate PDC algorithm
        // Simple allocation here for now
        *pdc_id = muxTx2PDCID(job_id,dest_fa,trafficclass,deliverymode,source_fa,identity);
        LOG_INFO("assign_pdc", "Allocated PDC ID: " + std::to_string(*pdc_id));
        if (*pdc_id >= MAX_PDC * 2) return false;
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

    // Mode-specific selection tuple, including mandatory FA/TC/mode fields.
    int muxTx2PDCID(uint32_t job_id,uint32_t dest_fa,uint8_t trafficclass,uint8_t deliverymode,
                    uint32_t source_fa=0,UET::PDS::PdcMappingIdentity identity={})
    {
        const auto fields=runtime_?runtime_->pdc_mapping.fields(deliverymode==ROD):UET::PDS::PdcMappingFields{};
        const UET::PDS::InitiatorPdcKey key{source_fa,dest_fa,trafficclass,deliverymode,
            fields.include_job_id?job_id:0,fields.include_source_pid?identity.source_pid:uint16_t{0},
            fields.include_target_pid?identity.target_pid:uint16_t{0},
            fields.include_resource_index?identity.resource_index:uint16_t{0}};
        auto found = tx_contexts_.find(key);
        if (found != tx_contexts_.end() && pdc_list[found->second].is_open) return found->second;
        const uint16_t capacity=initiatorCapacity();
        if (!capacity) return -1;
        const auto hash_key=key.allocation_hash();
        const uint16_t first = crc16_hash(hash_key,CRC16_POLY1,HASH_SEED1) % capacity;
        for (uint16_t offset=0;offset<capacity;++offset) {
            const uint16_t id = 1+(first+offset)%capacity;
            if (!pdc_list[id].is_open) {
                for (auto old=tx_contexts_.begin();old!=tx_contexts_.end();)
                    if (old->second==id) old=tx_contexts_.erase(old); else ++old;
                tx_contexts_[key]=id; return id;
            }
        }
        return -1;
    }

    uint16_t muxRx2PDCID(uint32_t src_addr, uint32_t dest_addr, uint16_t spdcid)
    {
        const auto key = std::make_tuple(src_addr,dest_addr,spdcid);
        auto found = rx_contexts_.find(key);
        if (found != rx_contexts_.end() && pdc_list[found->second].is_open) return found->second;
        const uint16_t capacity=targetCapacity();
        if (!capacity) return UINT16_MAX;
        const uint64_t hash_key = (uint64_t{src_addr}<<32) ^ dest_addr ^ (uint64_t{spdcid}<<16);
        const uint16_t first = crc16_hash(hash_key,CRC16_POLY1,HASH_SEED1)%capacity;
        for (uint16_t offset=0;offset<capacity;++offset) {
            const uint16_t id = MAX_PDC+(first+offset)%capacity;
            if (!pdc_list[id].is_open) {
                for (auto old=rx_contexts_.begin();old!=rx_contexts_.end();)
                    if (old->second==id) old=rx_contexts_.erase(old); else ++old;
                rx_contexts_[key]=id; return id;
            }
        }
        return UINT16_MAX;
    }

    int selectPDC2Close()
    {
        // Select PDC to close
        // Selection logic can be implemented based on actual requirements, here simply return first open PDC
        for (int i = 0; i < MAX_PDC; i++)
        {

            if (pdc_list[i].is_open && !IPDC_Processmanager.isConnectionClosing(i))
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
                if (auto deferred=deferred_close_requests_.find(pdc_id);deferred!=deferred_close_requests_.end()) {
                    for (auto& request:deferred->second) {
                        const auto& semantic=request.pkt.bth_header.Standard_Header;
                        quiesced_messages_.erase({semantic.job_id,request.dst_fep,request.tc,request.mode,semantic.msg_id});
                        SES_tx_req_q.push(std::move(request));
                    }
                    deferred_close_requests_.erase(deferred);
                }
                pdc_list[pdc_id].is_open = false;
                open_cnt--;
                if (closing_cnt > 0) --closing_cnt;
                break;
            case PDC_TYPE::TPDC:
                LOG_INFO("pdc_close", "Closing TPDC ID: " + std::to_string(pdc_id));
                TPDC_Processmanager.stopTPDCProcess(pdc_id);
                pdc_list[pdc_id].is_open = false;
                open_cnt--;
                if (closing_cnt > 0) --closing_cnt;
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
        if (pdc_id < MAX_PDC)
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
