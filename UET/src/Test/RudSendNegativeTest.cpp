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

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "../Network_Layer/UDP_Network_Layer.hpp"
#include "../SES/SES.hpp"
#include "../logger/Logger.hpp"

using namespace UET::NetworkLayer;

namespace {

struct ResponseEvent {
    uint16_t message_id{0};
    uint8_t opcode{0};
    uint8_t return_code{0};
    uint32_t modified_length{0};
};

static bool should_reorder_send_packet(const PDStoNET_pkt& pkt)
{
    if (pkt.PDS_type != RUOD_req_header) {
        return false;
    }
    return pkt.PDS_header.RUOD_req_header.type == RUD_REQ &&
           pkt.PDS_header.RUOD_req_header.flags.syn == 0;
}

static bool is_semantic_response(const PDStoNET_pkt& pkt)
{
    return pkt.PDS_type == RUOD_ack_header &&
           pkt.PDS_header.RUOD_ack_header.next_hdr == UET_HDR_RESPONSE &&
           pkt.SESpkt.bth_type == Semantic_Response_Header;
}

static bool send_one_packet(UDPNetworkLayer& udp_tx,
                            UDPNetworkLayer& udp_rx,
                            const PDStoNET_pkt& pkt)
{
    return udp_tx.sendPacket(pkt, "127.0.0.1", udp_rx.getLocalPort()) >= 0;
}

static void fill_payload(std::vector<uint8_t>& buf, uint8_t seed)
{
    for (size_t i = 0; i < buf.size(); ++i) {
        buf[i] = static_cast<uint8_t>((seed + i) & 0xFF);
    }
}

struct LoopbackHarness {
    SESManager ses_manager;
    UDPNetworkLayer udp_rx;
    UDPNetworkLayer udp_tx;
    std::atomic<bool> rx_running{true};
    std::thread rx_thread;
    std::vector<ResponseEvent> responses;
    std::vector<PDStoNET_pkt> captured_requests;
    bool response_before_missing_chunk{false};
    bool has_held_pkt{false};
    PDStoNET_pkt held_pkt{};
    std::function<bool(const PDStoNET_pkt&)> drop_packet;

    explicit LoopbackHarness(uint16_t listen_port)
        : udp_rx(listen_port), udp_tx(0)
    {
        if (!udp_rx.initialize() || !udp_tx.initialize()) {
            throw std::runtime_error("failed to initialize UDP harness");
        }
        rx_thread = std::thread([this]() {
            while (rx_running.load()) {
                PDStoNET_pkt rx_pkt;
                if (udp_rx.receivePDStoNETPacket(50, rx_pkt)) {
                    ses_manager.pds_process_manager.pushNetworkPacket(rx_pkt);
                }
            }
        });
    }

    ~LoopbackHarness()
    {
        rx_running.store(false);
        if (rx_thread.joinable()) {
            rx_thread.join();
        }
    }

    void postRecv(uint64_t job_id, uint32_t src_fep, uint64_t base_addr, uint32_t buffer_len)
    {
        PostedRecvEntry recv_entry{};
        recv_entry.completion_key = (job_id << 8) ^ static_cast<uint64_t>(buffer_len);
        recv_entry.base_addr = base_addr;
        recv_entry.buffer_len = buffer_len;
        recv_entry.job_id = job_id;
        recv_entry.pdc_id = 0;
        recv_entry.src_fep = src_fep;
        ses_manager.postRecv(recv_entry);
    }

    void submitSend(const OperationMetadata& metadata)
    {
        ses_manager.lfbric_ses_q.push(metadata);
        ses_manager.mainChk();
    }

    const PDStoNET_pkt* latestCapturedRequest(uint64_t job_id,
                                              uint16_t msg_id,
                                              bool som_only = true) const
    {
        for (auto it = captured_requests.rbegin(); it != captured_requests.rend(); ++it) {
            if (it->PDS_type != RUOD_req_header || it->SESpkt.bth_type != Standard_Header) {
                continue;
            }
            const auto& hdr = it->SESpkt.bth_header.Standard_Header;
            if (hdr.job_id != job_id || hdr.msg_id != msg_id) {
                continue;
            }
            if (som_only && !hdr.som) {
                continue;
            }
            return &(*it);
        }
        return nullptr;
    }

    bool pumpOnce(bool reorder_send)
    {
        bool did_work = false;
        PDStoNET_pkt tx_pkt;
        if (ses_manager.pds_process_manager.popNetworkPacket(tx_pkt)) {
            if (tx_pkt.PDS_type == RUOD_req_header &&
                tx_pkt.SESpkt.bth_type == Standard_Header &&
                tx_pkt.SESpkt.bth_header.Standard_Header.opcode == SEND) {
                captured_requests.push_back(tx_pkt);
            }
            if (is_semantic_response(tx_pkt)) {
                const auto& hdr = tx_pkt.SESpkt.bth_header.Semantic_Response_Header;
                responses.push_back(ResponseEvent{
                    hdr.message_id,
                    hdr.opcode,
                    hdr.return_code,
                    hdr.modified_length,
                });
                if (has_held_pkt) {
                    response_before_missing_chunk = true;
                }
            }

            if (drop_packet && drop_packet(tx_pkt)) {
                did_work = true;
            } else if (reorder_send && should_reorder_send_packet(tx_pkt)) {
                if (!has_held_pkt) {
                    held_pkt = tx_pkt;
                    has_held_pkt = true;
                } else {
                    if (!send_one_packet(udp_tx, udp_rx, tx_pkt) ||
                        !send_one_packet(udp_tx, udp_rx, held_pkt)) {
                        return false;
                    }
                    has_held_pkt = false;
                }
            } else {
                if (has_held_pkt) {
                    if (!send_one_packet(udp_tx, udp_rx, held_pkt)) {
                        return false;
                    }
                    has_held_pkt = false;
                }
                if (!send_one_packet(udp_tx, udp_rx, tx_pkt)) {
                    return false;
                }
            }
            did_work = true;
        }

        ses_manager.mainChk();

        const auto status = ses_manager.pds_process_manager.getQueueStatus();
        did_work = did_work ||
                   status.pdc_to_net_count != 0 ||
                   status.net_pkt_count != 0 ||
                   status.pdc_to_ses_req_count != 0 ||
                   status.pdc_to_ses_rsp_count != 0 ||
                   status.ses_req_count != 0 ||
                   status.ses_rsp_count != 0;
        return did_work;
    }

    bool driveUntil(const std::function<bool()>& done, int timeout_ms, bool reorder_send)
    {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
        while (std::chrono::steady_clock::now() < deadline) {
            if (done()) {
                break;
            }
            const bool did_work = pumpOnce(reorder_send);
            if (!did_work) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }

        if (has_held_pkt) {
            if (!send_one_packet(udp_tx, udp_rx, held_pkt)) {
                return false;
            }
            has_held_pkt = false;
        }

        const auto tail_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(200);
        while (std::chrono::steady_clock::now() < tail_deadline) {
            const bool did_work = pumpOnce(false);
            if (done()) {
                return true;
            }
            if (!did_work) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }
        return done();
    }
};

static OperationMetadata make_send_metadata(uint32_t msg_id,
                                            uint64_t job_id,
                                            uint32_t src_fep,
                                            uint32_t dst_fep,
                                            const std::vector<uint8_t>& payload)
{
    OperationMetadata md{};
    md.op_type = SEND;
    md.s_pid_on_fep = src_fep;
    md.t_pid_on_fep = dst_fep;
    md.job_id = job_id;
    md.messages_id = msg_id;
    md.memory.rkey = 0x1234567890ABCDEFULL;
    md.memory.idempotent_safe = true;
    md.payload.start_addr = reinterpret_cast<uint64_t>(payload.data());
    md.payload.length = payload.size();
    md.payload.imm_data = 0xDEADBEEF;
    md.use_optimized_header = false;
    md.has_imm_data = true;
    md.delivery_mode = RUD;
    md.res_index = 0;
    return md;
}

static void reset_rud_resource_pool()
{
    configureSharedRudResourcePool(1024, 64, 1u << 20);
    resetRudRuntimeStats();
}

static bool run_unexpected_buffered_case()
{
    constexpr uint16_t kPort = 2891;
    constexpr uint64_t kJobId = 20001;
    constexpr uint32_t kSrcFep = 1001;
    constexpr uint32_t kDstFep = 2001;

    reset_rud_resource_pool();
    LoopbackHarness harness(kPort);
    std::vector<uint8_t> payload(4096);
    std::vector<uint8_t> recv_buf(payload.size(), 0);
    fill_payload(payload, 0x10);
    harness.submitSend(make_send_metadata(1, kJobId, kSrcFep, kDstFep, payload));

    const bool buffered_without_completion = harness.driveUntil(
        [&]() {
            return std::any_of(harness.responses.begin(),
                               harness.responses.end(),
                               [&](const ResponseEvent& rsp) {
                                   return rsp.message_id == 1 &&
                                          rsp.opcode == static_cast<uint8_t>(RSP_OP_CODE::UET_DEFAULT_RESPONSE) &&
                                          rsp.return_code == static_cast<uint8_t>(RSP_RETURN_CODE::RC_OK) &&
                                          rsp.modified_length == payload.size();
                               });
        },
        800,
        false);
    const bool early_semantic_success = buffered_without_completion;
    const bool recv_still_empty = std::all_of(recv_buf.begin(), recv_buf.end(), [](uint8_t v) { return v == 0; });
    const size_t response_count_before_post = harness.responses.size();
    const RudRuntimeStats pre_post_stats = getRudRuntimeStats();

    harness.postRecv(kJobId, kSrcFep, reinterpret_cast<uint64_t>(recv_buf.data()), recv_buf.size());
    const bool done = harness.driveUntil(
        [&]() {
            return recv_buf == payload;
        },
        3000,
        false);

    const bool single_semantic_response = harness.responses.size() == response_count_before_post;
    const bool semantic_only_before_post =
        pre_post_stats.send_semantic_accept_success >= 1 &&
        pre_post_stats.send_target_delivery_complete_success == 0;
    const bool ok = early_semantic_success && recv_still_empty && done &&
                    single_semantic_response && semantic_only_before_post;
    std::cout << "[RudSendNegativeTest] unexpected_buffered="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

static bool run_no_unexpected_resource_case()
{
    constexpr uint16_t kPort = 2894;
    constexpr uint64_t kJobId = 20004;
    constexpr uint32_t kSrcFep = 1001;
    constexpr uint32_t kDstFep = 2001;

    configureSharedRudResourcePool(1024, 0, 0);
    resetRudRuntimeStats();
    LoopbackHarness harness(kPort);
    std::vector<uint8_t> payload(4096);
    fill_payload(payload, 0x20);
    harness.submitSend(make_send_metadata(1, kJobId, kSrcFep, kDstFep, payload));

    const bool done = harness.driveUntil(
        [&]() {
            return std::any_of(harness.responses.begin(),
                               harness.responses.end(),
                               [](const ResponseEvent& rsp) {
                                   return rsp.message_id == 1 &&
                                          rsp.opcode == static_cast<uint8_t>(RSP_OP_CODE::UET_NACK) &&
                                          rsp.return_code == static_cast<uint8_t>(RSP_RETURN_CODE::RC_NO_MATCH) &&
                                          rsp.modified_length == 0;
                               });
        },
        3000,
        false);
    const RudRuntimeStats stats = getRudRuntimeStats();
    reset_rud_resource_pool();

    const bool ok = done && stats.failure_rc_no_match > 0 && stats.failure_rc_no_buffer == 0;
    std::cout << "[RudSendNegativeTest] no_unexpected_resource="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

static bool run_retry_after_no_match_case()
{
    constexpr uint16_t kPort = 2898;
    constexpr uint64_t kJobId = 20005;
    constexpr uint32_t kSrcFep = 1001;
    constexpr uint32_t kDstFep = 2001;

    configureSharedRudResourcePool(1024, 0, 0);
    resetRudRuntimeStats();
    LoopbackHarness harness(kPort);
    std::vector<uint8_t> payload(4096);
    std::vector<uint8_t> recv_buf(payload.size(), 0);
    fill_payload(payload, 0x44);
    harness.submitSend(make_send_metadata(1, kJobId, kSrcFep, kDstFep, payload));

    const bool saw_retry_signal = harness.driveUntil(
        [&]() {
            return std::any_of(harness.responses.begin(),
                               harness.responses.end(),
                               [](const ResponseEvent& rsp) {
                                   return rsp.message_id == 1 &&
                                          rsp.opcode == static_cast<uint8_t>(RSP_OP_CODE::UET_NACK) &&
                                          rsp.return_code == static_cast<uint8_t>(RSP_RETURN_CODE::RC_NO_MATCH);
                               });
        },
        1500,
        false);

    harness.postRecv(kJobId, kSrcFep, reinterpret_cast<uint64_t>(recv_buf.data()), recv_buf.size());
    const bool done = harness.driveUntil(
        [&]() {
            const bool saw_success = std::any_of(harness.responses.begin(),
                                                 harness.responses.end(),
                                                 [&](const ResponseEvent& rsp) {
                                                     return rsp.message_id == 1 &&
                                                            rsp.opcode == static_cast<uint8_t>(RSP_OP_CODE::UET_DEFAULT_RESPONSE) &&
                                                            rsp.return_code == static_cast<uint8_t>(RSP_RETURN_CODE::RC_OK) &&
                                                            rsp.modified_length == payload.size();
                                                 });
            return recv_buf == payload && saw_success;
        },
        4000,
        false);

    reset_rud_resource_pool();
    const bool ok = saw_retry_signal && done &&
                    std::any_of(harness.responses.begin(),
                                harness.responses.end(),
                                [&](const ResponseEvent& rsp) {
                                    return rsp.message_id == 1 &&
                                           rsp.opcode == static_cast<uint8_t>(RSP_OP_CODE::UET_DEFAULT_RESPONSE) &&
                                           rsp.return_code == static_cast<uint8_t>(RSP_RETURN_CODE::RC_OK) &&
                                           rsp.modified_length == payload.size();
                                });
    std::cout << "[RudSendNegativeTest] retry_after_no_match="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

static bool run_retry_probe_case()
{
    constexpr uint16_t kPort = 2903;
    constexpr uint64_t kJobId = 20009;
    constexpr uint32_t kSrcFep = 1001;
    constexpr uint32_t kDstFep = 2001;

    configureSharedRudResourcePool(1024, 0, 0);
    resetRudRuntimeStats();
    LoopbackHarness harness(kPort);
    std::vector<uint8_t> payload(4096);
    std::vector<uint8_t> recv_buf(payload.size(), 0);
    fill_payload(payload, 0x45);
    harness.submitSend(make_send_metadata(1, kJobId, kSrcFep, kDstFep, payload));

    SendRetryProbe retry_probe_after_no_match{};
    const bool saw_retry_probe = harness.driveUntil(
        [&]() {
            const bool saw_no_match = std::any_of(harness.responses.begin(),
                                                  harness.responses.end(),
                                                  [](const ResponseEvent& rsp) {
                                                      return rsp.message_id == 1 &&
                                                             rsp.opcode == static_cast<uint8_t>(RSP_OP_CODE::UET_NACK) &&
                                                             rsp.return_code == static_cast<uint8_t>(RSP_RETURN_CODE::RC_NO_MATCH);
                                                  });
            retry_probe_after_no_match = harness.ses_manager.querySendRetryProbe(kJobId, 1, kDstFep);
            return saw_no_match && retry_probe_after_no_match.present &&
                   retry_probe_after_no_match.retry_count >= 1;
        },
        2000,
        false);

    configureSharedRudResourcePool(1024, 64, 1u << 20);
    harness.postRecv(kJobId, kSrcFep, reinterpret_cast<uint64_t>(recv_buf.data()), recv_buf.size());
    const bool done = harness.driveUntil(
        [&]() {
            const bool saw_success = std::any_of(harness.responses.begin(),
                                                 harness.responses.end(),
                                                 [&](const ResponseEvent& rsp) {
                                                     return rsp.message_id == 1 &&
                                                            rsp.opcode == static_cast<uint8_t>(RSP_OP_CODE::UET_DEFAULT_RESPONSE) &&
                                                            rsp.return_code == static_cast<uint8_t>(RSP_RETURN_CODE::RC_OK) &&
                                                            rsp.modified_length == payload.size();
                                                 });
            const SendRetryProbe final_probe = harness.ses_manager.querySendRetryProbe(kJobId, 1, kDstFep);
            return recv_buf == payload && saw_success && !final_probe.present;
        },
        4000,
        false);

    const SendRetryProbe final_probe = harness.ses_manager.querySendRetryProbe(kJobId, 1, kDstFep);
    reset_rud_resource_pool();
    const bool ok = saw_retry_probe &&
                    retry_probe_after_no_match.retry_count >= 1 &&
                    done &&
                    !final_probe.present;
    std::cout << "[RudSendNegativeTest] retry_probe="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

static bool run_retry_success_late_duplicate_replay_case()
{
    constexpr uint16_t kPort = 2904;
    constexpr uint64_t kJobId = 20010;
    constexpr uint32_t kSrcFep = 1001;
    constexpr uint32_t kDstFep = 2001;

    configureSharedRudResourcePool(1024, 0, 0);
    resetRudRuntimeStats();
    LoopbackHarness harness(kPort);
    std::vector<uint8_t> payload(4096);
    std::vector<uint8_t> recv_buf(payload.size(), 0);
    fill_payload(payload, 0x46);
    harness.submitSend(make_send_metadata(1, kJobId, kSrcFep, kDstFep, payload));

    const bool saw_no_match = harness.driveUntil(
        [&]() {
            return std::any_of(harness.responses.begin(),
                               harness.responses.end(),
                               [](const ResponseEvent& rsp) {
                                   return rsp.message_id == 1 &&
                                          rsp.opcode == static_cast<uint8_t>(RSP_OP_CODE::UET_NACK) &&
                                          rsp.return_code == static_cast<uint8_t>(RSP_RETURN_CODE::RC_NO_MATCH);
                               });
        },
        1500,
        false);

    configureSharedRudResourcePool(1024, 64, 1u << 20);
    harness.postRecv(kJobId, kSrcFep, reinterpret_cast<uint64_t>(recv_buf.data()), recv_buf.size());
    const bool recovered = harness.driveUntil(
        [&]() {
            return recv_buf == payload &&
                   std::any_of(harness.responses.begin(),
                               harness.responses.end(),
                               [&](const ResponseEvent& rsp) {
                                   return rsp.message_id == 1 &&
                                          rsp.opcode == static_cast<uint8_t>(RSP_OP_CODE::UET_DEFAULT_RESPONSE) &&
                                          rsp.return_code == static_cast<uint8_t>(RSP_RETURN_CODE::RC_OK) &&
                                          rsp.modified_length == payload.size();
                               });
        },
        4000,
        false);

    const PDStoNET_pkt* captured = harness.latestCapturedRequest(kJobId, 1);
    PDStoNET_pkt replay_pkt{};
    const size_t response_count_before_replay = harness.responses.size();
    const RudResourceStats resource_before = getSharedRudResourceStats();
    const RudRuntimeStats runtime_before = getRudRuntimeStats();
    bool replay_sent = false;
    if (captured) {
        replay_pkt = *captured;
        replay_sent = send_one_packet(harness.udp_tx, harness.udp_rx, replay_pkt);
    }

    const bool replay_rc_ok = replay_sent && harness.driveUntil(
        [&]() {
            return std::any_of(harness.responses.begin() + static_cast<std::ptrdiff_t>(response_count_before_replay),
                               harness.responses.end(),
                               [&](const ResponseEvent& rsp) {
                                   return rsp.message_id == 1 &&
                                          rsp.opcode == static_cast<uint8_t>(RSP_OP_CODE::UET_DEFAULT_RESPONSE) &&
                                          rsp.return_code == static_cast<uint8_t>(RSP_RETURN_CODE::RC_OK) &&
                                          rsp.modified_length == payload.size();
                               });
        },
        3000,
        false);

    const bool replay_saw_no_match = std::any_of(
        harness.responses.begin() + static_cast<std::ptrdiff_t>(response_count_before_replay),
        harness.responses.end(),
        [](const ResponseEvent& rsp) {
            return rsp.message_id == 1 &&
                   rsp.opcode == static_cast<uint8_t>(RSP_OP_CODE::UET_NACK) &&
                   rsp.return_code == static_cast<uint8_t>(RSP_RETURN_CODE::RC_NO_MATCH);
        });
    const UnexpectedSendProbe unexpected_probe =
        harness.ses_manager.queryUnexpectedSendProbe(kJobId, 1, kSrcFep);
    const RudResourceStats resource_after = getSharedRudResourceStats();
    const RudRuntimeStats runtime_after = getRudRuntimeStats();
    reset_rud_resource_pool();

    const bool no_unexpected_growth =
        resource_after.unexpected_msgs_in_use == resource_before.unexpected_msgs_in_use &&
        runtime_after.unexpected_buffered_in_use == runtime_before.unexpected_buffered_in_use &&
        runtime_after.unexpected_semantic_accepted_in_use == runtime_before.unexpected_semantic_accepted_in_use &&
        runtime_after.unexpected_partial_in_use == runtime_before.unexpected_partial_in_use;
    const bool ok = saw_no_match &&
                    captured != nullptr &&
                    recovered &&
                    replay_sent &&
                    replay_rc_ok &&
                    !replay_saw_no_match &&
                    !unexpected_probe.present &&
                    recv_buf == payload &&
                    no_unexpected_growth;
    std::cout << "[RudSendNegativeTest] retry_success_late_duplicate_replay="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

static bool run_small_buffer_case()
{
    constexpr uint16_t kPort = 2892;
    constexpr uint64_t kJobId = 20002;
    constexpr uint32_t kSrcFep = 1001;
    constexpr uint32_t kDstFep = 2001;

    reset_rud_resource_pool();
    resetRudRuntimeStats();
    LoopbackHarness harness(kPort);
    std::vector<uint8_t> payload(4096);
    std::vector<uint8_t> recv_buf(1024, 0);
    fill_payload(payload, 0x30);
    harness.postRecv(kJobId, kSrcFep, reinterpret_cast<uint64_t>(recv_buf.data()), recv_buf.size());
    harness.submitSend(make_send_metadata(1, kJobId, kSrcFep, kDstFep, payload));

    const bool done = harness.driveUntil(
        [&]() {
            return std::any_of(harness.responses.begin(),
                               harness.responses.end(),
                               [](const ResponseEvent& rsp) {
                                   return rsp.message_id == 1 &&
                                          rsp.opcode == static_cast<uint8_t>(RSP_OP_CODE::UET_NACK) &&
                                          rsp.return_code == static_cast<uint8_t>(RSP_RETURN_CODE::RC_PARTIAL_WRITE);
                               });
        },
        3000,
        false);

    const bool untouched = std::all_of(recv_buf.begin(), recv_buf.end(), [](uint8_t v) { return v == 0; });
    const RudRuntimeStats stats = getRudRuntimeStats();
    const bool ok = done && untouched && stats.failure_rc_partial_write > 0;
    std::cout << "[RudSendNegativeTest] small_buffer="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

static bool run_fifo_match_case()
{
    constexpr uint16_t kPort = 2893;
    constexpr uint64_t kJobId = 20003;
    constexpr uint32_t kSrcFep = 1001;
    constexpr uint32_t kDstFep = 2001;

    reset_rud_resource_pool();
    resetRudRuntimeStats();
    LoopbackHarness harness(kPort);
    std::vector<uint8_t> payload_a(3072);
    std::vector<uint8_t> payload_b(2048);
    std::vector<uint8_t> recv_a(payload_a.size(), 0);
    std::vector<uint8_t> recv_b(payload_b.size(), 0);
    fill_payload(payload_a, 0x50);
    fill_payload(payload_b, 0x80);

    harness.postRecv(kJobId, kSrcFep, reinterpret_cast<uint64_t>(recv_a.data()), recv_a.size());
    harness.postRecv(kJobId, kSrcFep, reinterpret_cast<uint64_t>(recv_b.data()), recv_b.size());
    harness.submitSend(make_send_metadata(1, kJobId, kSrcFep, kDstFep, payload_a));
    harness.submitSend(make_send_metadata(2, kJobId, kSrcFep, kDstFep, payload_b));

    const bool done = harness.driveUntil(
        [&]() {
            const RudRuntimeStats stats = getRudRuntimeStats();
            return recv_a == payload_a && recv_b == payload_b &&
                   stats.send_semantic_accept_success == 2 &&
                   stats.send_target_delivery_complete_success == 2;
        },
        4000,
        false);

    const bool order_ok = (recv_a == payload_a) && (recv_b == payload_b);
    const RudRuntimeStats stats = getRudRuntimeStats();
    const bool ok = done && order_ok &&
                    stats.send_semantic_accept_success == 2 &&
                    stats.send_target_delivery_complete_success == 2;
    std::cout << "[RudSendNegativeTest] fifo_match="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

static bool run_partial_unexpected_timeout_case()
{
    constexpr uint16_t kPort = 2899;
    constexpr uint64_t kJobId = 20006;
    constexpr uint32_t kSrcFep = 1001;
    constexpr uint32_t kDstFep = 2001;
    constexpr int64_t kTimeoutMs = Base_RTO + (Base_RTO << 1) + (Base_RTO << 2) +
                                   (Base_RTO << 3) + (Base_RTO << 4) + (Base_RTO << 5) + 600;

    reset_rud_resource_pool();
    resetRudRuntimeStats();
    LoopbackHarness harness(kPort);
    std::vector<uint8_t> payload(5000);
    fill_payload(payload, 0x55);
    harness.drop_packet = [kJobId](const PDStoNET_pkt& pkt) {
        // Cold connections can emit the SEND tail chunk with SYN=1, so the
        // test must match the case's EOM packet semantically rather than by
        // post-establishment header shape.
        return pkt.PDS_type == RUOD_req_header &&
               pkt.SESpkt.bth_type == Standard_Header &&
               pkt.SESpkt.bth_header.Standard_Header.opcode == SEND &&
               pkt.SESpkt.bth_header.Standard_Header.eom == 1 &&
               pkt.SESpkt.bth_header.Standard_Header.job_id == kJobId &&
               pkt.SESpkt.bth_header.Standard_Header.msg_id == 1;
    };

    harness.submitSend(make_send_metadata(1, kJobId, kSrcFep, kDstFep, payload));
    const bool saw_unexpected_alloc = harness.driveUntil(
        [&]() { return getSharedRudResourceStats().unexpected_msgs_in_use > 0; },
        1500,
        false);

    const bool cleaned = harness.driveUntil(
        [&]() { return getSharedRudResourceStats().unexpected_msgs_in_use == 0; },
        static_cast<int>(kTimeoutMs),
        false);
    const bool no_semantic_response = harness.responses.empty();
    const RudRuntimeStats stats = getRudRuntimeStats();
    const bool ok = saw_unexpected_alloc && cleaned && no_semantic_response &&
                    stats.unexpected_partial_timeout_cleanups > 0 &&
                    stats.unexpected_buffered_in_use == 0 &&
                    stats.unexpected_partial_in_use == 0;
    std::cout << "[RudSendNegativeTest] partial_unexpected_timeout="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

static bool run_close_releases_buffered_state_case()
{
    constexpr uint16_t kPort = 2902;
    constexpr uint64_t kJobId = 20008;
    constexpr uint32_t kSrcFep = 1001;
    constexpr uint32_t kDstFep = 2001;

    reset_rud_resource_pool();
    resetRudRuntimeStats();
    bool semantic_ok = false;
    {
        LoopbackHarness harness(kPort);
        std::vector<uint8_t> payload(4096);
        fill_payload(payload, 0x77);
        harness.submitSend(make_send_metadata(1, kJobId, kSrcFep, kDstFep, payload));

        semantic_ok = harness.driveUntil(
            [&]() {
                const bool saw_rsp = std::any_of(harness.responses.begin(),
                                                 harness.responses.end(),
                                                 [&](const ResponseEvent& rsp) {
                                                     return rsp.message_id == 1 &&
                                                            rsp.opcode == static_cast<uint8_t>(RSP_OP_CODE::UET_DEFAULT_RESPONSE) &&
                                                            rsp.return_code == static_cast<uint8_t>(RSP_RETURN_CODE::RC_OK) &&
                                                            rsp.modified_length == payload.size();
                                                 });
                const RudResourceStats resource = getSharedRudResourceStats();
                return saw_rsp && resource.unexpected_msgs_in_use > 0;
            },
            4000,
            false);
    }

    const RudResourceStats resource = getSharedRudResourceStats();
    const RudRuntimeStats stats = getRudRuntimeStats();
    const bool cleaned = resource.arrival_blocks_in_use == 0 &&
                         resource.unexpected_msgs_in_use == 0 &&
                         stats.unexpected_buffered_in_use == 0 &&
                         stats.unexpected_semantic_accepted_in_use == 0 &&
                         stats.unexpected_partial_in_use == 0;

    const bool no_local_delivery = getRudRuntimeStats().send_target_delivery_complete_success == 0;
    const bool ok = semantic_ok && cleaned && no_local_delivery;
    std::cout << "[RudSendNegativeTest] close_releases_buffered_state="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

static bool run_arrival_block_release_case()
{
    constexpr uint16_t kPort = 2900;
    constexpr uint64_t kJobId = 20007;
    constexpr uint32_t kSrcFep = 1001;
    constexpr uint32_t kDstFep = 2001;
    constexpr size_t kChunkPayload = MAX_MTU - sizeof(SES_Standard_Header);
    constexpr size_t kPayloadLen = kChunkPayload * 64 + 32;

    reset_rud_resource_pool();
    resetRudRuntimeStats();
    std::vector<uint8_t> payload(kPayloadLen);
    std::vector<uint8_t> recv_buf(payload.size(), 0);
    fill_payload(payload, 0x66);
    bool saw_block_alloc = false;
    {
        LoopbackHarness harness(kPort);
        harness.postRecv(kJobId, kSrcFep, reinterpret_cast<uint64_t>(recv_buf.data()), recv_buf.size());
        harness.drop_packet = [](const PDStoNET_pkt& pkt) {
            return pkt.PDS_type == RUOD_req_header &&
                   pkt.SESpkt.bth_type == Standard_Header &&
                   pkt.SESpkt.bth_header.Standard_Header.opcode == SEND &&
                   pkt.SESpkt.bth_header.Standard_Header.eom == 1 &&
                   pkt.PDS_header.RUOD_req_header.flags.syn == 0;
        };

        harness.submitSend(make_send_metadata(1, kJobId, kSrcFep, kDstFep, payload));
        saw_block_alloc = harness.driveUntil(
            [&]() {
                const RudResourceStats stats = getSharedRudResourceStats();
                return stats.arrival_blocks_in_use > 0;
            },
            15000,
            false);
    }

    bool released = false;
    RudResourceStats resource_stats{};
    RudRuntimeStats stats{};
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (std::chrono::steady_clock::now() < deadline) {
        resource_stats = getSharedRudResourceStats();
        stats = getRudRuntimeStats();
        if (resource_stats.arrival_blocks_in_use == 0 && stats.arrival_block_release_count > 0) {
            released = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    const bool ok = saw_block_alloc && released;
    if (!ok) {
        std::cout << "[RudSendNegativeTest] arrival_debug saw_block_alloc=" << saw_block_alloc
                  << " arrival_in_use=" << resource_stats.arrival_blocks_in_use
                  << " arrival_peak=" << resource_stats.arrival_blocks_peak
                  << " release_count=" << stats.arrival_block_release_count
                  << std::endl;
    }
    std::cout << "[RudSendNegativeTest] arrival_block_release="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

} // namespace

int main()
{
    Logger::initialize("RudSendNegativeTest.log", LogLevel::DEBUG, 1, 1);

    const bool unexpected_ok = run_unexpected_buffered_case();
    const bool no_resource_ok = run_no_unexpected_resource_case();
    const bool retry_ok = run_retry_after_no_match_case();
    const bool retry_probe_ok = run_retry_probe_case();
    const bool retry_late_duplicate_ok = run_retry_success_late_duplicate_replay_case();
    const bool small_buf_ok = run_small_buffer_case();
    const bool fifo_ok = run_fifo_match_case();
    const bool partial_timeout_ok = run_partial_unexpected_timeout_case();
    const bool close_release_ok = run_close_releases_buffered_state_case();
    const bool ok = unexpected_ok && no_resource_ok && retry_ok && retry_probe_ok &&
                    retry_late_duplicate_ok && small_buf_ok && fifo_ok &&
                    partial_timeout_ok && close_release_ok;
    std::cout << (ok ? "RudSendNegativeTest PASS" : "RudSendNegativeTest FAIL") << std::endl;
    return ok ? 0 : 1;
}
