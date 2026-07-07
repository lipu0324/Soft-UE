#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <iostream>
#include <random>
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
    uint64_t job_id{0};
    uint16_t message_id{0};
    uint8_t opcode{0};
    uint8_t return_code{0};
    uint32_t modified_length{0};
};

static bool is_semantic_response(const PDStoNET_pkt& pkt)
{
    return pkt.PDS_type == RUOD_ack_header &&
           pkt.PDS_header.RUOD_ack_header.next_hdr == UET_HDR_RESPONSE &&
           pkt.SESpkt.bth_type == Semantic_Response_Header;
}

static bool is_reorderable_data_packet(const PDStoNET_pkt& pkt)
{
    if (pkt.PDS_type == RUOD_req_header) {
        return pkt.PDS_header.RUOD_req_header.type == RUD_REQ &&
               pkt.PDS_header.RUOD_req_header.flags.syn == 0;
    }
    if (pkt.PDS_type == RUOD_ack_header) {
        return pkt.PDS_header.RUOD_ack_header.next_hdr == UET_HDR_RESPONSE_DATA ||
               pkt.PDS_header.RUOD_ack_header.next_hdr == UET_HDR_RESPONSE_DATA_SMALL;
    }
    return false;
}

static bool send_one_packet(UDPNetworkLayer& udp_tx,
                            UDPNetworkLayer& udp_rx,
                            const PDStoNET_pkt& pkt)
{
    return udp_tx.sendPacket(pkt, "127.0.0.1", udp_rx.getLocalPort()) >= 0;
}

static void fill_pattern(std::vector<uint8_t>& buf, uint8_t seed)
{
    for (size_t i = 0; i < buf.size(); ++i) {
        buf[i] = static_cast<uint8_t>((seed + i) & 0xFF);
    }
}

struct SoakFailureContext {
    bool present{false};
    size_t op_index{0};
    const char* op_kind{"unknown"};
    uint64_t job_id{0};
    uint16_t msg_id{0};
    std::string stage;
};

class RudSoakHarness {
public:
    explicit RudSoakHarness(uint16_t listen_port)
        : udp_rx(listen_port), udp_tx(0), rng_(0xC0FFEE)
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

    ~RudSoakHarness()
    {
        rx_running.store(false);
        if (rx_thread.joinable()) {
            rx_thread.join();
        }
    }

    void setFaultModel(double reorder_probability, double drop_probability)
    {
        reorder_probability_ = reorder_probability;
        drop_probability_ = drop_probability;
    }

    void clearFaultModel()
    {
        reorder_probability_ = 0.0;
        drop_probability_ = 0.0;
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

    void submit(const OperationMetadata& metadata)
    {
        ses_manager.lfbric_ses_q.push(metadata);
        ses_manager.mainChk();
    }

    size_t responseCount() const
    {
        return responses.size();
    }

    const ResponseEvent* latestResponseFor(uint64_t job_id, uint16_t msg_id) const
    {
        for (auto it = responses.rbegin(); it != responses.rend(); ++it) {
            if (it->job_id == job_id && it->message_id == msg_id) {
                return &(*it);
            }
        }
        return nullptr;
    }

    bool sawReturnCodeFor(uint64_t job_id, uint16_t msg_id, uint8_t return_code) const
    {
        return std::any_of(responses.begin(),
                           responses.end(),
                           [&](const ResponseEvent& rsp) {
                               return rsp.job_id == job_id &&
                                      rsp.message_id == msg_id &&
                                      rsp.return_code == return_code;
                           });
    }

    bool sawSemanticResponseSince(size_t base_idx,
                                  uint64_t job_id,
                                  uint16_t msg_id,
                                  uint8_t opcode,
                                  uint8_t return_code,
                                  uint32_t modified_length) const
    {
        return std::any_of(responses.begin() + static_cast<std::ptrdiff_t>(base_idx),
                           responses.end(),
                           [&](const ResponseEvent& rsp) {
                               return rsp.job_id == job_id &&
                                      rsp.message_id == msg_id &&
                                      rsp.opcode == opcode &&
                                      rsp.return_code == return_code &&
                                      rsp.modified_length == modified_length;
                           });
    }

    bool driveUntil(const std::function<bool()>& done, int timeout_ms)
    {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
        while (std::chrono::steady_clock::now() < deadline) {
            if (done()) {
                break;
            }
            const bool did_work = pumpOnce();
            if (!did_work) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }

        if (has_held_pkt_) {
            if (!send_one_packet(udp_tx, udp_rx, held_pkt_)) {
                return false;
            }
            has_held_pkt_ = false;
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

    bool flushHeldPacket()
    {
        if (!has_held_pkt_) {
            return true;
        }
        if (!send_one_packet(udp_tx, udp_rx, held_pkt_)) {
            return false;
        }
        has_held_pkt_ = false;
        return true;
    }

    bool pumpWithoutFaults()
    {
        return pumpOnce(false);
    }

    SESManager ses_manager;

private:
    bool shouldDrop(const PDStoNET_pkt& pkt)
    {
        if (drop_probability_ <= 0.0 || !is_reorderable_data_packet(pkt)) {
            return false;
        }
        std::bernoulli_distribution dist(drop_probability_);
        return dist(rng_);
    }

    bool shouldReorder(const PDStoNET_pkt& pkt)
    {
        if (reorder_probability_ <= 0.0 || !is_reorderable_data_packet(pkt)) {
            return false;
        }
        std::bernoulli_distribution dist(reorder_probability_);
        return dist(rng_);
    }

    bool pumpOnce(bool allow_reorder = true)
    {
        bool did_work = false;
        PDStoNET_pkt tx_pkt;
        if (ses_manager.pds_process_manager.popNetworkPacket(tx_pkt)) {
            if (is_semantic_response(tx_pkt)) {
                const auto& hdr = tx_pkt.SESpkt.bth_header.Semantic_Response_Header;
                responses.push_back(ResponseEvent{
                    hdr.job_id,
                    hdr.message_id,
                    hdr.opcode,
                    hdr.return_code,
                    hdr.modified_length,
                });
            }

            if (shouldDrop(tx_pkt)) {
                did_work = true;
            } else if (allow_reorder && shouldReorder(tx_pkt)) {
                if (!has_held_pkt_) {
                    held_pkt_ = tx_pkt;
                    has_held_pkt_ = true;
                } else {
                    if (!send_one_packet(udp_tx, udp_rx, tx_pkt) ||
                        !send_one_packet(udp_tx, udp_rx, held_pkt_)) {
                        return false;
                    }
                    has_held_pkt_ = false;
                }
                did_work = true;
            } else {
                if (has_held_pkt_) {
                    if (!send_one_packet(udp_tx, udp_rx, held_pkt_)) {
                        return false;
                    }
                    has_held_pkt_ = false;
                }
                if (!send_one_packet(udp_tx, udp_rx, tx_pkt)) {
                    return false;
                }
                did_work = true;
            }
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

    UDPNetworkLayer udp_rx;
    UDPNetworkLayer udp_tx;
    std::atomic<bool> rx_running{true};
    std::thread rx_thread;
    std::vector<ResponseEvent> responses;
    std::mt19937 rng_;
    double reorder_probability_{0.0};
    double drop_probability_{0.0};
    bool has_held_pkt_{false};
    PDStoNET_pkt held_pkt_{};
};

static void reset_runtime_defaults()
{
    configureSharedRudResourcePool(16, 4, 1u << 16);
    resetRudRuntimeStats();
}

static int64_t soakUnexpectedTimeoutMs()
{
    int64_t total = 0;
    for (int retry = 0; retry <= Max_RTO_Retx_Cnt; ++retry) {
        total += static_cast<int64_t>(Base_RTO) * (1LL << retry);
    }
    return total;
}

static const char* soakOpKindName(size_t op_index)
{
    switch (op_index % 5) {
        case 0: return "send_expected";
        case 1: return "send_unexpected";
        case 2: return "send_retry";
        case 3: return "write";
        default: return "read";
    }
}

static void captureSoakFailure(RudSoakHarness& harness,
                               size_t op_index,
                               uint64_t job_id,
                               uint16_t msg_id,
                               const char* stage,
                               SoakFailureContext& failure)
{
    failure.present = true;
    failure.op_index = op_index;
    failure.op_kind = soakOpKindName(op_index);
    failure.job_id = job_id;
    failure.msg_id = msg_id;
    failure.stage = stage;

    const ResponseEvent* latest_rsp = harness.latestResponseFor(job_id, msg_id);
    const bool saw_rc_ok = harness.sawReturnCodeFor(job_id, msg_id, static_cast<uint8_t>(RSP_RETURN_CODE::RC_OK));
    const bool saw_rc_no_match =
        harness.sawReturnCodeFor(job_id, msg_id, static_cast<uint8_t>(RSP_RETURN_CODE::RC_NO_MATCH));
    const RequestTerminalProbe request_probe =
        harness.ses_manager.queryRequestTerminalProbe(job_id, msg_id, 2001);
    const RequestTxProbe tx_probe =
        harness.ses_manager.queryRequestTxProbe(job_id, msg_id, 2001);
    const UnexpectedSendProbe unexpected_probe =
        harness.ses_manager.queryUnexpectedSendProbe(job_id, msg_id, 1001);
    const SendRetryProbe retry_probe =
        harness.ses_manager.querySendRetryProbe(job_id, msg_id, 2001);
    const RudResourceStats resource = getSharedRudResourceStats();
    const RudRuntimeStats runtime = getRudRuntimeStats();

    std::cout << "[RudSoakTest] failure_snapshot"
              << " op_index=" << op_index
              << " op_kind=" << failure.op_kind
              << " job_id=" << job_id
              << " msg_id=" << msg_id
              << " stage=" << stage
              << " saw_rc_ok=" << (saw_rc_ok ? "yes" : "no")
              << " saw_rc_no_match=" << (saw_rc_no_match ? "yes" : "no")
              << " latest_opcode="
              << (latest_rsp ? std::to_string(static_cast<unsigned>(latest_rsp->opcode)) : "none")
              << " latest_return_code="
              << (latest_rsp ? std::to_string(static_cast<unsigned>(latest_rsp->return_code)) : "none")
              << " latest_modified_length="
              << (latest_rsp ? std::to_string(latest_rsp->modified_length) : "none")
              << " request_retry_present=" << (request_probe.retry_present ? "yes" : "no")
              << " request_terminalized=" << (request_probe.terminalized ? "yes" : "no")
              << " request_terminal_reason="
              << (request_probe.terminalized ? std::to_string(static_cast<unsigned>(request_probe.reason)) : "none")
              << " request_tx_present=" << (tx_probe.present ? "yes" : "no")
              << " request_pending_psn_count=" << tx_probe.pending_psn_count
              << " request_pending_control_only=" << (tx_probe.pending_control_only ? "yes" : "no")
              << " request_pending_data_only=" << (tx_probe.pending_data_only ? "yes" : "no")
              << " request_last_tx_progress_ms=" << tx_probe.last_tx_progress_ms
              << " unexpected_present=" << (unexpected_probe.present ? "yes" : "no")
              << " unexpected_semantic_accepted=" << (unexpected_probe.semantic_accepted ? "yes" : "no")
              << " unexpected_buffered_complete=" << (unexpected_probe.buffered_complete ? "yes" : "no")
              << " unexpected_matched_to_recv=" << (unexpected_probe.matched_to_recv ? "yes" : "no")
              << " unexpected_chunks_done=" << unexpected_probe.chunks_done
              << " unexpected_expected_chunks=" << unexpected_probe.expected_chunks
              << " unexpected_completed=" << (unexpected_probe.completed ? "yes" : "no")
              << " unexpected_failed=" << (unexpected_probe.failed ? "yes" : "no")
              << " retry_present=" << (retry_probe.present ? "yes" : "no")
              << " retry_waiting_response=" << (retry_probe.waiting_response ? "yes" : "no")
              << " retry_count=" << retry_probe.retry_count
              << " retry_next_retry_ms=" << retry_probe.next_retry_ms
              << " resource_arrival_blocks_in_use=" << resource.arrival_blocks_in_use
              << " resource_unexpected_msgs_in_use=" << resource.unexpected_msgs_in_use
              << " resource_max_unexpected_msgs=" << resource.max_unexpected_msgs
              << " resource_max_unexpected_bytes=" << resource.max_unexpected_bytes
              << " resource_unexpected_alloc_failures=" << resource.unexpected_alloc_failures
              << " runtime_active_retry_states=" << runtime.active_retry_states
              << " runtime_active_read_response_states=" << runtime.active_read_response_states
              << " runtime_unexpected_buffered_in_use=" << runtime.unexpected_buffered_in_use
              << " runtime_unexpected_semantic_accepted_in_use=" << runtime.unexpected_semantic_accepted_in_use
              << " runtime_unexpected_partial_in_use=" << runtime.unexpected_partial_in_use
              << std::endl;
}

static bool isSoakQuiescent(RudSoakHarness& harness)
{
    const auto status = harness.ses_manager.pds_process_manager.getQueueStatus();
    const RudResourceStats resource = getSharedRudResourceStats();
    const RudRuntimeStats runtime = getRudRuntimeStats();
    return status.pdc_to_net_count == 0 &&
           status.net_pkt_count == 0 &&
           status.pdc_to_ses_req_count == 0 &&
           status.pdc_to_ses_rsp_count == 0 &&
           status.ses_req_count == 0 &&
           status.ses_rsp_count == 0 &&
           resource.arrival_blocks_in_use == 0 &&
           resource.unexpected_msgs_in_use == 0 &&
           runtime.active_retry_states == 0 &&
           runtime.active_read_response_states == 0 &&
           runtime.unexpected_buffered_in_use == 0 &&
           runtime.unexpected_semantic_accepted_in_use == 0 &&
           runtime.unexpected_partial_in_use == 0;
}

static bool quiesceAfterCase(RudSoakHarness& harness,
                             size_t op_index,
                             uint64_t job_id,
                             uint16_t msg_id,
                             SoakFailureContext& failure)
{
    if (!harness.flushHeldPacket()) {
        captureSoakFailure(harness, op_index, job_id, msg_id, "post_case_quiesce_timeout", failure);
        return false;
    }

    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(soakUnexpectedTimeoutMs() + 500);
    while (std::chrono::steady_clock::now() < deadline) {
        if (isSoakQuiescent(harness)) {
            return true;
        }
        const bool did_work = harness.pumpWithoutFaults();
        if (!did_work) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }

    captureSoakFailure(harness, op_index, job_id, msg_id, "post_case_quiesce_timeout", failure);
    return false;
}

static OperationMetadata make_send_metadata(uint16_t msg_id,
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
    md.memory.rkey = 0xABCDEFULL;
    md.memory.idempotent_safe = true;
    md.payload.start_addr = reinterpret_cast<uint64_t>(payload.data());
    md.payload.length = payload.size();
    md.payload.imm_data = 0xFACEB00CULL;
    md.has_imm_data = true;
    md.use_optimized_header = false;
    md.delivery_mode = RUD;
    md.res_index = 0;
    return md;
}

static bool run_send_expected_case(RudSoakHarness& harness,
                                   std::mt19937& rng,
                                   size_t op_index,
                                   uint64_t job_id,
                                   uint16_t msg_id,
                                   SoakFailureContext& failure)
{
    std::uniform_int_distribution<size_t> len_dist(4096, 8192);
    std::vector<uint8_t> payload(len_dist(rng));
    std::vector<uint8_t> recv(payload.size(), 0);
    fill_pattern(payload, static_cast<uint8_t>(msg_id));
    harness.postRecv(job_id, 1001, reinterpret_cast<uint64_t>(recv.data()), recv.size());
    const size_t rsp_base = harness.responseCount();
    harness.submit(make_send_metadata(msg_id, job_id, 1001, 2001, payload));
    const bool done = harness.driveUntil(
        [&]() {
            return recv == payload &&
                   harness.sawSemanticResponseSince(rsp_base,
                                                   job_id,
                                                   msg_id,
                                                   static_cast<uint8_t>(RSP_OP_CODE::UET_DEFAULT_RESPONSE),
                                                   static_cast<uint8_t>(RSP_RETURN_CODE::RC_OK),
                                                   static_cast<uint32_t>(payload.size()));
        },
        8000);
    if (!done) {
        captureSoakFailure(harness, op_index, job_id, msg_id, "send_expected_timeout", failure);
    }
    return done;
}

static bool run_send_unexpected_case(RudSoakHarness& harness,
                                     std::mt19937& rng,
                                     size_t op_index,
                                     uint64_t job_id,
                                     uint16_t msg_id,
                                     SoakFailureContext& failure)
{
    std::uniform_int_distribution<size_t> len_dist(4096, 8192);
    std::vector<uint8_t> payload(len_dist(rng));
    std::vector<uint8_t> recv(payload.size(), 0);
    fill_pattern(payload, static_cast<uint8_t>(msg_id + 17));
    const size_t rsp_base = harness.responseCount();
    harness.submit(make_send_metadata(msg_id, job_id, 1001, 2001, payload));
    const bool accepted = harness.driveUntil(
        [&]() {
            return harness.sawSemanticResponseSince(rsp_base,
                                                   job_id,
                                                   msg_id,
                                                   static_cast<uint8_t>(RSP_OP_CODE::UET_DEFAULT_RESPONSE),
                                                   static_cast<uint8_t>(RSP_RETURN_CODE::RC_OK),
                                                   static_cast<uint32_t>(payload.size()));
        },
        6000);
    if (!accepted) {
        captureSoakFailure(harness, op_index, job_id, msg_id, "send_unexpected_accept_timeout", failure);
        return false;
    }
    harness.postRecv(job_id, 1001, reinterpret_cast<uint64_t>(recv.data()), recv.size());
    const bool delivered = harness.driveUntil([&]() { return recv == payload; }, 6000);
    if (!delivered) {
        captureSoakFailure(harness, op_index, job_id, msg_id, "send_unexpected_delivery_timeout", failure);
    }
    return delivered;
}

static bool run_send_retry_case(RudSoakHarness& harness,
                                std::mt19937& rng,
                                size_t op_index,
                                uint64_t job_id,
                                uint16_t msg_id,
                                SoakFailureContext& failure)
{
    std::uniform_int_distribution<size_t> len_dist(4096, 6144);
    std::vector<uint8_t> payload(len_dist(rng));
    std::vector<uint8_t> recv(payload.size(), 0);
    fill_pattern(payload, static_cast<uint8_t>(msg_id + 33));
    configureSharedRudResourcePool(16, 0, 0);
    const size_t rsp_base = harness.responseCount();
    harness.submit(make_send_metadata(msg_id, job_id, 1001, 2001, payload));
    const bool saw_no_match = harness.driveUntil(
        [&]() {
            return harness.sawSemanticResponseSince(rsp_base,
                                                   job_id,
                                                   msg_id,
                                                   static_cast<uint8_t>(RSP_OP_CODE::UET_NACK),
                                                   static_cast<uint8_t>(RSP_RETURN_CODE::RC_NO_MATCH),
                                                   0);
        },
        2000);
    if (!saw_no_match) {
        captureSoakFailure(harness, op_index, job_id, msg_id, "send_retry_no_match_timeout", failure);
        configureSharedRudResourcePool(16, 4, 1u << 16);
        return false;
    }
    configureSharedRudResourcePool(16, 4, 1u << 16);

    harness.postRecv(job_id, 1001, reinterpret_cast<uint64_t>(recv.data()), recv.size());
    const bool done = harness.driveUntil(
        [&]() {
            return recv == payload &&
                   harness.sawSemanticResponseSince(rsp_base,
                                                   job_id,
                                                   msg_id,
                                                   static_cast<uint8_t>(RSP_OP_CODE::UET_DEFAULT_RESPONSE),
                                                   static_cast<uint8_t>(RSP_RETURN_CODE::RC_OK),
                                                   static_cast<uint32_t>(payload.size()));
        },
        8000);
    if (!done) {
        captureSoakFailure(harness, op_index, job_id, msg_id, "send_retry_recovery_timeout", failure);
    }
    return done;
}

static bool run_write_case(RudSoakHarness& harness,
                           std::mt19937& rng,
                           size_t op_index,
                           uint64_t job_id,
                           uint16_t msg_id,
                           SoakFailureContext& failure)
{
    std::uniform_int_distribution<size_t> len_dist(4096, 8192);
    std::vector<uint8_t> src(len_dist(rng));
    std::vector<uint8_t> dst(src.size(), 0);
    fill_pattern(src, static_cast<uint8_t>(msg_id + 51));
    const uint64_t rkey = 0x100000ULL + msg_id;
    harness.ses_manager.register_mr(rkey, reinterpret_cast<uint64_t>(dst.data()), dst.size());

    OperationMetadata md{};
    md.op_type = WRITE;
    md.s_pid_on_fep = 1001;
    md.t_pid_on_fep = 2001;
    md.job_id = job_id;
    md.messages_id = msg_id;
    md.memory.rkey = rkey;
    md.payload.start_addr = reinterpret_cast<uint64_t>(dst.data());
    md.payload.local_addr = reinterpret_cast<uint64_t>(src.data());
    md.payload.length = src.size();
    md.delivery_mode = RUD;

    harness.submit(md);
    const bool done = harness.driveUntil([&]() { return dst == src; }, 6000);
    if (!done) {
        captureSoakFailure(harness, op_index, job_id, msg_id, "write_timeout", failure);
    }
    return done;
}

static bool run_read_case(RudSoakHarness& harness,
                          std::mt19937& rng,
                          size_t op_index,
                          uint64_t job_id,
                          uint16_t msg_id,
                          SoakFailureContext& failure)
{
    std::uniform_int_distribution<size_t> len_dist(4096, 8192);
    std::vector<uint8_t> read_src(len_dist(rng));
    std::vector<uint8_t> read_dst(read_src.size(), 0);
    fill_pattern(read_src, static_cast<uint8_t>(msg_id + 73));
    const uint64_t rkey = 0x200000ULL + msg_id;
    harness.ses_manager.register_mr(rkey, reinterpret_cast<uint64_t>(read_src.data()), read_src.size());

    OperationMetadata md{};
    md.op_type = READ;
    md.s_pid_on_fep = 1001;
    md.t_pid_on_fep = 2001;
    md.job_id = job_id;
    md.messages_id = msg_id;
    md.memory.rkey = rkey;
    md.payload.start_addr = reinterpret_cast<uint64_t>(read_src.data());
    md.payload.local_addr = reinterpret_cast<uint64_t>(read_dst.data());
    md.payload.length = read_src.size();
    md.delivery_mode = RUD;

    harness.submit(md);
    const bool done = harness.driveUntil([&]() { return read_dst == read_src; }, 6000);
    if (!done) {
        captureSoakFailure(harness, op_index, job_id, msg_id, "read_timeout", failure);
    }
    return done;
}

} // namespace

int main(int argc, char** argv)
{
    Logger::initialize("RudSoakTest.log", LogLevel::DEBUG, 1, 1);

    const bool long_mode = argc > 1 && std::string(argv[1]) == "long";
    const auto duration = std::chrono::seconds(long_mode ? 120 : 15);

    reset_runtime_defaults();
    RudSoakHarness harness(2901);
    std::mt19937 rng(0x12345678);
    const double base_reorder_probability = long_mode ? 0.05 : 0.02;
    const double base_drop_probability = long_mode ? 0.01 : 0.0;
    harness.setFaultModel(base_reorder_probability, base_drop_probability);

    size_t send_expected_ok = 0;
    size_t send_unexpected_ok = 0;
    size_t send_retry_ok = 0;
    size_t write_ok = 0;
    size_t read_ok = 0;
    uint16_t msg_id = 1;
    const uint64_t base_job_id = 50000;
    const auto deadline = std::chrono::steady_clock::now() + duration;
    size_t op_index = 0;
    SoakFailureContext failure;

    while (std::chrono::steady_clock::now() < deadline) {
        const uint64_t job_id = base_job_id + op_index;
        bool ok = false;
        switch (op_index % 5) {
            case 0:
                harness.setFaultModel(base_reorder_probability, base_drop_probability);
                ok = run_send_expected_case(harness, rng, op_index, job_id, msg_id++, failure);
                send_expected_ok += ok ? 1u : 0u;
                break;
            case 1:
                harness.clearFaultModel();
                ok = run_send_unexpected_case(harness, rng, op_index, job_id, msg_id++, failure);
                send_unexpected_ok += ok ? 1u : 0u;
                break;
            case 2:
                harness.clearFaultModel();
                ok = run_send_retry_case(harness, rng, op_index, job_id, msg_id++, failure);
                send_retry_ok += ok ? 1u : 0u;
                break;
            case 3:
                harness.setFaultModel(base_reorder_probability, base_drop_probability);
                ok = run_write_case(harness, rng, op_index, job_id, msg_id++, failure);
                write_ok += ok ? 1u : 0u;
                break;
            default:
                harness.setFaultModel(base_reorder_probability, base_drop_probability);
                ok = run_read_case(harness, rng, op_index, job_id, msg_id++, failure);
                read_ok += ok ? 1u : 0u;
                break;
        }

        if (!ok) {
            std::cerr << "RudSoakTest operation failed"
                      << " op_index=" << failure.op_index
                      << " op_kind=" << failure.op_kind
                      << " job_id=" << failure.job_id
                      << " msg_id=" << failure.msg_id
                      << " stage=" << failure.stage
                      << std::endl;
            return 1;
        }
        if (!quiesceAfterCase(harness, op_index, job_id, static_cast<uint16_t>(msg_id - 1), failure)) {
            std::cerr << "RudSoakTest operation failed"
                      << " op_index=" << failure.op_index
                      << " op_kind=" << failure.op_kind
                      << " job_id=" << failure.job_id
                      << " msg_id=" << failure.msg_id
                      << " stage=" << failure.stage
                      << std::endl;
            return 1;
        }
        ++op_index;
    }

    const bool drained = harness.driveUntil(
        [&]() {
            const auto resource = getSharedRudResourceStats();
            const auto runtime = getRudRuntimeStats();
            return resource.arrival_blocks_in_use == 0 &&
                   resource.unexpected_msgs_in_use == 0 &&
                   runtime.active_retry_states == 0 &&
                   runtime.active_read_response_states == 0 &&
                   runtime.unexpected_buffered_in_use == 0 &&
                   runtime.unexpected_semantic_accepted_in_use == 0 &&
                   runtime.unexpected_partial_in_use == 0;
        },
        5000);

    const RudResourceStats resource = getSharedRudResourceStats();
    const RudRuntimeStats runtime = getRudRuntimeStats();

    const bool ok = drained &&
                    send_expected_ok > 0 &&
                    send_unexpected_ok > 0 &&
                    send_retry_ok > 0 &&
                    write_ok > 0 &&
                    read_ok > 0 &&
                    resource.arrival_blocks_in_use == 0 &&
                    resource.unexpected_msgs_in_use == 0 &&
                    runtime.active_retry_states == 0 &&
                    runtime.active_read_response_states == 0 &&
                    runtime.unexpected_buffered_in_use == 0 &&
                    runtime.unexpected_semantic_accepted_in_use == 0 &&
                    runtime.unexpected_partial_in_use == 0;

    std::cout << "[RudSoakTest] mode=" << (long_mode ? "long" : "smoke")
              << " send_expected=" << send_expected_ok
              << " send_unexpected=" << send_unexpected_ok
              << " send_retry=" << send_retry_ok
              << " write=" << write_ok
              << " read=" << read_ok
              << " active_retry=" << runtime.active_retry_states
              << " active_read_response=" << runtime.active_read_response_states
              << " unexpected_in_use=" << runtime.unexpected_buffered_in_use
              << " arrival_in_use=" << resource.arrival_blocks_in_use
              << std::endl;
    std::cout << (ok ? "RudSoakTest PASS" : "RudSoakTest FAIL") << std::endl;
    return ok ? 0 : 1;
}
