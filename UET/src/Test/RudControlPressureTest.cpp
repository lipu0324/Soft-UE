#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <memory>
#include <optional>
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

enum class PressureProfile : uint8_t {
    Baseline,
    CreditPressure,
    Lossy,
    Mixed,
};

enum class OpKind : uint8_t {
    SendExpected,
    SendSpill,
    Write,
    Read,
};

struct ProfileSpec {
    std::string name;
    size_t max_bitmap_blocks{0};
    size_t max_unexpected_msgs{0};
    size_t max_unexpected_bytes{0};
    double reorder_probability{0.0};
    double drop_probability{0.0};
    int send_expected_weight{0};
    int send_spill_weight{0};
    int write_weight{0};
    int read_weight{0};
};

struct Config {
    PressureProfile profile{PressureProfile::Baseline};
    int seconds{30};
    int snapshot_ms{1000};
    int tail_grace_ms{30000};
    int dump_outstanding_limit{8};
    int jobs{8};
    int outstanding{16};
    uint32_t seed{0xBADC0DEu};
    bool long_mode{false};
};

struct QueueSnapshot {
    size_t ses_req_count{0};
    size_t ses_rsp_count{0};
    size_t net_pkt_count{0};
    size_t eager_req_count{0};
    size_t error_count{0};
    size_t pdc_to_net_count{0};
    size_t pdc_to_ses_req_count{0};
    size_t pdc_to_ses_rsp_count{0};
};

struct SnapshotStats {
    RudRuntimeStats runtime{};
    RudResourceStats resource{};
    QueueSnapshot queue{};
    size_t submitted_ops{0};
    size_t completed_ops{0};
};

static bool is_semantic_response(const PDStoNET_pkt &pkt)
{
    return pkt.PDS_type == RUOD_ack_header &&
           pkt.PDS_header.RUOD_ack_header.next_hdr == UET_HDR_RESPONSE &&
           pkt.SESpkt.bth_type == Semantic_Response_Header;
}

static bool is_reorderable_data_packet(const PDStoNET_pkt &pkt)
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

static bool send_one_packet(UDPNetworkLayer &udp_tx,
                            UDPNetworkLayer &udp_rx,
                            const PDStoNET_pkt &pkt)
{
    return udp_tx.sendPacket(pkt, "127.0.0.1", udp_rx.getLocalPort()) >= 0;
}

static void fill_pattern(std::vector<uint8_t> &buf, uint8_t seed)
{
    for (size_t i = 0; i < buf.size(); ++i) {
        buf[i] = static_cast<uint8_t>((seed + i) & 0xFF);
    }
}

static void reset_runtime_defaults(size_t max_bitmap_blocks,
                                   size_t max_unexpected_msgs,
                                   size_t max_unexpected_bytes)
{
    configureSharedRudResourcePool(max_bitmap_blocks, max_unexpected_msgs, max_unexpected_bytes);
    resetRudRuntimeStats();
}

class PressureHarness {
public:
    explicit PressureHarness(uint16_t listen_port)
        : udp_rx_(listen_port), udp_tx_(0), rng_(0xC0FFEEu)
    {
        if (!udp_rx_.initialize() || !udp_tx_.initialize()) {
            throw std::runtime_error("failed to initialize UDP pressure harness");
        }
        rx_thread_ = std::thread([this]() {
            while (rx_running_.load()) {
                PDStoNET_pkt rx_pkt;
                if (udp_rx_.receivePDStoNETPacket(50, rx_pkt)) {
                    ses_manager.pds_process_manager.pushNetworkPacket(rx_pkt);
                }
            }
        });
    }

    ~PressureHarness()
    {
        rx_running_.store(false);
        if (rx_thread_.joinable()) {
            rx_thread_.join();
        }
    }

    void setFaultModel(double reorder_probability, double drop_probability)
    {
        reorder_probability_ = reorder_probability;
        drop_probability_ = drop_probability;
    }

    void setSeed(uint32_t seed)
    {
        rng_.seed(seed);
    }

    void postRecv(uint64_t job_id, uint32_t src_fep, uint64_t base_addr, uint32_t buffer_len)
    {
        PostedRecvEntry recv_entry{};
        recv_entry.completion_key = (job_id << 16) ^ static_cast<uint64_t>(buffer_len);
        recv_entry.base_addr = base_addr;
        recv_entry.buffer_len = buffer_len;
        recv_entry.job_id = job_id;
        recv_entry.pdc_id = 0;
        recv_entry.src_fep = src_fep;
        ses_manager.postRecv(recv_entry);
    }

    void submit(const OperationMetadata &metadata)
    {
        ses_manager.lfbric_ses_q.push(metadata);
        ses_manager.mainChk();
    }

    bool pumpOnce(bool allow_reorder = true)
    {
        bool did_work = false;
        PDStoNET_pkt tx_pkt;
        if (ses_manager.pds_process_manager.popNetworkPacket(tx_pkt)) {
            if (is_semantic_response(tx_pkt)) {
                const auto &hdr = tx_pkt.SESpkt.bth_header.Semantic_Response_Header;
                responses_.push_back(ResponseEvent{
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
                    if (!send_one_packet(udp_tx_, udp_rx_, tx_pkt) ||
                        !send_one_packet(udp_tx_, udp_rx_, held_pkt_)) {
                        return false;
                    }
                    has_held_pkt_ = false;
                }
                did_work = true;
            } else {
                if (has_held_pkt_) {
                    if (!send_one_packet(udp_tx_, udp_rx_, held_pkt_)) {
                        return false;
                    }
                    has_held_pkt_ = false;
                }
                if (!send_one_packet(udp_tx_, udp_rx_, tx_pkt)) {
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

    bool flushHeldPacket()
    {
        if (!has_held_pkt_) {
            return true;
        }
        if (!send_one_packet(udp_tx_, udp_rx_, held_pkt_)) {
            return false;
        }
        has_held_pkt_ = false;
        return true;
    }

    size_t responseCount() const
    {
        return responses_.size();
    }

    const ResponseEvent &responseAt(size_t index) const
    {
        return responses_[index];
    }

    SESManager ses_manager;

private:
    bool shouldDrop(const PDStoNET_pkt &pkt)
    {
        if (drop_probability_ <= 0.0 || !is_reorderable_data_packet(pkt)) {
            return false;
        }
        std::bernoulli_distribution dist(drop_probability_);
        return dist(rng_);
    }

    bool shouldReorder(const PDStoNET_pkt &pkt)
    {
        if (reorder_probability_ <= 0.0 || !is_reorderable_data_packet(pkt)) {
            return false;
        }
        std::bernoulli_distribution dist(reorder_probability_);
        return dist(rng_);
    }

    UDPNetworkLayer udp_rx_;
    UDPNetworkLayer udp_tx_;
    std::atomic<bool> rx_running_{true};
    std::thread rx_thread_;
    std::vector<ResponseEvent> responses_;
    std::mt19937 rng_;
    double reorder_probability_{0.0};
    double drop_probability_{0.0};
    bool has_held_pkt_{false};
    PDStoNET_pkt held_pkt_{};
};

struct TickResult {
    bool done{false};
    bool success{false};
    bool progress{false};
    std::string progress_reason;
    std::string error;
};

struct TrackedOp {
    OpKind kind{OpKind::SendExpected};
    uint64_t job_id{0};
    size_t job_slot{0};
    uint16_t msg_id{0};
    uint32_t peer_fep{2001};
    uint64_t rkey{0};
    size_t payload_len{0};
    size_t rsp_scan_idx{0};
    bool saw_success_rsp{false};
    bool posted_after_accept{false};
    bool saw_any_rsp{false};
    uint8_t last_rsp_return_code{0};
    uint32_t last_rsp_modified_length{0};
    size_t matched_bytes{0};
    bool send_retry_present{false};
    bool send_retry_waiting_response{false};
    uint16_t send_retry_count{0};
    int64_t send_retry_next_retry_ms{0};
    bool unexpected_bound{false};
    bool unexpected_semantic_accepted{false};
    bool unexpected_matched_to_recv{false};
    bool request_terminalized{false};
    SenderTerminalReason request_terminal_reason{SenderTerminalReason::CLOSE_RESET};
    RequestCloseCause request_close_cause{RequestCloseCause::UNKNOWN};
    int64_t request_terminalized_at_ms{0};
    uint8_t request_close_state_at_terminalize{0};
    uint32_t request_tx_pending_count_at_terminalize{0};
    uint32_t request_unack_cnt_at_terminalize{0};
    bool request_all_ack_at_terminalize{false};
    bool request_retry_present_at_terminalize{false};
    bool request_read_track_present_at_terminalize{false};
    bool request_tx_probe_present{false};
    bool request_tx_pkt_map_present{false};
    bool request_tx_pkt_buffer_present{false};
    uint32_t request_oldest_pending_psn{0};
    uint32_t request_pending_psn_count{0};
    bool request_pending_control_only{false};
    bool request_pending_data_only{false};
    int64_t request_last_tx_progress_ms{0};
    bool read_track_present{false};
    bool read_terminalized{false};
    ReadResponseTerminalReason read_terminal_reason{ReadResponseTerminalReason::CLOSE_RESET};
    std::chrono::steady_clock::time_point last_progress_at{};
    std::string last_state_change_reason{"submitted"};
    std::vector<uint8_t> payload;
    std::vector<uint8_t> recv;
    std::chrono::steady_clock::time_point submitted_at{};
};

static const char *opKindName(OpKind kind)
{
    switch (kind) {
        case OpKind::SendExpected: return "send_expected";
        case OpKind::SendSpill: return "send_spill";
        case OpKind::Write: return "write";
        case OpKind::Read: return "read";
    }
    return "unknown";
}

static const char *readTerminalReasonName(ReadResponseTerminalReason reason)
{
    switch (reason) {
        case ReadResponseTerminalReason::RTO_EXHAUSTED: return "rto_exhausted";
        case ReadResponseTerminalReason::CLOSE_RESET: return "close_reset";
        case ReadResponseTerminalReason::TEARDOWN_ORPHAN: return "teardown_orphan";
    }
    return "unknown";
}

static const char *requestTerminalReasonName(SenderTerminalReason reason)
{
    switch (reason) {
        case SenderTerminalReason::RTO_EXHAUSTED: return "rto_exhausted";
        case SenderTerminalReason::CLOSE_RESET: return "close_reset";
        case SenderTerminalReason::TEARDOWN_ORPHAN: return "teardown_orphan";
    }
    return "unknown";
}

static const char *requestCloseCauseName(RequestCloseCause cause)
{
    switch (cause) {
        case RequestCloseCause::CLOSE_REQ_PATH: return "close_req_path";
        case RequestCloseCause::CLOSE_ERROR_PATH: return "close_error_path";
        case RequestCloseCause::SAFE_CLOSE_TEARDOWN: return "safe_close_teardown";
        case RequestCloseCause::RTO_EXHAUST_PATH: return "rto_exhaust_path";
        case RequestCloseCause::UNKNOWN: return "unknown";
    }
    return "unknown";
}

static std::string profileName(PressureProfile profile)
{
    switch (profile) {
        case PressureProfile::Baseline: return "baseline";
        case PressureProfile::CreditPressure: return "credit_pressure";
        case PressureProfile::Lossy: return "lossy";
        case PressureProfile::Mixed: return "mixed";
    }
    return "baseline";
}

static std::optional<PressureProfile> parseProfile(const std::string &value)
{
    if (value == "baseline") {
        return PressureProfile::Baseline;
    }
    if (value == "credit_pressure") {
        return PressureProfile::CreditPressure;
    }
    if (value == "lossy") {
        return PressureProfile::Lossy;
    }
    if (value == "mixed") {
        return PressureProfile::Mixed;
    }
    return std::nullopt;
}

static ProfileSpec makeProfileSpec(PressureProfile profile, bool long_mode)
{
    switch (profile) {
        case PressureProfile::Baseline:
            return ProfileSpec{"baseline", 64, 16, 256u * 1024u, 0.0, 0.0, 40, 20, 20, 20};
        case PressureProfile::CreditPressure:
            return ProfileSpec{"credit_pressure", 32, 4, 16u * 1024u, 0.0, 0.0, 35, 45, 10, 10};
        case PressureProfile::Lossy:
            return ProfileSpec{"lossy",
                               64,
                               16,
                               256u * 1024u,
                               long_mode ? 0.10 : 0.05,
                               long_mode ? 0.02 : 0.01,
                               40,
                               20,
                               20,
                               20};
        case PressureProfile::Mixed:
            return ProfileSpec{"mixed",
                               32,
                               4,
                               16u * 1024u,
                               long_mode ? 0.08 : 0.03,
                               long_mode ? 0.02 : 0.01,
                               30,
                               50,
                               10,
                               10};
    }
    return ProfileSpec{"baseline", 64, 16, 256u * 1024u, 0.0, 0.0, 40, 20, 20, 20};
}

static uint64_t millisBetween(const std::chrono::steady_clock::time_point &begin,
                              const std::chrono::steady_clock::time_point &end)
{
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count());
}

static size_t countMatchingBytes(const std::vector<uint8_t> &lhs, const std::vector<uint8_t> &rhs)
{
    const size_t limit = std::min(lhs.size(), rhs.size());
    size_t matched = 0;
    for (size_t i = 0; i < limit; ++i) {
        if (lhs[i] == rhs[i]) {
            ++matched;
        }
    }
    return matched;
}

static double percentileMs(std::vector<uint64_t> values, double pct)
{
    if (values.empty()) {
        return 0.0;
    }
    std::sort(values.begin(), values.end());
    const double clamped = std::clamp(pct, 0.0, 1.0);
    const size_t index = static_cast<size_t>(clamped * static_cast<double>(values.size() - 1));
    return static_cast<double>(values[index]);
}

static OperationMetadata makeSendMetadata(uint16_t msg_id,
                                          uint64_t job_id,
                                          const std::vector<uint8_t> &payload)
{
    OperationMetadata md{};
    md.op_type = SEND;
    md.s_pid_on_fep = 1001;
    md.t_pid_on_fep = 2001;
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

static OperationMetadata makeWriteMetadata(uint16_t msg_id,
                                           uint64_t job_id,
                                           uint64_t rkey,
                                           const std::vector<uint8_t> &src,
                                           const std::vector<uint8_t> &dst)
{
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
    md.res_index = 0;
    return md;
}

static OperationMetadata makeReadMetadata(uint16_t msg_id,
                                          uint64_t job_id,
                                          uint64_t rkey,
                                          const std::vector<uint8_t> &src,
                                          const std::vector<uint8_t> &dst)
{
    OperationMetadata md{};
    md.op_type = READ;
    md.s_pid_on_fep = 1001;
    md.t_pid_on_fep = 2001;
    md.job_id = job_id;
    md.messages_id = msg_id;
    md.memory.rkey = rkey;
    md.payload.start_addr = reinterpret_cast<uint64_t>(src.data());
    md.payload.local_addr = reinterpret_cast<uint64_t>(dst.data());
    md.payload.length = src.size();
    md.delivery_mode = RUD;
    md.res_index = 0;
    return md;
}

static TickResult tickOp(TrackedOp &op, PressureHarness &harness)
{
    TickResult result{};
    const auto now = std::chrono::steady_clock::now();
    for (; op.rsp_scan_idx < harness.responseCount(); ++op.rsp_scan_idx) {
        const auto &rsp = harness.responseAt(op.rsp_scan_idx);
        if (rsp.job_id != op.job_id || rsp.message_id != op.msg_id) {
            continue;
        }
        const bool rsp_changed =
            !op.saw_any_rsp ||
            op.last_rsp_return_code != rsp.return_code ||
            op.last_rsp_modified_length != rsp.modified_length;
        op.saw_any_rsp = true;
        op.last_rsp_return_code = rsp.return_code;
        op.last_rsp_modified_length = rsp.modified_length;
        if (rsp_changed && !result.progress) {
            result.progress = true;
            result.progress_reason = "semantic_response";
            op.last_progress_at = now;
            op.last_state_change_reason = "semantic_response";
        }
        if (rsp.return_code == static_cast<uint8_t>(RSP_RETURN_CODE::RC_OK) &&
            rsp.modified_length == op.payload.size() &&
            !op.saw_success_rsp) {
            op.saw_success_rsp = true;
            result.progress = true;
            result.progress_reason = "semantic_response_ok";
            op.last_progress_at = now;
            op.last_state_change_reason = "semantic_response_ok";
        }
    }

    const size_t matched_bytes = countMatchingBytes(op.recv, op.payload);
    if (matched_bytes > op.matched_bytes) {
        op.matched_bytes = matched_bytes;
        result.progress = true;
        result.progress_reason = "recv_match_progress";
        op.last_progress_at = now;
        op.last_state_change_reason = "recv_match_progress";
    }

    const RequestTerminalProbe request_probe =
        harness.ses_manager.queryRequestTerminalProbe(op.job_id, op.msg_id, op.peer_fep);
    if (request_probe.retry_present != op.send_retry_present ||
        request_probe.terminalized != op.request_terminalized ||
        (request_probe.terminalized && request_probe.reason != op.request_terminal_reason)) {
        result.progress = true;
        result.progress_reason = "request_terminal_update";
        op.last_progress_at = now;
        op.last_state_change_reason =
            request_probe.terminalized
                ? std::string("request_terminal_") + requestTerminalReasonName(request_probe.reason)
                : "request_terminal_cleared";
    }
    op.send_retry_present = request_probe.retry_present;
    op.request_terminalized = request_probe.terminalized;
    op.request_terminal_reason = request_probe.reason;
    op.request_terminalized_at_ms = request_probe.terminalized_at_ms;
    op.request_close_cause = request_probe.close_cause;
    op.request_close_state_at_terminalize = request_probe.close_state_at_terminalize;
    op.request_tx_pending_count_at_terminalize = request_probe.tx_pending_count_at_terminalize;
    op.request_unack_cnt_at_terminalize = request_probe.unack_cnt_at_terminalize;
    op.request_all_ack_at_terminalize = request_probe.all_ack_at_terminalize;
    op.request_retry_present_at_terminalize = request_probe.retry_present_at_terminalize;
    op.request_read_track_present_at_terminalize = request_probe.read_track_present_at_terminalize;

    const SendRetryProbe retry_probe =
        harness.ses_manager.querySendRetryProbe(op.job_id, op.msg_id, op.peer_fep);
    op.send_retry_present = retry_probe.present;
    op.send_retry_waiting_response = retry_probe.waiting_response;
    op.send_retry_count = retry_probe.retry_count;
    op.send_retry_next_retry_ms = retry_probe.next_retry_ms;

    const RequestTxProbe tx_probe =
        harness.ses_manager.queryRequestTxProbe(op.job_id, op.msg_id, op.peer_fep);
    if (tx_probe.present != op.request_tx_probe_present ||
        tx_probe.has_tx_pkt_map_entries != op.request_tx_pkt_map_present ||
        tx_probe.has_tx_pkt_buffer_entries != op.request_tx_pkt_buffer_present ||
        tx_probe.pending_psn_count != op.request_pending_psn_count ||
        tx_probe.pending_control_only != op.request_pending_control_only ||
        tx_probe.pending_data_only != op.request_pending_data_only) {
        result.progress = true;
        result.progress_reason = "request_tx_probe_update";
        op.last_progress_at = now;
        op.last_state_change_reason = tx_probe.present ? "request_tx_probe_present" : "request_tx_probe_cleared";
    }
    op.request_tx_probe_present = tx_probe.present;
    op.request_tx_pkt_map_present = tx_probe.has_tx_pkt_map_entries;
    op.request_tx_pkt_buffer_present = tx_probe.has_tx_pkt_buffer_entries;
    op.request_oldest_pending_psn = tx_probe.oldest_pending_psn;
    op.request_pending_psn_count = tx_probe.pending_psn_count;
    op.request_pending_control_only = tx_probe.pending_control_only;
    op.request_pending_data_only = tx_probe.pending_data_only;
    op.request_last_tx_progress_ms = tx_probe.last_tx_progress_ms;

    const UnexpectedSendProbe unexpected_probe =
        harness.ses_manager.queryUnexpectedSendProbe(op.job_id, op.msg_id, 1001);
    if (unexpected_probe.present != op.unexpected_bound ||
        unexpected_probe.semantic_accepted != op.unexpected_semantic_accepted ||
        unexpected_probe.matched_to_recv != op.unexpected_matched_to_recv) {
        result.progress = true;
        result.progress_reason = "unexpected_probe_update";
        op.last_progress_at = now;
        op.last_state_change_reason =
            unexpected_probe.present
                ? (unexpected_probe.semantic_accepted ? "unexpected_semantic_accepted"
                                                      : "unexpected_buffered")
                : "unexpected_released";
    }
    op.unexpected_bound = unexpected_probe.present;
    op.unexpected_semantic_accepted = unexpected_probe.semantic_accepted;
    op.unexpected_matched_to_recv = unexpected_probe.matched_to_recv;

    if (op.kind == OpKind::Read) {
        const ReadResponseProbe probe = harness.ses_manager.queryReadResponseProbe(op.job_id, op.msg_id, op.peer_fep);
        if (probe.track_present != op.read_track_present ||
            probe.terminalized != op.read_terminalized ||
            (probe.terminalized && probe.reason != op.read_terminal_reason)) {
            result.progress = true;
            result.progress_reason = "read_probe_update";
            op.last_progress_at = now;
            op.last_state_change_reason =
                probe.terminalized ? std::string("read_terminal_") + readTerminalReasonName(probe.reason)
                                   : (probe.track_present ? "read_track_present" : "read_track_cleared");
        }
        op.read_track_present = probe.track_present;
        op.read_terminalized = probe.terminalized;
        op.read_terminal_reason = probe.reason;
    }

    switch (op.kind) {
        case OpKind::SendExpected:
            if (op.request_terminalized) {
                result.done = true;
                result.success = false;
                result.progress = true;
                result.progress_reason =
                    std::string("request_terminal_") + requestTerminalReasonName(op.request_terminal_reason);
                result.error =
                    std::string("request_terminalized_") + requestTerminalReasonName(op.request_terminal_reason);
                op.last_progress_at = now;
                op.last_state_change_reason = result.progress_reason;
                return result;
            }
            if (op.saw_success_rsp && op.recv == op.payload) {
                result.done = true;
                result.success = true;
                result.progress = true;
                result.progress_reason = "send_expected_complete";
                op.last_progress_at = now;
                op.last_state_change_reason = "send_expected_complete";
                return result;
            }
            break;
        case OpKind::SendSpill:
            if (op.request_terminalized) {
                result.done = true;
                result.success = false;
                result.progress = true;
                result.progress_reason =
                    std::string("request_terminal_") + requestTerminalReasonName(op.request_terminal_reason);
                result.error =
                    std::string("request_terminalized_") + requestTerminalReasonName(op.request_terminal_reason);
                op.last_progress_at = now;
                op.last_state_change_reason = result.progress_reason;
                return result;
            }
            if (op.saw_success_rsp && !op.posted_after_accept) {
                harness.postRecv(op.job_id,
                                 1001,
                                 reinterpret_cast<uint64_t>(op.recv.data()),
                                 static_cast<uint32_t>(op.recv.size()));
                op.posted_after_accept = true;
                result.progress = true;
                result.progress_reason = "spill_post_recv";
                op.last_progress_at = now;
                op.last_state_change_reason = "spill_post_recv";
            }
            if (op.posted_after_accept && op.recv == op.payload) {
                result.done = true;
                result.success = true;
                result.progress = true;
                result.progress_reason = "send_spill_complete";
                op.last_progress_at = now;
                op.last_state_change_reason = "send_spill_complete";
                return result;
            }
            break;
        case OpKind::Write:
            if (op.request_terminalized) {
                result.done = true;
                result.success = false;
                result.progress = true;
                result.progress_reason =
                    std::string("request_terminal_") + requestTerminalReasonName(op.request_terminal_reason);
                result.error =
                    std::string("request_terminalized_") + requestTerminalReasonName(op.request_terminal_reason);
                op.last_progress_at = now;
                op.last_state_change_reason = result.progress_reason;
                return result;
            }
            if (op.recv == op.payload) {
                result.done = true;
                result.success = true;
                result.progress = true;
                result.progress_reason = "write_complete";
                op.last_progress_at = now;
                op.last_state_change_reason = result.progress_reason;
                return result;
            }
            break;
        case OpKind::Read:
            if (op.request_terminalized) {
                result.done = true;
                result.success = false;
                result.progress = true;
                result.progress_reason =
                    std::string("request_terminal_") + requestTerminalReasonName(op.request_terminal_reason);
                result.error =
                    std::string("request_terminalized_") + requestTerminalReasonName(op.request_terminal_reason);
                op.last_progress_at = now;
                op.last_state_change_reason = result.progress_reason;
                return result;
            }
            if (op.recv == op.payload) {
                result.done = true;
                result.success = true;
                result.progress = true;
                result.progress_reason = "read_complete";
                op.last_progress_at = now;
                op.last_state_change_reason = result.progress_reason;
                return result;
            }
            if (op.read_terminalized) {
                result.done = true;
                result.success = false;
                result.progress = true;
                result.progress_reason = std::string("read_terminal_") + readTerminalReasonName(op.read_terminal_reason);
                result.error = std::string("read_response_terminalized_") + readTerminalReasonName(op.read_terminal_reason);
                op.last_progress_at = now;
                op.last_state_change_reason = result.progress_reason;
                return result;
            }
            if (!op.read_track_present &&
                !op.request_terminalized &&
                !op.send_retry_present &&
                !op.unexpected_bound &&
                op.matched_bytes != op.payload.size()) {
                result.done = true;
                result.success = false;
                result.progress = true;
                result.progress_reason = "read_response_accounting_gap";
                result.error = "read_response_accounting_gap";
                op.last_progress_at = now;
                op.last_state_change_reason = result.progress_reason;
                return result;
            }
            break;
    }

    return result;
}

static bool isFullyDrained()
{
    const auto resource = getSharedRudResourceStats();
    const auto runtime = getRudRuntimeStats();
    return resource.arrival_blocks_in_use == 0 &&
           resource.bitmap_blocks_in_use == 0 &&
           resource.unexpected_msgs_in_use == 0 &&
           resource.unexpected_bytes_in_use == 0 &&
           runtime.active_retry_states == 0 &&
           runtime.active_read_response_states == 0 &&
           runtime.unexpected_buffered_in_use == 0 &&
           runtime.unexpected_semantic_accepted_in_use == 0 &&
           runtime.unexpected_partial_in_use == 0;
}

static QueueSnapshot captureQueueSnapshot(PressureHarness &harness)
{
    const auto status = harness.ses_manager.pds_process_manager.getQueueStatus();
    QueueSnapshot queue{};
    queue.ses_req_count = status.ses_req_count;
    queue.ses_rsp_count = status.ses_rsp_count;
    queue.net_pkt_count = status.net_pkt_count;
    queue.eager_req_count = status.eager_req_count;
    queue.error_count = status.error_count;
    queue.pdc_to_net_count = status.pdc_to_net_count;
    queue.pdc_to_ses_req_count = status.pdc_to_ses_req_count;
    queue.pdc_to_ses_rsp_count = status.pdc_to_ses_rsp_count;
    return queue;
}

static bool sameQueueSnapshot(const QueueSnapshot &lhs, const QueueSnapshot &rhs)
{
    return lhs.ses_req_count == rhs.ses_req_count &&
           lhs.ses_rsp_count == rhs.ses_rsp_count &&
           lhs.net_pkt_count == rhs.net_pkt_count &&
           lhs.eager_req_count == rhs.eager_req_count &&
           lhs.error_count == rhs.error_count &&
           lhs.pdc_to_net_count == rhs.pdc_to_net_count &&
           lhs.pdc_to_ses_req_count == rhs.pdc_to_ses_req_count &&
           lhs.pdc_to_ses_rsp_count == rhs.pdc_to_ses_rsp_count;
}

static void printSnapshot(const ProfileSpec &profile,
                          double elapsed_sec,
                          double interval_sec,
                          const SnapshotStats &prev,
                          const SnapshotStats &curr,
                          const std::vector<uint64_t> &interval_latencies_ms,
                          uint32_t seed)
{
    const auto &r0 = prev.runtime;
    const auto &r1 = curr.runtime;
    const auto &res = curr.resource;
    const auto &q = curr.queue;
    const size_t completed_delta = curr.completed_ops - prev.completed_ops;
    const double ops_per_sec = interval_sec > 0.0 ? static_cast<double>(completed_delta) / interval_sec : 0.0;
    std::cout << std::fixed << std::setprecision(2)
              << "[RudControlPressureTest][snapshot] profile=" << profile.name
              << " seed=" << seed
              << " elapsed_sec=" << elapsed_sec
              << " submitted_ops=" << curr.submitted_ops
              << " completed_ops=" << curr.completed_ops
              << " ops_per_sec=" << ops_per_sec
              << " p50_ms=" << percentileMs(interval_latencies_ms, 0.50)
              << " p95_ms=" << percentileMs(interval_latencies_ms, 0.95)
              << " p99_ms=" << percentileMs(interval_latencies_ms, 0.99)
              << " retry_fired_delta=" << (r1.retry_fired - r0.retry_fired)
              << " retry_rc_no_match_delta=" << (r1.retry_rc_no_match_scheduled - r0.retry_rc_no_match_scheduled)
              << " ctrl_ack_req_delta=" << (r1.ctrl_ack_req_sent - r0.ctrl_ack_req_sent)
              << " ctrl_sack_delta=" << (r1.ctrl_sack_sent - r0.ctrl_sack_sent)
              << " ctrl_nack_loss_delta=" << (r1.ctrl_nack_loss_sent - r0.ctrl_nack_loss_sent)
              << " ctrl_nack_resource_delta=" << (r1.ctrl_nack_resource_sent - r0.ctrl_nack_resource_sent)
              << " ack_ctrl_ext_delta=" << (r1.ack_ctrl_ext_sent - r0.ack_ctrl_ext_sent)
              << " ack_credit_piggyback_delta="
              << (r1.ack_credit_piggyback_sent - r0.ack_credit_piggyback_sent)
              << " ack_receiver_pressure_delta="
              << (r1.ack_receiver_pressure_piggyback_sent - r0.ack_receiver_pressure_piggyback_sent)
              << " credit_refresh_delta=" << (r1.credit_refresh_sent - r0.credit_refresh_sent)
              << " credit_req_delta=" << (r1.credit_req_sent - r0.credit_req_sent)
              << " credit_gate_blocked_delta=" << (r1.credit_gate_blocked - r0.credit_gate_blocked)
              << " ctrl_budget_class_b_deferred_delta="
              << (r1.ctrl_budget_class_b_deferred - r0.ctrl_budget_class_b_deferred)
              << " ctrl_budget_class_c_deferred_delta="
              << (r1.ctrl_budget_class_c_deferred - r0.ctrl_budget_class_c_deferred)
              << " failure_rc_no_match_delta=" << (r1.failure_rc_no_match - r0.failure_rc_no_match)
              << " active_retry_states=" << r1.active_retry_states
              << " active_read_response_states=" << r1.active_read_response_states
              << " unexpected_buffered_in_use=" << r1.unexpected_buffered_in_use
              << " unexpected_semantic_accepted_in_use=" << r1.unexpected_semantic_accepted_in_use
              << " unexpected_partial_in_use=" << r1.unexpected_partial_in_use
              << " unexpected_msgs_in_use=" << res.unexpected_msgs_in_use
              << " unexpected_bytes_in_use=" << res.unexpected_bytes_in_use
              << " bitmap_blocks_in_use=" << res.bitmap_blocks_in_use
              << " arrival_blocks_in_use=" << res.arrival_blocks_in_use
              << " pdc_to_net_count=" << q.pdc_to_net_count
              << " net_pkt_count=" << q.net_pkt_count
              << " pdc_to_ses_req_count=" << q.pdc_to_ses_req_count
              << " pdc_to_ses_rsp_count=" << q.pdc_to_ses_rsp_count
              << " ses_req_count=" << q.ses_req_count
              << " ses_rsp_count=" << q.ses_rsp_count
              << std::endl;
}

static void printSummary(const ProfileSpec &profile,
                         double total_sec,
                         size_t submitted_ops,
                         size_t completed_ops,
                         const RudRuntimeStats &runtime,
                         const RudResourceStats &resource,
                         const std::vector<uint64_t> &all_latencies_ms,
                         bool drained,
                         uint32_t seed,
                         size_t outstanding_ops,
                         uint64_t oldest_outstanding_ms,
                         uint64_t last_progress_ago_ms)
{
    const double success_rate =
        submitted_ops == 0 ? 0.0 : (100.0 * static_cast<double>(completed_ops) / static_cast<double>(submitted_ops));
    const double avg_ops_per_sec = total_sec > 0.0 ? static_cast<double>(completed_ops) / total_sec : 0.0;
    std::cout << std::fixed << std::setprecision(2)
              << "[RudControlPressureTest][summary] profile=" << profile.name
              << " seed=" << seed
              << " total_ops=" << submitted_ops
              << " completed_ops=" << completed_ops
              << " success_rate=" << success_rate
              << " avg_ops_per_sec=" << avg_ops_per_sec
              << " p50_ms=" << percentileMs(all_latencies_ms, 0.50)
              << " p95_ms=" << percentileMs(all_latencies_ms, 0.95)
              << " p99_ms=" << percentileMs(all_latencies_ms, 0.99)
              << " failure_rc_no_match=" << runtime.failure_rc_no_match
              << " credit_gate_blocked=" << runtime.credit_gate_blocked
              << " credit_req_sent=" << runtime.credit_req_sent
              << " credit_refresh_sent=" << runtime.credit_refresh_sent
              << " ctrl_budget_class_b_deferred=" << runtime.ctrl_budget_class_b_deferred
              << " ctrl_budget_class_c_deferred=" << runtime.ctrl_budget_class_c_deferred
              << " ack_ctrl_ext_sent=" << runtime.ack_ctrl_ext_sent
              << " standalone_fallback_sent=" << runtime.standalone_fallback_sent
              << " unexpected_alloc_failures=" << resource.unexpected_alloc_failures
              << " arrival_alloc_failures=" << resource.arrival_alloc_failures
              << " outstanding_ops=" << outstanding_ops
              << " oldest_outstanding_ms=" << oldest_outstanding_ms
              << " last_progress_ago_ms=" << last_progress_ago_ms
              << " active_retry_states=" << runtime.active_retry_states
              << " active_read_response_states=" << runtime.active_read_response_states
              << " drain_ok=" << (drained ? "yes" : "no")
              << " final_unexpected_msgs_in_use=" << resource.unexpected_msgs_in_use
              << " final_unexpected_bytes_in_use=" << resource.unexpected_bytes_in_use
              << " final_bitmap_blocks_in_use=" << resource.bitmap_blocks_in_use
              << " final_arrival_blocks_in_use=" << resource.arrival_blocks_in_use
              << std::endl;
}

static void dumpOutstandingOps(const ProfileSpec &profile,
                               const std::vector<std::unique_ptr<TrackedOp>> &outstanding_ops,
                               size_t limit,
                               uint32_t seed)
{
    std::vector<const TrackedOp *> ordered;
    ordered.reserve(outstanding_ops.size());
    for (const auto &op : outstanding_ops) {
        ordered.push_back(op.get());
    }
    std::sort(ordered.begin(), ordered.end(), [](const TrackedOp *lhs, const TrackedOp *rhs) {
        return lhs->submitted_at < rhs->submitted_at;
    });

    const auto now = std::chrono::steady_clock::now();
    const size_t dump_count = std::min(limit, ordered.size());
    for (size_t i = 0; i < dump_count; ++i) {
        const auto *op = ordered[i];
        std::cout << "[RudControlPressureTest][outstanding] profile=" << profile.name
                  << " seed=" << seed
                  << " idx=" << i
                  << " op_kind=" << opKindName(op->kind)
                  << " job_id=" << op->job_id
                  << " msg_id=" << op->msg_id
                  << " payload_len=" << op->payload_len
                  << " age_ms=" << millisBetween(op->submitted_at, now)
                  << " recv_matches_payload=" << (op->recv == op->payload ? "yes" : "no")
                  << " matched_bytes=" << op->matched_bytes
                  << " saw_success_rsp=" << (op->saw_success_rsp ? "yes" : "no")
                  << " posted_after_accept=" << (op->posted_after_accept ? "yes" : "no")
                  << " last_rsp_return_code="
                  << (op->saw_any_rsp ? std::to_string(static_cast<unsigned>(op->last_rsp_return_code)) : "none")
                  << " last_rsp_modified_length="
                  << (op->saw_any_rsp ? std::to_string(op->last_rsp_modified_length) : "none")
                  << " send_retry_present=" << (op->send_retry_present ? "yes" : "no")
                  << " send_retry_waiting_response=" << (op->send_retry_waiting_response ? "yes" : "no")
                  << " send_retry_count=" << op->send_retry_count
                  << " send_retry_next_retry_ms=" << op->send_retry_next_retry_ms
                  << " unexpected_bound=" << (op->unexpected_bound ? "yes" : "no")
                  << " unexpected_semantic_accepted=" << (op->unexpected_semantic_accepted ? "yes" : "no")
                  << " unexpected_matched_to_recv=" << (op->unexpected_matched_to_recv ? "yes" : "no")
                  << " request_terminalized=" << (op->request_terminalized ? "yes" : "no")
                  << " request_terminal_reason="
                  << (op->request_terminalized ? requestTerminalReasonName(op->request_terminal_reason) : "none")
                  << " request_close_cause="
                  << (op->request_terminalized ? requestCloseCauseName(op->request_close_cause) : "none")
                  << " request_terminalized_at_ms="
                  << (op->request_terminalized ? std::to_string(op->request_terminalized_at_ms) : "none")
                  << " request_close_state_at_terminalize="
                  << (op->request_terminalized ? std::to_string(op->request_close_state_at_terminalize) : "none")
                  << " request_tx_pending_count_at_terminalize="
                  << (op->request_terminalized ? std::to_string(op->request_tx_pending_count_at_terminalize) : "none")
                  << " request_unack_cnt_at_terminalize="
                  << (op->request_terminalized ? std::to_string(op->request_unack_cnt_at_terminalize) : "none")
                  << " request_all_ack_at_terminalize="
                  << (op->request_terminalized ? (op->request_all_ack_at_terminalize ? "yes" : "no") : "none")
                  << " request_retry_present_at_terminalize="
                  << (op->request_terminalized ? (op->request_retry_present_at_terminalize ? "yes" : "no") : "none")
                  << " request_read_track_present_at_terminalize="
                  << (op->request_terminalized ? (op->request_read_track_present_at_terminalize ? "yes" : "no") : "none")
                  << " request_tx_probe_present=" << (op->request_tx_probe_present ? "yes" : "no")
                  << " request_tx_pkt_map_present=" << (op->request_tx_pkt_map_present ? "yes" : "no")
                  << " request_tx_pkt_buffer_present=" << (op->request_tx_pkt_buffer_present ? "yes" : "no")
                  << " request_oldest_pending_psn=" << op->request_oldest_pending_psn
                  << " request_pending_psn_count=" << op->request_pending_psn_count
                  << " request_pending_control_only=" << (op->request_pending_control_only ? "yes" : "no")
                  << " request_pending_data_only=" << (op->request_pending_data_only ? "yes" : "no")
                  << " request_last_tx_progress_ms=" << op->request_last_tx_progress_ms
                  << " read_track_present=" << (op->kind == OpKind::Read
                                                    ? (op->read_track_present ? "yes" : "no")
                                                    : "n/a")
                  << " read_terminalized=" << (op->kind == OpKind::Read
                                                   ? (op->read_terminalized ? "yes" : "no")
                                                   : "n/a")
                  << " read_terminal_reason="
                  << (op->kind == OpKind::Read && op->read_terminalized
                          ? readTerminalReasonName(op->read_terminal_reason)
                          : "none")
                  << " last_progress_ago_ms=" << millisBetween(op->last_progress_at, now)
                  << " last_state_change_reason=" << op->last_state_change_reason
                  << std::endl;
    }
}

static std::unique_ptr<TrackedOp> submitOneOp(PressureHarness &harness,
                                              std::mt19937 &rng,
                                              const std::vector<uint64_t> &job_ids,
                                              size_t job_slot,
                                              uint16_t msg_id,
                                              OpKind kind)
{
    auto op = std::make_unique<TrackedOp>();
    op->kind = kind;
    op->job_slot = job_slot;
    op->job_id = job_ids[job_slot];
    op->msg_id = msg_id;
    op->submitted_at = std::chrono::steady_clock::now();
    op->last_progress_at = op->submitted_at;
    op->rsp_scan_idx = harness.responseCount();

    std::uniform_int_distribution<size_t> send_len_dist(4096, 8192);
    std::uniform_int_distribution<size_t> rw_len_dist(4096, 8192);

    switch (kind) {
        case OpKind::SendExpected: {
            op->payload.resize(send_len_dist(rng));
            op->recv.assign(op->payload.size(), 0);
            op->payload_len = op->payload.size();
            fill_pattern(op->payload, static_cast<uint8_t>(msg_id));
            harness.postRecv(op->job_id,
                             1001,
                             reinterpret_cast<uint64_t>(op->recv.data()),
                             static_cast<uint32_t>(op->recv.size()));
            harness.submit(makeSendMetadata(op->msg_id, op->job_id, op->payload));
            break;
        }
        case OpKind::SendSpill: {
            op->payload.resize(send_len_dist(rng));
            op->recv.assign(op->payload.size(), 0);
            op->payload_len = op->payload.size();
            fill_pattern(op->payload, static_cast<uint8_t>(msg_id + 17));
            harness.submit(makeSendMetadata(op->msg_id, op->job_id, op->payload));
            break;
        }
        case OpKind::Write: {
            op->payload.resize(rw_len_dist(rng));
            op->recv.assign(op->payload.size(), 0);
            op->payload_len = op->payload.size();
            fill_pattern(op->payload, static_cast<uint8_t>(msg_id + 51));
            op->rkey = 0x300000ULL + static_cast<uint64_t>(op->msg_id);
            harness.ses_manager.register_mr(op->rkey,
                                            reinterpret_cast<uint64_t>(op->recv.data()),
                                            op->recv.size());
            harness.submit(makeWriteMetadata(op->msg_id, op->job_id, op->rkey, op->payload, op->recv));
            break;
        }
        case OpKind::Read: {
            op->payload.resize(rw_len_dist(rng));
            op->recv.assign(op->payload.size(), 0);
            op->payload_len = op->payload.size();
            fill_pattern(op->payload, static_cast<uint8_t>(msg_id + 73));
            op->rkey = 0x400000ULL + static_cast<uint64_t>(op->msg_id);
            harness.ses_manager.register_mr(op->rkey,
                                            reinterpret_cast<uint64_t>(op->payload.data()),
                                            op->payload.size());
            harness.submit(makeReadMetadata(op->msg_id, op->job_id, op->rkey, op->payload, op->recv));
            break;
        }
    }

    return op;
}

static bool parseArgs(int argc, char **argv, Config &config)
{
    bool seconds_explicit = false;
    bool snapshot_explicit = false;
    bool jobs_explicit = false;
    bool outstanding_explicit = false;
    bool seed_explicit = false;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--profile" && i + 1 < argc) {
            const auto parsed = parseProfile(argv[++i]);
            if (!parsed.has_value()) {
                std::cerr << "Unknown profile: " << argv[i] << std::endl;
                return false;
            }
            config.profile = *parsed;
        } else if (arg == "--seconds" && i + 1 < argc) {
            config.seconds = std::max(1, std::stoi(argv[++i]));
            seconds_explicit = true;
        } else if (arg == "--snapshot-ms" && i + 1 < argc) {
            config.snapshot_ms = std::max(100, std::stoi(argv[++i]));
            snapshot_explicit = true;
        } else if (arg == "--tail-grace-ms" && i + 1 < argc) {
            config.tail_grace_ms = std::max(1000, std::stoi(argv[++i]));
        } else if (arg == "--dump-outstanding-limit" && i + 1 < argc) {
            config.dump_outstanding_limit = std::max(1, std::stoi(argv[++i]));
        } else if (arg == "--jobs" && i + 1 < argc) {
            config.jobs = std::max(1, std::stoi(argv[++i]));
            jobs_explicit = true;
        } else if (arg == "--outstanding" && i + 1 < argc) {
            config.outstanding = std::max(1, std::stoi(argv[++i]));
            outstanding_explicit = true;
        } else if (arg == "--seed" && i + 1 < argc) {
            config.seed = static_cast<uint32_t>(std::stoul(argv[++i]));
            seed_explicit = true;
        } else if (arg == "--long") {
            config.long_mode = true;
        } else {
            std::cerr << "Unknown argument: " << arg << std::endl;
            return false;
        }
    }

    if (config.long_mode) {
        if (!seconds_explicit) {
            config.seconds = 180;
        }
        if (!jobs_explicit) {
            config.jobs = 16;
        }
        if (!outstanding_explicit) {
            config.outstanding = 64;
        }
        if (!snapshot_explicit) {
            config.snapshot_ms = 1000;
        }
        if (!seed_explicit) {
            config.seed = 0xC0DEC0DEu;
        }
    }
    return true;
}

} // namespace

int main(int argc, char **argv)
{
    Logger::initialize("RudControlPressureTest.log", LogLevel::DEBUG, 1, 1);

    Config config;
    if (!parseArgs(argc, argv, config)) {
        std::cerr << "Usage: ./RudControlPressureTest --profile baseline|credit_pressure|lossy|mixed "
                     "[--seconds N] [--snapshot-ms N] [--tail-grace-ms N] [--dump-outstanding-limit N] "
                     "[--jobs N] [--outstanding N] [--seed N] [--long]"
                  << std::endl;
        return 2;
    }

    const ProfileSpec profile = makeProfileSpec(config.profile, config.long_mode);
    reset_runtime_defaults(profile.max_bitmap_blocks,
                           profile.max_unexpected_msgs,
                           profile.max_unexpected_bytes);

    PressureHarness harness(2902);
    harness.setSeed(config.seed);
    harness.setFaultModel(profile.reorder_probability, profile.drop_probability);

    std::vector<uint64_t> job_ids;
    job_ids.reserve(static_cast<size_t>(config.jobs));
    for (int i = 0; i < config.jobs; ++i) {
        job_ids.push_back(70000ULL + static_cast<uint64_t>(i));
    }

    std::mt19937 rng(config.seed ^ 0x13579BDFu);
    std::discrete_distribution<int> op_dist{
        profile.send_expected_weight,
        profile.send_spill_weight,
        profile.write_weight,
        profile.read_weight,
    };

    std::vector<std::unique_ptr<TrackedOp>> outstanding_ops;
    outstanding_ops.reserve(static_cast<size_t>(config.outstanding) * 2);
    std::vector<std::unique_ptr<TrackedOp>> retired_ops;
    std::vector<size_t> active_ops_per_job(static_cast<size_t>(config.jobs), 0);
    std::vector<uint64_t> interval_latencies_ms;
    std::vector<uint64_t> all_latencies_ms;
    size_t submitted_ops = 0;
    size_t completed_ops = 0;
    size_t job_cursor = 0;
    uint16_t msg_id = 1;
    bool had_failure = false;
    std::string failure_reason;

    const auto started_at = std::chrono::steady_clock::now();
    const auto deadline = started_at + std::chrono::seconds(config.seconds);
    auto last_snapshot_at = started_at;
    SnapshotStats last_snapshot{};
    last_snapshot.runtime = getRudRuntimeStats();
    last_snapshot.resource = getSharedRudResourceStats();
    last_snapshot.queue = captureQueueSnapshot(harness);
    last_snapshot.submitted_ops = 0;
    last_snapshot.completed_ops = 0;
    RudRuntimeStats last_progress_runtime = last_snapshot.runtime;
    RudResourceStats last_progress_resource = last_snapshot.resource;
    QueueSnapshot last_progress_queue = last_snapshot.queue;
    size_t last_progress_completed_ops = 0;
    auto last_progress_at = started_at;

    while ((!had_failure && std::chrono::steady_clock::now() < deadline) ||
           (!outstanding_ops.empty() &&
            millisBetween(last_progress_at, std::chrono::steady_clock::now()) <
                static_cast<uint64_t>(config.tail_grace_ms))) {
        const auto now = std::chrono::steady_clock::now();
        const bool submitting = !had_failure && now < deadline;
        while (submitting && outstanding_ops.size() < static_cast<size_t>(config.outstanding)) {
            const OpKind kind = static_cast<OpKind>(op_dist(rng));
            std::optional<size_t> selected_job_slot;
            for (size_t attempt = 0; attempt < job_ids.size(); ++attempt) {
                const size_t candidate = (job_cursor + attempt) % job_ids.size();
                if (active_ops_per_job[candidate] == 0) {
                    selected_job_slot = candidate;
                    break;
                }
            }
            if (!selected_job_slot.has_value()) {
                break;
            }
            outstanding_ops.push_back(
                submitOneOp(harness, rng, job_ids, *selected_job_slot, msg_id++, kind));
            ++active_ops_per_job[*selected_job_slot];
            job_cursor = (*selected_job_slot + 1) % job_ids.size();
            ++submitted_ops;
            last_progress_at = std::chrono::steady_clock::now();
        }

        const bool did_work = harness.pumpOnce();
        if (!did_work && !had_failure) {
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }

        for (size_t i = 0; i < outstanding_ops.size();) {
            auto &op = *outstanding_ops[i];
            const TickResult tick = tickOp(op, harness);
            const auto op_age_ms = millisBetween(op.submitted_at, std::chrono::steady_clock::now());
            if (tick.progress) {
                last_progress_at = std::chrono::steady_clock::now();
            }
            if (tick.done) {
                if (!tick.success) {
                    active_ops_per_job[op.job_slot] = std::max<size_t>(0, active_ops_per_job[op.job_slot] - 1);
                    had_failure = true;
                    failure_reason = tick.error;
                    break;
                }
                all_latencies_ms.push_back(op_age_ms);
                interval_latencies_ms.push_back(op_age_ms);
                ++completed_ops;
                active_ops_per_job[op.job_slot] = std::max<size_t>(0, active_ops_per_job[op.job_slot] - 1);
                retired_ops.push_back(std::move(outstanding_ops[i]));
                outstanding_ops.erase(outstanding_ops.begin() + static_cast<std::ptrdiff_t>(i));
                continue;
            }
            ++i;
        }

        const RudRuntimeStats current_runtime = getRudRuntimeStats();
        const RudResourceStats current_resource = getSharedRudResourceStats();
        const QueueSnapshot current_queue = captureQueueSnapshot(harness);
        const bool transport_progress =
            current_runtime.active_retry_states != last_progress_runtime.active_retry_states ||
            current_runtime.active_read_response_states != last_progress_runtime.active_read_response_states ||
            current_runtime.unexpected_buffered_in_use != last_progress_runtime.unexpected_buffered_in_use ||
            current_runtime.unexpected_semantic_accepted_in_use != last_progress_runtime.unexpected_semantic_accepted_in_use ||
            current_runtime.unexpected_partial_in_use != last_progress_runtime.unexpected_partial_in_use ||
            current_resource.arrival_blocks_in_use != last_progress_resource.arrival_blocks_in_use ||
            current_resource.bitmap_blocks_in_use != last_progress_resource.bitmap_blocks_in_use ||
            current_resource.unexpected_msgs_in_use != last_progress_resource.unexpected_msgs_in_use ||
            current_resource.unexpected_bytes_in_use != last_progress_resource.unexpected_bytes_in_use ||
            completed_ops != last_progress_completed_ops ||
            !sameQueueSnapshot(current_queue, last_progress_queue);
        if (transport_progress) {
            last_progress_at = std::chrono::steady_clock::now();
            last_progress_runtime = current_runtime;
            last_progress_resource = current_resource;
            last_progress_queue = current_queue;
            last_progress_completed_ops = completed_ops;
        }

        const auto snapshot_now = std::chrono::steady_clock::now();
        const auto snapshot_elapsed_ms = millisBetween(last_snapshot_at, snapshot_now);
        if (snapshot_elapsed_ms >= static_cast<uint64_t>(config.snapshot_ms)) {
            SnapshotStats current{};
            current.runtime = current_runtime;
            current.resource = current_resource;
            current.queue = current_queue;
            current.submitted_ops = submitted_ops;
            current.completed_ops = completed_ops;
            printSnapshot(profile,
                          static_cast<double>(millisBetween(started_at, snapshot_now)) / 1000.0,
                          static_cast<double>(snapshot_elapsed_ms) / 1000.0,
                          last_snapshot,
                          current,
                          interval_latencies_ms,
                          config.seed);
            last_snapshot = current;
            last_snapshot_at = snapshot_now;
            interval_latencies_ms.clear();
        }

        if (had_failure) {
            break;
        }
    }

    if (!harness.flushHeldPacket()) {
        had_failure = true;
        failure_reason = "failed to flush held packet";
    }

    if (!had_failure && !outstanding_ops.empty()) {
        had_failure = true;
        failure_reason = "completion tail deadline exceeded with " + std::to_string(outstanding_ops.size()) +
                         " outstanding operations";
    }

    if (had_failure && !outstanding_ops.empty()) {
        dumpOutstandingOps(profile,
                           outstanding_ops,
                           static_cast<size_t>(config.dump_outstanding_limit),
                           config.seed);
    }

    harness.ses_manager.pds_process_manager.requestCloseAllOpenIPDCs();
    const auto drain_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (std::chrono::steady_clock::now() < drain_deadline && !isFullyDrained()) {
        const bool did_work = harness.pumpOnce(false);
        if (!did_work) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }

    const RudRuntimeStats runtime = getRudRuntimeStats();
    const RudResourceStats resource = getSharedRudResourceStats();
    const bool drained = isFullyDrained();
    uint64_t oldest_outstanding_ms = 0;
    if (!outstanding_ops.empty()) {
        const auto now = std::chrono::steady_clock::now();
        for (const auto &op : outstanding_ops) {
            oldest_outstanding_ms = std::max(oldest_outstanding_ms, millisBetween(op->submitted_at, now));
        }
    }
    const uint64_t last_progress_ago_ms = millisBetween(last_progress_at, std::chrono::steady_clock::now());

    printSummary(profile,
                 static_cast<double>(millisBetween(started_at, std::chrono::steady_clock::now())) / 1000.0,
                 submitted_ops,
                 completed_ops,
                 runtime,
                 resource,
                 all_latencies_ms,
                 drained,
                 config.seed,
                 outstanding_ops.size(),
                 oldest_outstanding_ms,
                 last_progress_ago_ms);

    const bool ok = !had_failure &&
                    drained &&
                    submitted_ops > 0 &&
                    completed_ops == submitted_ops &&
                    resource.arrival_blocks_in_use == 0 &&
                    resource.bitmap_blocks_in_use == 0 &&
                    resource.unexpected_msgs_in_use == 0 &&
                    resource.unexpected_bytes_in_use == 0 &&
                    runtime.active_retry_states == 0 &&
                    runtime.active_read_response_states == 0 &&
                    runtime.unexpected_buffered_in_use == 0 &&
                    runtime.unexpected_semantic_accepted_in_use == 0 &&
                    runtime.unexpected_partial_in_use == 0;

    if (had_failure) {
        std::array<size_t, 5> close_cause_counts{};
        for (const auto &op : outstanding_ops) {
            if (!op->request_terminalized) {
                continue;
            }
            const size_t idx = static_cast<size_t>(op->request_close_cause);
            if (idx < close_cause_counts.size()) {
                close_cause_counts[idx]++;
            }
        }
        std::cerr << "[RudControlPressureTest] close_cause_counts"
                  << " close_req_path=" << close_cause_counts[static_cast<size_t>(RequestCloseCause::CLOSE_REQ_PATH)]
                  << " close_error_path=" << close_cause_counts[static_cast<size_t>(RequestCloseCause::CLOSE_ERROR_PATH)]
                  << " safe_close_teardown=" << close_cause_counts[static_cast<size_t>(RequestCloseCause::SAFE_CLOSE_TEARDOWN)]
                  << " rto_exhaust_path=" << close_cause_counts[static_cast<size_t>(RequestCloseCause::RTO_EXHAUST_PATH)]
                  << " unknown=" << close_cause_counts[static_cast<size_t>(RequestCloseCause::UNKNOWN)]
                  << std::endl;
        std::cerr << "[RudControlPressureTest] failure_reason=" << failure_reason << std::endl;
    }
    std::cout << (ok ? "RudControlPressureTest PASS" : "RudControlPressureTest FAIL") << std::endl;
    return ok ? 0 : 1;
}
