#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <cstdint>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "../Network_Layer/UDP_Network_Layer.hpp"
#include "../PDS/PDC/IPDC.hpp"
#include "../PDS/PDC/TPDC.hpp"
#include "../SES/SES.hpp"
#include "../logger/Logger.hpp"

using namespace UET::NetworkLayer;

namespace {

struct ResponseEvent {
    uint16_t message_id{0};
    uint8_t opcode{0};
    uint8_t return_code{0};
};

struct BitmapHarness {
    SESManager ses_manager;
    UDPNetworkLayer udp_rx;
    UDPNetworkLayer udp_tx;
    std::atomic<bool> rx_running{true};
    std::thread rx_thread;
    std::vector<ResponseEvent> responses;
    std::vector<PDS_Nack_Codes> nack_codes;

    explicit BitmapHarness(uint16_t listen_port)
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

    ~BitmapHarness()
    {
        rx_running.store(false);
        if (rx_thread.joinable()) {
            rx_thread.join();
        }
    }

    bool pumpOnce()
    {
        bool did_work = false;
        PDStoNET_pkt tx_pkt;
        if (ses_manager.pds_process_manager.popNetworkPacket(tx_pkt)) {
            if (tx_pkt.PDS_type == nack_header) {
                nack_codes.push_back(tx_pkt.PDS_header.nack_header.nack_code);
                did_work = true;
            } else if (tx_pkt.PDS_type == RUOD_ack_header &&
                       tx_pkt.PDS_header.RUOD_ack_header.next_hdr == UET_HDR_RESPONSE &&
                       tx_pkt.SESpkt.bth_type == Semantic_Response_Header) {
                const auto &hdr = tx_pkt.SESpkt.bth_header.Semantic_Response_Header;
                responses.push_back(ResponseEvent{hdr.message_id, hdr.opcode, hdr.return_code});
                did_work = true;
            } else {
                did_work = udp_tx.sendPacket(tx_pkt, "127.0.0.1", udp_rx.getLocalPort()) >= 0;
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

    bool driveUntil(const std::function<bool()> &done, int timeout_ms)
    {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
        int idle_rounds = 0;
        while (std::chrono::steady_clock::now() < deadline && idle_rounds < 100) {
            if (done()) {
                return true;
            }
            const bool did_work = pumpOnce();
            if (did_work) {
                idle_rounds = 0;
            } else {
                ++idle_rounds;
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }
        return done();
    }
};

static void fill_pattern(std::vector<uint8_t> &buf, uint8_t seed)
{
    for (size_t i = 0; i < buf.size(); ++i) {
        buf[i] = static_cast<uint8_t>((seed + i) & 0xFF);
    }
}

static void reset_rud_resource_pool()
{
    configureSharedRudResourcePool(1024, 64, 1u << 20);
    resetRudRuntimeStats();
}

static bool saw_bitmap_nack(const BitmapHarness &harness)
{
    return std::find(harness.nack_codes.begin(), harness.nack_codes.end(), UET_NO_BITMAP) != harness.nack_codes.end();
}

static bool saw_no_buffer_semantic(const BitmapHarness &harness)
{
    return std::any_of(harness.responses.begin(),
                       harness.responses.end(),
                       [](const ResponseEvent &rsp) {
                           return rsp.opcode == static_cast<uint8_t>(RSP_OP_CODE::UET_NACK) &&
                                  rsp.return_code == static_cast<uint8_t>(RSP_RETURN_CODE::RC_NO_BUFFER);
                       });
}

static int64_t expected_sack_refresh_ms()
{
    return std::max<int64_t>(15, std::min<int64_t>(50, static_cast<int64_t>(Base_RTO) / 4));
}

static int64_t expected_credit_delay_ms()
{
    return std::max<int64_t>(50, std::min<int64_t>(200, static_cast<int64_t>(Base_RTO) / 2));
}

static uint8_t expected_ack_ext_len(uint16_t section_mask)
{
    uint16_t len = sizeof(PDS_RUOD_ack_ctrl_prefix);
    if ((section_mask & ACK_CTRL_SECTION_SACK) != 0) {
        len = static_cast<uint16_t>(len + sizeof(PDS_RUOD_ack_ctrl_sack_section));
    }
    if ((section_mask & ACK_CTRL_SECTION_CREDIT) != 0) {
        len = static_cast<uint16_t>(len + sizeof(PDS_RUOD_ack_ctrl_credit_section));
    }
    if ((section_mask & ACK_CTRL_SECTION_ACKREQ_HINT) != 0) {
        len = static_cast<uint16_t>(len + sizeof(PDS_RUOD_ack_ctrl_ackreq_hint_section));
    }
    if ((section_mask & ACK_CTRL_SECTION_RECEIVER_PRESSURE) != 0) {
        len = static_cast<uint16_t>(len + sizeof(PDS_RUOD_ack_ctrl_receiver_pressure_section));
    }
    return static_cast<uint8_t>(len);
}

static uint32_t extract_sack_bitmap(const PDStoNET_pkt &pkt)
{
    uint32_t bitmap = 0;
    if (pkt.SESpkt.payload.data() && pkt.SESpkt.payload.size() >= sizeof(bitmap)) {
        std::memcpy(&bitmap, pkt.SESpkt.payload.data(), sizeof(bitmap));
    }
    return bitmap;
}

static PDS_PDC_req make_send_front_req(uint16_t msg_id, uint32_t job_id)
{
    PDS_PDC_req req{};
    req.next_hdr = UET_HDR_NONE;
    req.som = true;
    req.eom = true;
    req.pkt.bth_type = Standard_Header;
    req.pkt.bth_header.Standard_Header.opcode = SEND;
    req.pkt.bth_header.Standard_Header.msg_id = msg_id;
    req.pkt.bth_header.Standard_Header.job_id = job_id;
    req.pkt.bth_header.Standard_Header.som = 1;
    req.pkt.bth_header.Standard_Header.eom = 1;
    return req;
}

static OperationMetadata make_retry_send_metadata(uint64_t job_id, uint16_t msg_id, uint32_t dst_fep)
{
    static std::vector<uint8_t> payload(256, 0x5A);
    OperationMetadata md{};
    md.op_type = SEND;
    md.s_pid_on_fep = 1001;
    md.t_pid_on_fep = dst_fep;
    md.job_id = job_id;
    md.messages_id = msg_id;
    md.payload.start_addr = reinterpret_cast<uint64_t>(payload.data());
    md.payload.length = payload.size();
    md.delivery_mode = RUD;
    return md;
}

static OperationMetadata make_read_track_metadata(uint64_t job_id,
                                                  uint16_t msg_id,
                                                  uint32_t src_fep,
                                                  uint32_t dst_fep,
                                                  std::vector<uint8_t> &remote_buf,
                                                  std::vector<uint8_t> &local_buf)
{
    OperationMetadata md{};
    md.op_type = READ;
    md.s_pid_on_fep = src_fep;
    md.t_pid_on_fep = dst_fep;
    md.job_id = job_id;
    md.messages_id = msg_id;
    md.memory.rkey = 0xDEADBEEFULL;
    md.payload.start_addr = reinterpret_cast<uint64_t>(remote_buf.data());
    md.payload.local_addr = reinterpret_cast<uint64_t>(local_buf.data());
    md.payload.length = remote_buf.size();
    md.delivery_mode = RUD;
    return md;
}

static void set_credit_cp_payload(PDStoNET_pkt &pkt,
                                  uint32_t job_id,
                                  uint16_t credit_gen,
                                  uint16_t posted_recv_credits,
                                  uint16_t unexpected_msg_credits,
                                  uint16_t unexpected_byte_credits)
{
    const PDS_RUOD_credit_cp_payload wire{
        job_id,
        credit_gen,
        posted_recv_credits,
        unexpected_msg_credits,
        unexpected_byte_credits,
        static_cast<uint8_t>(12),
        0,
    };
    pkt.SESpkt.payload.allocate(sizeof(wire));
    std::memcpy(pkt.SESpkt.payload.data(), &wire, sizeof(wire));
}

static void set_credit_req_cp_payload(PDStoNET_pkt &pkt, uint32_t job_id, uint16_t last_seen_credit_gen)
{
    const PDS_RUOD_credit_req_cp_payload wire{job_id, last_seen_credit_gen, 0};
    pkt.SESpkt.payload.allocate(sizeof(wire));
    std::memcpy(pkt.SESpkt.payload.data(), &wire, sizeof(wire));
}

static void seed_local_credit(PDC &pdc,
                              uint32_t job_id,
                              bool dirty,
                              int64_t last_sent_ms = 0)
{
    pdc.observed_receiver_jobs_.insert(job_id);
    auto &state = pdc.local_receiver_credits_[job_id];
    state.snapshot.job_id = job_id;
    state.snapshot.byte_credit_shift = 12;
    state.snapshot.flags = 0;
    state.dirty = dirty;
    state.last_sent_ms = last_sent_ms;
}

static bool run_ack_req_guard_case()
{
    resetRudRuntimeStats();
    I_PDC ipdc;
    ipdc.initPDC(4101, RUD);
    ipdc.state = ESTABLISHED;
    ipdc.DPDCID = 5101;
    ipdc.clear_psn = 900;
    PDStoNET_pkt first_pkt{};
    const bool first_sent = ipdc.sendCtrlAckReq(&first_pkt) &&
                            first_pkt.PDS_header.RUOD_cp_header.ctl_type == ACK_req &&
                            first_pkt.PDS_header.RUOD_cp_header.psn == 901;

    PDStoNET_pkt suppressed_pkt{};
    const bool second_suppressed = !ipdc.sendCtrlAckReq(&suppressed_pkt);

    ipdc.clear_psn = 901;
    PDStoNET_pkt changed_pkt{};
    const bool changed_psn_sent = ipdc.sendCtrlAckReq(&changed_pkt) &&
                                  changed_pkt.PDS_header.RUOD_cp_header.ctl_type == ACK_req &&
                                  changed_pkt.PDS_header.RUOD_cp_header.psn == 902;

    const RudRuntimeStats stats = getRudRuntimeStats();
    const bool ok = first_sent &&
                    second_suppressed &&
                    changed_psn_sent &&
                    stats.ctrl_ack_req_sent == 2 &&
                    stats.ctrl_ack_req_suppressed >= 1;
    std::cout << "[RudBitmapResourceTest] ack_req_guard="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

static bool run_sack_guard_case()
{
    resetRudRuntimeStats();
    ThreadSafeQueue<PDStoNET_pkt> net_q;
    T_PDC tpdc;
    tpdc.initPDC(4201, RUD);
    tpdc.state = ESTABLISHED;
    tpdc.DPDCID = 5201;
    tpdc.rx_cur_psn = 1000;
    tpdc.rud_rx_ooo_psns.insert(1002);
    tpdc.setPublicQueues(&net_q, nullptr, nullptr, nullptr);

    tpdc.gen_cm = SACK_CTRL;
    tpdc.txCtrl();
    PDStoNET_pkt first_pkt{};
    const bool first_sent = net_q.pop(first_pkt) &&
                            first_pkt.PDS_type == RUOD_cp_header &&
                            first_pkt.PDS_header.RUOD_cp_header.ctl_type == SACK;
    const uint32_t first_base = first_pkt.PDS_header.RUOD_cp_header.payload;
    const uint32_t first_bitmap = extract_sack_bitmap(first_pkt);

    tpdc.gen_cm = SACK_CTRL;
    tpdc.txCtrl();
    PDStoNET_pkt suppressed_pkt{};
    const bool second_suppressed = !net_q.pop(suppressed_pkt);

    std::this_thread::sleep_for(std::chrono::milliseconds(expected_sack_refresh_ms() + 5));
    tpdc.gen_cm = SACK_CTRL;
    tpdc.txCtrl();
    PDStoNET_pkt refresh_pkt{};
    const bool refresh_sent = net_q.pop(refresh_pkt) &&
                              refresh_pkt.PDS_header.RUOD_cp_header.ctl_type == SACK &&
                              refresh_pkt.PDS_header.RUOD_cp_header.payload == first_base &&
                              extract_sack_bitmap(refresh_pkt) == first_bitmap;

    tpdc.rud_rx_ooo_psns.insert(1003);
    tpdc.gen_cm = SACK_CTRL;
    tpdc.txCtrl();
    PDStoNET_pkt changed_pkt{};
    const bool changed_sent = net_q.pop(changed_pkt) &&
                              changed_pkt.PDS_header.RUOD_cp_header.ctl_type == SACK &&
                              extract_sack_bitmap(changed_pkt) != first_bitmap;

    const RudRuntimeStats stats = getRudRuntimeStats();
    const bool ok = first_sent &&
                    second_suppressed &&
                    refresh_sent &&
                    changed_sent &&
                    stats.ctrl_sack_sent == 3 &&
                    stats.ctrl_sack_suppressed >= 1;
    std::cout << "[RudBitmapResourceTest] sack_guard="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

static bool run_gap_nack_backoff_case()
{
    resetRudRuntimeStats();
    ThreadSafeQueue<PDStoNET_pkt> net_q;
    T_PDC tpdc;
    tpdc.initPDC(4301, RUD);
    tpdc.state = ESTABLISHED;
    tpdc.DPDCID = 5301;
    tpdc.rx_cur_psn = 1000;
    tpdc.rud_rx_ooo_psns.insert(1002);
    tpdc.setPublicQueues(&net_q, nullptr, nullptr, nullptr);
    tpdc.refreshRudGapState();
    tpdc.rud_gap_first_ms = tpdc.nowMs() - tpdc.kRudGapDelayMs;

    tpdc.maybeTriggerRudControl();
    PDStoNET_pkt first_pkt{};
    const bool first_sent = net_q.pop(first_pkt) &&
                            first_pkt.PDS_type == nack_header &&
                            first_pkt.PDS_header.nack_header.nack_code == UET_RCVR_INFER_LOSS &&
                            first_pkt.PDS_header.nack_header.nack_psn == 1001;

    tpdc.maybeTriggerRudControl();
    PDStoNET_pkt suppressed_pkt{};
    const bool immediate_suppressed = !net_q.pop(suppressed_pkt);

    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    tpdc.maybeTriggerRudControl();
    PDStoNET_pkt before_backoff_pkt{};
    const bool before_backoff_suppressed = !net_q.pop(before_backoff_pkt);

    std::this_thread::sleep_for(std::chrono::milliseconds(15));
    tpdc.maybeTriggerRudControl();
    PDStoNET_pkt second_pkt{};
    const bool second_sent = net_q.pop(second_pkt) &&
                             second_pkt.PDS_header.nack_header.nack_code == UET_RCVR_INFER_LOSS &&
                             second_pkt.PDS_header.nack_header.nack_psn == 1001;

    std::this_thread::sleep_for(std::chrono::milliseconds(35));
    tpdc.maybeTriggerRudControl();
    PDStoNET_pkt before_third_pkt{};
    const bool before_third_suppressed = !net_q.pop(before_third_pkt);

    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    tpdc.maybeTriggerRudControl();
    PDStoNET_pkt third_pkt{};
    const bool third_sent = net_q.pop(third_pkt) &&
                            third_pkt.PDS_header.nack_header.nack_code == UET_RCVR_INFER_LOSS &&
                            third_pkt.PDS_header.nack_header.nack_psn == 1001;

    tpdc.rud_rx_ooo_psns.clear();
    tpdc.refreshRudGapState();
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    tpdc.maybeTriggerRudControl();
    PDStoNET_pkt after_clear_pkt{};
    const bool cleared = !net_q.pop(after_clear_pkt);

    const RudRuntimeStats stats = getRudRuntimeStats();
    const bool ok = first_sent &&
                    immediate_suppressed &&
                    before_backoff_suppressed &&
                    second_sent &&
                    before_third_suppressed &&
                    third_sent &&
                    cleared &&
                    stats.ctrl_gap_nack_sent == 3 &&
                    stats.ctrl_gap_nack_suppressed >= 1;
    std::cout << "[RudBitmapResourceTest] gap_nack_backoff="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

static bool run_control_merge_case()
{
    resetRudRuntimeStats();
    ThreadSafeQueue<PDStoNET_pkt> net_q;
    T_PDC tpdc;
    tpdc.initPDC(4401, RUD);
    tpdc.state = ESTABLISHED;
    tpdc.DPDCID = 5401;
    tpdc.clear_psn = tpdc.tx_cur_psn - static_cast<uint32_t>(tpdc.MPR / 2);
    tpdc.rx_cur_psn = 1000;
    tpdc.rud_rx_ooo_psns.insert(1002);
    tpdc.setPublicQueues(&net_q, nullptr, nullptr, nullptr);

    tpdc.updateTxPsnTracker();
    const bool ack_pending = (tpdc.gen_cm == ACK_REQ);

    tpdc.noteRudSackPending();
    tpdc.rud_sack_first_ms = tpdc.nowMs() - tpdc.kRudSackDelayMs;
    tpdc.maybeTriggerRudControl();
    const bool upgraded_to_sack = (tpdc.gen_cm == SACK_CTRL);

    tpdc.updateTxPsnTracker();
    const bool sack_not_overwritten = (tpdc.gen_cm == SACK_CTRL);

    tpdc.txCtrl();
    PDStoNET_pkt sack_pkt{};
    const bool emitted_sack = net_q.pop(sack_pkt) &&
                              sack_pkt.PDS_type == RUOD_cp_header &&
                              sack_pkt.PDS_header.RUOD_cp_header.ctl_type == SACK;

    tpdc.gen_cm = ACK_REQ;
    while (tpdc.tx_ack_buffer.size() + 5 < tpdc.tx_ack_buffer_capa) {
        tpdc.tx_ack_buffer.emplace(static_cast<uint32_t>(tpdc.tx_ack_buffer.size() + 1), PDStoNET_pkt{});
    }
    tpdc.chkClear();
    const bool clear_overrides_ack = (tpdc.gen_cm == CLR_REQ);

    const bool ok = ack_pending &&
                    upgraded_to_sack &&
                    sack_not_overwritten &&
                    emitted_sack &&
                    clear_overrides_ack;
    std::cout << "[RudBitmapResourceTest] control_merge="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

static bool run_gap_cp_merge_case()
{
    resetRudRuntimeStats();
    ThreadSafeQueue<PDStoNET_pkt> net_q;
    T_PDC tpdc;
    tpdc.initPDC(4501, RUD);
    tpdc.state = ESTABLISHED;
    tpdc.DPDCID = 5501;
    tpdc.clear_psn = 900;
    tpdc.gen_cm = ACK_REQ;
    tpdc.rx_cur_psn = 1000;
    tpdc.rud_rx_ooo_psns.insert(1002);
    tpdc.setPublicQueues(&net_q, nullptr, nullptr, nullptr);
    tpdc.refreshRudGapState();
    tpdc.rud_gap_first_ms = tpdc.nowMs() - tpdc.kRudGapDelayMs;

    tpdc.openChk();
    PDStoNET_pkt first_pkt{};
    const bool gap_first = net_q.pop(first_pkt) &&
                           first_pkt.PDS_type == nack_header &&
                           first_pkt.PDS_header.nack_header.nack_code == UET_RCVR_INFER_LOSS;
    PDStoNET_pkt extra_pkt{};
    const bool no_cp_same_round = !net_q.pop(extra_pkt);
    const bool ack_still_pending = (tpdc.gen_cm == ACK_REQ);

    tpdc.rud_rx_ooo_psns.clear();
    tpdc.refreshRudGapState();
    tpdc.openChk();
    PDStoNET_pkt ack_pkt{};
    const bool ack_next_round = net_q.pop(ack_pkt) &&
                                ack_pkt.PDS_type == RUOD_cp_header &&
                                ack_pkt.PDS_header.RUOD_cp_header.ctl_type == ACK_req;

    const bool ok = gap_first &&
                    no_cp_same_round &&
                    ack_still_pending &&
                    ack_next_round;
    std::cout << "[RudBitmapResourceTest] gap_cp_merge="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

static bool run_ctrl_budget_case()
{
    resetRudRuntimeStats();
    ThreadSafeQueue<PDStoNET_pkt> net_q;
    I_PDC ipdc;
    ipdc.initPDC(4601, RUD);
    ipdc.state = ESTABLISHED;
    ipdc.DPDCID = 5601;
    ipdc.setPublicQueues(&net_q, nullptr, nullptr, nullptr);

    bool first_eight_sent = true;
    for (int i = 0; i < ipdc.kRudCtrlBudgetCapacity; ++i) {
        ipdc.clear_psn = 1000 + static_cast<uint32_t>(i);
        ipdc.gen_cm = ACK_REQ;
        ipdc.txCtrl();
        PDStoNET_pkt pkt{};
        first_eight_sent = first_eight_sent &&
                           net_q.pop(pkt) &&
                           pkt.PDS_type == RUOD_cp_header &&
                           pkt.PDS_header.RUOD_cp_header.ctl_type == ACK_req;
    }

    ipdc.clear_psn = 2000;
    ipdc.gen_cm = ACK_REQ;
    ipdc.txCtrl();
    PDStoNET_pkt deferred_pkt{};
    const bool deferred = !net_q.pop(deferred_pkt) &&
                          ipdc.ctrl_tx_deferred_ &&
                          ipdc.gen_cm == ACK_REQ;

    std::this_thread::sleep_for(std::chrono::milliseconds(110));
    ipdc.txCtrl();
    PDStoNET_pkt refill_pkt{};
    const bool refill_sent = net_q.pop(refill_pkt) &&
                             refill_pkt.PDS_type == RUOD_cp_header &&
                             refill_pkt.PDS_header.RUOD_cp_header.ctl_type == ACK_req &&
                             ipdc.gen_cm == NONE;

    const RudRuntimeStats stats = getRudRuntimeStats();
    const bool ok = first_eight_sent &&
                    deferred &&
                    refill_sent &&
                    stats.ctrl_budget_deferred >= 1;
    std::cout << "[RudBitmapResourceTest] ctrl_budget="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

static bool run_ctrl_rate_stats_case()
{
    resetRudRuntimeStats();
    I_PDC ipdc;
    ipdc.initPDC(4701, RUD);
    ipdc.state = ESTABLISHED;
    ipdc.DPDCID = 5701;
    ipdc.clear_psn = 700;

    PDStoNET_pkt ack_pkt{};
    const bool ack_ok = ipdc.sendCtrlAckReq(&ack_pkt);

    ipdc.rx_cur_psn = 1000;
    ipdc.rud_rx_ooo_psns.insert(1002);
    PDStoNET_pkt sack_pkt{};
    const bool sack_ok = ipdc.sendCtrlSack(&sack_pkt);

    ipdc.sendNack(0, 1001, UET_RCVR_INFER_LOSS, 1001, nullptr);
    noteRudRcNoMatchRetryScheduled();

    const RudRuntimeStats live_stats = getRudRuntimeStats();
    const bool live_ok = ack_ok &&
                         sack_ok &&
                         live_stats.ctrl_ack_req_last_1s >= 1 &&
                         live_stats.ctrl_sack_last_1s >= 1 &&
                         live_stats.ctrl_nack_last_1s >= 1 &&
                         live_stats.retry_rc_no_match_last_1s >= 1;

    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    const RudRuntimeStats aged_stats = getRudRuntimeStats();
    const bool aged_ok = aged_stats.ctrl_ack_req_last_1s == 0 &&
                         aged_stats.ctrl_sack_last_1s == 0 &&
                         aged_stats.ctrl_nack_last_1s == 0 &&
                         aged_stats.retry_rc_no_match_last_1s == 0;

    const bool ok = live_ok && aged_ok;
    std::cout << "[RudBitmapResourceTest] ctrl_rate_stats="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

static bool run_ack_ctrl_ext_wire_case()
{
    constexpr uint16_t kPort = 2898;
    UDPNetworkLayer udp_rx(kPort);
    UDPNetworkLayer udp_tx(0);
    if (!udp_rx.initialize() || !udp_tx.initialize()) {
        throw std::runtime_error("failed to initialize ACK ext wire harness");
    }

    PDStoNET_pkt tx{};
    tx.src_fep = 1001;
    tx.dst_fep = 2001;
    tx.PDS_type = RUOD_ack_header;
    tx.PDS_header.RUOD_ack_header.type = ACK;
    tx.PDS_header.RUOD_ack_header.next_hdr = UET_HDR_RESPONSE_DATA;
    tx.PDS_header.RUOD_ack_header.flags.x = 1;
    tx.PDS_header.RUOD_ack_header.cack_psn = 1234;
    tx.PDS_header.RUOD_ack_header.ack_psn_off = 1;
    tx.PDS_header.RUOD_ack_header.spdcid = 77;
    tx.PDS_header.RUOD_ack_header.dpdcid = 88;
    tx.ack_ctrl_ext.prefix.version = 2;
    tx.ack_ctrl_ext.prefix.section_mask = ACK_CTRL_SECTION_SACK | ACK_CTRL_SECTION_CREDIT;
    tx.ack_ctrl_ext.prefix.total_len = expected_ack_ext_len(tx.ack_ctrl_ext.prefix.section_mask);
    tx.ack_ctrl_ext.credit.job_id = 41001;
    tx.ack_ctrl_ext.credit.credit_gen = 9;
    tx.ack_ctrl_ext.credit.posted_recv_credits = 3;
    tx.ack_ctrl_ext.credit.unexpected_msg_credits = 5;
    tx.ack_ctrl_ext.credit.unexpected_byte_credits = 7;
    tx.ack_ctrl_ext.credit.byte_credit_shift = 12;
    tx.ack_ctrl_ext.credit.flags = 0;
    tx.ack_ctrl_ext.sack.sack_base_psn = 2222;
    tx.ack_ctrl_ext.sack.sack_bitmap = 0xA5A5000Fu;
    tx.SESpkt.bth_type = Semantic_Response_with_Data_Header;
    tx.SESpkt.bth_header.Semantic_Response_with_Data_Header.opcode =
        static_cast<uint8_t>(RSP_OP_CODE::UET_RESPONSE_W_DATA);
    tx.SESpkt.bth_header.Semantic_Response_with_Data_Header.payload_length = 4;
    const std::vector<uint8_t> payload{0x11, 0x22, 0x33, 0x44};
    tx.SESpkt.payload.assign(payload.begin(), payload.end());

    const bool sent = udp_tx.sendPacket(tx, "127.0.0.1", udp_rx.getLocalPort()) >= 0;
    PDStoNET_pkt rx{};
    const bool received = udp_rx.receivePDStoNETPacket(1000, rx);
    const bool ok = sent &&
                    received &&
                    rx.PDS_type == RUOD_ack_header &&
                    rx.PDS_header.RUOD_ack_header.flags.x == 1 &&
                    rx.ack_ctrl_ext.prefix.version == 2 &&
                    rx.ack_ctrl_ext.prefix.section_mask == tx.ack_ctrl_ext.prefix.section_mask &&
                    rx.ack_ctrl_ext.prefix.total_len == tx.ack_ctrl_ext.prefix.total_len &&
                    rx.ack_ctrl_ext.credit.job_id == tx.ack_ctrl_ext.credit.job_id &&
                    rx.ack_ctrl_ext.credit.credit_gen == tx.ack_ctrl_ext.credit.credit_gen &&
                    rx.ack_ctrl_ext.credit.posted_recv_credits == tx.ack_ctrl_ext.credit.posted_recv_credits &&
                    rx.ack_ctrl_ext.credit.unexpected_msg_credits == tx.ack_ctrl_ext.credit.unexpected_msg_credits &&
                    rx.ack_ctrl_ext.credit.unexpected_byte_credits == tx.ack_ctrl_ext.credit.unexpected_byte_credits &&
                    rx.ack_ctrl_ext.credit.byte_credit_shift == tx.ack_ctrl_ext.credit.byte_credit_shift &&
                    rx.ack_ctrl_ext.sack.sack_base_psn == tx.ack_ctrl_ext.sack.sack_base_psn &&
                    rx.ack_ctrl_ext.sack.sack_bitmap == tx.ack_ctrl_ext.sack.sack_bitmap &&
                    rx.SESpkt.bth_type == Semantic_Response_with_Data_Header &&
                    rx.SESpkt.payload.size() == 4 &&
                    rx.SESpkt.payload.data() != nullptr &&
                    rx.SESpkt.payload[0] == 0x11 &&
                    rx.SESpkt.payload[3] == 0x44;
    std::cout << "[RudBitmapResourceTest] ack_ctrl_ext_wire="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

static bool run_ack_credit_only_case()
{
    resetRudRuntimeStats();
    ThreadSafeQueue<PDStoNET_pkt> net_q;
    I_PDC ipdc;
    ipdc.initPDC(4801, RUD);
    ipdc.state = ESTABLISHED;
    ipdc.DPDCID = 5801;
    ipdc.setPublicQueues(&net_q, nullptr, nullptr, nullptr);
    constexpr uint32_t kJobId = 48001;
    seed_local_credit(ipdc, kJobId, true);
    ipdc.rud_sack_pending = false;
    ipdc.sendAck(PDS_next_hdr::UET_HDR_NONE, 0, 0, 1001, nullptr, false, kJobId);
    PDStoNET_pkt pkt{};
    const RudRuntimeStats stats = getRudRuntimeStats();
    const bool ok = net_q.pop(pkt) &&
                    pkt.PDS_type == RUOD_ack_header &&
                    pkt.PDS_header.RUOD_ack_header.flags.x == 1 &&
                    pkt.ack_ctrl_ext.prefix.section_mask ==
                        static_cast<uint16_t>(ACK_CTRL_SECTION_CREDIT |
                                              ACK_CTRL_SECTION_RECEIVER_PRESSURE) &&
                    pkt.ack_ctrl_ext.credit.job_id == kJobId &&
                    pkt.ack_ctrl_ext.credit.unexpected_msg_credits > 0 &&
                    pkt.ack_ctrl_ext.credit.unexpected_byte_credits > 0 &&
                    pkt.ack_ctrl_ext.credit.byte_credit_shift == 12 &&
                    stats.ack_ctrl_ext_sent >= 1 &&
                    stats.ack_credit_piggyback_sent >= 1 &&
                    stats.ack_receiver_pressure_piggyback_sent >= 1;
    std::cout << "[RudBitmapResourceTest] ack_credit_only="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

static bool run_ack_sack_only_case()
{
    resetRudRuntimeStats();
    ThreadSafeQueue<PDStoNET_pkt> net_q;
    T_PDC tpdc;
    tpdc.initPDC(4901, RUD);
    tpdc.state = ESTABLISHED;
    tpdc.DPDCID = 5901;
    tpdc.rx_cur_psn = 1000;
    tpdc.rud_rx_ooo_psns.insert(1002);
    tpdc.rud_sack_pending = true;
    tpdc.rud_sack_first_ms = tpdc.nowMs() - tpdc.kRudSackDelayMs;
    tpdc.receiver_pressure_dirty_ = true;
    tpdc.setPublicQueues(&net_q, nullptr, nullptr, nullptr);

    tpdc.sendAck(PDS_next_hdr::UET_HDR_NONE, 0, 0, 1001, nullptr, false);
    PDStoNET_pkt pkt{};
    const RudRuntimeStats stats = getRudRuntimeStats();
    const bool ok = net_q.pop(pkt) &&
                    pkt.PDS_type == RUOD_ack_header &&
                    pkt.PDS_header.RUOD_ack_header.flags.x == 1 &&
                    pkt.ack_ctrl_ext.prefix.section_mask ==
                        static_cast<uint16_t>(ACK_CTRL_SECTION_SACK |
                                              ACK_CTRL_SECTION_RECEIVER_PRESSURE) &&
                    pkt.ack_ctrl_ext.sack.sack_base_psn == 1000 &&
                    pkt.ack_ctrl_ext.sack.sack_bitmap == 0x2u &&
                    !tpdc.rud_sack_pending &&
                    stats.ack_sack_piggyback_sent >= 1 &&
                    stats.ack_receiver_pressure_piggyback_sent >= 1;
    std::cout << "[RudBitmapResourceTest] ack_sack_only="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

static bool run_ack_sack_and_credit_case()
{
    resetRudRuntimeStats();
    ThreadSafeQueue<PDStoNET_pkt> net_q;
    T_PDC tpdc;
    tpdc.initPDC(5001, RUD);
    tpdc.state = ESTABLISHED;
    tpdc.DPDCID = 6001;
    tpdc.rx_cur_psn = 1000;
    tpdc.rud_rx_ooo_psns.insert(1002);
    tpdc.rud_sack_pending = true;
    tpdc.rud_sack_first_ms = tpdc.nowMs() - tpdc.kRudSackDelayMs;
    constexpr uint32_t kJobId = 50001;
    seed_local_credit(tpdc, kJobId, true);
    tpdc.setPublicQueues(&net_q, nullptr, nullptr, nullptr);

    tpdc.sendAck(PDS_next_hdr::UET_HDR_NONE, 0, 0, 1001, nullptr, false, kJobId);
    PDStoNET_pkt pkt{};
    const RudRuntimeStats stats = getRudRuntimeStats();
    const bool ok = net_q.pop(pkt) &&
                    pkt.PDS_type == RUOD_ack_header &&
                    pkt.PDS_header.RUOD_ack_header.flags.x == 1 &&
                    pkt.ack_ctrl_ext.prefix.section_mask ==
                        static_cast<uint16_t>(ACK_CTRL_SECTION_SACK | ACK_CTRL_SECTION_CREDIT |
                                              ACK_CTRL_SECTION_RECEIVER_PRESSURE) &&
                    pkt.ack_ctrl_ext.sack.sack_base_psn == 1000 &&
                    pkt.ack_ctrl_ext.sack.sack_bitmap == 0x2u &&
                    pkt.ack_ctrl_ext.credit.job_id == kJobId &&
                    pkt.ack_ctrl_ext.credit.unexpected_msg_credits > 0 &&
                    stats.ack_sack_piggyback_sent >= 1 &&
                    stats.ack_credit_piggyback_sent >= 1;
    std::cout << "[RudBitmapResourceTest] ack_sack_and_credit="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

static bool run_credit_reorder_ignore_stale_case()
{
    resetRudRuntimeStats();
    I_PDC ipdc;
    ipdc.initPDC(5101, RUD);
    ipdc.state = ESTABLISHED;

    PDStoNET_pkt fresh{};
    fresh.PDS_type = RUOD_cp_header;
    fresh.PDS_header.RUOD_cp_header.flags.isrod = 0;
    fresh.PDS_header.RUOD_cp_header.ctl_type = Credit;
    set_credit_cp_payload(fresh, 51001, 2, 0, 5, 5);
    ipdc.rxCtrl(&fresh);

    PDStoNET_pkt stale{};
    stale.PDS_type = RUOD_cp_header;
    stale.PDS_header.RUOD_cp_header.flags.isrod = 0;
    stale.PDS_header.RUOD_cp_header.ctl_type = Credit;
    set_credit_cp_payload(stale, 51001, 1, 0, 9, 9);
    ipdc.rxCtrl(&stale);

    const RudRuntimeStats stats = getRudRuntimeStats();
    const auto peer_it = ipdc.peer_receiver_credits_.find(51001);
    const bool ok = peer_it != ipdc.peer_receiver_credits_.end() &&
                    peer_it->second.valid &&
                    peer_it->second.credit_gen_seen == 2 &&
                    peer_it->second.unexpected_msg_credits == 5 &&
                    stats.credit_updates_rx >= 1 &&
                    stats.credit_stale_ignored >= 1;
    std::cout << "[RudBitmapResourceTest] credit_reorder_ignore_stale="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

static bool run_bootstrap_then_hard_gate_case()
{
    resetRudRuntimeStats();
    ThreadSafeQueue<PDStoNET_pkt> net_q;
    I_PDC ipdc;
    ipdc.initPDC(5201, RUD);
    ipdc.state = ESTABLISHED;
    ipdc.DPDCID = 6201;
    ipdc.setPublicQueues(&net_q, nullptr, nullptr, nullptr);
    const PDS_PDC_req req = make_send_front_req(17, 41001);
    const int64_t now = ipdc.nowMs();

    const bool bootstrap_ok = ipdc.canDispatchFrontReq(req, now);
    const bool gated_before_credit = !ipdc.canDispatchFrontReq(req, now);
    std::this_thread::sleep_for(std::chrono::milliseconds(expected_credit_delay_ms() + 5));
    const bool requested_credit = !ipdc.canDispatchFrontReq(req, ipdc.nowMs()) &&
                                  ipdc.pending_credit_req_job_id_ == 41001;

    PDStoNET_pkt credit_pkt{};
    credit_pkt.PDS_type = RUOD_cp_header;
    credit_pkt.PDS_header.RUOD_cp_header.flags.isrod = 0;
    credit_pkt.PDS_header.RUOD_cp_header.ctl_type = Credit;
    set_credit_cp_payload(credit_pkt, 41001, 3, 0, 2, 2);
    ipdc.rxCtrl(&credit_pkt);

    const bool first_after_credit = ipdc.canDispatchFrontReq(req, ipdc.nowMs());
    const bool second_after_credit = ipdc.canDispatchFrontReq(req, ipdc.nowMs());
    const bool gated_after_credit = !ipdc.canDispatchFrontReq(req, ipdc.nowMs());

    const RudRuntimeStats stats = getRudRuntimeStats();
    const bool ok = bootstrap_ok &&
                    gated_before_credit &&
                    requested_credit &&
                    first_after_credit &&
                    second_after_credit &&
                    gated_after_credit &&
                    stats.credit_gate_blocked >= 1 &&
                    stats.credit_updates_rx >= 1;
    std::cout << "[RudBitmapResourceTest] bootstrap_then_hard_gate="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

static bool run_credit_refresh_case()
{
    resetRudRuntimeStats();
    ThreadSafeQueue<PDStoNET_pkt> net_q;
    I_PDC ipdc;
    ipdc.initPDC(5251, RUD);
    ipdc.state = ESTABLISHED;
    ipdc.DPDCID = 6251;
    ipdc.setPublicQueues(&net_q, nullptr, nullptr, nullptr);
    constexpr uint32_t kJobId = 52510;
    seed_local_credit(ipdc, kJobId, true, ipdc.nowMs() - expected_credit_delay_ms() - 5);
    ipdc.receiver_pressure_dirty_ = false;
    ipdc.last_credit_sent_ms_ = ipdc.nowMs() - expected_credit_delay_ms() - 5;
    PDStoNET_pkt cached{};
    ipdc.tx_pkt_buffer.emplace(777, cached);

    ipdc.maybeTriggerRudControl();
    const bool credit_pending = (ipdc.gen_cm == CREDIT);
    ipdc.txCtrl();
    PDStoNET_pkt pkt{};
    const RudRuntimeStats stats = getRudRuntimeStats();
    const bool ok = credit_pending &&
                    net_q.pop(pkt) &&
                    pkt.PDS_type == RUOD_cp_header &&
                    pkt.PDS_header.RUOD_cp_header.ctl_type == Credit &&
                    pkt.SESpkt.payload.size() == sizeof(PDS_RUOD_credit_cp_payload) &&
                    stats.credit_refresh_sent >= 1 &&
                    stats.credit_cp_sent >= 1 &&
                    stats.credit_refresh_last_1s >= 1;
    std::cout << "[RudBitmapResourceTest] credit_refresh="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

static bool run_resource_nack_governance_case()
{
    resetRudRuntimeStats();
    ThreadSafeQueue<PDStoNET_pkt> net_q;
    I_PDC ipdc;
    ipdc.initPDC(5252, RUD);
    ipdc.state = ESTABLISHED;
    ipdc.DPDCID = 6252;
    ipdc.setPublicQueues(&net_q, nullptr, nullptr, nullptr);

    ipdc.sendNack(0, 88, UET_NO_RESOURCE, 5, nullptr);
    PDStoNET_pkt first{};
    const bool first_ok = net_q.pop(first) &&
                          first.PDS_header.nack_header.nack_code == UET_NO_RESOURCE;
    ipdc.sendNack(0, 88, UET_NO_RESOURCE, 5, nullptr);
    PDStoNET_pkt second{};
    const bool second_suppressed = !net_q.pop(second);
    std::this_thread::sleep_for(std::chrono::milliseconds(7));
    ipdc.sendNack(0, 88, UET_NO_RESOURCE, 5, nullptr);
    PDStoNET_pkt third{};
    const bool third_ok = net_q.pop(third) &&
                          third.PDS_header.nack_header.nack_code == UET_NO_RESOURCE;
    const RudRuntimeStats stats = getRudRuntimeStats();
    const bool ok = first_ok &&
                    second_suppressed &&
                    third_ok &&
                    stats.ctrl_nack_resource_sent == 2 &&
                    stats.ctrl_nack_resource_suppressed >= 1;
    std::cout << "[RudBitmapResourceTest] resource_nack_governance="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

static bool run_fatal_nack_passthrough_case()
{
    resetRudRuntimeStats();
    ThreadSafeQueue<PDStoNET_pkt> net_q;
    I_PDC ipdc;
    ipdc.initPDC(5253, RUD);
    ipdc.state = ESTABLISHED;
    ipdc.DPDCID = 6253;
    ipdc.setPublicQueues(&net_q, nullptr, nullptr, nullptr);

    ipdc.sendNack(0, 99, UET_INV_DPDCID, 0, nullptr);
    ipdc.sendNack(0, 99, UET_INV_DPDCID, 0, nullptr);

    PDStoNET_pkt first{};
    PDStoNET_pkt second{};
    const RudRuntimeStats stats = getRudRuntimeStats();
    const bool ok = net_q.pop(first) &&
                    net_q.pop(second) &&
                    first.PDS_header.nack_header.nack_code == UET_INV_DPDCID &&
                    second.PDS_header.nack_header.nack_code == UET_INV_DPDCID &&
                    stats.ctrl_nack_fatal_sent == 2 &&
                    stats.ctrl_nack_resource_suppressed == 0;
    std::cout << "[RudBitmapResourceTest] fatal_nack_passthrough="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

static bool run_ackreq_hint_only_case()
{
    resetRudRuntimeStats();
    ThreadSafeQueue<PDStoNET_pkt> net_q;
    I_PDC ipdc;
    ipdc.initPDC(5254, RUD);
    ipdc.state = ESTABLISHED;
    ipdc.DPDCID = 6254;
    ipdc.clear_psn = 900;
    ipdc.local_credit_dirty_ = false;
    ipdc.receiver_pressure_dirty_ = false;
    ipdc.gen_cm = ACK_REQ;
    ipdc.setPublicQueues(&net_q, nullptr, nullptr, nullptr);

    ipdc.sendAck(PDS_next_hdr::UET_HDR_NONE, 0, 0, 901, nullptr, false);
    PDStoNET_pkt pkt{};
    const RudRuntimeStats stats = getRudRuntimeStats();
    const bool ok = net_q.pop(pkt) &&
                    pkt.PDS_header.RUOD_ack_header.flags.x == 1 &&
                    (pkt.ack_ctrl_ext.prefix.section_mask & ACK_CTRL_SECTION_ACKREQ_HINT) != 0 &&
                    pkt.ack_ctrl_ext.ackreq_hint.req_psn == 901 &&
                    ipdc.gen_cm == NONE &&
                    stats.ack_ackreq_hint_piggyback_sent >= 1;
    std::cout << "[RudBitmapResourceTest] ackreq_hint_only="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

static bool run_receiver_pressure_only_case()
{
    resetRudRuntimeStats();
    ThreadSafeQueue<PDStoNET_pkt> net_q;
    I_PDC ipdc;
    ipdc.initPDC(5255, RUD);
    ipdc.state = ESTABLISHED;
    ipdc.DPDCID = 6255;
    const RudResourceStats stats_snapshot = getSharedRudResourceStats();
    const uint16_t unexpected_in_use = static_cast<uint16_t>(stats_snapshot.unexpected_msgs_in_use);
    ipdc.last_unexpected_msgs_in_use_ = unexpected_in_use;
    ipdc.last_receiver_pressure_unexpected_byte_credits_ = stats_snapshot.unexpected_bytes_available / 4096;
    ipdc.last_receiver_pressure_bitmap_blocks_available_ = stats_snapshot.bitmap_blocks_available;
    ipdc.last_receiver_pressure_arrival_blocks_available_ = 0;
    ipdc.receiver_pressure_dirty_ = true;
    ipdc.setPublicQueues(&net_q, nullptr, nullptr, nullptr);

    ipdc.sendAck(PDS_next_hdr::UET_HDR_NONE, 0, 0, 901, nullptr, false);
    PDStoNET_pkt pkt{};
    const RudRuntimeStats stats = getRudRuntimeStats();
    const bool ok = net_q.pop(pkt) &&
                    pkt.PDS_header.RUOD_ack_header.flags.x == 1 &&
                    pkt.ack_ctrl_ext.prefix.section_mask == ACK_CTRL_SECTION_RECEIVER_PRESSURE &&
                    pkt.ack_ctrl_ext.receiver_pressure.unexpected_msgs_in_use == unexpected_in_use &&
                    pkt.ack_ctrl_ext.receiver_pressure.unexpected_byte_credits_available ==
                        ipdc.last_receiver_pressure_unexpected_byte_credits_ &&
                    pkt.ack_ctrl_ext.receiver_pressure.bitmap_blocks_available ==
                        ipdc.last_receiver_pressure_bitmap_blocks_available_ &&
                    stats.ack_receiver_pressure_piggyback_sent >= 1;
    std::cout << "[RudBitmapResourceTest] receiver_pressure_only="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

static bool run_ack_sack_credit_ackreq_case()
{
    resetRudRuntimeStats();
    ThreadSafeQueue<PDStoNET_pkt> net_q;
    T_PDC tpdc;
    tpdc.initPDC(5256, RUD);
    tpdc.state = ESTABLISHED;
    tpdc.DPDCID = 6256;
    tpdc.clear_psn = 900;
    tpdc.rx_cur_psn = 1000;
    tpdc.rud_rx_ooo_psns.insert(1002);
    tpdc.rud_sack_pending = true;
    tpdc.rud_sack_first_ms = tpdc.nowMs() - tpdc.kRudSackDelayMs;
    constexpr uint32_t kJobId = 52560;
    seed_local_credit(tpdc, kJobId, true);
    tpdc.gen_cm = ACK_REQ;
    tpdc.setPublicQueues(&net_q, nullptr, nullptr, nullptr);

    tpdc.sendAck(PDS_next_hdr::UET_HDR_NONE, 0, 0, 1001, nullptr, false, kJobId);
    PDStoNET_pkt pkt{};
    const RudRuntimeStats stats = getRudRuntimeStats();
    const bool ok = net_q.pop(pkt) &&
                    pkt.PDS_header.RUOD_ack_header.flags.x == 1 &&
                    pkt.ack_ctrl_ext.prefix.section_mask ==
                        static_cast<uint16_t>(ACK_CTRL_SECTION_SACK |
                                              ACK_CTRL_SECTION_CREDIT |
                                              ACK_CTRL_SECTION_ACKREQ_HINT |
                                              ACK_CTRL_SECTION_RECEIVER_PRESSURE) &&
                    pkt.ack_ctrl_ext.sack.sack_bitmap == 0x2u &&
                    pkt.ack_ctrl_ext.ackreq_hint.req_psn == 901 &&
                    stats.ack_sack_piggyback_sent >= 1 &&
                    stats.ack_credit_piggyback_sent >= 1 &&
                    stats.ack_ackreq_hint_piggyback_sent >= 1 &&
                    stats.piggyback_promoted >= 2;
    std::cout << "[RudBitmapResourceTest] ack_sack_credit_ackreq="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

static bool run_class_b_budget_priority_case()
{
    resetRudRuntimeStats();
    I_PDC ipdc;
    ipdc.initPDC(5257, RUD);
    ipdc.state = ESTABLISHED;
    ipdc.DPDCID = 6257;
    ipdc.rud_ctrl_budget_tokens_ = 2;
    ipdc.pending_credit_req_job_id_ = 52570;
    PDStoNET_pkt credit_req{};
    const bool class_b_ok = ipdc.sendCtrlCreditReq(&credit_req) &&
                            credit_req.PDS_header.RUOD_cp_header.ctl_type == Credit_req &&
                            credit_req.SESpkt.payload.size() == sizeof(PDS_RUOD_credit_req_cp_payload);

    ipdc.rud_ctrl_budget_tokens_ = 0;
    ipdc.clear_psn = 100;
    PDStoNET_pkt ack_req{};
    const bool class_c_deferred = !ipdc.sendCtrlAckReq(&ack_req);

    const RudRuntimeStats stats = getRudRuntimeStats();
    const bool ok = class_b_ok &&
                    class_c_deferred &&
                    stats.ctrl_budget_class_b_deferred == 0 &&
                    stats.ctrl_budget_class_c_deferred >= 1;
    std::cout << "[RudBitmapResourceTest] class_b_budget_priority="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

static bool run_posted_recv_credit_exact_key_case()
{
    SESManager ses_manager;
    PostedRecvEntry entry_a{};
    entry_a.job_id = 61001;
    entry_a.pdc_id = 7001;
    entry_a.src_fep = 8001;
    PostedRecvEntry entry_b = entry_a;
    entry_b.completion_key = 2;
    ses_manager.postRecv(entry_a);
    ses_manager.postRecv(entry_b);

    const bool ok = ses_manager.postedRecvCredits(61001, 7001, 8001) == 2 &&
                    ses_manager.postedRecvCredits(61001, 7002, 8001) == 0;
    std::cout << "[RudBitmapResourceTest] posted_recv_credit_exact_key="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

static bool run_posted_recv_credit_wildcard_pdcid_case()
{
    SESManager ses_manager;
    PostedRecvEntry wildcard{};
    wildcard.job_id = 61002;
    wildcard.pdc_id = 0;
    wildcard.src_fep = 8002;
    ses_manager.postRecv(wildcard);

    const bool ok = ses_manager.postedRecvCredits(61002, 7101, 8002) == 1 &&
                    ses_manager.postedRecvCredits(61002, 0, 8002) == 1;
    std::cout << "[RudBitmapResourceTest] posted_recv_credit_wildcard_pdcid="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

static bool run_job_scoped_credit_isolation_case()
{
    I_PDC ipdc;
    ipdc.initPDC(6103, RUD);
    ipdc.state = ESTABLISHED;

    auto &peer_a = ipdc.peer_receiver_credits_[62001];
    peer_a.valid = true;
    peer_a.credit_gen_seen = 1;
    peer_a.unexpected_msg_credits = 1;
    peer_a.unexpected_byte_credits = 1;
    auto &peer_b = ipdc.peer_receiver_credits_[62002];
    peer_b.bootstrap_used = true;
    peer_b.blocked_since_ms = ipdc.nowMs() - expected_credit_delay_ms() - 5;

    const bool allow_a = ipdc.canDispatchFrontReq(make_send_front_req(1, 62001), ipdc.nowMs());
    const bool block_b = !ipdc.canDispatchFrontReq(make_send_front_req(2, 62002), ipdc.nowMs());
    const bool ok = allow_a && block_b &&
                    ipdc.pending_credit_req_job_id_ == 62002 &&
                    ipdc.gen_cm == CREDIT_REQ;
    std::cout << "[RudBitmapResourceTest] job_scoped_credit_isolation="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

static bool run_standalone_credit_v2_wire_case()
{
    resetRudRuntimeStats();
    I_PDC ipdc;
    ipdc.initPDC(6104, RUD);
    ipdc.state = ESTABLISHED;
    ipdc.DPDCID = 7104;

    constexpr uint32_t kJobId = 62004;
    seed_local_credit(ipdc, kJobId, false);
    ipdc.pending_credit_job_id_ = kJobId;
    ipdc.pending_credit_reason_ = CreditControlReason::REFRESH;
    PDStoNET_pkt credit_pkt{};
    const bool credit_ok = ipdc.sendCtrlCredit(&credit_pkt) &&
                           credit_pkt.PDS_header.RUOD_cp_header.ctl_type == Credit &&
                           credit_pkt.SESpkt.payload.size() == sizeof(PDS_RUOD_credit_cp_payload);

    ipdc.pending_credit_req_job_id_ = kJobId;
    PDStoNET_pkt credit_req_pkt{};
    const bool credit_req_ok = ipdc.sendCtrlCreditReq(&credit_req_pkt) &&
                               credit_req_pkt.PDS_header.RUOD_cp_header.ctl_type == Credit_req &&
                               credit_req_pkt.SESpkt.payload.size() == sizeof(PDS_RUOD_credit_req_cp_payload);
    std::cout << "[RudBitmapResourceTest] standalone_credit_v2_wire="
              << ((credit_ok && credit_req_ok) ? "PASS" : "FAIL") << std::endl;
    return credit_ok && credit_req_ok;
}

static bool run_terminal_retry_rto_case()
{
    resetRudRuntimeStats();
    SESManager ses_manager;
    constexpr uint64_t kJobId = 63001;
    constexpr uint16_t kMsgId = 21;
    constexpr uint32_t kDstFep = 9301;
    ses_manager.process_send_packet(make_retry_send_metadata(kJobId, kMsgId, kDstFep));
    ses_manager.completeSenderTerminal(SenderTerminalCompletion{
        kJobId, kMsgId, kDstFep, SenderTerminalReason::RTO_EXHAUSTED});
    const RudRuntimeStats stats = getRudRuntimeStats();
    const bool ok = stats.active_retry_states == 0 &&
                    stats.retry_terminalized_by_rto_exhaust == 1 &&
                    stats.retry_terminalized_last_1s >= 1;
    std::cout << "[RudBitmapResourceTest] sender_terminal_rto="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

static bool run_terminal_retry_close_reset_case()
{
    resetRudRuntimeStats();
    SESManager ses_manager;
    constexpr uint64_t kJobId = 63002;
    constexpr uint16_t kMsgId = 22;
    constexpr uint32_t kDstFep = 9302;
    ses_manager.process_send_packet(make_retry_send_metadata(kJobId, kMsgId, kDstFep));
    ses_manager.completeSenderTerminal(SenderTerminalCompletion{
        kJobId, kMsgId, kDstFep, SenderTerminalReason::CLOSE_RESET});
    const RudRuntimeStats stats = getRudRuntimeStats();
    const bool ok = stats.active_retry_states == 0 &&
                    stats.retry_terminalized_by_close_reset == 1;
    std::cout << "[RudBitmapResourceTest] sender_terminal_close_reset="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

static bool run_terminal_retry_duplicate_case()
{
    resetRudRuntimeStats();
    SESManager ses_manager;
    constexpr uint64_t kJobId = 63003;
    constexpr uint16_t kMsgId = 23;
    constexpr uint32_t kDstFep = 9303;
    const SenderTerminalCompletion completion{kJobId, kMsgId, kDstFep, SenderTerminalReason::TEARDOWN_ORPHAN};
    ses_manager.process_send_packet(make_retry_send_metadata(kJobId, kMsgId, kDstFep));
    ses_manager.completeSenderTerminal(completion);
    ses_manager.completeSenderTerminal(completion);
    const RudRuntimeStats stats = getRudRuntimeStats();
    const bool ok = stats.active_retry_states == 0 &&
                    stats.retry_terminalized_by_teardown_orphan == 1 &&
                    stats.retry_terminal_duplicates_ignored >= 1;
    std::cout << "[RudBitmapResourceTest] sender_terminal_duplicate="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

static bool run_terminal_retry_orphan_case()
{
    resetRudRuntimeStats();
    SESManager ses_manager;
    ses_manager.completeSenderTerminal(SenderTerminalCompletion{
        63004, 24, 9304, SenderTerminalReason::TEARDOWN_ORPHAN});
    const RudRuntimeStats stats = getRudRuntimeStats();
    const bool ok = stats.retry_state_orphan_cleanups >= 1;
    std::cout << "[RudBitmapResourceTest] sender_terminal_orphan="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

static bool run_read_response_terminal_rto_case()
{
    resetRudRuntimeStats();
    SESManager ses_manager;
    constexpr uint64_t kJobId = 63101;
    constexpr uint16_t kMsgId = 31;
    constexpr uint32_t kSrcFep = 1001;
    constexpr uint32_t kDstFep = 2001;
    std::vector<uint8_t> remote_buf(2048, 0xAB);
    std::vector<uint8_t> local_buf(remote_buf.size(), 0);
    ses_manager.process_send_packet(
        make_read_track_metadata(kJobId, kMsgId, kSrcFep, kDstFep, remote_buf, local_buf));
    const ReadResponseProbe before = ses_manager.queryReadResponseProbe(kJobId, kMsgId, kDstFep);
    ses_manager.completeReadResponseTerminal(
        ReadResponseTerminalCompletion{kJobId, kMsgId, kDstFep, ReadResponseTerminalReason::RTO_EXHAUSTED});
    const ReadResponseProbe after = ses_manager.queryReadResponseProbe(kJobId, kMsgId, kDstFep);
    const RudRuntimeStats stats = getRudRuntimeStats();
    const bool ok = before.track_present &&
                    !before.terminalized &&
                    !after.track_present &&
                    after.terminalized &&
                    after.reason == ReadResponseTerminalReason::RTO_EXHAUSTED &&
                    stats.active_read_response_states == 0 &&
                    stats.read_response_terminalized_by_rto_exhaust == 1 &&
                    stats.read_response_terminalized_last_1s >= 1;
    std::cout << "[RudBitmapResourceTest] read_response_terminal_rto="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

static bool run_read_response_terminal_close_reset_case()
{
    resetRudRuntimeStats();
    SESManager ses_manager;
    constexpr uint64_t kJobId = 63102;
    constexpr uint16_t kMsgId = 32;
    constexpr uint32_t kSrcFep = 1001;
    constexpr uint32_t kDstFep = 2001;
    std::vector<uint8_t> remote_buf(1024, 0xCD);
    std::vector<uint8_t> local_buf(remote_buf.size(), 0);
    ses_manager.process_send_packet(
        make_read_track_metadata(kJobId, kMsgId, kSrcFep, kDstFep, remote_buf, local_buf));
    ses_manager.completeReadResponseTerminal(
        ReadResponseTerminalCompletion{kJobId, kMsgId, kDstFep, ReadResponseTerminalReason::CLOSE_RESET});
    const ReadResponseProbe probe = ses_manager.queryReadResponseProbe(kJobId, kMsgId, kDstFep);
    const RudRuntimeStats stats = getRudRuntimeStats();
    const bool ok = !probe.track_present &&
                    probe.terminalized &&
                    probe.reason == ReadResponseTerminalReason::CLOSE_RESET &&
                    stats.active_read_response_states == 0 &&
                    stats.read_response_terminalized_by_close_reset == 1;
    std::cout << "[RudBitmapResourceTest] read_response_terminal_close_reset="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

static bool run_read_response_terminal_duplicate_case()
{
    resetRudRuntimeStats();
    SESManager ses_manager;
    constexpr uint64_t kJobId = 63103;
    constexpr uint16_t kMsgId = 33;
    constexpr uint32_t kSrcFep = 1001;
    constexpr uint32_t kDstFep = 2001;
    std::vector<uint8_t> remote_buf(1024, 0xEF);
    std::vector<uint8_t> local_buf(remote_buf.size(), 0);
    ses_manager.process_send_packet(
        make_read_track_metadata(kJobId, kMsgId, kSrcFep, kDstFep, remote_buf, local_buf));
    const ReadResponseTerminalCompletion completion{
        kJobId, kMsgId, kDstFep, ReadResponseTerminalReason::TEARDOWN_ORPHAN};
    ses_manager.completeReadResponseTerminal(completion);
    ses_manager.completeReadResponseTerminal(completion);
    const ReadResponseProbe probe = ses_manager.queryReadResponseProbe(kJobId, kMsgId, kDstFep);
    const RudRuntimeStats stats = getRudRuntimeStats();
    const bool ok = !probe.track_present &&
                    probe.terminalized &&
                    probe.reason == ReadResponseTerminalReason::TEARDOWN_ORPHAN &&
                    stats.read_response_terminalized_by_teardown_orphan == 1 &&
                    stats.read_response_terminal_duplicates_ignored >= 1;
    std::cout << "[RudBitmapResourceTest] read_response_terminal_duplicate="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

static bool run_write_bitmap_case()
{
    constexpr uint16_t kPort = 2895;
    configureSharedRudResourcePool(0, 64, 1u << 20);
    resetRudRuntimeStats();
    BitmapHarness harness(kPort);

    std::vector<uint8_t> src(2048);
    std::vector<uint8_t> dst(src.size(), 0);
    fill_pattern(src, 0x11);
    const uint64_t rkey = 0x5001;
    harness.ses_manager.register_mr(rkey, reinterpret_cast<uint64_t>(dst.data()), dst.size());

    OperationMetadata md{};
    md.op_type = WRITE;
    md.s_pid_on_fep = 1001;
    md.t_pid_on_fep = 2001;
    md.job_id = 31001;
    md.messages_id = 11;
    md.memory.rkey = rkey;
    md.payload.start_addr = reinterpret_cast<uint64_t>(dst.data());
    md.payload.local_addr = reinterpret_cast<uint64_t>(src.data());
    md.payload.length = src.size();
    md.delivery_mode = RUD;

    harness.ses_manager.lfbric_ses_q.push(md);
    harness.ses_manager.mainChk();

    const bool done = harness.driveUntil([&]() { return saw_bitmap_nack(harness); }, 3000);
    const RudRuntimeStats stats = getRudRuntimeStats();
    reset_rud_resource_pool();
    const bool ok = done && !saw_no_buffer_semantic(harness) &&
                    stats.failure_uet_no_bitmap > 0 &&
                    stats.failure_rc_no_buffer == 0;
    std::cout << "[RudBitmapResourceTest] write_bitmap="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

static bool run_send_bitmap_case()
{
    constexpr uint16_t kPort = 2896;
    configureSharedRudResourcePool(0, 64, 1u << 20);
    resetRudRuntimeStats();
    BitmapHarness harness(kPort);

    std::vector<uint8_t> payload(2048);
    std::vector<uint8_t> recv(payload.size(), 0);
    fill_pattern(payload, 0x22);

    PostedRecvEntry recv_entry{};
    recv_entry.completion_key = 0x6001;
    recv_entry.base_addr = reinterpret_cast<uint64_t>(recv.data());
    recv_entry.buffer_len = recv.size();
    recv_entry.job_id = 32001;
    recv_entry.pdc_id = 0;
    recv_entry.src_fep = 1001;
    harness.ses_manager.postRecv(recv_entry);

    OperationMetadata md{};
    md.op_type = SEND;
    md.s_pid_on_fep = 1001;
    md.t_pid_on_fep = 2001;
    md.job_id = 32001;
    md.messages_id = 12;
    md.payload.start_addr = reinterpret_cast<uint64_t>(payload.data());
    md.payload.length = payload.size();
    md.has_imm_data = true;
    md.payload.imm_data = 0xABCD1234;
    md.delivery_mode = RUD;

    harness.ses_manager.lfbric_ses_q.push(md);
    harness.ses_manager.mainChk();

    const bool done = harness.driveUntil([&]() { return saw_bitmap_nack(harness); }, 3000);
    const RudRuntimeStats stats = getRudRuntimeStats();
    reset_rud_resource_pool();
    const bool ok = done && !saw_no_buffer_semantic(harness) &&
                    stats.failure_uet_no_bitmap > 0 &&
                    stats.failure_rc_no_buffer == 0;
    std::cout << "[RudBitmapResourceTest] send_bitmap="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

static bool run_read_bitmap_case()
{
    constexpr uint16_t kPort = 2897;
    configureSharedRudResourcePool(0, 64, 1u << 20);
    resetRudRuntimeStats();
    BitmapHarness harness(kPort);

    std::vector<uint8_t> read_src(4096);
    std::vector<uint8_t> read_dst(read_src.size(), 0);
    fill_pattern(read_src, 0x33);
    const uint64_t rkey = 0x7001;
    harness.ses_manager.register_mr(rkey, reinterpret_cast<uint64_t>(read_src.data()), read_src.size());

    OperationMetadata md{};
    md.op_type = READ;
    md.s_pid_on_fep = 1001;
    md.t_pid_on_fep = 2001;
    md.job_id = 33001;
    md.messages_id = 13;
    md.memory.rkey = rkey;
    md.payload.start_addr = reinterpret_cast<uint64_t>(read_src.data());
    md.payload.local_addr = reinterpret_cast<uint64_t>(read_dst.data());
    md.payload.length = read_src.size();
    md.delivery_mode = RUD;

    harness.ses_manager.lfbric_ses_q.push(md);
    harness.ses_manager.mainChk();

    const bool done = harness.driveUntil([&]() { return saw_bitmap_nack(harness); }, 3000);
    const RudRuntimeStats stats = getRudRuntimeStats();
    reset_rud_resource_pool();
    const bool no_buffer_semantic = saw_no_buffer_semantic(harness);
    const bool ok = done && !no_buffer_semantic &&
                    stats.failure_uet_no_bitmap > 0 &&
                    stats.failure_rc_no_buffer == 0;
    if (!ok) {
        std::cout << "[RudBitmapResourceTest] read_bitmap detail: "
                  << "done=" << done
                  << " no_buffer_semantic=" << no_buffer_semantic
                  << " failure_uet_no_bitmap=" << stats.failure_uet_no_bitmap
                  << " failure_rc_no_buffer=" << stats.failure_rc_no_buffer
                  << " nack_count=" << harness.nack_codes.size()
                  << " response_count=" << harness.responses.size()
                  << std::endl;
    }
    std::cout << "[RudBitmapResourceTest] read_bitmap="
              << (ok ? "PASS" : "FAIL") << std::endl;
    return ok;
}

} // namespace

int main()
{
    Logger::initialize("RudBitmapResourceTest.log", LogLevel::DEBUG, 1, 1);

    const bool ack_req_guard_ok = run_ack_req_guard_case();
    const bool sack_guard_ok = run_sack_guard_case();
    const bool gap_nack_backoff_ok = run_gap_nack_backoff_case();
    const bool control_merge_ok = run_control_merge_case();
    const bool gap_cp_merge_ok = run_gap_cp_merge_case();
    const bool ctrl_budget_ok = run_ctrl_budget_case();
    const bool ctrl_rate_stats_ok = run_ctrl_rate_stats_case();
    const bool ack_ctrl_ext_wire_ok = run_ack_ctrl_ext_wire_case();
    const bool ack_credit_only_ok = run_ack_credit_only_case();
    const bool ack_sack_only_ok = run_ack_sack_only_case();
    const bool ack_sack_credit_ok = run_ack_sack_and_credit_case();
    const bool credit_reorder_ok = run_credit_reorder_ignore_stale_case();
    const bool bootstrap_credit_ok = run_bootstrap_then_hard_gate_case();
    const bool credit_refresh_ok = run_credit_refresh_case();
    const bool resource_nack_ok = run_resource_nack_governance_case();
    const bool fatal_nack_ok = run_fatal_nack_passthrough_case();
    const bool ackreq_hint_ok = run_ackreq_hint_only_case();
    const bool receiver_pressure_ok = run_receiver_pressure_only_case();
    const bool ack_sack_credit_ackreq_ok = run_ack_sack_credit_ackreq_case();
    const bool class_b_budget_ok = run_class_b_budget_priority_case();
    const bool posted_recv_exact_ok = run_posted_recv_credit_exact_key_case();
    const bool posted_recv_wildcard_ok = run_posted_recv_credit_wildcard_pdcid_case();
    const bool job_scoped_isolation_ok = run_job_scoped_credit_isolation_case();
    const bool standalone_credit_v2_ok = run_standalone_credit_v2_wire_case();
    const bool terminal_rto_ok = run_terminal_retry_rto_case();
    const bool terminal_close_ok = run_terminal_retry_close_reset_case();
    const bool terminal_duplicate_ok = run_terminal_retry_duplicate_case();
    const bool terminal_orphan_ok = run_terminal_retry_orphan_case();
    const bool read_terminal_rto_ok = run_read_response_terminal_rto_case();
    const bool read_terminal_close_ok = run_read_response_terminal_close_reset_case();
    const bool read_terminal_duplicate_ok = run_read_response_terminal_duplicate_case();
    const bool write_ok = run_write_bitmap_case();
    const bool send_ok = run_send_bitmap_case();
    const bool read_ok = run_read_bitmap_case();

    const bool ok = ack_req_guard_ok &&
                    sack_guard_ok &&
                    gap_nack_backoff_ok &&
                    control_merge_ok &&
                    gap_cp_merge_ok &&
                    ctrl_budget_ok &&
                    ctrl_rate_stats_ok &&
                    ack_ctrl_ext_wire_ok &&
                    ack_credit_only_ok &&
                    ack_sack_only_ok &&
                    ack_sack_credit_ok &&
                    credit_reorder_ok &&
                    bootstrap_credit_ok &&
                    credit_refresh_ok &&
                    resource_nack_ok &&
                    fatal_nack_ok &&
                    ackreq_hint_ok &&
                    receiver_pressure_ok &&
                    ack_sack_credit_ackreq_ok &&
                    class_b_budget_ok &&
                    posted_recv_exact_ok &&
                    posted_recv_wildcard_ok &&
                    job_scoped_isolation_ok &&
                    standalone_credit_v2_ok &&
                    terminal_rto_ok &&
                    terminal_close_ok &&
                    terminal_duplicate_ok &&
                    terminal_orphan_ok &&
                    read_terminal_rto_ok &&
                    read_terminal_close_ok &&
                    read_terminal_duplicate_ok &&
                    write_ok &&
                    send_ok &&
                    read_ok;
    std::cout << (ok ? "RudBitmapResourceTest PASS" : "RudBitmapResourceTest FAIL") << std::endl;
    return ok ? 0 : 1;
}
