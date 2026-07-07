#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
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

    bool pumpOnce()
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

            if (!send_one_packet(udp_tx, udp_rx, tx_pkt)) {
                return false;
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

    bool driveUntil(const std::function<bool()>& done, int timeout_ms)
    {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
        while (std::chrono::steady_clock::now() < deadline) {
            if (done()) {
                return true;
            }
            const bool did_work = pumpOnce();
            if (!did_work) {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }
        return done();
    }
};

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

static std::pair<std::pair<uint64_t, uint16_t>, std::pair<uint64_t, uint16_t>>
find_collision_pair(PDS_Manager& manager)
{
    struct Candidate {
        uint64_t job_id;
        uint16_t tx_pdcid;
    };

    std::vector<std::pair<int, Candidate>> by_preferred;
    for (uint64_t job_id = 60000; job_id < 61024; ++job_id) {
        const int tx_pdcid = manager.muxTx2PDCID(job_id, 2001, 0, RUD);
        if (tx_pdcid < 0) {
            continue;
        }
        const int preferred = manager.muxRx2PDCID(1001, 2001, static_cast<uint16_t>(tx_pdcid));
        if (preferred < 0) {
            continue;
        }
        for (const auto& entry : by_preferred) {
            if (entry.first == preferred && entry.second.tx_pdcid != static_cast<uint16_t>(tx_pdcid)) {
                return {
                    {entry.second.job_id, entry.second.tx_pdcid},
                    {job_id, static_cast<uint16_t>(tx_pdcid)},
                };
            }
        }
        by_preferred.push_back({preferred, Candidate{job_id, static_cast<uint16_t>(tx_pdcid)}});
    }
    throw std::runtime_error("failed to find colliding tx/rx PDC pair");
}

static bool saw_ok_response_since(const std::vector<ResponseEvent>& responses,
                                  size_t base_idx,
                                  uint64_t job_id,
                                  uint16_t msg_id,
                                  size_t payload_len)
{
    return std::any_of(responses.begin() + static_cast<std::ptrdiff_t>(base_idx),
                       responses.end(),
                       [&](const ResponseEvent& rsp) {
                           return rsp.job_id == job_id &&
                                  rsp.message_id == msg_id &&
                                  rsp.opcode == static_cast<uint8_t>(RSP_OP_CODE::UET_DEFAULT_RESPONSE) &&
                                  rsp.return_code == static_cast<uint8_t>(RSP_RETURN_CODE::RC_OK) &&
                                  rsp.modified_length == payload_len;
                       });
}

static bool run_collision_fallback_case()
{
    configureSharedRudResourcePool(1024, 64, 1u << 20);
    resetRudRuntimeStats();

    constexpr uint16_t kPort = 2913;
    constexpr uint32_t kSrcFep = 1001;
    constexpr uint32_t kDstFep = 2001;
    LoopbackHarness harness(kPort);
    PDS_Manager probe;

    const auto pair = find_collision_pair(probe);
    const uint64_t job1 = pair.first.first;
    const uint16_t tx_pdcid1 = pair.first.second;
    const uint64_t job2 = pair.second.first;
    const uint16_t tx_pdcid2 = pair.second.second;
    const int preferred_tpdc1 = probe.muxRx2PDCID(kSrcFep, kDstFep, tx_pdcid1);
    const int preferred_tpdc2 = probe.muxRx2PDCID(kSrcFep, kDstFep, tx_pdcid2);
    if (preferred_tpdc1 < MAX_PDC || preferred_tpdc1 != preferred_tpdc2) {
        throw std::runtime_error("invalid preferred TPDC");
    }

    std::vector<uint8_t> payload1(4096);
    std::vector<uint8_t> recv1(payload1.size(), 0);
    fill_payload(payload1, 0x11);
    harness.postRecv(job1, kSrcFep, reinterpret_cast<uint64_t>(recv1.data()), recv1.size());
    const size_t rsp_base1 = harness.responses.size();
    harness.submitSend(make_send_metadata(1, job1, kSrcFep, kDstFep, payload1));
    const bool ok1 = harness.driveUntil(
        [&]() { return recv1 == payload1 && saw_ok_response_since(harness.responses, rsp_base1, job1, 1, payload1.size()); },
        8000);
    if (!ok1) {
        return false;
    }

    std::vector<uint8_t> payload2(4096);
    std::vector<uint8_t> recv2(payload2.size(), 0);
    fill_payload(payload2, 0x33);
    harness.postRecv(job2, kSrcFep, reinterpret_cast<uint64_t>(recv2.data()), recv2.size());
    const size_t rsp_base2 = harness.responses.size();
    harness.submitSend(make_send_metadata(2, job2, kSrcFep, kDstFep, payload2));
    const bool ok2 = harness.driveUntil(
        [&]() { return recv2 == payload2 && saw_ok_response_since(harness.responses, rsp_base2, job2, 2, payload2.size()); },
        8000);
    if (!ok2) {
        return false;
    }
    return true;
}

static bool run_same_binding_reuse_case()
{
    configureSharedRudResourcePool(1024, 64, 1u << 20);
    resetRudRuntimeStats();

    constexpr uint16_t kPort = 2914;
    constexpr uint64_t kJobId = 62001;
    constexpr uint32_t kSrcFep = 1001;
    constexpr uint32_t kDstFep = 2001;
    LoopbackHarness harness(kPort);

    std::vector<uint8_t> payload1(2048);
    std::vector<uint8_t> recv1(payload1.size(), 0);
    fill_payload(payload1, 0x55);
    harness.postRecv(kJobId, kSrcFep, reinterpret_cast<uint64_t>(recv1.data()), recv1.size());
    harness.submitSend(make_send_metadata(10, kJobId, kSrcFep, kDstFep, payload1));
    if (!harness.driveUntil([&]() { return recv1 == payload1; }, 6000)) {
        return false;
    }

    std::vector<uint8_t> payload2(2048);
    std::vector<uint8_t> recv2(payload2.size(), 0);
    fill_payload(payload2, 0x77);
    harness.postRecv(kJobId, kSrcFep, reinterpret_cast<uint64_t>(recv2.data()), recv2.size());
    harness.submitSend(make_send_metadata(11, kJobId, kSrcFep, kDstFep, payload2));
    return harness.driveUntil([&]() { return recv2 == payload2; }, 6000);
}

} // namespace

int main()
{
    Logger::initialize("RudSynCollisionTest.log", LogLevel::DEBUG, 1, 1);

    const bool collision_ok = run_collision_fallback_case();
    const bool same_binding_ok = run_same_binding_reuse_case();
    const bool ok = collision_ok && same_binding_ok;

    std::cout << (ok ? "RudSynCollisionTest PASS" : "RudSynCollisionTest FAIL") << std::endl;
    return ok ? 0 : 1;
}
