#include "SES.hpp"

SES_PDS_rsp SESManager::buildSemanticResponse(const PDC_RX_completion &completion) const
{
    SES_PDS_rsp rsp{};
    rsp.PDCID = completion.pdcid;
    rsp.rx_pkt_handle = completion.rx_pkt_handle;
    rsp.gtd_del = false;
    rsp.ses_nack = false;
    rsp.rsp_len = 12;
    rsp.rsp.bth_type = Semantic_Response_Header;

    SES_Semantic_Response_Header hdr{};
    hdr.list = 1;
    hdr.version = 2;
    hdr.job_id = completion.job_id;
    hdr.message_id = completion.msg_id;
    hdr.modified_length = completion.modified_length;
    hdr.opcode = completion.success ? static_cast<uint8_t>(RSP_OP_CODE::UET_DEFAULT_RESPONSE)
                                    : static_cast<uint8_t>(RSP_OP_CODE::UET_NACK);
    hdr.return_code = completion.return_code;
    rsp.rsp.bth_header.Semantic_Response_Header = hdr;
    return rsp;
}

SES_PDS_rsp SESManager::buildPdsNackResponse(const PDC_RX_completion &completion) const
{
    SES_PDS_rsp rsp{};
    rsp.PDCID = completion.pdcid;
    rsp.rx_pkt_handle = completion.rx_pkt_handle;
    rsp.gtd_del = false;
    rsp.ses_nack = true;
    rsp.nack_payload.nack_code = static_cast<uint8_t>(NackCode::RESOURCE);
    rsp.nack_payload.expected_psn = 0;
    rsp.nack_payload.current_window = 0;
    rsp.rsp_len = 0;
    return rsp;
}

void SESManager::completeRxOperation(const PDC_RX_completion &completion)
{
    if (completion.success) {
        noteRudCompletionSuccess(completion.type, completion.notify_kind);
    } else if (completion.failure_kind == PDC_RX_failure_kind::PDS_NACK) {
        if (completion.pds_nack_code == UET_NO_BITMAP) {
            noteRudFailureBucket(RudFailureBucket::UET_NO_BITMAP);
        }
    } else {
        switch (static_cast<RSP_RETURN_CODE>(completion.return_code)) {
            case RSP_RETURN_CODE::RC_NO_MATCH:
                noteRudFailureBucket(RudFailureBucket::RC_NO_MATCH);
                break;
            case RSP_RETURN_CODE::RC_PARTIAL_WRITE:
                noteRudFailureBucket(RudFailureBucket::RC_PARTIAL_WRITE);
                break;
            case RSP_RETURN_CODE::RC_PROTOCOL_ERROR:
                noteRudFailureBucket(RudFailureBucket::RC_PROTOCOL_ERROR);
                break;
            case RSP_RETURN_CODE::RC_NO_BUFFER:
                noteRudFailureBucket(RudFailureBucket::RC_NO_BUFFER);
                break;
            default:
                break;
        }
    }

    if (!completion.success && completion.failure_kind == PDC_RX_failure_kind::PDS_NACK) {
        SES_PDS_rsp rsp = buildPdsNackResponse(completion);
        send_rsp_to_pds(rsp);
        if (completion.type == PDC_RX_completion_type::READ_RESPONSE) {
            const ReadTrackKey key{completion.job_id, completion.msg_id, completion.src_fep};
            std::lock_guard<std::mutex> lock(read_track_mu_);
            read_track_.erase(key);
            setRudActiveReadResponseStates(read_track_.size());
        }
        return;
    }

    if (completion.type == PDC_RX_completion_type::WRITE) {
        SES_PDS_rsp rsp = buildSemanticResponse(completion);
        send_rsp_to_pds(rsp);
        return;
    }

    if (completion.type == PDC_RX_completion_type::READ_RESPONSE) {
        const ReadTrackKey key{completion.job_id, completion.msg_id, completion.src_fep};
        std::lock_guard<std::mutex> lock(read_track_mu_);
        read_track_.erase(key);
        setRudActiveReadResponseStates(read_track_.size());
        return;
    }

    if (completion.type == PDC_RX_completion_type::SEND) {
        if (completion.notify_kind == PDC_RX_completion_notify_kind::TARGET_DELIVERY_COMPLETE) {
            return;
        }
        if (!completion.success || completion.response_required ||
            completion.notify_kind == PDC_RX_completion_notify_kind::SEMANTIC_ACCEPT ||
            completion.notify_kind == PDC_RX_completion_notify_kind::DUPLICATE_REPLAY) {
            SES_PDS_rsp rsp = buildSemanticResponse(completion);
            send_rsp_to_pds(rsp);
        }
    }
}

bool SESManager::clearReadTrackIfPresent(const ReadTrackKey &key)
{
    std::lock_guard<std::mutex> lock(read_track_mu_);
    auto it = read_track_.find(key);
    if (it == read_track_.end()) {
        return false;
    }
    read_track_.erase(it);
    setRudActiveReadResponseStates(read_track_.size());
    return true;
}

void SESManager::completeSenderTerminal(const SenderTerminalCompletion &completion)
{
    PDC_SES_rsp rsp{};
    rsp.mode = RUD;
    rsp.src_fep = completion.dst_fep;
    rsp.pkt.bth_type = Semantic_Response_Header;
    auto &hdr = rsp.pkt.bth_header.Semantic_Response_Header;
    hdr.list = 1;
    hdr.version = 2;
    hdr.job_id = completion.job_id;
    hdr.message_id = completion.msg_id;
    hdr.modified_length = 0;
    hdr.opcode = static_cast<uint8_t>(RSP_OP_CODE::UET_NACK);
    hdr.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_RESOURCE_EXHAUST);

    const bool cleared =
        clearSendRetryStateIfPresent(completion.job_id, completion.msg_id, completion.dst_fep);
    if (cleared) {
        noteRudRetryTerminalized(completion.reason);
        LOG_INFO(__FUNCTION__,
                 "Sender terminal completion retired retry state: job_id=" +
                     std::to_string(completion.job_id) + " msg_id=" +
                     std::to_string(completion.msg_id) + " dst_fep=" +
                     std::to_string(completion.dst_fep) + " reason=" +
                     std::to_string(static_cast<int>(completion.reason)));
        return;
    }

    {
        std::lock_guard<std::mutex> lock(send_retry_mu_);
        const SendRetryKey key{completion.job_id, completion.msg_id, completion.dst_fep};
        if (retired_send_retry_.count(key) != 0) {
            noteRudRetryTerminalDuplicateIgnored();
            LOG_DEBUG(__FUNCTION__,
                      "Duplicate sender terminal completion ignored: job_id=" +
                          std::to_string(completion.job_id) + " msg_id=" +
                          std::to_string(completion.msg_id));
            return;
        }
    }

    noteRudRetryStateOrphanCleanup();
    LOG_WARN(__FUNCTION__,
             "Sender terminal completion found no retry state: job_id=" +
                 std::to_string(completion.job_id) + " msg_id=" +
                 std::to_string(completion.msg_id) + " dst_fep=" +
                 std::to_string(completion.dst_fep));
}

void SESManager::completeRequestTerminal(const RequestTerminalCompletion &completion)
{
    const SendRetryKey key{completion.job_id, completion.msg_id, completion.dst_fep};
    std::lock_guard<std::mutex> lock(send_retry_mu_);
    auto retired_it = retired_request_terminal_.find(key);
    if (retired_it != retired_request_terminal_.end()) {
        retired_it->second = completion;
        return;
    }
    RequestTerminalCompletion stored = completion;
    stored.retry_present_at_terminalize = (send_retry_.find(key) != send_retry_.end());
    stored.read_track_present_at_terminalize =
        clearReadTrackIfPresent(ReadTrackKey{completion.job_id, completion.msg_id, completion.dst_fep});
    retired_request_terminal_[key] = stored;
}

void SESManager::completeReadResponseTerminal(const ReadResponseTerminalCompletion &completion)
{
    const ReadTrackKey key{completion.job_id, completion.msg_id, completion.dst_fep};
    const bool cleared = clearReadTrackIfPresent(key);

    {
        std::lock_guard<std::mutex> lock(read_track_mu_);
        auto retired_it = retired_read_response_.find(key);
        if (retired_it != retired_read_response_.end()) {
            noteRudReadResponseTerminalDuplicateIgnored();
            LOG_DEBUG(__FUNCTION__,
                      "Duplicate READ response terminal completion ignored: job_id=" +
                          std::to_string(completion.job_id) + " msg_id=" +
                          std::to_string(completion.msg_id) + " dst_fep=" +
                          std::to_string(completion.dst_fep));
            return;
        }
        retired_read_response_[key] = completion.reason;
        if (cleared) {
            noteRudReadResponseTerminalized(completion.reason);
        } else {
            noteRudReadResponseOrphanCleanup();
        }
        setRudActiveReadResponseStates(read_track_.size());
    }

    if (cleared) {
        LOG_INFO(__FUNCTION__,
                 "READ response terminal completion retired read_track: job_id=" +
                     std::to_string(completion.job_id) + " msg_id=" +
                     std::to_string(completion.msg_id) + " dst_fep=" +
                     std::to_string(completion.dst_fep) + " reason=" +
                     std::to_string(static_cast<int>(completion.reason)));
        return;
    }

    LOG_WARN(__FUNCTION__,
             "READ response terminal completion found no read_track: job_id=" +
                 std::to_string(completion.job_id) + " msg_id=" +
                 std::to_string(completion.msg_id) + " dst_fep=" +
                 std::to_string(completion.dst_fep));
}

ReadResponseProbe SESManager::queryReadResponseProbe(uint64_t job_id, uint16_t msg_id, uint32_t src_fep)
{
    const ReadTrackKey key{job_id, msg_id, src_fep};
    std::lock_guard<std::mutex> lock(read_track_mu_);
    ReadResponseProbe probe{};
    probe.track_present = (read_track_.find(key) != read_track_.end());
    auto retired_it = retired_read_response_.find(key);
    if (retired_it != retired_read_response_.end()) {
        probe.terminalized = true;
        probe.reason = retired_it->second;
    }
    return probe;
}

RequestTerminalProbe SESManager::queryRequestTerminalProbe(uint64_t job_id, uint16_t msg_id, uint32_t dst_fep)
{
    const SendRetryKey key{job_id, msg_id, dst_fep};
    std::lock_guard<std::mutex> lock(send_retry_mu_);
    RequestTerminalProbe probe{};
    probe.retry_present = (send_retry_.find(key) != send_retry_.end());
    auto retired_it = retired_request_terminal_.find(key);
    if (retired_it != retired_request_terminal_.end()) {
        probe.terminalized = true;
        probe.reason = retired_it->second.reason;
        probe.terminalized_at_ms = retired_it->second.terminalized_at_ms;
        probe.close_cause = retired_it->second.close_cause;
        probe.close_state_at_terminalize = retired_it->second.close_state_at_terminalize;
        probe.tx_pending_count_at_terminalize = retired_it->second.tx_pending_count_at_terminalize;
        probe.unack_cnt_at_terminalize = retired_it->second.unack_cnt_at_terminalize;
        probe.all_ack_at_terminalize = retired_it->second.all_ack_at_terminalize;
        probe.retry_present_at_terminalize = retired_it->second.retry_present_at_terminalize;
        probe.read_track_present_at_terminalize = retired_it->second.read_track_present_at_terminalize;
    }
    return probe;
}

SendRetryProbe SESManager::querySendRetryProbe(uint64_t job_id, uint16_t msg_id, uint32_t dst_fep)
{
    const SendRetryKey key{job_id, msg_id, dst_fep};
    std::lock_guard<std::mutex> lock(send_retry_mu_);
    SendRetryProbe probe{};
    auto it = send_retry_.find(key);
    if (it == send_retry_.end()) {
        return probe;
    }
    probe.present = true;
    probe.waiting_response = it->second.waiting_response;
    probe.retry_count = it->second.retry_count;
    probe.next_retry_ms = it->second.next_retry_ms;
    return probe;
}

RequestTxProbe SESManager::queryRequestTxProbe(uint64_t job_id, uint16_t msg_id, uint32_t dst_fep)
{
    return PDC::queryRequestTxProbe(job_id, msg_id, dst_fep);
}

UnexpectedSendProbe SESManager::queryUnexpectedSendProbe(uint64_t job_id, uint16_t msg_id, uint32_t src_fep)
{
    return PDC::queryUnexpectedSendProbe(job_id, msg_id, src_fep);
}
