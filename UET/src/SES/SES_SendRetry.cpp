#include "SES.hpp"

void SESManager::trackSendRetry(const OperationMetadata& metadata, bool is_retry)
{
    if (metadata.op_type != SEND || metadata.delivery_mode != RUD) {
        return;
    }

    const SendRetryKey key{metadata.job_id, static_cast<uint16_t>(metadata.messages_id), metadata.t_pid_on_fep};
    std::lock_guard<std::mutex> lock(send_retry_mu_);
    auto &state = send_retry_[key];
    retired_send_retry_.erase(key);
    if (!is_retry || state.metadata.payload.start_addr == 0) {
        state.metadata = metadata;
        if (!is_retry) {
            state.retry_count = 0;
            state.next_retry_ms = 0;
        }
    }
    state.waiting_response = true;
    setRudActiveRetryStates(send_retry_.size());
}

void SESManager::processDueSendRetries()
{
    OperationMetadata due_metadata{};
    bool have_due = false;
    const int64_t now_ms = currentTimeMs();
    {
        std::lock_guard<std::mutex> lock(send_retry_mu_);
        for (auto &entry : send_retry_) {
            SendRetryState &state = entry.second;
            if (!state.waiting_response && state.next_retry_ms > 0 && state.next_retry_ms <= now_ms) {
                due_metadata = state.metadata;
                state.waiting_response = true;
                state.next_retry_ms = 0;
                have_due = true;
                break;
            }
        }
    }

    if (have_due) {
        noteRudRetryFired();
        process_send_packet(due_metadata, true);
    }
}

void SESManager::clearSendRetryState(uint64_t job_id, uint16_t msg_id, uint32_t dst_fep)
{
    std::lock_guard<std::mutex> lock(send_retry_mu_);
    const SendRetryKey key{job_id, msg_id, dst_fep};
    send_retry_.erase(key);
    retired_send_retry_.insert(key);
    setRudActiveRetryStates(send_retry_.size());
}

bool SESManager::clearSendRetryStateIfPresent(uint64_t job_id, uint16_t msg_id, uint32_t dst_fep)
{
    std::lock_guard<std::mutex> lock(send_retry_mu_);
    const SendRetryKey key{job_id, msg_id, dst_fep};
    auto it = send_retry_.find(key);
    if (it == send_retry_.end()) {
        return false;
    }
    send_retry_.erase(it);
    retired_send_retry_.insert(key);
    setRudActiveRetryStates(send_retry_.size());
    return true;
}

int64_t SESManager::currentTimeMs() const
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

int64_t SESManager::retryDelayMs(uint16_t retry_count) const
{
    return static_cast<int64_t>(Base_RTO) * (1LL << retry_count);
}
