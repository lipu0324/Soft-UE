#include "SES.hpp"

#include <limits>

SESManager::SESManager()
{
    initialize();
    PDC::setRxCallbacks(
        [this](const PDC_SES_req& req) { return resolveRxPlacement(req); },
        [this](const PDC_SES_rsp& rsp) { return resolveRxPlacement(rsp); },
        [this](const PDC_RX_completion& completion) { completeRxOperation(completion); },
        [this](const RequestTerminalCompletion& completion) { completeRequestTerminal(completion); },
        [this](const SenderTerminalCompletion& completion) { completeSenderTerminal(completion); },
        [this](const ReadResponseTerminalCompletion& completion) { completeReadResponseTerminal(completion); },
        [this](uint64_t job_id, uint16_t pdc_id, uint32_t src_fep) {
            return postedRecvCredits(job_id, pdc_id, src_fep);
        });
}

SESManager::~SESManager()
{
    PDC::setRxCallbacks({}, {}, {}, {}, {}, {}, {});
}

void SESManager::initialize()
{
    static std::mutex init_mu;
    std::lock_guard<std::mutex> lock(init_mu);
    if (pds_process_manager.getProcessState() == PDSProcessManager::STOPPED) {
        (void)pds_process_manager.start();
    }
}

void SESManager::register_mr(uint64_t key, uint64_t start_addr, size_t length)
{
    std::lock_guard<std::mutex> lock(mr_mu_);
    mr_table_[key] = MemoryRegion{start_addr, length};
}

void SESManager::unregister_mr(uint64_t key)
{
    std::lock_guard<std::mutex> lock(mr_mu_);
    mr_table_.erase(key);
}

void SESManager::process_pdc_2_ses()
{
    PDC_SES_req req{};
    while (pds_process_manager.popSESRequest(req)) {
        process_recv_req_packet(req);
    }

    PDC_SES_rsp rsp{};
    while (pds_process_manager.popSESResponse(rsp)) {
        process_recv_rsp_packet(rsp);
    }

    PDS_SES_error err{};
    while (pds_process_manager.popErrorEvent(err)) {
    }
}

void SESManager::mainChk()
{
    processDueSendRetries();
    if (!lfbric_ses_q.empty()) {
        OperationMetadata metadata = lfbric_ses_q.front();
        lfbric_ses_q.pop();
        process_send_packet(metadata);
    }
    process_pdc_2_ses();
}

bool SESManager::validate_version(uint8_t version)
{
    return version == 2;
}

bool SESManager::validate_header_type(SES_BTH_header_type type)
{
    return type == Standard_Header;
}

bool SESManager::validate_pid_on_fep(uint32_t pid_on_fep, uint32_t, bool)
{
    return pid_on_fep != 0;
}

bool SESManager::validate_opcode(OpType opcode)
{
    switch (opcode) {
    case SEND:
    case READ:
    case WRITE:
    case DEFERRABLE:
        return true;
    default:
        return false;
    }
}

bool SESManager::validate_job_id(uint64_t job_id)
{
    (void)job_id;
    return true;
}

bool SESManager::validate_data_length(size_t data_length, size_t payload_length)
{
    return data_length == payload_length;
}

bool SESManager::validate_pdc_status(uint16_t, uint32_t)
{
    return true;
}

bool SESManager::validate_rkey(uint64_t rkey, uint32_t)
{
    return rkey != 0;
}

bool SESManager::validate_msn(uint32_t, uint64_t, uint64_t requires_length, uint32_t, bool, bool, uint8_t)
{
    return requires_length <= std::numeric_limits<uint32_t>::max();
}

bool SESManager::validate_need_ack(uint32_t messages_id, bool delivery_complete)
{
    return messages_id == 1 && delivery_complete;
}
