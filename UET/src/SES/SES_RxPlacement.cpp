#include "SES.hpp"

#include <limits>

void SESManager::postRecv(const PostedRecvEntry &entry)
{
    if (PDC::matchUnexpectedSend(
            entry.job_id, entry.pdc_id, entry.src_fep, entry.completion_key, entry.base_addr, entry.buffer_len)) {
        return;
    }
    std::lock_guard<std::mutex> lock(posted_recv_mu_);
    const PostedRecvKey key{entry.job_id, entry.pdc_id, entry.src_fep};
    posted_recv_q_[key].push_back(entry);
}

uint16_t SESManager::postedRecvCredits(uint64_t job_id, uint16_t pdc_id, uint32_t src_fep)
{
    std::lock_guard<std::mutex> lock(posted_recv_mu_);
    size_t credits = 0;
    const auto exact_it = posted_recv_q_.find(PostedRecvKey{job_id, pdc_id, src_fep});
    if (exact_it != posted_recv_q_.end()) {
        credits += exact_it->second.size();
    }
    if (pdc_id != 0) {
        const auto wildcard_it = posted_recv_q_.find(PostedRecvKey{job_id, 0, src_fep});
        if (wildcard_it != posted_recv_q_.end()) {
            credits += wildcard_it->second.size();
        }
    }
    return static_cast<uint16_t>(std::min<size_t>(credits, std::numeric_limits<uint16_t>::max()));
}

bool SESManager::tryPopPostedRecv(const PostedRecvKey &key, PostedRecvEntry &entry)
{
    std::lock_guard<std::mutex> lock(posted_recv_mu_);
    auto pop_from = [&](const PostedRecvKey &lookup_key) -> bool {
        auto it = posted_recv_q_.find(lookup_key);
        if (it == posted_recv_q_.end() || it->second.empty()) {
            return false;
        }
        entry = it->second.front();
        it->second.pop_front();
        if (it->second.empty()) {
            posted_recv_q_.erase(it);
        }
        return true;
    };

    if (pop_from(key)) {
        return true;
    }
    if (key.pdc_id != 0) {
        return pop_from(PostedRecvKey{key.job_id, 0, key.src_fep});
    }
    return false;
}

RxPlacementDescriptor SESManager::resolveRxPlacement(const PDC_SES_req &req)
{
    RxPlacementDescriptor desc{};
    desc.opcode = req.pkt.bth_header.Standard_Header.opcode;
    desc.job_id = req.pkt.bth_header.Standard_Header.job_id;
    desc.msg_id = req.pkt.bth_header.Standard_Header.msg_id;
    desc.src_fep = req.src_fep;
    desc.pdcid = req.PDCID;
    desc.chunk_payload_size = static_cast<uint32_t>(MAX_MTU - sizeof(SES_Standard_Header));
    desc.total_len = req.pkt.bth_header.Standard_Header.request_length;
    desc.response_required = true;
    desc.completion_key =
        (static_cast<uint64_t>(desc.job_id) << 16) ^ static_cast<uint64_t>(desc.msg_id) ^ static_cast<uint64_t>(req.PDCID);

    if (req.pkt.bth_type != Standard_Header) {
        desc.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_INVALID_OP);
        return desc;
    }

    OperationMetadata metadata = parse_pdc_2_ses_req(req);
    if (!validate_pdc_status(req.orig_pdcid, req.orig_psn) ||
        !validate_version(req.pkt.bth_header.Standard_Header.version) ||
        !validate_header_type(req.pkt.bth_type)) {
        desc.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_PROTOCOL_ERROR);
        return desc;
    }
    if (!validate_job_id(metadata.job_id)) {
        desc.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_ACCESS_DENIED);
        return desc;
    }
    if (!validate_pid_on_fep(metadata.t_pid_on_fep, metadata.job_id, metadata.relative)) {
        desc.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_ADDR_UNREACHABLE);
        return desc;
    }
    if (!validate_opcode(metadata.op_type)) {
        desc.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_INVALID_OP);
        return desc;
    }
    const size_t expected_payload_len =
        (metadata.op_type == READ) ? 0 : metadata.payload.length;
    if (!validate_data_length(req.pkt_len, expected_payload_len)) {
        desc.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_INTEGRITY_CHECK_FAIL);
        return desc;
    }

    if (req.pkt.bth_header.Standard_Header.opcode == SEND) {
        PostedRecvEntry recv_entry{};
        if (!tryPopPostedRecv(PostedRecvKey{desc.job_id, desc.pdcid, desc.src_fep}, recv_entry)) {
            desc.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_NO_MATCH);
            desc.response_required = true;
            return desc;
        }

        desc.base_addr = recv_entry.base_addr;
        desc.buffer_offset = 0;
        desc.completion_key = recv_entry.completion_key != 0 ? recv_entry.completion_key : desc.completion_key;
        desc.rkey_ok = true;
        desc.bounds_ok = recv_entry.buffer_len >= desc.total_len;
        desc.return_code = desc.bounds_ok ? static_cast<uint8_t>(RSP_RETURN_CODE::RC_OK)
                                          : static_cast<uint8_t>(RSP_RETURN_CODE::RC_PARTIAL_WRITE);
        desc.valid = desc.bounds_ok && ((desc.total_len == 0) || desc.base_addr != 0);
        if (!desc.valid && desc.total_len > 0 && desc.return_code == static_cast<uint8_t>(RSP_RETURN_CODE::RC_OK)) {
            desc.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_NO_BUFFER);
        }
        desc.response_required = true;
        return desc;
    }

    if (req.pkt.bth_header.Standard_Header.opcode != WRITE) {
        desc.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_INVALID_OP);
        return desc;
    }

    if (!validate_rkey(metadata.memory.rkey, req.pkt.bth_header.Standard_Header.msg_id)) {
        desc.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_INVALID_KEY);
        return desc;
    }

    const MemoryRegion mr = decode_rkey_to_mr(req.pkt.bth_header.Standard_Header.match_bits);
    if (mr.start_addr == 0 || mr.length == 0) {
        desc.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_INVALID_KEY);
        return desc;
    }

    desc.base_addr = mr.start_addr;
    desc.buffer_offset = req.pkt.bth_header.Standard_Header.buffer_offset;
    desc.rkey_ok = true;
    desc.bounds_ok = (static_cast<uint64_t>(desc.buffer_offset) + static_cast<uint64_t>(desc.total_len) <= mr.length);
    desc.return_code = desc.bounds_ok ? static_cast<uint8_t>(RSP_RETURN_CODE::RC_OK)
                                      : static_cast<uint8_t>(RSP_RETURN_CODE::RC_PARTIAL_WRITE);
    desc.valid = desc.bounds_ok;
    return desc;
}

RxPlacementDescriptor SESManager::resolveRxPlacement(const PDC_SES_rsp &rsp)
{
    RxPlacementDescriptor desc{};
    if (rsp.pkt.bth_type != Semantic_Response_with_Data_Header) {
        desc.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_PROTOCOL_ERROR);
        return desc;
    }

    const auto &hdr = rsp.pkt.bth_header.Semantic_Response_with_Data_Header;
    desc.opcode = static_cast<uint8_t>(READ);
    desc.job_id = hdr.job_id;
    desc.msg_id = hdr.read_request_msg_id;
    desc.src_fep = rsp.src_fep;
    desc.pdcid = rsp.PDCID;
    desc.total_len = hdr.modified_length;
    desc.chunk_payload_size = static_cast<uint32_t>(MAX_MTU - sizeof(SES_Semantic_Response_with_Data_Header));
    desc.response_required = false;
    desc.completion_key =
        (static_cast<uint64_t>(desc.job_id) << 16) ^ static_cast<uint64_t>(desc.msg_id) ^ static_cast<uint64_t>(rsp.src_fep);

    const ReadTrackKey key{hdr.job_id, hdr.read_request_msg_id, rsp.src_fep};
    std::lock_guard<std::mutex> lock(read_track_mu_);
    auto it = read_track_.find(key);
    if (it == read_track_.end()) {
        desc.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_NO_MATCH);
        return desc;
    }

    auto &st = it->second;
    if (st.total_len != 0 && st.total_len != hdr.modified_length) {
        desc.return_code = static_cast<uint8_t>(RSP_RETURN_CODE::RC_PROTOCOL_ERROR);
        return desc;
    }
    if (st.total_len == 0) {
        st.total_len = hdr.modified_length;
    }

    desc.base_addr = (st.dst_addr != 0)
                         ? st.dst_addr
                         : (st.buffer.empty() ? 0 : reinterpret_cast<uint64_t>(st.buffer.data()));
    desc.rkey_ok = true;
    desc.bounds_ok = (desc.base_addr != 0) || (st.total_len == 0);
    desc.return_code = desc.bounds_ok ? static_cast<uint8_t>(RSP_RETURN_CODE::RC_OK)
                                      : static_cast<uint8_t>(RSP_RETURN_CODE::RC_NO_BUFFER);
    desc.valid = desc.bounds_ok;
    return desc;
}
