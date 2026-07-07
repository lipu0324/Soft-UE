#ifndef UET_PROVIDER_INTERNAL_HELPERS_HPP
#define UET_PROVIDER_INTERNAL_HELPERS_HPP

static uint64_t uet_new_session_id()
{
    static std::atomic<uint64_t> fallback{1};
    uint64_t v = static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
    v ^= (static_cast<uint64_t>(::getpid()) << 17);
    try {
        std::random_device rd;
        v ^= (static_cast<uint64_t>(rd()) << 1);
        v ^= (static_cast<uint64_t>(rd()) << 33);
    } catch (...) {
        v ^= fallback.fetch_add(1, std::memory_order_relaxed);
    }
    if (v == 0) {
        v = fallback.fetch_add(1, std::memory_order_relaxed);
    }
    return v;
}

[[maybe_unused]] static std::vector<uint8_t> uet_encode_ctrl_msg(uint16_t type, uint64_t session_id,
                                                                  uint32_t job_id,
                                                                  uint32_t resource_index,
                                                                  const void* payload,
                                                                  size_t payload_len)
{
    uet_ctrl_hdr hdr{};
    hdr.magic = kUetCtrlMagic;
    hdr.version = kUetCtrlVersion;
    hdr.msg_type = type;
    hdr.hdr_len = sizeof(uet_ctrl_hdr);
    hdr.total_len = static_cast<uint32_t>(sizeof(uet_ctrl_hdr) + payload_len);
    hdr.session_id = session_id;
    hdr.job_id = job_id;
    hdr.resource_index = resource_index;

    std::vector<uint8_t> out(sizeof(uet_ctrl_hdr) + payload_len);
    std::memcpy(out.data(), &hdr, sizeof(hdr));
    if (payload_len > 0 && payload) {
        std::memcpy(out.data() + sizeof(hdr), payload, payload_len);
    }
    return out;
}

static const char* uet_ctrl_msg_type_name(uint16_t type)
{
    switch (type) {
        case UET_CTRL_HELLO: return "HELLO";
        case UET_CTRL_MRDESC: return "MRDESC";
        case UET_CTRL_ACK: return "ACK";
        case UET_CTRL_ERR: return "ERR";
        case UET_CTRL_WRITE_NOTIFY: return "WRITE_NOTIFY";
        case UET_CTRL_WRITE_ACK: return "WRITE_ACK";
        case UET_CTRL_RDMA_CONN_REQ: return "RDMA_CONN_REQ";
        case UET_CTRL_RDMA_CONN_RESP: return "RDMA_CONN_RESP";
        default: return "UNKNOWN";
    }
}

static bool uet_decode_ctrl_msg(const uint8_t* data, size_t len, uet_ctrl_view& out)
{
    if (!data || len < sizeof(uet_ctrl_hdr)) {
        return false;
    }
    std::memcpy(&out.hdr, data, sizeof(out.hdr));
    if (out.hdr.magic != kUetCtrlMagic) {
        return false;
    }
    if (out.hdr.version != kUetCtrlVersion) {
        return false;
    }
    if (out.hdr.hdr_len != sizeof(uet_ctrl_hdr)) {
        return false;
    }
    if (out.hdr.total_len != len || out.hdr.total_len < out.hdr.hdr_len) {
        return false;
    }
    if (out.hdr.msg_type != UET_CTRL_HELLO && out.hdr.msg_type != UET_CTRL_MRDESC &&
        out.hdr.msg_type != UET_CTRL_ACK && out.hdr.msg_type != UET_CTRL_ERR &&
        out.hdr.msg_type != UET_CTRL_WRITE_NOTIFY && out.hdr.msg_type != UET_CTRL_WRITE_ACK &&
        out.hdr.msg_type != UET_CTRL_RDMA_CONN_REQ && out.hdr.msg_type != UET_CTRL_RDMA_CONN_RESP) {
        return false;
    }
    out.payload = data + out.hdr.hdr_len;
    out.payload_len = len - out.hdr.hdr_len;
    return true;
}

static bool uet_try_cache_mrdesc(uet_ep* uep, const std::vector<uint8_t>& msg, fi_addr_t src_addr)
{
    auto& soft = uep->soft;
    if (src_addr == FI_ADDR_UNSPEC || msg.size() < sizeof(uet_ctrl_hdr)) {
        return false;
    }

    uint32_t maybe_magic = 0;
    std::memcpy(&maybe_magic, msg.data(), sizeof(maybe_magic));
    if (maybe_magic != kUetCtrlMagic) {
        return false;
    }

    uet_ctrl_view ctrl{};
    if (!uet_decode_ctrl_msg(msg.data(), msg.size(), ctrl)) {
        uet_dbg("ctrl", "ctrl_parse_err peer=%" PRIu64 " len=%zu", static_cast<uint64_t>(src_addr), msg.size());
        return false;
    }

    const bool update_peer_session =
        ctrl.hdr.msg_type == UET_CTRL_HELLO ||
        ctrl.hdr.msg_type == UET_CTRL_MRDESC ||
        ctrl.hdr.msg_type == UET_CTRL_ACK;
    if (update_peer_session) {
        std::lock_guard<std::mutex> lock(soft.peer_mu);
        soft.peer_session_by_fiaddr[src_addr] = ctrl.hdr.session_id;
    }

    if (ctrl.hdr.msg_type == UET_CTRL_HELLO) {
        uet_dbg("ctrl", "ctrl cache %s peer=%" PRIu64 " session=0x%" PRIx64 " payload=%zu",
                uet_ctrl_msg_type_name(ctrl.hdr.msg_type),
                static_cast<uint64_t>(src_addr),
                static_cast<uint64_t>(ctrl.hdr.session_id),
                ctrl.payload_len);
        return true;
    }

    if (ctrl.hdr.msg_type == UET_CTRL_ACK || ctrl.hdr.msg_type == UET_CTRL_ERR) {
        uet_dbg("ctrl", "ctrl cache %s peer=%" PRIu64 " session=0x%" PRIx64 " payload=%zu",
                  uet_ctrl_msg_type_name(ctrl.hdr.msg_type),
                  static_cast<uint64_t>(src_addr),
                  static_cast<uint64_t>(ctrl.hdr.session_id), ctrl.payload_len);
        return true;
    }

    if (ctrl.hdr.msg_type != UET_CTRL_MRDESC || ctrl.payload_len < sizeof(uet_mrdesc)) {
        uet_dbg("ctrl", "ctrl_parse_err peer=%" PRIu64 " type=%u payload=%zu",
                static_cast<uint64_t>(src_addr), static_cast<unsigned>(ctrl.hdr.msg_type), ctrl.payload_len);
        return false;
    }

    uet_mrdesc desc{};
    std::memcpy(&desc, ctrl.payload, sizeof(desc));
    if (desc.magic != kUetMrdescMagic || desc.version != kUetMrdescVersion) {
        uet_dbg("ctrl", "ctrl_parse_err peer=%" PRIu64 " invalid mrdesc magic/version",
                static_cast<uint64_t>(src_addr));
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(soft.mrdesc_mu);
        const uet_mrdesc_key key{
            .peer = src_addr,
            .session_id = ctrl.hdr.session_id,
            .job_id = desc.job_id,
            .pid_on_fep = desc.pid_on_fep,
            .resource_index = desc.resource_index,
            .rkey = desc.rkey,
            .reg_epoch = desc.reg_epoch,
        };
        soft.mrdesc_registry[key] = desc;
    }
    {
        std::lock_guard<std::mutex> lock(soft.peer_mu);
        soft.peer_mrdesc_session_by_fiaddr[src_addr] = ctrl.hdr.session_id;
    }

    if (desc.pid_on_fep != 0 && uep->bound_av) {
        if (auto peer = uet_av_resolve(uep->bound_av, src_addr)) {
            std::lock_guard<std::mutex> lock(soft.peer_mu);
            soft.peer_by_fep[desc.pid_on_fep] = *peer;
            soft.fiaddr_by_fep[desc.pid_on_fep] = src_addr;
        }
    }

    soft.ses.register_mr(desc.rkey, 0, static_cast<size_t>(desc.len));

    uet_dbg("mrdesc",
            "cached peer=%" PRIu64 " session=0x%" PRIx64 " job=%u pid=%u ri=%u rkey=0x%x addr=0x%" PRIx64 " len=%" PRIu64 " access=0x%x reg_epoch=%" PRIu64,
            static_cast<uint64_t>(src_addr),
            static_cast<uint64_t>(ctrl.hdr.session_id),
            desc.job_id,
            desc.pid_on_fep,
            desc.resource_index,
            desc.rkey,
            static_cast<uint64_t>(desc.remote_addr),
            static_cast<uint64_t>(desc.len),
            desc.access,
            static_cast<uint64_t>(desc.reg_epoch));
    return true;
}

enum class uet_mr_lookup_rc
{
    ok = 0,
    not_found = 1,
    key_mismatch = 2,
};

static bool uet_get_peer_session(uet_ep* uep, fi_addr_t peer, uint64_t& session_id)
{
    auto& soft = uep->soft;
    std::lock_guard<std::mutex> lock(soft.peer_mu);
    auto it = soft.peer_session_by_fiaddr.find(peer);
    if (it == soft.peer_session_by_fiaddr.end()) {
        return false;
    }
    session_id = it->second;
    return true;
}

static bool uet_get_peer_mrdesc_session(uet_ep* uep, fi_addr_t peer, uint64_t& session_id)
{
    auto& soft = uep->soft;
    std::lock_guard<std::mutex> lock(soft.peer_mu);
    auto it = soft.peer_mrdesc_session_by_fiaddr.find(peer);
    if (it != soft.peer_mrdesc_session_by_fiaddr.end()) {
        session_id = it->second;
        return true;
    }
    it = soft.peer_session_by_fiaddr.find(peer);
    if (it == soft.peer_session_by_fiaddr.end()) {
        return false;
    }
    session_id = it->second;
    return true;
}

static uet_mr_lookup_rc uet_lookup_mrdesc(uet_ep* uep, fi_addr_t peer, uint64_t session_id,
                                          uint64_t rkey, uet_mrdesc& out)
{
    auto& soft = uep->soft;
    std::lock_guard<std::mutex> lock(soft.mrdesc_mu);
    size_t matches = 0;
    for (const auto& it : soft.mrdesc_registry) {
        if (it.first.peer == peer && it.first.session_id == session_id &&
            it.first.rkey == static_cast<uint32_t>(rkey)) {
            out = it.second;
            ++matches;
            if (matches > 1) {
                break;
            }
        }
    }
    if (matches == 1) {
        return uet_mr_lookup_rc::ok;
    }
    if (matches > 1) {
        return uet_mr_lookup_rc::key_mismatch;
    }
    return uet_mr_lookup_rc::not_found;
}

static int uet_ep_queue_ctrl_send(uet_ep* uep, fi_addr_t dest_addr, const std::vector<uint8_t>& msg)
{
    if (!uep || !uep->bound_av) return -FI_EINVAL;
    auto dest = uet_av_resolve(uep->bound_av, dest_addr);
    if (!dest) return -FI_EINVAL;

    uet_ctrl_view ctrl{};
    const bool has_ctrl = uet_decode_ctrl_msg(msg.data(), msg.size(), ctrl);

    OperationMetadata md;
    md.op_type = SEND;
    md.s_pid_on_fep = uep->soft.udp_rx ? uep->soft.udp_rx->getLocalPort() : 0;
    md.t_pid_on_fep = ntohs(dest->sin_port);
    md.job_id = uep->job_id;
    md.messages_id = uep->msg_seq.fetch_add(1);
    auto owned = std::make_shared<std::vector<uint8_t>>(msg);
    md.payload.start_addr = reinterpret_cast<uint64_t>(owned->data());
    md.payload.length = owned->size();
    md.has_imm_data = false;

    uet_dbg("ctrl_tx",
            "queue_ctrl_send peer=%" PRIu64 " ip=%s:%u msg_id=%u bytes=%zu local_fep=%u has_ctrl=%d type=%s session=0x%" PRIx64 " job=%u",
            static_cast<uint64_t>(dest_addr),
            sockaddr_in_to_ip_string(*dest).c_str(),
            static_cast<unsigned>(md.t_pid_on_fep),
            static_cast<unsigned>(md.messages_id),
            owned->size(),
            static_cast<unsigned>(md.s_pid_on_fep),
            static_cast<int>(has_ctrl),
            has_ctrl ? uet_ctrl_msg_type_name(ctrl.hdr.msg_type) : "RAW",
            has_ctrl ? static_cast<uint64_t>(ctrl.hdr.session_id) : 0,
            has_ctrl ? ctrl.hdr.job_id : 0);

    {
        std::lock_guard<std::mutex> lock(uep->soft.peer_mu);
        uep->soft.peer_by_fep[md.t_pid_on_fep] = *dest;
        uep->soft.fiaddr_by_fep[md.t_pid_on_fep] = dest_addr;
    }
    {
        std::lock_guard<std::mutex> lock(uep->soft.op_mu);
        uep->soft.op_q.push(uet_pending_send{
            .md = md,
            .context = nullptr,
            .len = owned->size(),
            .track_completion = false,
            .owned_buffer = std::move(owned),
        });
    }
    uep->soft.op_cv.notify_one();
    return 0;
}

#endif
