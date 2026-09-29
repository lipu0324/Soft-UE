#include "RdmaChannel.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <algorithm>
#include <chrono>
#include <cstring>
#include <random>
#include <stdexcept>
#include <thread>

namespace UET::NetworkLayer {
namespace {

void require(bool condition, const char* operation) {
    if (!condition) throw std::runtime_error(operation);
}

void write_all(int fd, const uint8_t* p, size_t size) {
    while (size) {
        const ssize_t n = ::send(fd, p, size, MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR) continue;
        require(n > 0, "TCP control send failed");
        p += n;
        size -= static_cast<size_t>(n);
    }
}

void read_all(int fd, uint8_t* p, size_t size) {
    while (size) {
        const ssize_t n = ::recv(fd, p, size, 0);
        if (n < 0 && errno == EINTR) continue;
        require(n > 0, "TCP control receive failed");
        p += n;
        size -= static_cast<size_t>(n);
    }
}

void store16(uint8_t* p, uint16_t value) {
    p[0] = static_cast<uint8_t>(value >> 8);
    p[1] = static_cast<uint8_t>(value);
}

void store32(uint8_t* p, uint32_t value) {
    for (int i = 0; i < 4; ++i) p[i] = static_cast<uint8_t>(value >> (24 - i * 8));
}

uint16_t load16(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

uint32_t load32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | p[3];
}

} // namespace

RdmaChannel::RdmaChannel(const Config& config) : port_(config.ib_port) {
    try {
        open_control(config);
        open_verbs(config);
        connect_qp();
    } catch (...) {
        cleanup();
        throw;
    }
}

RdmaChannel::~RdmaChannel() { cleanup(); }

void RdmaChannel::cleanup() noexcept {
    if (qp_) ibv_destroy_qp(qp_);
    if (send_mr_) ibv_dereg_mr(send_mr_);
    if (recv_mr_) ibv_dereg_mr(recv_mr_);
    if (cq_) ibv_destroy_cq(cq_);
    if (pd_) ibv_dealloc_pd(pd_);
    if (context_) ibv_close_device(context_);
    if (control_fd_ >= 0) ::close(control_fd_);
    qp_ = nullptr; send_mr_ = nullptr; recv_mr_ = nullptr;
    cq_ = nullptr; pd_ = nullptr; context_ = nullptr; control_fd_ = -1;
}

void RdmaChannel::open_control(const Config& config) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    require(fd >= 0, "TCP control socket failed");
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(config.tcp_port);
    if (config.server) {
        const int one = 1;
        ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        address.sin_addr.s_addr = INADDR_ANY;
        if (::bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 ||
            ::listen(fd, 1) != 0) {
            ::close(fd);
            throw std::runtime_error("TCP control bind/listen failed");
        }
        pollfd wait{fd, POLLIN, 0};
        if (::poll(&wait, 1, 10000) != 1 || !(wait.revents & POLLIN)) {
            ::close(fd);
            throw std::runtime_error("TCP control accept timed out");
        }
        control_fd_ = ::accept(fd, nullptr, nullptr);
        ::close(fd);
        require(control_fd_ >= 0, "TCP control accept failed");
    } else {
        if (::inet_pton(AF_INET, config.peer_ip.c_str(), &address.sin_addr) != 1) {
            ::close(fd);
            throw std::invalid_argument("peer_ip must be an IPv4 address");
        }
        const int flags = ::fcntl(fd, F_GETFL, 0);
        if (flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
            ::close(fd);
            throw std::runtime_error("TCP control nonblocking setup failed");
        }
        int result = ::connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address));
        if (result != 0 && errno == EINPROGRESS) {
            pollfd wait{fd, POLLOUT, 0};
            result = ::poll(&wait, 1, 10000);
            int error = 0;
            socklen_t length = sizeof(error);
            if (result != 1 || !(wait.revents & POLLOUT) ||
                ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) != 0 || error != 0)
                result = -1;
            else result = 0;
        }
        if (result != 0) {
            ::close(fd);
            throw std::runtime_error("TCP control connect failed");
        }
        ::fcntl(fd, F_SETFL, flags);
        control_fd_ = fd;
    }
    timeval tv{10, 0};
    ::setsockopt(control_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(control_fd_, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

void RdmaChannel::open_verbs(const Config& config) {
    int count = 0;
    ibv_device** devices = ibv_get_device_list(&count);
    require(devices != nullptr, "ibv_get_device_list failed");
    for (int i = 0; i < count; ++i) {
        if (config.device == ibv_get_device_name(devices[i])) {
            context_ = ibv_open_device(devices[i]);
            break;
        }
    }
    ibv_free_device_list(devices);
    require(context_ != nullptr, "requested RDMA device unavailable");
    require(ibv_query_port(context_, port_, &port_attr_) == 0 &&
            port_attr_.state == IBV_PORT_ACTIVE &&
            port_attr_.link_layer == IBV_LINK_LAYER_INFINIBAND,
            "requested InfiniBand port is not active");

    pd_ = ibv_alloc_pd(context_);
    require(pd_ != nullptr, "ibv_alloc_pd failed");
    cq_ = ibv_create_cq(context_, 32, nullptr, nullptr, 0);
    require(cq_ != nullptr, "ibv_create_cq failed");
    ibv_qp_init_attr init{};
    init.send_cq = cq_;
    init.recv_cq = cq_;
    init.qp_type = IBV_QPT_RC;
    init.cap.max_send_wr = 1;
    init.cap.max_recv_wr = kReceiveSlots;
    init.cap.max_send_sge = 1;
    init.cap.max_recv_sge = 1;
    qp_ = ibv_create_qp(pd_, &init);
    require(qp_ != nullptr, "ibv_create_qp failed");
    send_mr_ = ibv_reg_mr(pd_, send_buffer_.data(), send_buffer_.size(),
                          IBV_ACCESS_LOCAL_WRITE);
    recv_mr_ = ibv_reg_mr(pd_, receive_buffers_.data(), sizeof(receive_buffers_),
                          IBV_ACCESS_LOCAL_WRITE);
    require(send_mr_ && recv_mr_, "ibv_reg_mr failed");

    ibv_qp_attr state{};
    state.qp_state = IBV_QPS_INIT;
    state.pkey_index = 0;
    state.port_num = port_;
    state.qp_access_flags = 0;
    require(ibv_modify_qp(qp_, &state, IBV_QP_STATE | IBV_QP_PKEY_INDEX |
                                     IBV_QP_PORT | IBV_QP_ACCESS_FLAGS) == 0,
            "QP INIT failed");
    for (size_t i = 0; i < kReceiveSlots; ++i) post_receive(i);
    psn_ = std::random_device{}() & 0xffffffu;
}

void RdmaChannel::post_receive(size_t index) {
    ibv_sge sge{};
    sge.addr = reinterpret_cast<uintptr_t>(receive_buffers_[index].data());
    sge.length = kSlotSize;
    sge.lkey = recv_mr_->lkey;
    ibv_recv_wr wr{};
    wr.wr_id = index;
    wr.sg_list = &sge;
    wr.num_sge = 1;
    ibv_recv_wr* bad = nullptr;
    require(ibv_post_recv(qp_, &wr, &bad) == 0, "ibv_post_recv failed");
}

void RdmaChannel::connect_qp() {
    // 20-byte, versioned, network-order TCP control record.
    uint8_t local[20]{};
    store32(local, 0x53554551); // SUEQ
    local[4] = 1;
    local[5] = port_;
    store16(local + 6, port_attr_.lid);
    store32(local + 8, qp_->qp_num);
    store32(local + 12, psn_);
    store16(local + 16, static_cast<uint16_t>(port_attr_.active_mtu));
    write_all(control_fd_, local, sizeof(local));
    uint8_t peer[20]{};
    read_all(control_fd_, peer, sizeof(peer));
    require(load32(peer) == 0x53554551 && peer[4] == 1 &&
            load16(peer + 6) != 0 && load32(peer + 8) != 0 &&
            peer[18] == 0 && peer[19] == 0,
            "peer RDMA control record invalid");
    const uint16_t remote_mtu = load16(peer + 16);
    const uint16_t local_mtu = static_cast<uint16_t>(port_attr_.active_mtu);
    require(remote_mtu >= IBV_MTU_256 && remote_mtu <= IBV_MTU_4096,
            "peer RDMA MTU invalid");

    ibv_qp_attr attr{};
    attr.qp_state = IBV_QPS_RTR;
    attr.path_mtu = static_cast<ibv_mtu>(std::min(local_mtu, remote_mtu));
    attr.dest_qp_num = load32(peer + 8);
    attr.rq_psn = load32(peer + 12);
    attr.max_dest_rd_atomic = 1;
    attr.min_rnr_timer = 12;
    attr.ah_attr.is_global = 0;
    attr.ah_attr.dlid = load16(peer + 6);
    attr.ah_attr.sl = 0;
    attr.ah_attr.src_path_bits = 0;
    attr.ah_attr.port_num = port_;
    require(ibv_modify_qp(qp_, &attr, IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU |
                                       IBV_QP_DEST_QPN | IBV_QP_RQ_PSN |
                                       IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER) == 0,
            "QP RTR failed");
    attr = {};
    attr.qp_state = IBV_QPS_RTS;
    attr.timeout = 14;
    attr.retry_cnt = 7;
    attr.rnr_retry = 7;
    attr.sq_psn = psn_;
    attr.max_rd_atomic = 1;
    require(ibv_modify_qp(qp_, &attr, IBV_QP_STATE | IBV_QP_TIMEOUT |
                                       IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY |
                                       IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC) == 0,
            "QP RTS failed");
}

void RdmaChannel::progress() {
    ibv_wc completions[16]{};
    const int count = ibv_poll_cq(cq_, 16, completions);
    require(count >= 0, "ibv_poll_cq failed");
    for (int i = 0; i < count; ++i) {
        const auto& wc = completions[i];
        if (wc.status != IBV_WC_SUCCESS) {
            if (wc.wr_id == kSendId) send_pending_ = false;
            throw std::runtime_error(std::string("RDMA work completion failed: ") +
                                     ibv_wc_status_str(wc.status));
        }
        if (wc.wr_id == kSendId) {
            send_pending_ = false;
        } else {
            require(wc.wr_id < kReceiveSlots && wc.byte_len <= kSlotSize,
                    "invalid RDMA receive completion");
            require(arrived_.size() < kReceiveSlots,
                    "RDMA receive queue exhausted");
            const auto& slot = receive_buffers_[wc.wr_id];
            arrived_.emplace_back(static_cast<size_t>(wc.wr_id),
                                  std::vector<uint8_t>(slot.begin(), slot.begin() + wc.byte_len));
        }
    }
}

void RdmaChannel::send_packet(const std::vector<uint8_t>& bytes,
                              std::chrono::milliseconds timeout) {
    require(!bytes.empty() && bytes.size() <= kSlotSize,
            "invalid RDMA send request");
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (send_pending_) {
        progress();
        if (!send_pending_) break;
        if (std::chrono::steady_clock::now() >= deadline)
            throw PacketTimeout("previous RDMA send completion timed out");
        std::this_thread::sleep_for(std::chrono::microseconds(50));
    }
    std::memcpy(send_buffer_.data(), bytes.data(), bytes.size());
    ibv_sge sge{};
    sge.addr = reinterpret_cast<uintptr_t>(send_buffer_.data());
    sge.length = static_cast<uint32_t>(bytes.size());
    sge.lkey = send_mr_->lkey;
    ibv_send_wr wr{};
    wr.wr_id = kSendId;
    wr.sg_list = &sge;
    wr.num_sge = 1;
    wr.opcode = IBV_WR_SEND;
    wr.send_flags = IBV_SEND_SIGNALED;
    ibv_send_wr* bad = nullptr;
    require(ibv_post_send(qp_, &wr, &bad) == 0, "ibv_post_send failed");
    send_pending_ = true;
    while (send_pending_) {
        progress();
        if (std::chrono::steady_clock::now() >= deadline)
            throw PacketTimeout("RDMA send completion timed out");
        if (send_pending_) std::this_thread::sleep_for(std::chrono::microseconds(50));
    }
}

std::vector<uint8_t> RdmaChannel::receive_packet(std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (arrived_.empty()) {
        progress();
        if (std::chrono::steady_clock::now() >= deadline)
            throw PacketTimeout("RDMA receive timed out");
        if (arrived_.empty()) std::this_thread::sleep_for(std::chrono::microseconds(50));
    }
    auto completed = std::move(arrived_.front());
    arrived_.pop_front();
    post_receive(completed.first);
    return std::move(completed.second);
}

} // namespace UET::NetworkLayer
