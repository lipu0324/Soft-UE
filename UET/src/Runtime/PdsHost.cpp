#include "PdsHost.hpp"

namespace UET::Runtime {

// Runtime/PDS progress and network adaptation compile once for all consumers.
// PdsHost.hpp retains the per-Host interface and owned state.

PdsHost::PdsHost(uint32_t node, EventLoop& loop, Trace& trace, IPacketPort& port,
            WireFormat format ,
            NetworkLayer::WireOptions network )
        : node_(node), loop_(loop), trace_(trace), port_(port),
          services_{loop, loop, [this] { wake(); }}, manager_(&services_), format_(format), network_(network) {
    if (format_==WireFormat::Uet11 && !network_.udp && !network_.native_ip_protocol)
        throw std::invalid_argument("native UET requires an explicit IP protocol number");
    services_.standard_wire=format_==WireFormat::Uet11;
    services_.initial_sequence_seed=sequence_seed_for_host(42,node_);
    services_.default_wire_entropy=network_.entropy;
    services_.actual_transmit_notifications=port_.provides_transmit_timing();
    services_.pdc_event=[this](const PdcEvent& event) { context_events_.push_back(event); };
    if (!manager_.start()) throw std::runtime_error("PDS initialization failed");
    set_receive_admission({},{});
    std::weak_ptr<int> life = lifetime_;
    port_.set_writable_handler([this, life] { if (!life.expired()) wake(); });
    port_.set_receiver([this, life](Frame frame) {
        if (life.expired() || stopped_) return;
        try {
            PDStoNET_pkt packet{};
            if (format_ == WireFormat::LegacySup1)
                packet = NetworkLayer::PdsPacketCodec::decode(frame.bytes.data(), frame.bytes.size());
            else {
                auto decoded = NetworkLayer::UetWireCodec::decode(frame.bytes.data(), frame.bytes.size(),
                    network_.crc,network_.native_ip_protocol,trimming_,network_.udp_destination_port,network_.udp);
                if (decoded.network.ipv6 != network_.ipv6 || decoded.network.udp != network_.udp ||
                    decoded.network.source.ip != address(frame.source).ip ||
                    decoded.network.destination.ip != address(node_).ip)
                    throw std::invalid_argument("network address or encapsulation mismatch");
                packet = std::move(decoded.packet);
                packet.wire_entropy=decoded.network.entropy; packet.network_ecn=decoded.network.ecn;
                packet.receive_time_ns=frame.has_arrival_timestamp?frame.first_byte_arrival_ns:loop_.now();
                packet.has_receive_timestamp=true;
                packet.nominal_packet_size=decoded.nominal_packet_size;
                packet.src_fep=frame.source; packet.dst_fep=frame.destination;
            }
            if (packet.dst_fep != node_ || packet.src_fep != frame.source)
                throw std::invalid_argument("frame and packet addressing disagree");
            if (!manager_.pushNetworkPacket(packet)) throw std::runtime_error("PDS inbound queue rejected frame");
            trace_.record(node_, "pds_rx", static_cast<uint64_t>(packet.PDS_type));
            if (packet.trimmed) trace_.record(node_,"trimmed_rx",packet.trimmed_last_hop?2:1);
            if (packet.PDS_type==nack_header)
                trace_.record(node_,"pds_nack",packet.PDS_header.nack_header.nack_code);
            wake();
        } catch (const NetworkLayer::PdsDecodeError& error) {
            // §3.5.11.1/.3: unknown types are counted and silently
            // discarded before queueing, allocation or peer-ID learning.
            if (error.reason()==NetworkLayer::PdsDecodeError::Reason::UnknownType) {
                services_.pds_error_counters.record_invalid_type();
                trace_.record(node_,"pds_type_invalid",error.value());
            } else {
                services_.pds_error_counters.record_invalid_control_type();
                trace_.record(node_,"pds_ctl_type_invalid",error.value());
            }
        } catch (const std::invalid_argument&) { trace_.record(node_, "malformed_frame"); }
    });
}

PdsHost::~PdsHost() { close(); }

auto PdsHost::manager() -> PDSProcessManager& { return manager_; }

auto PdsHost::closed() const -> bool { return stopped_; }

auto PdsHost::semantic_receive_identity(const PDC_SES_req& request) -> RetiredSemanticReceives::Key {
    const auto& header=request.pkt.bth_header.Standard_Header;
    const bool no_mid=request.request_wire_format==Optimized_Header || request.request_wire_format==Small_Message_RMA_Header;
    const uint64_t identity=no_mid?RetiredSemanticReceives::packet_identity|request.orig_psn:header.msg_id;
    return {request.source_fep,request.PDCID,header.job_id,header.initiator,identity,request.connection_start_psn};
}

auto PdsHost::services() -> Services& { return services_; }

auto PdsHost::pds_error_counters() const -> const PDS::ReceiveErrorCounters& { return services_.pds_error_counters; }

auto PdsHost::clear_pds_error_counters() -> void { services_.pds_error_counters={}; }

auto PdsHost::configure_retransmission_timeout(Time timeout_ns) -> void {
    if (stopped_ || manager_.getPDSStatus().open_cnt) throw std::logic_error("configure RTO before opening connections");
    if (timeout_ns>kMaximumInitialRtoNs) throw std::invalid_argument("initial RTO exceeds UE 1.1 eight-second range");
    services_.rto_ns=timeout_ns;
}

auto PdsHost::configure_negative_acknowledgment_delays(const std::array<Time,4>& delays_ns) -> void {
    if (stopped_ || manager_.getPDSStatus().open_cnt) throw std::logic_error("configure NACK delays before opening connections");
    if (std::any_of(delays_ns.begin(),delays_ns.end(),[](Time delay) { return delay>kMaximumInitialRtoNs; }))
        throw std::invalid_argument("NACK delay exceeds the eight-second configuration range");
    services_.nack_retransmission_delays_ns=delays_ns;
}

auto PdsHost::configure_retry_limit(uint32_t maximum_retries) -> void {
    if (stopped_ || manager_.getPDSStatus().open_cnt) throw std::logic_error("configure retry limit before opening connections");
    if (maximum_retries>kInfiniteRetryLimit) throw std::invalid_argument("retry limit must be 0..15");
    services_.maximum_packet_retries=static_cast<uint8_t>(maximum_retries);
}

auto PdsHost::configure_initial_sequence_seed(uint64_t scenario_seed) -> void {
    if (stopped_ || manager_.getPDSStatus().open_cnt) throw std::logic_error("configure initial sequence seed before opening connections");
    services_.initial_sequence_seed=sequence_seed_for_host(scenario_seed,node_);
}

auto PdsHost::enable_nscc(const CMS::NsccConfig& config) -> void {
    if (stopped_ || format_!=WireFormat::Uet11 || services_.congestion_control || manager_.getPDSStatus().open_cnt)
        throw std::logic_error("configure NSCC once before opening connections");
    congestion_=std::make_unique<CMS::NsccEngine>(config,loop_,[this] { wake(); },network_,&trace_,node_);
    services_.congestion_control=congestion_.get();
}

auto PdsHost::nscc() const -> const CMS::NsccEngine* { return congestion_.get(); }

auto PdsHost::enable_tfc(const CMS::TfcEngineConfig& config) -> void {
    if (stopped_ || format_!=WireFormat::Uet11 || flow_control_ || manager_.getPDSStatus().open_cnt ||
        (services_.congestion_control && services_.congestion_control!=congestion_.get()))
        throw std::logic_error("configure TFC once before opening connections; enable optional NSCC first");
    if (config.outgoing.payload_mtu_bytes!=config.incoming.payload_mtu_bytes)
        throw std::invalid_argument("PdsHost currently has one shared semantic Payload MTU");
    flow_control_=std::make_unique<CMS::TfcEngine>(config,loop_,loop_,[this] { wake(); },network_,
        congestion_.get(),&trace_,node_);
    services_.semantic_payload_mtu=config.outgoing.payload_mtu_bytes;
    services_.congestion_control=flow_control_.get();
}

auto PdsHost::tfc() const -> const CMS::TfcEngine* { return flow_control_.get(); }

auto PdsHost::configure_psn_ranges(const PDS::PsnRangeConfiguration& configured,uint32_t zero_override) -> void {
    if (stopped_ || manager_.getPDSStatus().open_cnt)
        throw std::logic_error("configure PSN ranges before opening connections");
    configured.validate(zero_override);
    services_.psn_ranges=configured; services_.mpr_zero_override=zero_override;
}

auto PdsHost::configure_pdc_mapping(const PDS::PdcMappingConfiguration& configured) -> void {
    if (stopped_ || manager_.getPDSStatus().open_cnt)
        throw std::logic_error("configure PDC mapping before opening connections");
    services_.pdc_mapping=configured;
}

auto PdsHost::configure_read_ack_data(uint32_t maximum_bytes) -> void {
    if (maximum_bytes>8192 || maximum_bytes%16)
        throw std::invalid_argument("Max_ACK_Data_Size must be 0..8192 in 16-byte units");
    if (stopped_ || manager_.getPDSStatus().open_cnt)
        throw std::logic_error("configure READ responses before opening connections");
    services_.max_ack_data_size=maximum_bytes;
}

auto PdsHost::configure_semantic_payload_mtu(uint32_t payload_bytes) -> void {
    if (!payload_bytes || payload_bytes>8192) throw std::invalid_argument("invalid semantic Payload MTU");
    if (stopped_ || (manager_.getPDSStatus().open_cnt && services_.semantic_payload_mtu!=payload_bytes))
        throw std::logic_error("configure semantic Payload MTU before opening connections");
    if (flow_control_ && flow_control_->config().outgoing.payload_mtu_bytes!=payload_bytes)
        throw std::logic_error("semantic Payload MTU must match the immutable TFC geometry");
    services_.semantic_payload_mtu=payload_bytes;
}

auto PdsHost::configure_trimming(const NetworkLayer::TrimmingOptions& options) -> void {
    options.validate();
    if (stopped_ || format_!=WireFormat::Uet11 || manager_.getPDSStatus().open_cnt)
        throw std::logic_error("configure trimming before opening connections");
    trimming_=options;
}

auto PdsHost::cancel_queued_message(uint32_t peer,uint32_t job,uint16_t message_id) -> void {
    if (!stopped_) manager_.cancelQueuedMessage(peer,job,message_id);
}

auto PdsHost::request_connection_close(uint16_t local_pdc_id) -> bool {
    if (stopped_ || !manager_.requestConnectionClose(local_pdc_id)) return false;
    wake();
    return true;
}

auto PdsHost::request_connection_probe(uint16_t local_pdc_id,uint32_t selective_base) -> bool {
    if (stopped_ || !manager_.requestConnectionProbe(local_pdc_id,selective_base)) return false;
    wake(); return true;
}

auto PdsHost::set_request_handler(std::function<void(const PDC_SES_req&)> callback) -> void {
    request_handler_ = std::move(callback);
    // Binding SES is configuration, not protocol work. Resume an existing
    // upcall without inventing an event for an otherwise idle Host.
    if (manager_.getQueueStatus().pdc_to_ses_req_count) wake();
}

auto PdsHost::set_receive_admission(std::function<SemanticAdmission(const PDC_SES_req&)> reserve,
                               std::function<void(const PDC_SES_req&)> cancel) -> void {
    services_.semantic_admission=[this,reserve=std::move(reserve)](const PDC_SES_req& request) {
        // Reverse READ data does not allocate a target message. Even a
        // closed source must be able to discard and acknowledge it.
        if (request.pkt.bth_type!=Standard_Header) return SemanticAdmission::ExistingMessage;
        if (request.pkt.bth_type==Standard_Header &&
            services_.retired_semantic_receives.contains(semantic_receive_identity(request)))
            return SemanticAdmission::ExistingMessage;
        // A live custom PDS/SES adapter may omit native message credits.
        // With no adapter, new reliable PSNs must stay unaccepted so the
        // peer can retry after binding rather than orphan an RX handle.
        if (!request_handler_) return SemanticAdmission::Rejected;
        return reserve?reserve(request):SemanticAdmission::ExistingMessage;
    };
    services_.cancel_semantic_reservation=std::move(cancel);
}

auto PdsHost::open_connection(uint32_t peer,uint32_t job,pdc_mode mode,bool negotiation,
                             PDS::PdcMappingIdentity identity) -> uint16_t {
    if (stopped_ || format_!=WireFormat::Uet11) return UINT16_MAX;
    if (!identity.valid()) return UINT16_MAX;
    const auto context=manager_.openWithControl(node_,peer,job,mode,negotiation,identity);
    if (context!=UINT16_MAX) wake();
    return context;
}

auto PdsHost::set_response_handler(std::function<void(const PDC_SES_rsp&)> callback) -> void { response_handler_ = std::move(callback); }

auto PdsHost::set_datagram_transmit_handler(std::function<void(uint16_t,SendResult)> callback) -> void {
    datagram_transmit_handler_ = std::move(callback);
}

auto PdsHost::set_context_event_handler(std::function<void(const PdcEvent&)> callback) -> void {
    context_event_handler_=std::move(callback);
}

auto PdsHost::submit(const SES_PDS_req& request) -> bool {
    if (stopped_ || request.src_fep != node_ || request.source_pid>0xfff) return false;
    if (flow_control_ && request.tc!=0) return false;
    if (!manager_.pushSESRequest(request)) return false;
    trace_.record(node_, "ses_submit", request.tx_pkt_handle);
    wake();
    return true;
}

auto PdsHost::submit_rudi(const SES_PDS_req& request) -> std::optional<uint32_t> {
    if (stopped_ || format_!=WireFormat::Uet11 || request.src_fep!=node_) return {};
    const auto packet_id=manager_.submitRudi(request);
    if (packet_id) { trace_.record(node_,"rudi_submit",*packet_id); wake(); }
    return packet_id;
}

auto PdsHost::respond_rudi(const PDC_SES_req& request,const SEStoPDS_pkt& response) -> bool {
    if (stopped_ || !manager_.respondRudi(request,node_,response)) return false;
    wake(); return true;
}

auto PdsHost::submit_return_data(const PDC_SES_req& original,const SEStoPDS_pkt& data) -> bool {
    if (stopped_ || format_!=WireFormat::Uet11 || original.pkt.bth_type!=Standard_Header ||
        data.bth_type!=Semantic_Response_with_Data_Header || data.payload.size()>8192) return false;
    const auto& request=original.pkt.bth_header.Standard_Header;
    const auto& response=data.bth_header.Semantic_Response_with_Data_Header;
    // §3.5.17 always returns fetching-atomic results in their ACK. Only
    // READ uses this size-dependent return-direction path in this API.
    if (request.opcode!=2 || request.request_length<=services_.max_ack_data_size ||
        services_.max_ack_data_size>=services_.semantic_payload_mtu || response.opcode!=2 || response.version ||
        response.read_request_msg_id!=request.msg_id || response.job_id!=request.job_id ||
        response.payload_length!=data.payload.size()) return false;
    if (!manager_.pushReturnData(original,data)) return false;
    trace_.record(node_,"ses_return_submit",response.response_message_id); wake(); return true;
}

auto PdsHost::wake() -> void {
    if (stopped_ || pending_) return;
    std::weak_ptr<int> life = lifetime_;
    pending_ = loop_.at(loop_.now(), [this, life] {
        if (life.expired()) return;
        pending_ = 0;
        pump();
    });
}

auto PdsHost::close() -> void {
    if (stopped_) return;
    stopped_ = true;
    lifetime_.reset();
    if (pending_) loop_.cancel(pending_);
    pending_ = 0;
    port_.set_receiver({});
    port_.set_writable_handler({});
    manager_.stop(); // Destroys PDCs and cancels their virtual timers.
    outbound_.clear();
    context_events_.clear();
    transmit_notifications_.clear();
    services_.retired_semantic_messages.clear();
    services_.retired_semantic_responses.clear();
    services_.retired_semantic_receives.clear();
    trace_.record(node_, "host_closed");
}

auto PdsHost::answer_inactive_receive(const PDC_SES_req& request) -> void {
    if (request.delivery_mode==UUD) {
        trace_.record(node_,"inactive_ses_datagram",request.source_fep); return;
    }
    if (request.delivery_mode==RUDI) {
        SEStoPDS_pkt response{}; response.bth_type=Semantic_Response_Header;
        auto& result=response.bth_header.Semantic_Response_Header;
        result.opcode=1; result.return_code=static_cast<uint8_t>(SES::SemanticReturnCode::Undeliverable);
        const auto& header=request.pkt.bth_header.Standard_Header;
        result.job_id=header.job_id; result.message_id=header.msg_id; result.ri_generation=header.ri_generation;
        if (!respond_rudi(request,response)) throw std::runtime_error("PDS rejected inactive RUDI result");
        return;
    }
    if (request.pkt.bth_type==Semantic_Response_with_Data_Header) {
        // §3.4.5.2: cancelled/late READ data still drains its reliable
        // reverse direction, without writing an application result MR.
        SES_PDS_rsp response{}; response.PDCID=request.PDCID; response.rx_pkt_handle=request.rx_pkt_handle;
        response.rsp_len=12; response.rsp=UET::PDS::default_semantic_response(request.pkt);
        if (!manager_.pushSESResponse(response)) throw std::runtime_error("PDS rejected inactive READ data result");
        wake(); return;
    }
    if (request.pkt.bth_type==Standard_Header) {
        // A custom adapter can disappear after acceptance without owning
        // native Incoming state. Give that accepted message the same
        // bounded, Clear/Close-retired error ownership as native SES.
        const auto& header=request.pkt.bth_header.Standard_Header;
        services_.retired_semantic_receives.retain(semantic_receive_identity(request),
            {0,0,false,false,static_cast<uint8_t>(SES::SemanticReturnCode::Undeliverable),
                static_cast<uint8_t>(header.ri_generation),0});
        answer_retired_receive(request);
    }
}

auto PdsHost::answer_retired_receive(const PDC_SES_req& request) -> bool {
    if ((request.delivery_mode!=RUD && request.delivery_mode!=ROD) || request.pkt.bth_type!=Standard_Header) return false;
    const auto& header=request.pkt.bth_header.Standard_Header;
    const auto result=services_.retired_semantic_receives.answer(semantic_receive_identity(request),request.orig_psn,header.eom);
    if (!result) return false;
    // Table3-25 / §3.4.4.3: repeat the closed message's sticky error.
    // Its first error has a delivery guarantee; later fragments still
    // consume their RX handles, without allocating another guarantee.
    SES_PDS_rsp response{}; response.PDCID=request.PDCID; response.rx_pkt_handle=request.rx_pkt_handle;
    response.rsp_len=12; response.gtd_del=result->guaranteed; response.rsp.bth_type=Semantic_Response_Header;
    auto& semantic=response.rsp.bth_header.Semantic_Response_Header;
    semantic.opcode=1; semantic.return_code=result->return_code;
    semantic.job_id=header.job_id; semantic.message_id=header.msg_id;
    semantic.modified_length=result->modified_length; semantic.ri_generation=result->generation;
    semantic.list=result->response_list;
    if (!manager_.pushSESResponse(response)) throw std::runtime_error("PDS rejected retired receive response");
    trace_.record(node_,"retired_ses_request",request.orig_psn); wake(); return true;
}

auto PdsHost::sequence_seed_for_host(uint64_t scenario_seed,uint32_t host) -> uint64_t {
    // Independent deterministic streams for equal-seed simulated hosts.
    return scenario_seed^(uint64_t{host}<<32)^host;
}

auto PdsHost::address(uint32_t node) const -> NetworkLayer::WireAddress {
    NetworkLayer::WireAddress result;
    result.mac[0]=2;
    if (network_.ipv6) { result.ip[0]=0xfd; }
    const auto offset=network_.ipv6?12:0;
    for (size_t i=0; i<4; ++i) {
        const auto value=static_cast<uint8_t>(node >> (24-8*i));
        result.ip[offset+i]=value; result.mac[2+i]=value;
    }
    return result;
}

auto PdsHost::pump() -> void {
    for (size_t step=0; step<256; ++step) {
        bool worked=false;
        while (!transmit_notifications_.empty()) {
            const auto notification=transmit_notifications_.front(); transmit_notifications_.pop_front();
            if (manager_.notifyTransmit(notification))
                trace_.record(node_,notification.outcome==TransmitOutcome::Started?"mac_tx":"nic_rejected",notification.identity.sequence);
            worked=true;
        }
        worked=manager_.progressOne() || worked;
        // Retire old semantic state before delivering requests that may
        // reuse an identifier cleared by the same PDS progress step.
        while (!context_events_.empty()) {
            const auto event=context_events_.front(); context_events_.pop_front();
            services_.retired_semantic_messages.observe(event,MAX_PDC);
            services_.retired_semantic_responses.observe(event,MAX_PDC*2,MAX_PDC);
            services_.retired_semantic_receives.observe(event);
            services_.retired_semantic_messages.request_read_retirement(
                [this](uint16_t local_pdc) { return request_connection_close(local_pdc); });
            if (context_event_handler_) context_event_handler_(event);
            if (stopped_) return;
            worked=true;
        }
        PDStoNET_pkt packet{};
        while (manager_.popNetworkPacket(packet)) {
            Frame frame;
            frame.source = packet.src_fep;
            frame.destination = packet.dst_fep;
            if (format_ == WireFormat::LegacySup1)
                frame.bytes = NetworkLayer::PdsPacketCodec::encode(packet);
            else {
                auto options=network_;
                options.source=address(packet.src_fep); options.destination=address(packet.dst_fep);
                const bool rudi=packet.PDS_type==RUDI_header;
                // Table3-86: RUDI WRITE responses are CONTROL; READ data
                // responses may be trimmed just like the requests.
                const bool rudi_data=rudi && (packet.PDS_header.RUDI_header.type==RUDI_REQ ||
                    packet.SESpkt.bth_type==Semantic_Response_with_Data_Header);
                const bool data=packet.PDS_type==RUOD_req_header || packet.PDS_type==UUD_req_header || rudi_data;
                const bool ordered_control=packet.PDS_type==RUOD_cp_header && packet.control_uses_request_traffic_class;
                frame.traffic_class=(data || ordered_control)?0:1;
                if (rudi_data) frame.traffic_class=2; // Local policy: separate uncontrolled RUDI from UET-CC traffic (§3.5.7.4).
                if (services_.congestion_control || !data) options.entropy=packet.wire_entropy;
                frame.entropy=options.entropy; // ECMP uses the actual on-wire EV, including without CMS.
                if (services_.congestion_control || rudi) {
                    options.ecn=packet.network_ecn;
                    if (packet.PDS_type==UUD_req_header) options.ecn=2; // ECT without reliable NSCC admission.
                }
                if (trimming_ && data) options.dscp=trimming_->trimmable_dscp;
                if (!data) {
                    // §3.5.16 / §3.6.4.7: numbered ROD controls cannot
                    // overtake data via the ACK TC. NO_TRIM shares the
                    // request TC while keeping all CPs non-trimmable.
                    options.dscp=ordered_control?(trimming_?trimming_->no_trim_dscp:network_.dscp):
                        (trimming_?trimming_->control_dscp:48);
                }
                frame.bytes=NetworkLayer::UetWireCodec::encode(packet,options);
                if (services_.congestion_control && packet.PDS_type==RUOD_ack_header &&
                    packet.PDS_header.RUOD_ack_header.type==ACK_CC && packet.acknowledgment_trigger_arrival_ns) {
                    const auto arrival=*packet.acknowledgment_trigger_arrival_ns;
                    frame.prepare_transmission=[arrival,crc=options.crc,protocol=options.native_ip_protocol,
                        udp_destination_port=options.udp_destination_port,udp_encapsulation=options.udp](uint64_t departure,std::vector<uint8_t>& bytes) {
                        NetworkLayer::UetWireCodec::stamp_service_time(bytes,departure,arrival,crc,protocol,udp_destination_port,udp_encapsulation);
                    };
                }
            }
            if (packet.transmit_identity) {
                const auto identity=*packet.transmit_identity;
                std::weak_ptr<int> lifetime=lifetime_;
                frame.transmission_event=[this,lifetime,identity](uint64_t time,TransmitOutcome outcome) {
                    if (lifetime.expired() || stopped_) return;
                    transmit_notifications_.push_back({identity,time,outcome});
                    wake(); // The NIC never re-enters a PDC state machine.
                };
            }
            outbound_.push_back({std::move(frame),packet.PDS_type==UUD_req_header,packet.local_tx_handle,packet.transmit_identity});
            trace_.record(node_, "pds_tx", static_cast<uint64_t>(packet.PDS_type));
            if (packet.PDS_type==RUOD_cp_header)
                trace_.record(node_,"pds_control",packet.PDS_header.RUOD_cp_header.ctl_type);
            worked = true;
        }
        while (!outbound_.empty()) {
            auto& queued=outbound_.front();
            if (queued.identity && queued.identity->kind==TransmitKind::RudiRequest && !manager_.activeRudiAttempt(*queued.identity)) {
                outbound_.pop_front(); worked=true; continue; // Cancelled/backpressured attempt, no stale transmit.
            }
            std::optional<Frame> submission_frame;
            if (!services_.actual_transmit_notifications && queued.frame.prepare_transmission) {
                // Unsupported adapters expose the send-submission boundary.
                // Keep the original hook if WouldBlock requires a later try.
                submission_frame=queued.frame; prepare_first_transmission(*submission_frame,loop_.now());
            }
            const auto result=port_.try_send(submission_frame?*submission_frame:queued.frame);
            if (result == SendResult::WouldBlock) {
                // No busy polling: external adapters call wake() when writable.
                return;
            }
            if (result != SendResult::Accepted) {
                trace_.record(node_, "port_drop", static_cast<uint64_t>(result));
                if (queued.identity) {
                    transmit_notifications_.push_back({*queued.identity,loop_.now(),TransmitOutcome::Rejected});
                    wake();
                }
            }
            const auto transmitted=std::move(outbound_.front());
            outbound_.pop_front();
            if (!services_.actual_transmit_notifications && result==SendResult::Accepted && transmitted.identity &&
                transmitted.identity->kind==TransmitKind::RudiRequest) {
                transmit_notifications_.push_back({*transmitted.identity,loop_.now(),TransmitOutcome::Started});
                wake(); // Adapters without NIC timing expose local acceptance as their documented boundary.
            }
            if (transmitted.is_datagram) {
                services_.retired_semantic_messages.datagram_completed(transmitted.local_tx_handle);
                if (datagram_transmit_handler_) datagram_transmit_handler_(transmitted.local_tx_handle,result);
            }
            if (stopped_) return;
        }
        {
            PDC_SES_req request{};
            while (manager_.popSESRequest(request)) {
                trace_.record(node_, "ses_request", request.orig_psn);
                if (!answer_retired_receive(request)) {
                    if (request_handler_) request_handler_(request);
                    else answer_inactive_receive(request);
                }
                if (services_.congestion_control && (request.delivery_mode==RUD || request.delivery_mode==ROD)) {
                    // The transport buffer is reusable after the validated
                    // upcall hands its contents to SES. Unexpected-message
                    // storage retained by SES is a separate resource domain.
                    services_.congestion_control->handed_to_semantics(
                        {request.source_fep,request.PDCID,request.connection_start_psn,request.delivery_mode==ROD},
                        request.orig_psn);
                }
                if (stopped_) return;
                worked = true;
            }
        }
        {
            PDC_SES_rsp response{};
            while (manager_.popSESResponse(response)) {
                trace_.record(node_, "ses_response",response.original_sequence);
                if (response_handler_) response_handler_(response);
                else trace_.record(node_,"inactive_ses_result",response.original_sequence);
                if (stopped_) return;
                worked = true;
            }
        }
        if (!worked) return;
    }
    // Yield fairly to other hosts at the same simulated instant. The event
    // budget detects a non-quiescing legacy state machine instead of hanging.
    wake();
}

} // namespace UET::Runtime
