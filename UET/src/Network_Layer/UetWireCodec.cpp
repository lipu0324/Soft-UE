#include "UetWireCodec.hpp"
#include <algorithm>
#include <stdexcept>

namespace UET::NetworkLayer {
namespace {
using Bytes = std::vector<uint8_t>;
void put(Bytes& encoded_bytes, uint64_t value, size_t width) {
    for (size_t i=width; i>0; --i) encoded_bytes.push_back(static_cast<uint8_t>(value >> ((i-1)*8)));
}
uint64_t get(const uint8_t* input_bytes, size_t width) {
    uint64_t value = 0;
    for (size_t i=0; i<width; ++i) value = (value << 8) | input_bytes[i];
    return value;
}
class Reader {
public:
    Reader(const uint8_t* bytes, size_t size) : bytes_(bytes), size_(size) {}
    uint64_t take(size_t width) {
        if (width > size_ - offset_) throw std::invalid_argument("truncated UET header");
        const auto value = get(bytes_+offset_,width); offset_ += width; return value;
    }
    Bytes rest() const { return Bytes(bytes_+offset_,bytes_+size_); }
private:
    const uint8_t* bytes_;
    size_t size_, offset_ = 0;
};
uint16_t ip_checksum(const uint8_t* bytes) {
    uint32_t sum = 0;
    for (size_t i=0; i<20; i+=2) sum += static_cast<uint16_t>(get(bytes+i,2));
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}
uint8_t next_wire(PDS_next_hdr next) {
    switch (next) {
    case UET_HDR_NONE: return 0;
    case UET_HDR_REQUEST_SMALL: return 1;
    case UET_HDR_REQUEST_MEDIUM: return 2;
    case UET_HDR_REQUEST_STD: return 3;
    case UET_HDR_RESPONSE: return 4;
    case UET_HDR_RESPONSE_DATA: return 5;
    case UET_HDR_RESPONSE_DATA_SMALL: return 6;
    case UET_HDR_CP_ACK: return 9;
    default: throw std::invalid_argument("invalid next header");
    }
}
PDS_next_hdr next_host(uint8_t next) {
    if (next==9) return UET_HDR_CP_ACK;
    static constexpr PDS_next_hdr names[] = {UET_HDR_NONE,UET_HDR_REQUEST_SMALL,
        UET_HDR_REQUEST_MEDIUM,UET_HDR_REQUEST_STD,UET_HDR_RESPONSE,
        UET_HDR_RESPONSE_DATA,UET_HDR_RESPONSE_DATA_SMALL};
    if (next > 6) throw std::invalid_argument("unsupported next header");
    return names[next];
}
size_t negotiation_payload_size(uint32_t payload_prefix) {
    const auto type=payload_prefix>>24;
    const auto length=(payload_prefix>>16)&0xffu;
    // §3.5.16.7: NO_NEG/length=0 deliberately retains the older fixed
    // 32-byte payload. Other negotiation lengths include their first 4 bytes.
    if (!type && !length) return 32;
    if (!length) throw std::invalid_argument("zero-length negotiation payload");
    return length*4;
}
// The same operation extension follows STD, SMALL and MEDIUM headers.
// Keep extension byte order independent of each request's abbreviated fields.
void put_request_extensions(Bytes& encoded_bytes,const SEStoPDS_pkt& semantic,uint8_t opcode) {
    if (opcode==0x10 || opcode==0x11) {
        const bool synchronized_atomic=opcode==0x11;
        if (semantic.eth_type!=(synchronized_atomic?Synchronized_Atomic_Extension_Headers:Synchronized_Operation_Extension_Header))
            throw std::invalid_argument("missing synchronized operation extensions");
        const auto& synchronization=synchronized_atomic?
            semantic.eth_header.Synchronized_Atomic_Extension_Headers.synchronization:
            semantic.eth_header.Synchronized_Operation_Extension_Header;
        // Figure3-24 and Table3-20 define the extension in each request format.
        // Group counts/ordering are SES obligations, not codec state.
        put(encoded_bytes,synchronization.sync_group,2); put(encoded_bytes,synchronization.sync_count,2);
        if (synchronized_atomic) {
            const auto& atomic=semantic.eth_header.Synchronized_Atomic_Extension_Headers.atomic;
            if (atomic.rsvd) throw std::invalid_argument("reserved synchronized atomic extension bits");
            put(encoded_bytes,atomic.atomic_opcode,1); put(encoded_bytes,atomic.atomic_datatype,1);
            put(encoded_bytes,atomic.semantic_contol,1); put(encoded_bytes,0,1);
        }
    } else if (opcode==6 || opcode==10) {
        // §3.4.3.4/Figure3-21: this 24-byte extension follows EVERY
        // rendezvous SEND/TSEND fragment, independently of SOM/EOM.
        // Its read address remains data for later checked READ admission;
        // the codec must never resolve it as a local process address.
        if (semantic.eth_type!=Rendezvous_Extension_Header)
            throw std::invalid_argument("missing rendezvous extension");
        const auto& rendezvous=semantic.eth_header.Rendezvous_Extension_Header;
        put(encoded_bytes,rendezvous.eager_length,4);
        put(encoded_bytes,(uint32_t{rendezvous.read_ri_generation}<<24)|
            (uint32_t{rendezvous.read_PIDonFEP}<<12)|rendezvous.read_resource_index,4);
        put(encoded_bytes,rendezvous.read_offset,8); put(encoded_bytes,rendezvous.read_mem_key,8);
    } else if (opcode==3 || opcode==4 || opcode==0x0d || opcode==0x0e) {
        const auto& atomic=semantic.eth_header.Atomic_Operation_Extension_Header;
        if (atomic.rsvd) throw std::invalid_argument("reserved atomic extension bits");
        put(encoded_bytes,atomic.atomic_opcode,1); put(encoded_bytes,atomic.atomic_datatype,1);
        put(encoded_bytes,atomic.semantic_contol,1); put(encoded_bytes,0,1);
    }
}
void get_request_extensions(Reader& reader,SEStoPDS_pkt& semantic,uint8_t opcode) {
    if (opcode==0x10 || opcode==0x11) {
        const bool synchronized_atomic=opcode==0x11;
        semantic.eth_type=synchronized_atomic?Synchronized_Atomic_Extension_Headers:Synchronized_Operation_Extension_Header;
        auto& synchronization=synchronized_atomic?
            semantic.eth_header.Synchronized_Atomic_Extension_Headers.synchronization:
            semantic.eth_header.Synchronized_Operation_Extension_Header;
        synchronization.sync_group=reader.take(2); synchronization.sync_count=reader.take(2);
        if (synchronized_atomic) {
            auto& atomic=semantic.eth_header.Synchronized_Atomic_Extension_Headers.atomic;
            atomic.atomic_opcode=reader.take(1); atomic.atomic_datatype=reader.take(1);
            atomic.semantic_contol=reader.take(1); reader.take(1); // Reserved after integrity validation.
        }
    } else if (opcode==6 || opcode==10) {
        semantic.eth_type=Rendezvous_Extension_Header;
        auto& rendezvous=semantic.eth_header.Rendezvous_Extension_Header;
        rendezvous.eager_length=reader.take(4);
        const auto read_address=reader.take(4);
        rendezvous.read_ri_generation=read_address>>24;
        rendezvous.read_PIDonFEP=(read_address>>12)&0xfff;
        rendezvous.read_resource_index=read_address&0xfff;
        rendezvous.read_offset=reader.take(8); rendezvous.read_mem_key=reader.take(8);
    } else if (opcode==3 || opcode==4 || opcode==0x0d || opcode==0x0e) {
        semantic.eth_type=Atomic_Operation_Extension_Header;
        auto& atomic=semantic.eth_header.Atomic_Operation_Extension_Header;
        atomic.atomic_opcode=reader.take(1); atomic.atomic_datatype=reader.take(1);
        atomic.semantic_contol=reader.take(1);
        reader.take(1); // Reserved octet, ignored after integrity validation.
    }
}
void put_semantic(Bytes& encoded_bytes, const PDStoNET_pkt& packet, PDS_next_hdr next) {
    if (next==UET_HDR_CP_ACK) {
        const auto& acknowledgement=packet.control_ack;
        if (acknowledgement.cp_ack_type!=Close_cmd || acknowledgement.cp_ack_length!=2 ||
            acknowledgement.reserved || acknowledgement.start_psn_method>1)
            throw std::invalid_argument("unsupported control acknowledgement");
        put(encoded_bytes,acknowledgement.cp_ack_type,1); put(encoded_bytes,2,1);
        put(encoded_bytes,acknowledgement.start_psn_method,1); put(encoded_bytes,0,1);
        put(encoded_bytes,acknowledgement.expected_psn,4);
        return;
    }
    if (next == UET_HDR_NONE) {
        if (!packet.SESpkt.payload.empty()) throw std::invalid_argument("payload without SES header");
        return;
    }
    if (next==UET_HDR_REQUEST_SMALL || next==UET_HDR_REQUEST_MEDIUM) {
        const bool medium=next==UET_HDR_REQUEST_MEDIUM;
        if (packet.SESpkt.bth_type!=(medium?Small_Message_RMA_Header:Optimized_Header))
            throw std::invalid_argument("optimized request header type mismatch");
        const auto put_common=[&](const auto& header) {
            if (header.version || header.opcode>0x3f || header.dc>1 || header.ie>1 || header.rel>1 || header.hd>1 ||
                header.som>1 || header.eom>1 || (!medium && header.hd) || header.request_length>0x3fff ||
                header.job_id>0xffffff || header.PIDonFEP>0xfff || header.resource_index>0xfff)
                throw std::invalid_argument("invalid optimized request field");
            put(encoded_bytes,header.opcode,1);
            put(encoded_bytes,(header.dc<<5)|(header.ie<<4)|(header.rel<<3)|(header.hd<<2)|(header.eom<<1)|header.som,1);
            put(encoded_bytes,header.request_length,2);
            put(encoded_bytes,(uint32_t{header.ri_generation}<<24)|header.job_id,4);
            put(encoded_bytes,header.PIDonFEP,2); put(encoded_bytes,header.resource_index,2); put(encoded_bytes,header.buffer_offset,8);
        };
        uint8_t opcode;
        if (medium) {
            const auto& header=packet.SESpkt.bth_header.Small_Message_RMA_Header;
            put_common(header); put(encoded_bytes,header.initiator,4); put(encoded_bytes,header.match_bits,8); opcode=header.opcode;
        } else {
            const auto& header=packet.SESpkt.bth_header.Optimized_Header;
            put_common(header); opcode=header.opcode;
        }
        put_request_extensions(encoded_bytes,packet.SESpkt,opcode);
    } else if (next == UET_HDR_REQUEST_STD) {
        if (packet.SESpkt.bth_type != Standard_Header) throw std::invalid_argument("SES header type mismatch");
        const auto& header = packet.SESpkt.bth_header.Standard_Header;
        if (header.version != 0) throw std::invalid_argument("unsupported SES version");
        put(encoded_bytes,header.opcode,1);
        put(encoded_bytes,(header.dc<<5)|(header.ie<<4)|(header.rel<<3)|(header.hd<<2)|(header.eom<<1)|header.som,1);
        put(encoded_bytes,header.msg_id,2); put(encoded_bytes,(uint32_t{header.ri_generation}<<24)|header.job_id,4);
        put(encoded_bytes,header.PIDonFEP,2); put(encoded_bytes,header.resource_index,2);
        put(encoded_bytes,header.buffer_offset,8); put(encoded_bytes,header.initiator,4); put(encoded_bytes,header.match_bits,8);
        if (header.som) put(encoded_bytes,header.diff.som_true.header_data,8);
        else put(encoded_bytes,(uint64_t{header.diff.som_false.payload_length}<<32)|header.diff.som_false.message_offset,8);
        put(encoded_bytes,header.request_length,4);
        put_request_extensions(encoded_bytes,packet.SESpkt,header.opcode);
    } else if (next == UET_HDR_RESPONSE) {
        if (packet.SESpkt.bth_type != Semantic_Response_Header) throw std::invalid_argument("SES header type mismatch");
        const auto& header = packet.SESpkt.bth_header.Semantic_Response_Header;
        if (header.version != 0) throw std::invalid_argument("unsupported SES version");
        put(encoded_bytes,(header.list<<6)|header.opcode,1); put(encoded_bytes,header.return_code,1); put(encoded_bytes,header.message_id,2);
        put(encoded_bytes,(uint32_t{header.ri_generation}<<24)|header.job_id,4); put(encoded_bytes,header.modified_length,4);
    } else if (next==UET_HDR_RESPONSE_DATA_SMALL) {
        if (packet.SESpkt.bth_type!=Optimized_Response_with_Data_Header) throw std::invalid_argument("optimized response type mismatch");
        const auto& header=packet.SESpkt.bth_header.Optimized_Response_with_Data_Header;
        if (header.version || (header.opcode!=2 && header.payload_length)) throw std::invalid_argument("invalid optimized response field");
        put(encoded_bytes,(header.list<<6)|header.opcode,1); put(encoded_bytes,header.return_code,1);
        put(encoded_bytes,header.opcode==2?header.payload_length:0,2); put(encoded_bytes,header.job_id,4);
        put(encoded_bytes,header.original_request_psn,4);
    } else if (next == UET_HDR_RESPONSE_DATA) {
        if (packet.SESpkt.bth_type != Semantic_Response_with_Data_Header) throw std::invalid_argument("SES header type mismatch");
        const auto& header = packet.SESpkt.bth_header.Semantic_Response_with_Data_Header;
        if (header.version != 0) throw std::invalid_argument("unsupported SES version");
        put(encoded_bytes,(header.list<<6)|header.opcode,1); put(encoded_bytes,header.return_code,1); put(encoded_bytes,header.response_message_id,2);
        put(encoded_bytes,header.job_id,4); put(encoded_bytes,header.read_request_msg_id,2); put(encoded_bytes,header.payload_length,2);
        put(encoded_bytes,header.modified_length,4); put(encoded_bytes,header.message_offset,4);
    } else throw std::invalid_argument("SES wire format not implemented");
    encoded_bytes.insert(encoded_bytes.end(),packet.SESpkt.payload.begin(),packet.SESpkt.payload.end());
}
void get_semantic(Reader& reader, PDStoNET_pkt& packet, PDS_next_hdr next) {
    if (next==UET_HDR_CP_ACK) {
        auto& acknowledgement=packet.control_ack;
        acknowledgement.cp_ack_type=reader.take(1); acknowledgement.cp_ack_length=reader.take(1);
        acknowledgement.start_psn_method=reader.take(1); reader.take(1); // Reserved CP_ACK octet is ignored.
        acknowledgement.expected_psn=reader.take(4);
        if (acknowledgement.cp_ack_type!=Close_cmd || acknowledgement.cp_ack_length!=2 ||
            acknowledgement.start_psn_method>1 || !reader.rest().empty())
            throw std::invalid_argument("invalid control acknowledgement");
        return;
    }
    if (next == UET_HDR_NONE) {
        if (!reader.rest().empty()) throw std::invalid_argument("unexpected UET payload");
        return;
    }
    if (next==UET_HDR_REQUEST_SMALL || next==UET_HDR_REQUEST_MEDIUM) {
        const bool medium=next==UET_HDR_REQUEST_MEDIUM;
        packet.SESpkt.bth_type=medium?Small_Message_RMA_Header:Optimized_Header;
        const auto get_common=[&](auto& header) {
            const auto opcode=reader.take(1),flags=reader.take(1);
            if (flags&0xc0) throw std::invalid_argument("unsupported optimized request version");
            header.opcode=opcode&0x3f; header.version=0; header.dc=(flags>>5)&1; header.ie=(flags>>4)&1;
            header.rel=(flags>>3)&1; header.hd=medium?((flags>>2)&1):0; header.eom=(flags>>1)&1; header.som=flags&1;
            header.request_length=reader.take(2)&0x3fff;
            const auto job=reader.take(4); header.ri_generation=job>>24; header.job_id=job&0xffffff;
            header.PIDonFEP=reader.take(2)&0xfff; header.resource_index=reader.take(2)&0xfff; header.buffer_offset=reader.take(8);
        };
        uint8_t opcode;
        if (medium) {
            auto& header=packet.SESpkt.bth_header.Small_Message_RMA_Header;
            get_common(header); header.initiator=reader.take(4); header.match_bits=reader.take(8); opcode=header.opcode;
        } else {
            auto& header=packet.SESpkt.bth_header.Optimized_Header; get_common(header); opcode=header.opcode;
        }
        get_request_extensions(reader,packet.SESpkt,opcode);
    } else if (next == UET_HDR_REQUEST_STD) {
        packet.SESpkt.bth_type = Standard_Header;
        auto& header = packet.SESpkt.bth_header.Standard_Header;
        const auto opcode=reader.take(1), flags=reader.take(1);
        // §3.4.3: reserved fields are zero on transmit and ignored on receive.
        // The version field is meaningful, so an unsupported version remains
        // an error rather than being silently treated as version zero.
        if (flags&0xc0) throw std::invalid_argument("unsupported SES version");
        header.opcode=opcode&0x3f; header.dc=(flags>>5)&1; header.ie=(flags>>4)&1; header.rel=(flags>>3)&1;
        header.hd=(flags>>2)&1; header.eom=(flags>>1)&1; header.som=flags&1;
        header.msg_id=reader.take(2); const auto job=reader.take(4); header.ri_generation=job>>24; header.job_id=job&0xffffff;
        const auto pid=reader.take(2), ri=reader.take(2);
        header.PIDonFEP=pid&0xfff; header.resource_index=ri&0xfff; header.buffer_offset=reader.take(8);
        header.initiator=reader.take(4); header.match_bits=reader.take(8); const auto data=reader.take(8);
        if (header.som) header.diff.som_true.header_data=data;
        else {
            header.diff.som_false.payload_length=(data>>32)&0x3fff;
            header.diff.som_false.message_offset=data&0xffffffff;
        }
        header.request_length=reader.take(4);
        get_request_extensions(reader,packet.SESpkt,header.opcode);
    } else if (next == UET_HDR_RESPONSE) {
        packet.SESpkt.bth_type=Semantic_Response_Header;
        auto& header=packet.SESpkt.bth_header.Semantic_Response_Header;
        const auto op=reader.take(1), code=reader.take(1);
        if (code&0xc0) throw std::invalid_argument("unsupported SES response version");
        header.list=op>>6; header.opcode=op&0x3f; header.return_code=code; header.message_id=reader.take(2);
        const auto job=reader.take(4); header.ri_generation=job>>24; header.job_id=job&0xffffff;
        header.modified_length=reader.take(4);
    } else if (next==UET_HDR_RESPONSE_DATA_SMALL) {
        packet.SESpkt.bth_type=Optimized_Response_with_Data_Header;
        auto& header=packet.SESpkt.bth_header.Optimized_Response_with_Data_Header;
        const auto opcode=reader.take(1),code=reader.take(1);
        if (code&0xc0) throw std::invalid_argument("unsupported optimized response version");
        header.list=opcode>>6; header.opcode=opcode&0x3f; header.version=0; header.return_code=code&0x3f;
        const auto length=reader.take(2); header.payload_length=header.opcode==2?(length&0x3fff):0;
        header.job_id=reader.take(4)&0xffffff; header.original_request_psn=reader.take(4);
    } else if (next == UET_HDR_RESPONSE_DATA) {
        packet.SESpkt.bth_type=Semantic_Response_with_Data_Header;
        auto& header=packet.SESpkt.bth_header.Semantic_Response_with_Data_Header;
        const auto op=reader.take(1), code=reader.take(1);
        if (code&0xc0) throw std::invalid_argument("unsupported SES response version");
        header.list=op>>6; header.opcode=op&0x3f; header.return_code=code; header.response_message_id=reader.take(2);
        const auto job=reader.take(4);
        header.job_id=job&0xffffff; header.read_request_msg_id=reader.take(2); const auto length=reader.take(2);
        header.payload_length=length&0x3fff; header.modified_length=reader.take(4); header.message_offset=reader.take(4);
    } else throw std::invalid_argument("SES wire format not implemented");
    packet.SESpkt.payload=reader.rest();
}
Bytes encode_pds(const PDStoNET_pkt& packet) {
    Bytes encoded_bytes; PDS_next_hdr next=UET_HDR_NONE;
    // §3.5.10: the 16-bit prologue contains type[15:11], next-header[10:7]
    // and flags[6:0]. Pack fields explicitly; C++ bitfield layout is not wire ABI.
    if (packet.PDS_type == RUOD_req_header) {
        const auto& header=packet.PDS_header.RUOD_req_header;
        if (header.type!=RUD_REQ && header.type!=ROD_REQ) throw std::invalid_argument("unsupported request type");
        next=header.next_hdr;
        put(encoded_bytes,(uint16_t{header.type}<<11)|(next_wire(next)<<7)|(header.flags.retx<<4)|(header.flags.ar<<3)|(header.flags.syn<<2),2);
        put(encoded_bytes,header.clear_psn_off,2); put(encoded_bytes,header.psn,4); put(encoded_bytes,header.spdcid,2);
        put(encoded_bytes,header.flags.syn ? ((header.pdc_info&1)<<12)|header.psn_off : header.dpdcid,2);
    } else if (packet.PDS_type == RUDI_header) {
        const auto& header=packet.PDS_header.RUDI_header;
        if ((header.type!=RUDI_REQ && header.type!=RUDI_RESP) || header.flags.retx>1 || header.flags.m>1 ||
            (header.type==RUDI_REQ && header.flags.m)) throw std::invalid_argument("invalid RUDI header");
        next=header.next_hdr;
        put(encoded_bytes,(uint16_t{header.type}<<11)|(next_wire(next)<<7)|(header.flags.m<<5)|(header.flags.retx<<4),2);
        put(encoded_bytes,0,2); // Figure3-74 reserved word precedes pkt_id.
        put(encoded_bytes,header.pkt_id,4);
    } else if (packet.PDS_type == RUOD_ack_header) {
        const auto& header=packet.PDS_header.RUOD_ack_header;
        if (header.type!=ACK && header.type!=ACK_CC) throw std::invalid_argument("ACK extension not implemented");
        next=header.next_hdr;
        put(encoded_bytes,((header.type==ACK?7:8)<<11)|(next_wire(next)<<7)|(header.flags.m<<5)|(header.flags.retx<<4)|(header.flags.p<<3)|(header.flags.req<<1),2);
        put(encoded_bytes,static_cast<uint16_t>(header.ack_psn_off),2); put(encoded_bytes,header.cack_psn,4); put(encoded_bytes,header.spdcid,2); put(encoded_bytes,header.dpdcid,2);
        if (header.type==ACK_CC) {
            const auto& congestion=packet.congestion_ack;
            if (congestion.type!=0 || congestion.receiver_window_penalty>127 || congestion.received_byte_units>0xffffff)
                throw std::invalid_argument("unsupported ACK_CC state");
            put(encoded_bytes,congestion.type<<4,1); put(encoded_bytes,congestion.mpr,1);
            put(encoded_bytes,static_cast<uint16_t>(congestion.sack_psn_offset),2); put(encoded_bytes,congestion.sack_bitmap,8);
            put(encoded_bytes,congestion.service_time,2);
            put(encoded_bytes,(congestion.restore_window?0x80:0)|congestion.receiver_window_penalty,1);
            put(encoded_bytes,congestion.received_byte_units,3); put(encoded_bytes,congestion.out_of_order_count,2);
        }
    } else if (packet.PDS_type == nack_header) {
        const auto& header=packet.PDS_header.nack_header;
        if (header.type!=NACK || header.next_hdr!=UET_HDR_NONE) throw std::invalid_argument("unsupported NACK format");
        put(encoded_bytes,(10<<11)|(header.flags.m<<5)|(header.flags.retx<<4)|(header.flags.nt<<3),2);
        put(encoded_bytes,header.nack_code,1); put(encoded_bytes,header.vendor_code,1); put(encoded_bytes,header.nack_psn,4);
        put(encoded_bytes,header.spdcid,2); put(encoded_bytes,header.dpdcid,2); put(encoded_bytes,header.payload,4);
    } else if (packet.PDS_type == RUOD_cp_header) {
        const auto& header=packet.PDS_header.RUOD_cp_header;
        if (header.type!=CP) throw std::invalid_argument("invalid CP type");
        const bool carries_mode=header.ctl_type==Noop || header.ctl_type==Negotiation;
        const auto pdc_type=carries_mode?header.flags.pdc_type:0;
        put(encoded_bytes,(11<<11)|(header.ctl_type<<7)|(pdc_type<<5)|(header.flags.retx<<4)|(header.flags.ar<<3)|(header.flags.syn<<2),2);
        put(encoded_bytes,header.probe_opaque,2); put(encoded_bytes,header.psn,4); put(encoded_bytes,header.spdcid,2);
        put(encoded_bytes,header.flags.syn ? ((header.pdc_info&1)<<12)|header.psn_off : header.dpdcid,2); put(encoded_bytes,header.payload,4);
        if (header.ctl_type==Negotiation) {
            if (packet.control_extension.size()+4!=negotiation_payload_size(header.payload))
                throw std::invalid_argument("negotiation payload length mismatch");
            encoded_bytes.insert(encoded_bytes.end(),packet.control_extension.begin(),packet.control_extension.end());
        } else if (!packet.control_extension.empty()) throw std::invalid_argument("unexpected CP extension");
    } else if (packet.PDS_type == UUD_req_header) {
        next=packet.PDS_header.UUD_req_header.next_hdr;
        if (packet.PDS_header.UUD_req_header.type!=UUD_REQ)
            throw std::invalid_argument("invalid UUD packet type");
        // §3.5.10.14: no sequence, connection ID or acknowledgement state.
        put(encoded_bytes,(6u<<11)|(next_wire(next)<<7),2); put(encoded_bytes,0,2);
    } else throw std::invalid_argument("PDS wire format not implemented");
    put_semantic(encoded_bytes,packet,next);
    return encoded_bytes;
}
PDStoNET_pkt decode_pds(const uint8_t* bytes, size_t size) {
    PDStoNET_pkt packet{}; Reader reader(bytes,size);
    const auto prologue=reader.take(2), type=prologue>>11, flags=prologue&0x7f;
    // Table 3-39 defines 1..15; zero and 16..31 are reserved. Classify
    // before interpreting next_hdr, after the outer integrity check. A known
    // format disabled in this implementation must not become TYPE_INVALID.
    if (!type || type>=16) throw PdsDecodeError(PdsDecodeError::Reason::UnknownType,type);
    if (type==11 && ((prologue>>7)&0xf)>=10)
        throw PdsDecodeError(PdsDecodeError::Reason::UnknownControlType,(prologue>>7)&0xf);
    PDS_next_hdr next=type==11 ? UET_HDR_NONE : next_host((prologue>>7)&0xf);
    if (type==2 || type==3) {
        // RUD/ROD share a 12-byte header. During SYN the final two bytes
        // carry PDC info and start-PSN offset instead of destination PDCID.
        // §3.5.10: extract meaningful fields and ignore reserved receive bits.
        packet.PDS_type=RUOD_req_header; auto& header=packet.PDS_header.RUOD_req_header;
        header.type=static_cast<PDS_type>(type); header.next_hdr=next;
        header.flags.retx=(flags>>4)&1; header.flags.ar=(flags>>3)&1; header.flags.syn=(flags>>2)&1;
        header.clear_psn_off=static_cast<int16_t>(reader.take(2)); header.psn=reader.take(4); header.spdcid=reader.take(2);
        const auto destination=reader.take(2);
        if (header.flags.syn) { header.pdc_info=(destination>>12)&1; header.psn_off=destination&0xfff; }
        else header.dpdcid=destination;
    } else if (type==4 || type==5) {
        packet.PDS_type=RUDI_header; auto& header=packet.PDS_header.RUDI_header;
        header.type=type==4?RUDI_REQ:RUDI_RESP; header.next_hdr=next;
        header.flags.retx=(flags>>4)&1; header.flags.m=type==5?(flags>>5)&1:0;
        reader.take(2); // Reserved bits are ignored after outer integrity validation.
        header.pkt_id=reader.take(4);
    } else if (type==7 || type==8) {
        packet.PDS_type=RUOD_ack_header; auto& header=packet.PDS_header.RUOD_ack_header;
        header.type=type==7?ACK:ACK_CC; header.next_hdr=next; header.flags.m=(flags>>5)&1; header.flags.retx=(flags>>4)&1;
        header.flags.p=(flags>>3)&1; header.flags.req=(flags>>1)&3;
        header.ack_psn_off=static_cast<int16_t>(reader.take(2)); header.cack_psn=reader.take(4); header.spdcid=reader.take(2); header.dpdcid=reader.take(2);
        if (type==8) {
            auto& congestion=packet.congestion_ack;
            congestion.type=reader.take(1)>>4; congestion.mpr=reader.take(1);
            congestion.sack_psn_offset=static_cast<int16_t>(reader.take(2)); congestion.sack_bitmap=reader.take(8);
            // Unknown CC state still leaves a valid base ACK/SACK. Its opaque
            // bits must not accidentally become NSCC byte acknowledgments.
            const auto state=reader.take(8);
            if (congestion.type==0) {
                congestion.service_time=state>>48; congestion.restore_window=(state>>47)&1;
                congestion.receiver_window_penalty=(state>>40)&0x7f;
                congestion.received_byte_units=(state>>16)&0xffffff; congestion.out_of_order_count=state&0xffff;
            }
        }
    } else if (type==10) {
        if (next!=UET_HDR_NONE) throw std::invalid_argument("invalid NACK next header");
        packet.PDS_type=nack_header; auto& header=packet.PDS_header.nack_header;
        header.type=NACK; header.next_hdr=next; header.flags.m=(flags>>5)&1; header.flags.retx=(flags>>4)&1; header.flags.nt=(flags>>3)&1;
        header.nack_code=static_cast<PDS_Nack_Codes>(reader.take(1)); header.vendor_code=reader.take(1);
        header.nack_psn=reader.take(4); header.spdcid=reader.take(2); header.dpdcid=reader.take(2); header.payload=reader.take(4);
    } else if (type==11) {
        packet.PDS_type=RUOD_cp_header; auto& header=packet.PDS_header.RUOD_cp_header;
        header.type=CP; header.ctl_type=(prologue>>7)&0xf;
        const bool carries_mode=header.ctl_type==Noop || header.ctl_type==Negotiation;
        header.flags.pdc_type=carries_mode?(flags>>5)&3:0;
        header.flags.retx=(flags>>4)&1; header.flags.ar=(flags>>3)&1; header.flags.syn=(flags>>2)&1;
        header.probe_opaque=reader.take(2); header.psn=reader.take(4); header.spdcid=reader.take(2);
        const auto destination=reader.take(2);
        if (header.flags.syn) { header.pdc_info=(destination>>12)&1; header.psn_off=destination&0xfff; } else header.dpdcid=destination;
        header.payload=reader.take(4); next=UET_HDR_NONE;
        if (header.ctl_type==Negotiation) {
            packet.control_extension=reader.rest();
            if (packet.control_extension.size()+4!=negotiation_payload_size(header.payload))
                throw std::invalid_argument("invalid negotiation length");
            return packet;
        }
    } else if (type==6) {
        // UUD flags/reserved bits are ignored on reception (§3.5.10.14).
        reader.take(2);
        packet.PDS_type=UUD_req_header;
        packet.PDS_header.UUD_req_header.type=UUD_REQ;
        packet.PDS_header.UUD_req_header.next_hdr=next;
    } else throw std::invalid_argument("PDS wire format not implemented");
    get_semantic(reader,packet,next);
    return packet;
}
} // namespace

uint32_t UetWireCodec::crc32c(const uint8_t* bytes, size_t length) {
    // §3.5.26 / RFC 3385: reflected Castagnoli polynomial, all-ones initial
    // remainder and final complement. Serialization supplies network byte order.
    // Precompute each byte's eight polynomial steps. The generated table keeps
    // the definition auditable and makes large-message experiments practical;
    // golden vectors and the independent reference CRC check this same result.
    static const auto byte_remainders=[] {
        std::array<uint32_t,256> table{};
        for (size_t byte=0;byte<table.size();++byte) {
            uint32_t remainder=static_cast<uint32_t>(byte);
            for (unsigned bit=0;bit<8;++bit)
                remainder=(remainder>>1)^((remainder&1)?0x82f63b78u:0u);
            table[byte]=remainder;
        }
        return table;
    }();
    uint32_t crc=0xffffffff;
    for (size_t position=0;position<length;++position)
        crc=(crc>>8)^byte_remainders[(crc^bytes[position])&0xffu];
    return ~crc;
}
std::vector<uint8_t> UetWireCodec::encode(const PDStoNET_pkt& packet, const WireOptions& network_options) {
    if (packet.trimmed) throw std::invalid_argument("trimmed packets cannot be reconstituted as complete UET packets");
    if (network_options.dscp>63 || network_options.ecn>3 || !network_options.hop_limit) throw std::invalid_argument("invalid network fields");
    if (!network_options.udp && !network_options.native_ip_protocol)
        throw std::invalid_argument("native UET requires an explicit IP protocol number");
    const uint8_t ip_protocol=network_options.udp?17:*network_options.native_ip_protocol;
    const auto body=encode_pds(packet);
    const size_t ip_size=network_options.ipv6?40:20, transport=network_options.udp?8:4;
    const size_t ip_length=ip_size+transport+body.size()+(network_options.crc?4:0);
    if (ip_length>65535) throw std::length_error("packet exceeds supported MTU");
    Bytes encoded_bytes; encoded_bytes.insert(encoded_bytes.end(),network_options.destination.mac.begin(),network_options.destination.mac.end());
    encoded_bytes.insert(encoded_bytes.end(),network_options.source.mac.begin(),network_options.source.mac.end()); put(encoded_bytes,network_options.ipv6?0x86dd:0x0800,2);
    const size_t ip_begin=encoded_bytes.size();
    if (network_options.ipv6) {
        put(encoded_bytes,(6u<<28)|((uint32_t{network_options.dscp}<<2|network_options.ecn)<<20),4);
        put(encoded_bytes,ip_length-40,2); put(encoded_bytes,ip_protocol,1); put(encoded_bytes,network_options.hop_limit,1);
        encoded_bytes.insert(encoded_bytes.end(),network_options.source.ip.begin(),network_options.source.ip.end()); encoded_bytes.insert(encoded_bytes.end(),network_options.destination.ip.begin(),network_options.destination.ip.end());
    } else {
        put(encoded_bytes,0x45,1); put(encoded_bytes,(network_options.dscp<<2)|network_options.ecn,1); put(encoded_bytes,ip_length,2);
        put(encoded_bytes,0,2); put(encoded_bytes,0x4000,2); put(encoded_bytes,network_options.hop_limit,1); put(encoded_bytes,ip_protocol,1); put(encoded_bytes,0,2);
        encoded_bytes.insert(encoded_bytes.end(),network_options.source.ip.begin(),network_options.source.ip.begin()+4);
        encoded_bytes.insert(encoded_bytes.end(),network_options.destination.ip.begin(),network_options.destination.ip.begin()+4);
        const auto checksum=ip_checksum(encoded_bytes.data()+ip_begin);
        encoded_bytes[ip_begin+10]=checksum>>8; encoded_bytes[ip_begin+11]=checksum&255;
    }
    if (network_options.udp) {
        put(encoded_bytes,network_options.entropy,2); put(encoded_bytes,network_options.udp_destination_port,2);
        put(encoded_bytes,ip_length-ip_size,2); put(encoded_bytes,0,2);
    } else { put(encoded_bytes,network_options.entropy,2); put(encoded_bytes,0,2); }
    encoded_bytes.insert(encoded_bytes.end(),body.begin(),body.end());
    if (network_options.crc) {
        const auto start=ip_begin+(network_options.ipv6?8:12);
        const auto crc=crc32c(encoded_bytes.data()+start,encoded_bytes.size()-start);
        put(encoded_bytes,crc,4); // §3.5.26: CRC trailer uses network byte order.
    }
    return encoded_bytes;
}

DecodedPacket UetWireCodec::decode(const uint8_t* bytes, size_t size, bool crc_enabled,std::optional<uint8_t> native_ip_protocol,
                                  std::optional<TrimmingOptions> trimming,uint16_t udp_destination_port,
                                  std::optional<bool> udp_encapsulation) {
    if (!bytes || size<34) throw std::invalid_argument("truncated Ethernet/IP frame");
    DecodedPacket result;
    auto& network_options=result.network; network_options.crc=crc_enabled; network_options.native_ip_protocol=native_ip_protocol;
    network_options.udp_destination_port=udp_destination_port;
    std::copy_n(bytes,6,network_options.destination.mac.begin()); std::copy_n(bytes+6,6,network_options.source.mac.begin());
    const auto ether=get(bytes+12,2);
    if (ether!=0x0800 && ether!=0x86dd) throw std::invalid_argument("unsupported EtherType");
    network_options.ipv6=ether==0x86dd;
    const size_t ip_begin=14, ip_size=network_options.ipv6?40:20;
    if (size<ip_begin+ip_size) throw std::invalid_argument("truncated IP header");
    const auto* ip=bytes+ip_begin;
    size_t end; uint8_t protocol;
    if (network_options.ipv6) {
        if ((ip[0]>>4)!=6) throw std::invalid_argument("invalid IPv6 version");
        end=ip_begin+40+get(ip+4,2); protocol=ip[6]; network_options.hop_limit=ip[7];
        const auto traffic=static_cast<uint8_t>(get(ip,2)>>4); network_options.dscp=traffic>>2; network_options.ecn=traffic&3;
        std::copy_n(ip+8,16,network_options.source.ip.begin()); std::copy_n(ip+24,16,network_options.destination.ip.begin());
    } else {
        if (ip[0]!=0x45 || ip_checksum(ip)!=0 || (get(ip+6,2)&0xbfff)) throw std::invalid_argument("invalid or unsupported IPv4 header");
        end=ip_begin+get(ip+2,2); protocol=ip[9]; network_options.hop_limit=ip[8]; network_options.dscp=ip[1]>>2; network_options.ecn=ip[1]&3;
        std::copy_n(ip+12,4,network_options.source.ip.begin()); std::copy_n(ip+16,4,network_options.destination.ip.begin());
    }
    // A runtime knows its fabric's encapsulation. Keep that setting separate
    // from the configurable protocol byte, including native protocol 17.
    // Diagnostic callers may omit the mode and recognize ordinary UDP first.
    network_options.udp=udp_encapsulation.value_or(protocol==17);
    if (network_options.udp?(protocol!=17):(!native_ip_protocol || protocol!=*native_ip_protocol))
        throw std::invalid_argument("unsupported IP protocol or encapsulation");
    const size_t transport=network_options.udp?8:4, start=ip_begin+ip_size;
    if (trimming) trimming->validate();
    const bool trimmed=trimming && trimming->is_trimmed(network_options.dscp);
    if (trimmed) {
        // §3.5.15.1: neither the IP nor UDP length is verified for a trimmed
        // packet. Bounds below use captured bytes, never the untrusted lengths.
        // Its CRC may have been removed. No semantic header/payload is decoded.
        if (!network_options.hop_limit || size<start+transport+2)
            throw std::invalid_argument("truncated trimmed packet");
        network_options.entropy=get(bytes+start,2);
        if (network_options.udp && get(bytes+start+2,2)!=udp_destination_port)
            throw std::invalid_argument("unsupported trimmed UDP destination");
        auto& packet=result.packet;
        packet.trimmed=true;
        packet.trimmed_last_hop=trimming->last_hop_dscp && network_options.dscp==*trimming->last_hop_dscp;
        const auto* pds=bytes+start+transport;
        const auto type=get(pds,2)>>11;
        if (!type || type>=16) throw PdsDecodeError(PdsDecodeError::Reason::UnknownType,type);
        if (type==2 || type==3) {
            if (size<start+transport+12) throw std::invalid_argument("incomplete trimmed PDS request");
            packet.PDS_type=RUOD_req_header;
            auto& header=packet.PDS_header.RUOD_req_header;
            header.type=type==2?RUD_REQ:ROD_REQ; header.next_hdr=UET_HDR_NONE;
            const auto flags=get(pds,2)&0x7f;
            header.flags.syn=(flags>>2)&1; header.flags.retx=(flags>>4)&1; header.flags.ar=(flags>>3)&1;
            header.clear_psn_off=static_cast<int16_t>(get(pds+2,2)); header.psn=get(pds+4,4); header.spdcid=get(pds+8,2);
            const auto destination=get(pds+10,2);
            if (header.flags.syn) { header.pdc_info=(destination>>12)&1; header.psn_off=destination&0xfff; }
            else header.dpdcid=destination;
        } else if (type==4 || type==5) {
            if (size<start+transport+8) throw std::invalid_argument("incomplete trimmed RUDI header");
            packet.PDS_type=RUDI_header;
            auto& header=packet.PDS_header.RUDI_header;
            header.type=type==4?RUDI_REQ:RUDI_RESP; header.next_hdr=UET_HDR_NONE;
            header.flags.retx=(get(pds,2)>>4)&1; header.flags.m=type==5?((get(pds,2)>>5)&1):0;
            header.pkt_id=get(pds+4,4);
        } else if (type==7 || type==8 || type==9) packet.PDS_type=RUOD_ack_header;
        else if (type==11) packet.PDS_type=RUOD_cp_header;
        else if (type==10 || type==12) packet.PDS_type=nack_header;
        else if (type==6) packet.PDS_type=UUD_req_header;
        else throw std::invalid_argument("unsupported trimmed PDS type");
        return result;
    }
    if (!network_options.hop_limit || end>size || end<start+transport+2+(crc_enabled?4:0))
        throw std::invalid_argument("invalid IP length or hop limit");
    network_options.entropy=get(bytes+start,2);
    if (network_options.udp) {
        if (get(bytes+start+2,2)!=udp_destination_port || get(bytes+start+4,2)!=end-start)
            throw std::invalid_argument("unsupported or invalid UET UDP header");
    } // Native entropy's final 16 bits are reserved and ignored (§3.5.10.1).
    if (crc_enabled) {
        const auto crc_start=ip_begin+(network_options.ipv6?8:12);
        uint32_t crc;
        if (network_options.udp) {
            // §3.5.10: ignore UDP checksum on receive. §3.5.26 requires
            // treating it as zero when verifying the UET CRC as well.
            Bytes protected_bytes(bytes+crc_start,bytes+end-4);
            protected_bytes[start+6-crc_start]=0;
            protected_bytes[start+7-crc_start]=0;
            crc=crc32c(protected_bytes.data(),protected_bytes.size());
        } else crc=crc32c(bytes+crc_start,end-crc_start-4);
        const uint32_t actual=static_cast<uint32_t>(get(bytes+end-4,4));
        if (crc!=actual) throw std::invalid_argument("UET CRC mismatch");
    }
    result.packet=decode_pds(bytes+start+transport,end-start-transport-(crc_enabled?4:0));
    result.nominal_packet_size=static_cast<uint32_t>(end-start+40);
    return result;
}

bool UetWireCodec::mark_ecn(std::vector<uint8_t>& frame) {
    if (frame.size()<34) throw std::invalid_argument("truncated ECN frame");
    const auto ether=get(frame.data()+12,2);
    if (ether==0x0800) {
        if (frame[14]!=0x45 || ip_checksum(frame.data()+14)!=0) throw std::invalid_argument("invalid ECN IPv4 header");
        const auto original=frame[15]&3;
        if (!original || original==3) return false;
        frame[15]|=3; frame[24]=frame[25]=0;
        const auto checksum=ip_checksum(frame.data()+14);
        frame[24]=checksum>>8; frame[25]=checksum&255;
    } else if (ether==0x86dd) {
        if (frame.size()<54) throw std::invalid_argument("truncated IPv6 ECN frame");
        if ((frame[14]>>4)!=6) throw std::invalid_argument("invalid ECN IPv6 header");
        const auto original=(frame[15]>>4)&3;
        if (!original || original==3) return false;
        frame[15]|=0x30;
    } else throw std::invalid_argument("unsupported ECN EtherType");
    return true;
}

bool UetWireCodec::trim_packet(std::vector<uint8_t>& frame,const TrimmingOptions& options,bool last_hop) {
    options.validate();
    if (frame.size()<34) throw std::invalid_argument("truncated trimming frame");
    const auto ether=get(frame.data()+12,2);
    const bool ipv6=ether==0x86dd;
    if (ether!=0x0800 && !ipv6) throw std::invalid_argument("trimming requires IP");
    const size_t ip_begin=14,ip_size=ipv6?40:20;
    if (frame.size()<ip_begin+ip_size) throw std::invalid_argument("truncated trimming IP header");
    auto* ip=frame.data()+ip_begin;
    uint8_t traffic;
    size_t ip_length;
    if (ipv6) {
        if ((ip[0]>>4)!=6) throw std::invalid_argument("invalid trimming IPv6 header");
        traffic=static_cast<uint8_t>(get(ip,2)>>4); ip_length=40+get(ip+4,2);
    } else {
        if (ip[0]!=0x45 || ip_checksum(ip)!=0 || (get(ip+6,2)&0xbfff))
            throw std::invalid_argument("invalid trimming IPv4 header");
        traffic=ip[1]; ip_length=get(ip+2,2);
    }
    if (ip_length<ip_size || ip_length>frame.size()-ip_begin)
        throw std::invalid_argument("invalid trimming IP length");
    if ((traffic>>2)!=options.trimmable_dscp) return false;
    const size_t retained=std::min(options.minimum_ip_payload,ip_length-ip_size);
    const auto codepoint=last_hop && options.last_hop_dscp?*options.last_hop_dscp:options.trimmed_dscp;
    traffic=static_cast<uint8_t>((codepoint<<2)|(traffic&3));
    if (ipv6) {
        ip[0]=static_cast<uint8_t>((ip[0]&0xf0)|(traffic>>4)); ip[1]=static_cast<uint8_t>((traffic<<4)|(ip[1]&0xf));
        ip[4]=static_cast<uint8_t>(retained>>8); ip[5]=static_cast<uint8_t>(retained);
    } else {
        ip[1]=traffic; const auto total=ip_size+retained;
        ip[2]=static_cast<uint8_t>(total>>8); ip[3]=static_cast<uint8_t>(total);
        ip[10]=ip[11]=0; const auto checksum=ip_checksum(ip);
        ip[10]=static_cast<uint8_t>(checksum>>8); ip[11]=static_cast<uint8_t>(checksum);
    }
    // §4.1: UDP length/checksum, entropy and PDS/SES bytes are untouched.
    // Ethernet FCS is abstracted by IPacketPort and absent from stored frames.
    // Release the discarded payload allocation as well as its logical length:
    // many tiny trim notifications must not retain MTU-sized vector buffers.
    Bytes retained_frame(frame.begin(),frame.begin()+ip_begin+ip_size+retained);
    frame.swap(retained_frame);
    return true;
}
std::optional<uint8_t> UetWireCodec::packet_dscp(const std::vector<uint8_t>& frame) {
    if (frame.size()<34) return {};
    const auto ether=get(frame.data()+12,2);
    if (ether==0x0800 && frame[14]==0x45 && ip_checksum(frame.data()+14)==0) return frame[15]>>2;
    if (ether==0x86dd && frame.size()>=54 && (frame[14]>>4)==6) {
        const auto traffic=static_cast<uint8_t>(get(frame.data()+14,2)>>4);
        return traffic>>2;
    }
    return {};
}
} // namespace UET::NetworkLayer

namespace UET::NetworkLayer {
bool UetWireCodec::stamp_service_time(std::vector<uint8_t>& frame,uint64_t departure_ns,uint64_t arrival_ns,
                                     bool crc_enabled,std::optional<uint8_t> native_ip_protocol,uint16_t udp_destination_port,
                                     std::optional<bool> udp_encapsulation) {
    if (departure_ns<arrival_ns) return false;
    DecodedPacket decoded;
    try { decoded=decode(frame.data(),frame.size(),crc_enabled,native_ip_protocol,{},udp_destination_port,udp_encapsulation); }
    catch (const std::invalid_argument&) { return false; }
    if (decoded.packet.PDS_type!=RUOD_ack_header || decoded.packet.PDS_header.RUOD_ack_header.type!=ACK_CC ||
        decoded.packet.congestion_ack.type!=0) return false;
    const size_t ip_start=14,ip_size=decoded.network.ipv6?40:20;
    const size_t transport_start=ip_start+ip_size;
    const size_t pds_start=transport_start+(decoded.network.udp?8:4);
    const uint64_t elapsed=departure_ns-arrival_ns;
    // Zero is reserved for an invalid measurement. A known sub-quantum delay
    // uses one 128 ns quantum; source-side near-zero RTT policy remains explicit.
    const uint64_t quanta=std::max<uint64_t>(1,elapsed/128+(elapsed%128!=0));
    const uint16_t encoded=static_cast<uint16_t>(std::min<uint64_t>(0xffff,quanta));
    frame[pds_start+24]=static_cast<uint8_t>(encoded>>8);
    frame[pds_start+25]=static_cast<uint8_t>(encoded);
    if (crc_enabled) {
        const size_t wire_end=decoded.network.ipv6?ip_start+40+get(frame.data()+ip_start+4,2):
            ip_start+get(frame.data()+ip_start+2,2);
        const size_t crc_start=ip_start+(decoded.network.ipv6?8:12);
        Bytes protected_bytes(frame.begin()+crc_start,frame.begin()+wire_end-4);
        if (decoded.network.udp) {
            protected_bytes[transport_start+6-crc_start]=0;
            protected_bytes[transport_start+7-crc_start]=0;
        }
        const auto crc=crc32c(protected_bytes.data(),protected_bytes.size());
        for (size_t byte=0;byte<4;++byte) frame[wire_end-4+byte]=static_cast<uint8_t>(crc>>(24-8*byte));
    }
    return true;
}
}
