#pragma once
#include "IntegerAtomics.hpp"
#include <array>

namespace UET::SES {

inline bool dual_operand_atomic(IntegerAtomicOperation operation) {
    const auto encoding=static_cast<uint8_t>(operation);
    return encoding>=0x0d && encoding<=0x13;
}

// Compare little-endian two's-complement elements without host integer casts.
// This covers 128-bit elements on every C++17 host, including alignment and
// endian combinations which cannot safely reinterpret an application pointer.
inline int compare_atomic_elements(const std::vector<uint8_t>& left,const std::vector<uint8_t>& right,bool signed_datatype) {
    if (left.empty() || left.size()!=right.size()) throw std::invalid_argument("atomic compare element sizes differ");
    const bool left_negative=signed_datatype && (left.back()&0x80);
    const bool right_negative=signed_datatype && (right.back()&0x80);
    if (left_negative!=right_negative) return left_negative?-1:1;
    for (size_t remaining=left.size();remaining;--remaining)
        if (left[remaining-1]!=right[remaining-1]) return left[remaining-1]<right[remaining-1]?-1:1;
    return 0;
}

// UE1.1 §3.4.3.5 / Tables3-27,3-28: one fetching element, up to16B.
// Arithmetic wraps at the element width. This byte-wise implementation is a
// behavioral model; atomicity comes from executing one indivisible runtime
// event, rather than from a hardware atomic instruction or a process mutex.
inline std::vector<uint8_t> fetching_atomic_update(const std::vector<uint8_t>& previous,
        const std::vector<uint8_t>& operand,const std::vector<uint8_t>& compare_or_mask,
        IntegerAtomicOperation operation,IntegerAtomicDatatype datatype) {
    const auto width=integer_atomic_width(datatype);
    if (previous.size()!=width || operand.size()!=width ||
        (dual_operand_atomic(operation)?compare_or_mask.size()!=width:!compare_or_mask.empty()))
        throw std::invalid_argument("fetching atomic requires exactly one complete element");
    const bool signed_datatype=(static_cast<uint8_t>(datatype)&1u)==0;
    const auto ordering=compare_atomic_elements(previous,operand,signed_datatype);
    std::vector<uint8_t> result(width,0);
    switch (operation) {
    case IntegerAtomicOperation::Minimum: return ordering<0?previous:operand;
    case IntegerAtomicOperation::Maximum: return ordering>0?previous:operand;
    case IntegerAtomicOperation::Sum: {
        unsigned carry=0;
        for (size_t byte=0;byte<width;++byte) {
            const unsigned sum=unsigned(previous[byte])+operand[byte]+carry;
            result[byte]=static_cast<uint8_t>(sum); carry=sum>>8;
        }
        break;
    }
    case IntegerAtomicOperation::Difference: {
        unsigned borrow=0;
        for (size_t byte=0;byte<width;++byte) {
            const unsigned subtrahend=unsigned(operand[byte])+borrow;
            borrow=previous[byte]<subtrahend;
            result[byte]=static_cast<uint8_t>(unsigned(previous[byte])-subtrahend);
        }
        break;
    }
    case IntegerAtomicOperation::Product:
        for (size_t left_byte=0;left_byte<width;++left_byte) {
            unsigned carry=0;
            for (size_t right_byte=0;right_byte+left_byte<width;++right_byte) {
                const auto position=left_byte+right_byte;
                const unsigned product=unsigned(previous[left_byte])*operand[right_byte]+result[position]+carry;
                result[position]=static_cast<uint8_t>(product); carry=product>>8;
            }
        }
        break;
    case IntegerAtomicOperation::LogicalOr:
    case IntegerAtomicOperation::LogicalAnd:
    case IntegerAtomicOperation::LogicalXor: {
        const bool target_nonzero=std::any_of(previous.begin(),previous.end(),[](auto byte) { return byte!=0; });
        const bool operand_nonzero=std::any_of(operand.begin(),operand.end(),[](auto byte) { return byte!=0; });
        result[0]=operation==IntegerAtomicOperation::LogicalOr?target_nonzero||operand_nonzero:
            operation==IntegerAtomicOperation::LogicalAnd?target_nonzero&&operand_nonzero:target_nonzero!=operand_nonzero;
        break;
    }
    case IntegerAtomicOperation::BitwiseOr:
    case IntegerAtomicOperation::BitwiseAnd:
    case IntegerAtomicOperation::BitwiseXor:
        for (size_t byte=0;byte<width;++byte)
            result[byte]=operation==IntegerAtomicOperation::BitwiseOr?previous[byte]|operand[byte]:
                operation==IntegerAtomicOperation::BitwiseAnd?previous[byte]&operand[byte]:previous[byte]^operand[byte];
        break;
    case IntegerAtomicOperation::Read: return previous;
    case IntegerAtomicOperation::Write: return operand;
    case IntegerAtomicOperation::CompareSwapEqual:
    case IntegerAtomicOperation::CompareSwapNotEqual:
    case IntegerAtomicOperation::CompareSwapLessEqual:
    case IntegerAtomicOperation::CompareSwapLess:
    case IntegerAtomicOperation::CompareSwapGreaterEqual:
    case IntegerAtomicOperation::CompareSwapGreater: {
        // The compare operand is the left-hand side (fi_atomic(3), the API
        // operation family underlying Table3-27): compare < target for LT.
        const auto comparison=compare_atomic_elements(compare_or_mask,previous,signed_datatype);
        const bool replace=operation==IntegerAtomicOperation::CompareSwapEqual?comparison==0:
            operation==IntegerAtomicOperation::CompareSwapNotEqual?comparison!=0:
            operation==IntegerAtomicOperation::CompareSwapLessEqual?comparison<=0:
            operation==IntegerAtomicOperation::CompareSwapLess?comparison<0:
            operation==IntegerAtomicOperation::CompareSwapGreaterEqual?comparison>=0:comparison>0;
        return replace?operand:previous;
    }
    case IntegerAtomicOperation::MaskedSwap:
        // Table3-27 defines Target=(Target & Mask) ^ Initiator. The UE mask
        // is therefore not the same mask convention as libfabric FI_MSWAP.
        for (size_t byte=0;byte<width;++byte) result[byte]=(previous[byte]&compare_or_mask[byte])^operand[byte];
        break;
    default: throw std::invalid_argument("unsupported fetching atomic operation");
    }
    return result;
}

// Figure3-23 always carries two16B fields for dual-operand operations, even
// when the datatype is smaller. Values occupy the low-order bytes of each
// network-order field; unused high bytes are emitted as zero.
inline std::vector<uint8_t> fetching_atomic_wire_operands(const std::vector<uint8_t>& operand,
        const std::vector<uint8_t>& compare_or_mask,IntegerAtomicOperation operation,IntegerAtomicDatatype datatype) {
    const auto width=integer_atomic_width(datatype);
    if (operand.size()!=width || (dual_operand_atomic(operation)?compare_or_mask.size()!=width:!compare_or_mask.empty()))
        throw std::invalid_argument("fetching atomic operand size mismatch");
    if (!dual_operand_atomic(operation)) {
        auto encoded=operand; convert_integer_atomic_byte_order(encoded,datatype); return encoded;
    }
    std::vector<uint8_t> encoded(32,0);
    for (size_t byte=0;byte<width;++byte) {
        encoded[15-byte]=compare_or_mask[byte]; encoded[31-byte]=operand[byte];
    }
    return encoded;
}

struct FetchingAtomicOperands { std::vector<uint8_t> operand,compare_or_mask; };
inline FetchingAtomicOperands decode_fetching_atomic_operands(const std::vector<uint8_t>& wire_payload,
        IntegerAtomicOperation operation,IntegerAtomicDatatype datatype) {
    const auto width=integer_atomic_width(datatype);
    if (wire_payload.size()!=(dual_operand_atomic(operation)?32:width))
        throw std::invalid_argument("fetching atomic wire payload size mismatch");
    FetchingAtomicOperands decoded;
    if (!dual_operand_atomic(operation)) {
        decoded.operand=wire_payload; convert_integer_atomic_byte_order(decoded.operand,datatype); return decoded;
    }
    decoded.operand.resize(width); decoded.compare_or_mask.resize(width);
    for (size_t byte=0;byte<width;++byte) {
        decoded.compare_or_mask[byte]=wire_payload[15-byte]; decoded.operand[byte]=wire_payload[31-byte];
    }
    return decoded;
}
} // namespace UET::SES
