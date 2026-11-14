#pragma once
#include <cstdint>
#include <cstddef>
#include <stdexcept>
#include <algorithm>
#include <vector>

namespace UET::SES {

// UE 1.1 Tables 3-27 and 3-28. These values are explicit wire encodings;
// they must not depend on an implementation's internal enum ordering.
enum class IntegerAtomicOperation : uint8_t {
    Minimum=0x00, Maximum=0x01, Sum=0x02, Difference=0x03, Product=0x04,
    LogicalOr=0x05, LogicalAnd=0x06, BitwiseOr=0x07, BitwiseAnd=0x08,
    LogicalXor=0x09, BitwiseXor=0x0a, Read=0x0b, Write=0x0c,
    CompareSwapEqual=0x0d, CompareSwapNotEqual=0x0e, CompareSwapLessEqual=0x0f,
    CompareSwapLess=0x10, CompareSwapGreaterEqual=0x11, CompareSwapGreater=0x12,
    MaskedSwap=0x13
};
enum class IntegerAtomicDatatype : uint8_t {
    Int8=0x00, Uint8=0x01, Int16=0x02, Uint16=0x03,
    Int32=0x04, Uint32=0x05, Int64=0x06, Uint64=0x07, Int128=0x08, Uint128=0x09
};

inline std::size_t integer_atomic_width(IntegerAtomicDatatype datatype) {
    const auto encoding=static_cast<uint8_t>(datatype);
    if (encoding>9) throw std::invalid_argument("unsupported integer atomic datatype");
    return std::size_t{1}<<(encoding/2);
}

// The native memory model represents integers in little-endian bytes. Atomic
// operand fields use network order on the standard wire (§3.4.3.5/§3.5.25).
// This element-wise involution is used at both SES wire boundaries; ordinary
// SEND/WRITE payloads remain opaque. Independent reference interop checks it.
inline void convert_integer_atomic_byte_order(std::vector<uint8_t>& operands,IntegerAtomicDatatype datatype) {
    const auto width=integer_atomic_width(datatype);
    if (operands.size()%width) throw std::invalid_argument("incomplete atomic element");
    for (size_t offset=0;offset<operands.size();offset+=width)
        std::reverse(operands.begin()+offset,operands.begin()+offset+width);
}

inline uint64_t integer_atomic_result(uint64_t target,uint64_t operand,
                                      IntegerAtomicOperation operation,IntegerAtomicDatatype datatype) {
    const auto width=integer_atomic_width(datatype);
    if (width>8) throw std::invalid_argument("scalar uint64 helper cannot represent a 128-bit element");
    const auto mask=width==8?UINT64_MAX:(uint64_t{1}<<(8*width))-1;
    target&=mask; operand&=mask;
    const bool signed_datatype=(static_cast<uint8_t>(datatype)&1u)==0;
    const auto sign_bit=signed_datatype?uint64_t{1}<<(8*width-1):0;
    // Flipping the sign bit orders two's-complement integers without signed
    // overflow or implementation-defined conversions from uint64_t.
    const bool target_is_smaller=(target^sign_bit)<(operand^sign_bit);
    uint64_t result;
    switch (operation) {
    case IntegerAtomicOperation::Minimum: result=target_is_smaller?target:operand; break;
    case IntegerAtomicOperation::Maximum: result=target_is_smaller?operand:target; break;
    case IntegerAtomicOperation::Sum: result=target+operand; break;
    case IntegerAtomicOperation::Difference: result=target-operand; break;
    case IntegerAtomicOperation::Product: result=target*operand; break;
    case IntegerAtomicOperation::LogicalOr: result=bool(target)||bool(operand); break;
    case IntegerAtomicOperation::LogicalAnd: result=bool(target)&&bool(operand); break;
    case IntegerAtomicOperation::BitwiseOr: result=target|operand; break;
    case IntegerAtomicOperation::BitwiseAnd: result=target&operand; break;
    case IntegerAtomicOperation::LogicalXor: result=bool(target)!=bool(operand); break;
    case IntegerAtomicOperation::BitwiseXor: result=target^operand; break;
    case IntegerAtomicOperation::Read: result=target; break;
    case IntegerAtomicOperation::Write: result=operand; break;
    default: throw std::invalid_argument("unsupported integer atomic operation");
    }
    return result&mask;
}
} // namespace UET::SES
