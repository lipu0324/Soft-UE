#pragma once
#include <cstdint>

namespace UET::SES {
// UE 1.1 Table 3-25, used by the standard native endpoint. The older
// RSP_RETURN_CODE enum belongs to the legacy SES path and has other values.
enum class SemanticReturnCode : uint8_t {
    Ok=0x01, BadGeneration=0x02, NoMatch=0x05, UnsupportedOperation=0x06,
    UnsupportedSize=0x07, AtomicUnsupportedOperation=0x0f,
    AtomicUnsupportedDatatype=0x10, AtomicUnsupportedSize=0x11, AtomicUnaligned=0x12,
    PermissionViolation=0x17, OperationViolation=0x18, BadIndex=0x19,
    BadPid=0x1a, BadJob=0x1b, BadMemoryKey=0x1c, BadAddress=0x1d,
    Cancelled=0x1e, Undeliverable=0x1f, Uncorrectable=0x20
};
} // namespace UET::SES
