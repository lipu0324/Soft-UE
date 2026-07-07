#include "LibfabricTestCommon.hpp"

#include <cstring>
#include <iostream>
#include <vector>

namespace {

using namespace UET::Test::Libfabric;

bool require(bool condition, const char* message)
{
    if (!condition) {
        std::cerr << "[LibfabricHarnessGuardTest] " << message << std::endl;
        return false;
    }
    return true;
}

bool test_ctrl_roundtrip()
{
    HelloMsg hello{};
    hello.client_id = 7;
    const auto msg = build_ctrl_msg(CTRL_HELLO, 0x1234ULL, 99, 3, &hello, sizeof(hello));

    CtrlHdr hdr{};
    const uint8_t* payload = nullptr;
    size_t payload_len = 0;
    if (!require(parse_ctrl_msg(msg.data(), msg.size(), hdr, payload, payload_len),
                 "parse_ctrl_msg should succeed")) return false;
    if (!require(hdr.msg_type == CTRL_HELLO, "ctrl type should round-trip")) return false;
    if (!require(hdr.session_id == 0x1234ULL, "session id should round-trip")) return false;
    HelloMsg parsed{};
    if (!require(decode_payload_copy(payload, payload_len, parsed),
                 "decode_payload_copy should succeed")) return false;
    return require(parsed.client_id == hello.client_id, "hello payload should round-trip");
}

bool test_mrdesc_roundtrip()
{
    MRDesc desc{};
    desc.magic = kMRDescMagic;
    desc.version = kMRDescVersion;
    desc.job_id = 11;
    desc.pid_on_fep = 22;
    desc.resource_index = 33;
    desc.rkey = 44;
    desc.remote_addr = 55;
    desc.len = 66;
    desc.access = 77;
    desc.reg_epoch = 88;

    const auto msg = build_ctrl_msg(CTRL_MRDESC, 0x55ULL, desc.job_id, desc.resource_index, &desc, sizeof(desc));
    CtrlHdr hdr{};
    const uint8_t* payload = nullptr;
    size_t payload_len = 0;
    if (!require(parse_ctrl_msg(msg.data(), msg.size(), hdr, payload, payload_len),
                 "parse_ctrl_msg(mrdesc) should succeed")) return false;
    MRDesc parsed{};
    if (!require(decode_payload_copy(payload, payload_len, parsed),
                 "decode_payload_copy(mrdesc) should succeed")) return false;
    return require(std::memcmp(&desc, &parsed, sizeof(desc)) == 0, "mrdesc payload should round-trip");
}

bool test_range_helpers()
{
    std::vector<uint8_t> buf(64, 0);
    fill_pattern(buf, 0x5A);
    if (!require(verify_pattern(buf, 0x5A), "verify_pattern should succeed")) return false;
    buf[17] = 0;
    if (!require(!verify_range_pattern(buf, 0, buf.size(), 0x5A),
                 "verify_range_pattern should detect mismatch")) return false;
    buf[17] = 0x5A;
    return require(wait_range_ok(buf, 0, buf.size(), 0x5A, 1),
                   "wait_range_ok should succeed for matched buffer");
}

} // namespace

int main()
{
    const bool ok = test_ctrl_roundtrip()
                 && test_mrdesc_roundtrip()
                 && test_range_helpers();
    std::cout << (ok ? "LibfabricHarnessGuardTest PASS" : "LibfabricHarnessGuardTest FAIL") << std::endl;
    return ok ? 0 : 1;
}
