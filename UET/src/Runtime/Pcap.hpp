#pragma once
#include "PacketPort.hpp"
#include "Runtime.hpp"
#include <fstream>

namespace UET::Runtime {
class Pcap {
public:
    explicit Pcap(const std::string& path) : out_(path,std::ios::binary) {
        if (!out_) throw std::runtime_error("cannot open PCAP output");
        put(0xa1b23c4d,4); put(2,2); put(4,2); put(0,4); put(0,4); put(65535,4); put(1,4);
    }
    void write(Time now, const Frame& frame) {
        if (now/1000000000>UINT32_MAX || frame.bytes.size()>65535)
            throw std::overflow_error("PCAP record exceeds format limits");
        put(now/1000000000,4); put(now%1000000000,4);
        put(frame.bytes.size(),4); put(frame.bytes.size(),4);
        out_.write(reinterpret_cast<const char*>(frame.bytes.data()),frame.bytes.size());
        if (!out_) throw std::runtime_error("PCAP write failed");
    }
private:
    std::ofstream out_;
    void put(uint64_t value, size_t width) {
        for (size_t i=0; i<width; ++i) out_.put(static_cast<char>(value>>(8*i)));
    }
};
} // namespace UET::Runtime
