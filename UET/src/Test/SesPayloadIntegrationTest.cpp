#include "../SES/SES.hpp"

#include <chrono>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <vector>

int main() {
    SESManager manager;
    OperationMetadata metadata;
    metadata.op_type = SEND;
    metadata.s_pid_on_fep = 1001;
    metadata.t_pid_on_fep = 2001;
    metadata.job_id = 12345;
    metadata.messages_id = 1;
    metadata.memory.rkey = 0x1234567890abcdefull;
    metadata.payload.data.resize(5000);
    for (size_t i = 0; i < metadata.payload.data.size(); ++i)
        metadata.payload.data[i] = static_cast<uint8_t>((i * 29u + 7u) & 0xffu);
    metadata.payload.length = metadata.payload.data.size();
    metadata.payload.start_addr = 0x1000;
    manager.process_send_packet(metadata);

    std::vector<uint8_t> received;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (std::chrono::steady_clock::now() < deadline) {
        PDStoNET_pkt packet{};
        if (manager.pds_process_manager.popNetworkPacket(packet)) {
            received.insert(received.end(), packet.SESpkt.payload.begin(),
                            packet.SESpkt.payload.end());
            if (packet.SESpkt.bth_header.Standard_Header.eom) break;
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
    }
    if (received != metadata.payload.data)
        throw std::runtime_error("SES/PDS payload bytes did not reach PDStoNET");
    std::cout << "PASS: SES owned payload reached PDStoNET with "
              << received.size() << " bytes" << std::endl;
}
