#pragma once
#include "PdcEvents.hpp"
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <tuple>

namespace UET::Runtime {
// A closed SES leaves message identity and error facts with its Host. A later
// fragment must not acquire the replacement Endpoint's buffers or MR rights.
// These records contain no payload, registration or callback into the old SES.
class RetiredSemanticReceives {
public:
    // Peer, local PDC, Job, initiator rank, MID (or marked optimized PSN), epoch.
    using Key=std::tuple<uint32_t,uint16_t,uint32_t,uint32_t,uint64_t,uint32_t>;
    static constexpr uint64_t packet_identity=uint64_t{1}<<32;
    struct Message {
        uint32_t modified_length=0,end_psn=0;
        bool end_seen=false,error_response_generated=false;
        uint8_t return_code=0,generation=0,response_list=0;
    };
    struct Result {
        uint32_t modified_length;
        uint8_t return_code,generation,response_list;
        bool guaranteed;
    };
    void retain(const Key& key,Message message) { messages_.insert_or_assign(key,message); }
    bool contains(const Key& key) const { return messages_.count(key)!=0; }
    std::size_t size() const { return messages_.size(); }
    void clear() { messages_.clear(); } // Only after Host shutdown has stopped PDS.
    std::optional<Result> answer(const Key& key,uint32_t sequence,bool end_of_message) {
        const auto found=messages_.find(key);
        if (found==messages_.end()) return {};
        auto& message=found->second;
        if (end_of_message && (!message.end_seen || sequence-message.end_psn<0x80000000u)) {
            message.end_seen=true; message.end_psn=sequence;
        }
        const bool guaranteed=!message.error_response_generated;
        message.error_response_generated=true;
        return Result{message.modified_length,message.return_code,message.generation,message.response_list,guaranteed};
    }
    void observe(const PdcEvent& event) {
        if (event.kind!=PdcEventKind::ReceiveCleared && event.kind!=PdcEventKind::ConnectionClosed) return;
        for (auto message=messages_.begin();message!=messages_.end();) {
            const auto& key=message->first;
            const bool same_connection=std::get<0>(key)==event.peer && std::get<1>(key)==event.local_pdc &&
                std::get<5>(key)==event.connection_start_psn;
            // Clearing an acknowledged prefix cannot retire an unfinished
            // message. Keep rejecting continuations until EOM Clear or Close.
            const bool terminal=event.kind==PdcEventKind::ConnectionClosed ||
                (message->second.end_seen && event.sequence-message->second.end_psn<0x80000000u);
            if (same_connection && terminal) message=messages_.erase(message);
            else ++message;
        }
    }
private:
    std::map<Key,Message> messages_;
};
} // namespace UET::Runtime
