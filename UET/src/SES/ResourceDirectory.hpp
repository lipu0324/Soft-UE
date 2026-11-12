#pragma once
#include "SemanticReturnCode.hpp"
#include <cstdint>
#include <map>
#include <stdexcept>
#include <tuple>

namespace UET::SES {
enum class ResourceSpace : uint8_t { Send, Tagged, Rma };
struct ResourceSelection { uint16_t absolute_pid,resource_index; uint8_t generation; };
class AddressingError : public std::runtime_error {
public:
    AddressingError(SemanticReturnCode code,uint8_t generation=0)
        : std::runtime_error("resource address rejected"),code(code),generation(generation) {}
    SemanticReturnCode code;
    uint8_t generation;
};

// §3.4.2.3: relative addressing selects {JobID, relative PID}; absolute
// addressing selects a node-wide PID. Neither mode is a process pointer.
// SEND, tagged and RMA index spaces are deliberately independent.
class ResourceDirectory {
public:
    ResourceDirectory() {
        configure_resource(1,1,ResourceSpace::Send);
        configure_resource(1,1,ResourceSpace::Rma);
    }
    void configure_resource(uint16_t absolute_pid,uint16_t resource_index,ResourceSpace space,
                            uint8_t generation=0,bool enabled=true) {
        if (absolute_pid>0xfff || resource_index>0xfff) throw std::invalid_argument("resource address exceeds 12 bits");
        resources_[{absolute_pid,resource_index,space}]={generation,enabled};
    }
    void map_relative_pid(uint32_t job,uint16_t relative_pid,uint16_t absolute_pid) {
        if (job>0xffffff || relative_pid>0xfff || absolute_pid>0xfff)
            throw std::invalid_argument("relative resource address exceeds wire width");
        relative_pids_[{job,relative_pid}]=absolute_pid;
    }
    uint8_t disable_for_exhaustion(uint16_t pid,uint16_t index,ResourceSpace space) {
        auto& resource=resources_.at({pid,index,space});
        resource.enabled=false; resource.generation_recovery=true;
        return resource.generation;
    }
    bool recover_after_exhaustion(uint16_t pid,uint16_t index,ResourceSpace space,uint8_t generation) {
        const auto found=resources_.find({pid,index,space});
        if (found==resources_.end() || found->second.enabled || !found->second.generation_recovery ||
            found->second.generation!=generation) return false;
        // §3.4.4.7.3.2: software supplies resources, increments the eight-bit
        // generation and only then enables the index. An explicit management
        // reconfiguration cancels this automatic recovery policy.
        ++found->second.generation; found->second.enabled=true; found->second.generation_recovery=false;
        return true;
    }
    ResourceSelection resolve(uint32_t job,bool relative,uint16_t wire_pid,uint16_t resource_index,
                              ResourceSpace space,uint8_t requested_generation) const {
        uint16_t absolute_pid=wire_pid;
        if (relative) {
            const auto mapping=relative_pids_.find({job,wire_pid});
            if (mapping!=relative_pids_.end()) absolute_pid=mapping->second;
            else if (wire_pid!=1) throw AddressingError(SemanticReturnCode::BadPid);
            // The default teaching endpoint provides relative PID 1 for each
            // registered job. Additional mappings are explicit management state.
        }
        bool process_exists=false;
        for (const auto& resource:resources_)
            if (std::get<0>(resource.first)==absolute_pid) { process_exists=true; break; }
        if (!process_exists) throw AddressingError(SemanticReturnCode::BadPid);
        const auto resource=resources_.find({absolute_pid,resource_index,space});
        if (resource==resources_.end()) throw AddressingError(SemanticReturnCode::BadIndex);
        if (!resource->second.enabled)
            throw AddressingError(!resource->second.generation_recovery && requested_generation==resource->second.generation?
                SemanticReturnCode::Disabled:SemanticReturnCode::DisabledGeneration,resource->second.generation);
        if (requested_generation!=resource->second.generation)
            throw AddressingError(SemanticReturnCode::BadGeneration,resource->second.generation);
        return {absolute_pid,resource_index,resource->second.generation};
    }
private:
    struct Resource { uint8_t generation; bool enabled; bool generation_recovery=false; };
    std::map<std::tuple<uint16_t,uint16_t,ResourceSpace>,Resource> resources_;
    std::map<std::pair<uint32_t,uint16_t>,uint16_t> relative_pids_;
};
} // namespace UET::SES
