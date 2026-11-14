#pragma once
#include <cstddef>
#include <cstdint>
#include <deque>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <stdexcept>
#include <tuple>
#include <vector>

namespace UET::SES {

// §3.4.4.8: a wire group is not reusable until all its messages complete.
// The FEP-owned cursor survives Endpoint replacement; abandoned IDs cannot
// silently wrap onto a target that is still tracking the previous group.
class SynchronizationIdPool {
public:
    explicit SynchronizationIdPool(uint32_t& fep_cursor,size_t maximum_live=64)
        :fep_cursor_(fep_cursor),maximum_live_(maximum_live) {
        if (!maximum_live || maximum_live>65536) throw std::invalid_argument("invalid synchronized group limit");
    }
    std::optional<uint16_t> allocate() {
        if (live_.size()>=maximum_live_) return {};
        uint16_t selected;
        if (!reusable_.empty()) { selected=reusable_.front(); reusable_.pop_front(); }
        else {
            if (fep_cursor_>UINT16_MAX) return {};
            selected=static_cast<uint16_t>(fep_cursor_++);
        }
        if (!live_.insert(selected).second) throw std::logic_error("synchronized group identifier collision");
        return selected;
    }
    bool release(uint16_t group,bool all_confirmed) {
        if (!live_.erase(group)) return false;
        if (all_confirmed) reusable_.push_back(group);
        return true; // Unknown/error outcomes quarantine the wire ID.
    }
    size_t live() const { return live_.size(); }
private:
    uint32_t& fep_cursor_;
    size_t maximum_live_;
    std::set<uint16_t> live_;
    std::deque<uint16_t> reusable_;
};

// Metadata for the target's aggregate action. PDS still owns reliability and
// Incoming still owns per-message deduplication and registered-memory access.
// In particular, Table3-31 counts FAILED messages too: this is a processed
// count, never a successful-write count or a count of received packets.
class SynchronizationGroups {
public:
    enum class State { Collecting, Ready, Completed, Expired };
    enum class Admission { Accepted, NoState, NoMessageState, WrongJob, InvalidCount, DuplicateCompleter, ExcessMember };
    struct Key {
        uint32_t peer; uint16_t wire_group;
        bool operator<(const Key& other) const { return std::tie(peer,wire_group)<std::tie(other.peer,other.wire_group); }
    };
    struct Snapshot {
        uint64_t owner;
        Key key;
        uint32_t job,admitted_messages,processed_messages;
        std::optional<uint16_t> expected_messages;
        std::optional<uint64_t> completing_member;
        State state;
        uint64_t expires_at;
    };
    struct Reservation {
        Admission status;
        uint64_t owner=0,member=0;
        bool new_group=false;
    };
    explicit SynchronizationGroups(size_t maximum_groups=64,uint64_t age_ns=100000000,size_t maximum_members=4096)
        :maximum_groups_(maximum_groups),maximum_members_(maximum_members),age_ns_(age_ns) {
        if (!maximum_groups || !age_ns || !maximum_members) throw std::invalid_argument("invalid synchronization tracking policy");
    }
    Reservation reserve(Key key,uint32_t job,bool completing,uint16_t count,uint64_t now) {
        if (job>0xffffff || (completing?!count:count!=0)) return {Admission::InvalidCount};
        if (members_.size()>=maximum_members_) return {Admission::NoMessageState};
        auto found=active_.find(key);
        const bool created=found==active_.end();
        if (created) {
            if (active_.size()>=maximum_groups_ || next_owner_==UINT64_MAX || now>UINT64_MAX-age_ns_)
                return {Admission::NoState};
            auto group=std::make_shared<Group>();
            group->view={++next_owner_,key,job,0,0,{}, {},State::Collecting,now+age_ns_};
            found=active_.emplace(key,std::move(group)).first;
        }
        const auto group=found->second; auto& view=group->view;
        if (view.job!=job) return {Admission::WrongJob};
        if (completing && view.completing_member) return {Admission::DuplicateCompleter};
        if (view.state!=State::Collecting || (view.expected_messages && view.admitted_messages>=*view.expected_messages) ||
            (!completing && !view.expected_messages && view.admitted_messages>=65534)) return {Admission::ExcessMember};
        const bool invalid_completer=completing && view.admitted_messages+1>count;
        if (next_member_==UINT64_MAX) {
            if (created) active_.erase(found);
            return {Admission::NoState};
        }
        const auto member=++next_member_;
        members_.emplace(member,Member{group,false,completing}); ++view.admitted_messages; ++group->live_members;
        if (completing) { view.expected_messages=count; view.completing_member=member; }
        // Table3-31 Case3 still binds the first completing message so that a
        // subsequent completer cannot replace it. It is acknowledged as an
        // error, counts as processed, and can never execute an aggregate action.
        group->invalid_completer_count=invalid_completer;
        return {invalid_completer?Admission::InvalidCount:Admission::Accepted,view.owner,member,created};
    }
    bool processed(uint64_t member,bool failed=false) {
        const auto found=members_.find(member); if (found==members_.end()) return false;
        auto& entry=found->second; auto& group=*entry.group;
        if (entry.processed) {
            // A held completing atomic may receive MSG_ERROR or lose its PDC
            // after its operand was counted but before the group is ready.
            // Suppress that action without counting this member twice.
            if (failed && entry.completing && !group.completer_failed) {
                group.completer_failed=true;
                if (group.view.state==State::Ready) group.view.state=State::Completed;
                return true;
            }
            return false;
        }
        entry.processed=true; ++group.view.processed_messages;
        if (entry.completing && failed) group.completer_failed=true;
        if (group.view.state==State::Collecting && group.invalid_completer_count &&
            group.view.processed_messages==group.view.admitted_messages) group.view.state=State::Completed;
        else if (group.view.state==State::Collecting && !group.invalid_completer_count && group.view.expected_messages &&
            group.view.processed_messages==*group.view.expected_messages)
            group.view.state=group.completer_failed?State::Completed:State::Ready;
        return true;
    }
    bool action_completed(uint64_t owner) {
        const auto group=find_owner(owner); if (!group || group->view.state!=State::Ready) return false;
        group->view.state=State::Completed; retire_if_finished(group); return true;
    }
    bool cleared(uint64_t member) {
        const auto found=members_.find(member); if (found==members_.end()) return false;
        if (!found->second.processed) throw std::logic_error("cleared unprocessed synchronized message");
        const auto group=found->second.group; members_.erase(found); --group->live_members;
        retire_if_finished(group); return true;
    }
    bool rollback(uint64_t member) {
        const auto found=members_.find(member); if (found==members_.end()) return false;
        if (found->second.processed) throw std::logic_error("rolled back processed synchronized message");
        const auto group=found->second.group;
        if (found->second.completing) {
            group->view.completing_member.reset(); group->view.expected_messages.reset(); group->invalid_completer_count=false;
        }
        members_.erase(found); --group->live_members; --group->view.admitted_messages;
        if (!group->view.admitted_messages) erase_active(group);
        return true;
    }
    std::vector<uint64_t> expire(uint64_t now) {
        std::vector<uint64_t> expired;
        for (auto entry=active_.begin();entry!=active_.end();) {
            auto& view=entry->second->view;
            if (view.state==State::Collecting && now>=view.expires_at) {
                view.state=State::Expired; expired.push_back(view.owner); entry=active_.erase(entry);
            } else ++entry;
        }
        return expired;
    }
    std::optional<Snapshot> snapshot(uint64_t owner) const {
        const auto group=find_owner(owner); return group?std::optional<Snapshot>{group->view}:std::nullopt;
    }
    std::optional<Snapshot> current(Key key) const {
        const auto found=active_.find(key);
        return found==active_.end()?std::nullopt:std::optional<Snapshot>{found->second->view};
    }
    std::optional<Snapshot> member_snapshot(uint64_t member) const {
        const auto found=members_.find(member);
        return found==members_.end()?std::nullopt:std::optional<Snapshot>{found->second.group->view};
    }
    size_t active_groups() const { return active_.size(); }
    size_t retained_members() const { return members_.size(); }
private:
    struct Group { Snapshot view{}; size_t live_members=0; bool completer_failed=false,invalid_completer_count=false; };
    struct Member { std::shared_ptr<Group> group; bool processed,completing; };
    std::shared_ptr<Group> find_owner(uint64_t owner) const {
        for (const auto& entry:active_) if (entry.second->view.owner==owner) return entry.second;
        return {};
    }
    void erase_active(const std::shared_ptr<Group>& group) {
        const auto found=active_.find(group->view.key);
        if (found!=active_.end() && found->second==group) active_.erase(found);
    }
    void retire_if_finished(const std::shared_ptr<Group>& group) {
        if (!group->live_members && group->view.state==State::Completed) erase_active(group);
    }
    size_t maximum_groups_,maximum_members_;
    uint64_t age_ns_,next_owner_=0,next_member_=0;
    std::map<Key,std::shared_ptr<Group>> active_;
    std::map<uint64_t,Member> members_; // Bounded by the owning Incoming budget.
};
} // namespace UET::SES
