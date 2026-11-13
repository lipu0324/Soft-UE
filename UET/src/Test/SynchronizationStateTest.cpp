#include "Check.hpp"
#include "../SES/SynchronizationState.hpp"
#include <iostream>
using namespace UET::SES;
using Groups=SynchronizationGroups;

void completion_order_and_failures(bool completer_first,bool failed_write,bool failed_completer) {
    Groups groups;
    Groups::Reservation first{},last{},completer{};
    if (completer_first) completer=groups.reserve({2,0},1,true,3,0);
    first=groups.reserve({2,0},1,false,0,0); last=groups.reserve({2,0},1,false,0,0);
    if (!completer_first) completer=groups.reserve({2,0},1,true,3,0);
    CHECK(first.status==Groups::Admission::Accepted && last.status==Groups::Admission::Accepted &&
        completer.status==Groups::Admission::Accepted && first.owner==completer.owner);
    CHECK(groups.processed(completer.member,failed_completer));
    CHECK(groups.snapshot(first.owner)->state==Groups::State::Collecting);
    CHECK(groups.processed(first.member,failed_write) && !groups.processed(first.member));
    CHECK(groups.snapshot(first.owner)->processed_messages==2);
    CHECK(groups.cleared(first.member));
    CHECK(groups.processed(last.member));
    CHECK(groups.snapshot(first.owner)->state==(failed_completer?Groups::State::Completed:Groups::State::Ready));
    if (!failed_completer) CHECK(groups.action_completed(first.owner) && !groups.action_completed(first.owner));
    CHECK(groups.cleared(last.member) && groups.cleared(completer.member));
    CHECK(!groups.active_groups() && !groups.retained_members());
}
void isolated_keys_and_bad_completers() {
    Groups groups;
    const auto first=groups.reserve({2,42},1,false,0,0);
    const auto other=groups.reserve({3,42},1,false,0,0);
    CHECK(first.owner!=other.owner && groups.active_groups()==2);
    CHECK(groups.reserve({2,42},2,false,0,0).status==Groups::Admission::WrongJob);
    CHECK(groups.reserve({2,42},1,false,1,0).status==Groups::Admission::InvalidCount);
    const auto second=groups.reserve({2,42},1,false,0,0);
    const auto invalid=groups.reserve({2,42},1,true,1,0);
    CHECK(invalid.status==Groups::Admission::InvalidCount && invalid.member);
    CHECK(groups.reserve({2,42},1,true,3,0).status==Groups::Admission::DuplicateCompleter);
    CHECK(groups.reserve({2,42},1,false,0,0).status==Groups::Admission::ExcessMember);
    CHECK(groups.processed(first.member) && groups.processed(second.member) && groups.processed(invalid.member,true));
    CHECK(groups.snapshot(first.owner)->state==Groups::State::Completed && !groups.action_completed(first.owner));
    CHECK(groups.cleared(first.member) && groups.cleared(second.member) && groups.cleared(invalid.member));
    CHECK(groups.rollback(other.member) && !groups.active_groups());
}
void excess_after_completion_and_rollback() {
    Groups groups;
    const auto first=groups.reserve({2,7},1,false,0,0);
    const auto completer=groups.reserve({2,7},1,true,2,0);
    CHECK(groups.reserve({2,7},1,true,2,0).status==Groups::Admission::DuplicateCompleter);
    CHECK(groups.reserve({2,7},1,false,0,0).status==Groups::Admission::ExcessMember);
    CHECK(groups.rollback(completer.member));
    const auto replacement=groups.reserve({2,7},1,true,2,0);
    CHECK(replacement.status==Groups::Admission::Accepted && replacement.member!=completer.member);
    CHECK(groups.processed(first.member) && groups.processed(replacement.member) && groups.action_completed(first.owner));
    CHECK(groups.reserve({2,7},1,false,0,0).status==Groups::Admission::ExcessMember);
    CHECK(groups.cleared(first.member) && groups.cleared(replacement.member));
    const auto reused=groups.reserve({2,7},1,true,1,0);
    CHECK(reused.status==Groups::Admission::Accepted && reused.owner!=first.owner);
    CHECK(groups.processed(reused.member) && groups.action_completed(reused.owner) && groups.cleared(reused.member));
}
void expiry_and_credit() {
    Groups groups(1,10,2);
    const auto first=groups.reserve({2,0},1,true,2,0);
    CHECK(groups.reserve({3,0},1,false,0,0).status==Groups::Admission::NoState);
    CHECK(groups.processed(first.member) && groups.expire(9).empty());
    CHECK(groups.expire(10)==std::vector<uint64_t>{first.owner});
    CHECK(!groups.action_completed(first.owner) && groups.member_snapshot(first.member)->state==Groups::State::Expired);
    const auto newer=groups.reserve({2,0},1,true,1,10);
    CHECK(newer.owner!=first.owner && groups.reserve({3,1},1,false,0,10).status==Groups::Admission::NoMessageState);
    CHECK(!groups.processed(first.member) && groups.processed(newer.member) && groups.action_completed(newer.owner));
    CHECK(groups.cleared(first.member) && groups.cleared(newer.member) && !groups.retained_members() && !groups.active_groups());
    check_throws<std::invalid_argument>([] { Groups invalid(0); });
}
void count_boundary() {
    Groups groups(1,100,2); uint64_t owner=0;
    for (uint32_t index=0;index<65534;++index) {
        const auto member=groups.reserve({2,65535},1,false,0,0);
        CHECK(member.status==Groups::Admission::Accepted); owner=member.owner;
        CHECK(groups.processed(member.member,index%2) && groups.cleared(member.member));
        CHECK(!groups.retained_members());
    }
    CHECK(groups.reserve({2,65535},1,false,0,0).status==Groups::Admission::ExcessMember);
    const auto completer=groups.reserve({2,65535},1,true,65535,0);
    CHECK(completer.status==Groups::Admission::Accepted && groups.processed(completer.member));
    CHECK(groups.snapshot(owner)->processed_messages==65535 && groups.action_completed(owner) && groups.cleared(completer.member));
    CHECK(!groups.active_groups());
}
void source_ids() {
    uint32_t cursor=0;
    {
        SynchronizationIdPool pool(cursor,1);
        const auto zero=pool.allocate(); CHECK(zero && *zero==0 && !pool.allocate());
        CHECK(pool.release(*zero,true)); const auto recycled=pool.allocate(); CHECK(recycled && *recycled==0 && cursor==1);
        CHECK(pool.release(*recycled,false) && !pool.release(*recycled,true));
        const auto abandoned=pool.allocate(); CHECK(abandoned && *abandoned==1);
    }
    SynchronizationIdPool replacement(cursor); CHECK(replacement.allocate()==std::optional<uint16_t>{2});
    uint32_t end=65535; SynchronizationIdPool boundary(end);
    CHECK(boundary.allocate()==std::optional<uint16_t>{65535} && end==65536 && !boundary.allocate());
    CHECK(boundary.release(65535,true) && boundary.allocate()==std::optional<uint16_t>{65535});
}
int main() {
    try {
        for (bool first:{false,true}) for (bool failed_write:{false,true}) for (bool failed_completer:{false,true})
            completion_order_and_failures(first,failed_write,failed_completer);
        isolated_keys_and_bad_completers(); excess_after_completion_and_rollback(); expiry_and_credit(); count_boundary(); source_ids();
        std::cout<<"PASS synchronized metadata counters, failed members, first completer, expiry, bounds and FEP identifier lifetime\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
