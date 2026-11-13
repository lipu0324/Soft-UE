#include "Check.hpp"
#include "../SES/MemoryRegistry.hpp"
#include <iostream>

using namespace UET::SES;
using AtomicOperation=IntegerAtomicOperation;
using AtomicDatatype=IntegerAtomicDatatype;

std::vector<uint8_t> integer_bytes(uint64_t value,size_t width) {
    std::vector<uint8_t> result(width,0);
    for (size_t byte=0;byte<std::min<size_t>(width,8);++byte) result[byte]=static_cast<uint8_t>(value>>(8*byte));
    return result;
}

void fixed_width_boundaries() {
    for (unsigned datatype_encoding=0;datatype_encoding<10;++datatype_encoding) {
        const auto datatype=static_cast<AtomicDatatype>(datatype_encoding);
        const auto width=integer_atomic_width(datatype);
        const auto one=integer_bytes(1,width),zero=integer_bytes(0,width),two=integer_bytes(2,width);
        const std::vector<uint8_t> maximum(width,0xff);
        CHECK(fetching_atomic_update(maximum,one,{},AtomicOperation::Sum,datatype)==zero);
        CHECK(fetching_atomic_update(zero,one,{},AtomicOperation::Difference,datatype)==maximum);
        CHECK(fetching_atomic_update(maximum,maximum,{},AtomicOperation::Product,datatype)==one);
        CHECK(fetching_atomic_update(one,two,{},AtomicOperation::Read,datatype)==one);
        CHECK(fetching_atomic_update(one,two,{},AtomicOperation::Write,datatype)==two);
        auto sign_bit=zero; sign_bit.back()=0x80;
        CHECK(fetching_atomic_update(sign_bit,one,{},AtomicOperation::Minimum,datatype)==
            ((datatype_encoding&1)?one:sign_bit));
        for (const auto operation:{AtomicOperation::CompareSwapEqual,AtomicOperation::CompareSwapNotEqual,
                AtomicOperation::CompareSwapLessEqual,AtomicOperation::CompareSwapLess,
                AtomicOperation::CompareSwapGreaterEqual,AtomicOperation::CompareSwapGreater}) {
            const auto replacement=integer_bytes(9,width);
            const bool lower_compare_replaces=operation==AtomicOperation::CompareSwapNotEqual ||
                operation==AtomicOperation::CompareSwapLessEqual || operation==AtomicOperation::CompareSwapLess;
            CHECK(fetching_atomic_update(two,replacement,one,operation,datatype)==(lower_compare_replaces?replacement:two));
            const bool equal_compare_replaces=operation==AtomicOperation::CompareSwapEqual ||
                operation==AtomicOperation::CompareSwapLessEqual || operation==AtomicOperation::CompareSwapGreaterEqual;
            CHECK(fetching_atomic_update(two,replacement,two,operation,datatype)==(equal_compare_replaces?replacement:two));
        }
        CHECK(fetching_atomic_update(integer_bytes(0xf0,width),integer_bytes(7,width),integer_bytes(0x3c,width),
            AtomicOperation::MaskedSwap,datatype)==integer_bytes(0x37,width));
        for (const auto operation:{AtomicOperation::LogicalOr,AtomicOperation::LogicalAnd,AtomicOperation::LogicalXor}) {
            const auto expected=operation==AtomicOperation::LogicalAnd?zero:one;
            CHECK(fetching_atomic_update(sign_bit,zero,{},operation,datatype)==expected);
        }
    }
    std::vector<uint8_t> below_64(16,0),double_below_64(16,0xff);
    std::fill_n(below_64.begin(),8,0xff); double_below_64[0]=0xfe;
    std::fill(double_below_64.begin()+8,double_below_64.end(),0); double_below_64[8]=1;
    CHECK(fetching_atomic_update(below_64,integer_bytes(2,16),{},AtomicOperation::Product,AtomicDatatype::Uint128)==double_below_64);
    std::vector<uint8_t> high_left(16,0),high_right(16,0); high_left[12]=16; high_right[5]=1;
    CHECK(fetching_atomic_update(high_left,high_right,{},AtomicOperation::Product,AtomicDatatype::Uint128)==std::vector<uint8_t>(16,0));
}

void independent_small_integer_oracle() {
    // An ordinary host integer is an independent arithmetic oracle for the
    // byte-carry implementation. Include values that cross each byte boundary.
    for (const size_t width:{size_t{1},size_t{2},size_t{4},size_t{8}}) {
        const auto datatype=width==1?AtomicDatatype::Uint8:width==2?AtomicDatatype::Uint16:
            width==4?AtomicDatatype::Uint32:AtomicDatatype::Uint64;
        for (const uint64_t target:{uint64_t{0},uint64_t{1},uint64_t{0xff},uint64_t{0x100},UINT64_MAX})
            for (const uint64_t operand:{uint64_t{0},uint64_t{1},uint64_t{3},uint64_t{0x101},UINT64_MAX}) {
                CHECK(fetching_atomic_update(integer_bytes(target,width),integer_bytes(operand,width),{},AtomicOperation::Sum,datatype)==integer_bytes(target+operand,width));
                CHECK(fetching_atomic_update(integer_bytes(target,width),integer_bytes(operand,width),{},AtomicOperation::Difference,datatype)==integer_bytes(target-operand,width));
                CHECK(fetching_atomic_update(integer_bytes(target,width),integer_bytes(operand,width),{},AtomicOperation::Product,datatype)==integer_bytes(target*operand,width));
                CHECK(fetching_atomic_update(integer_bytes(target,width),integer_bytes(operand,width),{},AtomicOperation::BitwiseOr,datatype)==integer_bytes(target|operand,width));
                CHECK(fetching_atomic_update(integer_bytes(target,width),integer_bytes(operand,width),{},AtomicOperation::BitwiseAnd,datatype)==integer_bytes(target&operand,width));
                CHECK(fetching_atomic_update(integer_bytes(target,width),integer_bytes(operand,width),{},AtomicOperation::BitwiseXor,datatype)==integer_bytes(target^operand,width));
            }
    }
}

void wire_operand_goldens() {
    const auto compare=integer_bytes(0x1122334455667788,8),replacement=integer_bytes(0x8877665544332211,8);
    const std::vector<uint8_t> expected_single{0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88};
    const std::vector<uint8_t> expected_dual{
        0,0,0,0,0,0,0,0,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
        0,0,0,0,0,0,0,0,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11};
    CHECK(fetching_atomic_wire_operands(compare,{},AtomicOperation::Sum,AtomicDatatype::Uint64)==expected_single);
    CHECK(fetching_atomic_wire_operands(replacement,compare,AtomicOperation::CompareSwapEqual,AtomicDatatype::Uint64)==expected_dual);
    const auto decoded=decode_fetching_atomic_operands(expected_dual,AtomicOperation::CompareSwapEqual,AtomicDatatype::Uint64);
    CHECK(decoded.operand==replacement && decoded.compare_or_mask==compare);
    check_throws<std::invalid_argument>([&] { decode_fetching_atomic_operands(expected_single,AtomicOperation::CompareSwapEqual,AtomicDatatype::Uint64); });
    check_throws<std::invalid_argument>([&] { fetching_atomic_wire_operands({},compare,AtomicOperation::CompareSwapEqual,AtomicDatatype::Uint64); });
    check_throws<std::invalid_argument>([&] { fetching_atomic_update(compare,replacement,{},AtomicOperation::CompareSwapEqual,AtomicDatatype::Uint64); });
    check_throws<std::invalid_argument>([&] { integer_atomic_width(static_cast<AtomicDatatype>(10)); });
    check_throws<std::invalid_argument>([&] { integer_atomic_result(0,0,AtomicOperation::Sum,AtomicDatatype::Uint128); });
}

void checked_memory_event() {
    MemoryRegistry registry; registry.add_job(1); registry.add_job(2);
    const auto region=registry.register_region(1,1,64,(Access::Read|Access::Write)|static_cast<uint8_t>(Access::Atomic));
    const auto original=integer_bytes(0xffffffffffffffff,16),increment=integer_bytes(1,16);
    registry.write(1,1,region.key,16,original);
    CHECK(registry.fetch_atomic_element(1,1,region.key,16,AtomicOperation::Sum,AtomicDatatype::Uint128,increment)==original);
    auto expected=integer_bytes(0,16); expected[8]=1;
    CHECK(registry.read(1,1,region.key,16,16)==expected);
    CHECK(registry.fetch_atomic_element(1,1,region.key,16,AtomicOperation::Read,AtomicDatatype::Uint128,increment)==expected);
    CHECK(registry.read(1,1,region.key,16,16)==expected);
    check_throws<MemoryAccessError>([&] { registry.fetch_atomic_element(2,1,region.key,16,AtomicOperation::Sum,AtomicDatatype::Uint128,increment); });
    check_throws<MemoryAccessError>([&] { registry.fetch_atomic_element(1,1,region.key,17,AtomicOperation::Sum,AtomicDatatype::Uint128,increment); });
    check_throws<MemoryAccessError>([&] { registry.fetch_atomic_element(1,1,region.key,64,AtomicOperation::Sum,AtomicDatatype::Uint128,increment); });
    check_throws<std::invalid_argument>([&] { registry.fetch_atomic_element(1,1,region.key,16,AtomicOperation::Sum,AtomicDatatype::Uint128,{}); });
    CHECK(registry.read(1,1,region.key,16,16)==expected);
    const auto no_write=registry.register_region(1,1,16,Access::Read|Access::Atomic);
    check_throws<MemoryAccessError>([&] { registry.fetch_atomic_element(1,1,no_write.key,0,AtomicOperation::Sum,AtomicDatatype::Uint128,increment); });
    registry.deregister(region);
    check_throws<MemoryAccessError>([&] { registry.fetch_atomic_element(1,1,region.key,16,AtomicOperation::Sum,AtomicDatatype::Uint128,increment); });
}

int main() {
    try {
        fixed_width_boundaries(); independent_small_integer_oracle(); wire_operand_goldens(); checked_memory_event();
        std::cout<<"PASS scalar fetching atomic values, 128-bit arithmetic, dual-operand wire goldens and checked MR events\n";
    } catch (const std::exception& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
