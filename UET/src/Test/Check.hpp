#pragma once
#include <stdexcept>
#include <string>
#include <utility>

#define CHECK(expression) do { if (!(expression)) throw std::runtime_error( \
    std::string(__FILE__) + ":" + std::to_string(__LINE__) + ": " #expression); } while (false)

template<class Exception, class Callback>
void check_throws(Callback&& callback) {
    bool caught = false;
    try { std::forward<Callback>(callback)(); }
    catch (const Exception&) { caught = true; }
    CHECK(caught);
}
