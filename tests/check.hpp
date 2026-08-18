// A test runner small enough to read in one sitting. There is no dependency on
// GoogleTest or Catch2 on purpose: this repository must build on a clean machine
// that has nothing but a C++20 compiler and CMake.
#pragma once
#include <cstdio>
#include <functional>
#include <string>
#include <vector>

namespace testing {

struct failure {
    std::string file;
    int line;
    std::string text;
};

struct test_case {
    std::string name;
    std::function<void(std::vector<failure>&)> body;
};

std::vector<test_case>& registry();

struct registrar {
    registrar(const char* name, std::function<void(std::vector<failure>&)> body) {
        registry().push_back({name, std::move(body)});
    }
};

}  // namespace testing

// Records the failure and keeps going, so one broken expectation does not hide
// the next twenty.
#define CHECK(expr)                                                        \
    do {                                                                   \
        if (!(expr)) {                                                     \
            failures_.push_back({__FILE__, __LINE__, "CHECK(" #expr ")"}); \
        }                                                                  \
    } while (false)

#define CHECK_EQ(a, b)                                                             \
    do {                                                                           \
        auto lhs_ = (a);                                                           \
        auto rhs_ = (b);                                                           \
        if (!(lhs_ == rhs_)) {                                                     \
            failures_.push_back({__FILE__, __LINE__,                               \
                                 "CHECK_EQ(" #a ", " #b ") -> " +                  \
                                     ::testing::show(lhs_) + " != " +              \
                                     ::testing::show(rhs_)});                      \
        }                                                                          \
    } while (false)

// Abandons the rest of the case. Used when continuing would dereference a value
// that is known to be absent.
#define REQUIRE(expr)                                                              \
    do {                                                                           \
        if (!(expr)) {                                                             \
            failures_.push_back({__FILE__, __LINE__, "REQUIRE(" #expr ")"});       \
            return;                                                                \
        }                                                                          \
    } while (false)

#define TEST(name)                                                                 \
    static void name(std::vector<::testing::failure>&);                            \
    static ::testing::registrar reg_##name(#name, name);                           \
    static void name([[maybe_unused]] std::vector<::testing::failure>& failures_)

namespace testing {
inline std::string show(const std::string& v) { return "\"" + v + "\""; }
inline std::string show(bool v) { return v ? "true" : "false"; }
inline std::string show(const char* v) { return std::string("\"") + v + "\""; }
template <class T>
std::string show(const T& v) {
    return std::to_string(v);
}
}  // namespace testing
