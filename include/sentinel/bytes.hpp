// Bounds-checked reading over a borrowed byte buffer.
//
// Everything above this header parses attacker-supplied input. A truncated or
// deliberately malformed message is normal traffic for such code, not an
// exceptional condition, so nothing here throws: a read past the end sets a
// sticky failure on the reader and every later read is a no-op. The caller
// checks once at the end instead of after every field.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <utility>

namespace sentinel {

using bytes_view = std::span<const std::uint8_t>;

// A value or the reason there is not one. std::expected is C++23 and this
// project targets C++20, so this is the small stand-in.
template <class T>
class result {
public:
    result(T value) : value_(std::move(value)) {}
    static result failure(std::string why) {
        result r;
        r.error_ = std::move(why);
        return r;
    }

    explicit operator bool() const { return value_.has_value(); }
    bool ok() const { return value_.has_value(); }
    const T& operator*() const { return *value_; }
    T& operator*() { return *value_; }
    const T* operator->() const { return &*value_; }
    T* operator->() { return &*value_; }
    const std::string& error() const { return error_; }

private:
    result() = default;
    std::optional<T> value_;
    std::string error_;
};

class byte_reader {
public:
    explicit byte_reader(bytes_view buf) : buf_(buf) {}

    std::size_t offset() const { return pos_; }
    std::size_t remaining() const { return failed_ ? 0 : buf_.size() - pos_; }
    bool ok() const { return !failed_; }
    bool empty() const { return remaining() == 0; }
    const std::string& error() const { return error_; }

    // Marks the reader failed. The first reason wins: a later cascading failure
    // says less about the input than the one that started it.
    void fail(std::string why) {
        if (!failed_) {
            failed_ = true;
            error_ = std::move(why) + " at offset " + std::to_string(pos_);
        }
    }

    bool have(std::size_t n) const { return !failed_ && buf_.size() - pos_ >= n; }

    std::uint8_t u8() { return read(1) ? buf_[pos_ - 1] : 0; }

    std::uint16_t u16() {
        if (!read(2)) return 0;
        return static_cast<std::uint16_t>(buf_[pos_ - 2] << 8 | buf_[pos_ - 1]);
    }

    // TLS carries lengths as three bytes in several places, so it gets its own
    // accessor rather than a shifted u32.
    std::uint32_t u24() {
        if (!read(3)) return 0;
        return static_cast<std::uint32_t>(buf_[pos_ - 3]) << 16 |
               static_cast<std::uint32_t>(buf_[pos_ - 2]) << 8 |
               static_cast<std::uint32_t>(buf_[pos_ - 1]);
    }

    std::uint32_t u32() {
        if (!read(4)) return 0;
        return static_cast<std::uint32_t>(buf_[pos_ - 4]) << 24 |
               static_cast<std::uint32_t>(buf_[pos_ - 3]) << 16 |
               static_cast<std::uint32_t>(buf_[pos_ - 2]) << 8 |
               static_cast<std::uint32_t>(buf_[pos_ - 1]);
    }

    bytes_view take(std::size_t n) {
        if (!read(n)) return {};
        return buf_.subspan(pos_ - n, n);
    }

    // Length-prefixed vector, the shape TLS uses everywhere.
    bytes_view take_u8_prefixed() { return take(u8()); }
    bytes_view take_u16_prefixed() { return take(u16()); }
    bytes_view take_u24_prefixed() { return take(u24()); }

    bytes_view rest() { return take(remaining()); }

private:
    bool read(std::size_t n) {
        if (failed_) return false;
        if (buf_.size() - pos_ < n) {
            fail("need " + std::to_string(n) + " byte(s), " +
                 std::to_string(buf_.size() - pos_) + " left");
            return false;
        }
        pos_ += n;
        return true;
    }

    bytes_view buf_;
    std::size_t pos_ = 0;
    bool failed_ = false;
    std::string error_;
};

std::string to_hex(bytes_view b, std::size_t max_bytes = 0);

}  // namespace sentinel
