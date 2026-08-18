// A DER decoder, only as much of it as X.509 needs.
//
// DER is the strict subset of BER that ITU-T X.509 mandates for certificates:
// one canonical encoding per value. This decoder enforces the parts of that
// strictness which have a security consequence, because a decoder that accepts
// several encodings of the same value is how two implementations end up
// disagreeing about what a certificate says.
//
// Rejected on sight: indefinite lengths, non-minimal length encodings, and the
// high tag number form, none of which may appear in a conforming certificate.
#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "sentinel/bytes.hpp"

namespace sentinel::der {

enum class tag_class : std::uint8_t {
    universal = 0,
    application = 1,
    context = 2,
    private_ = 3,
};

namespace tag {
inline constexpr std::uint32_t boolean = 1;
inline constexpr std::uint32_t integer = 2;
inline constexpr std::uint32_t bit_string = 3;
inline constexpr std::uint32_t octet_string = 4;
inline constexpr std::uint32_t null_value = 5;
inline constexpr std::uint32_t oid = 6;
inline constexpr std::uint32_t utf8_string = 12;
inline constexpr std::uint32_t sequence = 16;
inline constexpr std::uint32_t set = 17;
inline constexpr std::uint32_t printable_string = 19;
inline constexpr std::uint32_t t61_string = 20;
inline constexpr std::uint32_t ia5_string = 22;
inline constexpr std::uint32_t utc_time = 23;
inline constexpr std::uint32_t generalized_time = 24;
inline constexpr std::uint32_t bmp_string = 30;
}  // namespace tag

struct tlv {
    tag_class cls = tag_class::universal;
    bool constructed = false;
    std::uint32_t number = 0;
    bytes_view content;
    bytes_view whole;  // header and content together, needed to hash a TBSCertificate

    bool is(std::uint32_t universal_tag) const {
        return cls == tag_class::universal && number == universal_tag;
    }
    bool is_context(std::uint32_t n) const { return cls == tag_class::context && number == n; }
};

class reader {
public:
    explicit reader(bytes_view b) : buf_(b) {}

    bool empty() const { return pos_ >= buf_.size() || failed_; }
    bool ok() const { return !failed_; }
    const std::string& error() const { return error_; }
    std::size_t offset() const { return pos_; }

    // Reads the next element. Returns nothing and records a reason if the bytes
    // are not a well-formed DER element.
    std::optional<tlv> next();

    // Reads the next element and requires it to carry the given universal tag.
    std::optional<tlv> next(std::uint32_t universal_tag);

    static reader into(const tlv& t) { return reader(t.content); }

    void fail(std::string why);

private:
    bytes_view buf_;
    std::size_t pos_ = 0;
    bool failed_ = false;
    std::string error_;
};

// 1.2.840.113549.1.1.11 and the like. Returns an empty string if the encoding is
// not a valid object identifier.
std::string oid_to_string(bytes_view content);

// Human name for the identifiers this project recognises; the dotted form
// otherwise, so an unknown identifier is still reported rather than dropped.
std::string oid_label(const std::string& dotted);

result<std::int64_t> parse_integer(bytes_view content);
std::string integer_to_hex(bytes_view content);
result<bool> parse_boolean(bytes_view content);

// Returns the payload of a BIT STRING and the number of unused trailing bits.
result<bytes_view> parse_bit_string(bytes_view content, std::uint8_t& unused_bits);

// UTCTime and GeneralizedTime, converted to seconds since the Unix epoch so that
// validity windows can be compared with plain arithmetic.
result<std::int64_t> parse_time(const tlv& t);
std::string format_time(std::int64_t seconds);

// PrintableString, UTF8String, IA5String and the rest of the directory string
// choices, flattened to a UTF-8 std::string.
result<std::string> parse_string(const tlv& t);

}  // namespace sentinel::der
