#include "check.hpp"
#include "sentinel/der.hpp"

#include <cstdint>
#include <vector>

using namespace sentinel;

namespace {

der::reader over(const std::vector<std::uint8_t>& v) {
    return der::reader(bytes_view(v.data(), v.size()));
}

}  // namespace

TEST(der_reads_a_nested_sequence_and_reports_the_exact_bytes_of_each_element) {
    // SEQUENCE { INTEGER 5, OCTET STRING "hi" }
    const std::vector<std::uint8_t> raw = {0x30, 0x07, 0x02, 0x01, 0x05, 0x04, 0x02, 'h', 'i'};
    auto r = over(raw);
    auto seq = r.next(der::tag::sequence);
    REQUIRE(seq.has_value());
    CHECK_EQ(seq->whole.size(), std::size_t(9));
    CHECK_EQ(seq->content.size(), std::size_t(7));

    auto inner = der::reader::into(*seq);
    auto n = inner.next(der::tag::integer);
    REQUIRE(n.has_value());
    auto value = der::parse_integer(n->content);
    REQUIRE(value.ok());
    CHECK_EQ(*value, std::int64_t(5));

    auto os = inner.next(der::tag::octet_string);
    REQUIRE(os.has_value());
    CHECK_EQ(to_hex(os->content), std::string("6869"));
    CHECK(inner.empty());
}

// BER allows an indefinite length terminated by two zero bytes. DER does not,
// and a decoder that accepts both lets the same bytes mean two things.
TEST(der_rejects_an_indefinite_length) {
    const std::vector<std::uint8_t> raw = {0x30, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00};
    auto r = over(raw);
    CHECK(!r.next().has_value());
    CHECK(r.error().find("indefinite length") != std::string::npos);
}

TEST(der_rejects_a_length_encoded_in_more_bytes_than_it_needs) {
    // 0x81 0x05 means "one length byte follows, value 5", but 5 fits in the
    // short form, so this is not DER.
    const std::vector<std::uint8_t> raw = {0x04, 0x81, 0x05, 1, 2, 3, 4, 5};
    auto r = over(raw);
    CHECK(!r.next().has_value());
    CHECK(r.error().find("non-minimal length") != std::string::npos);

    const std::vector<std::uint8_t> leading_zero = {0x04, 0x82, 0x00, 0x80};
    auto r2 = over(leading_zero);
    CHECK(!r2.next().has_value());
    CHECK(r2.error().find("leading zero byte") != std::string::npos);
}

TEST(der_rejects_the_high_tag_number_form) {
    const std::vector<std::uint8_t> raw = {0x1f, 0x81, 0x00, 0x00};
    auto r = over(raw);
    CHECK(!r.next().has_value());
    CHECK(r.error().find("high tag number") != std::string::npos);
}

TEST(der_rejects_an_element_that_claims_more_bytes_than_are_present) {
    const std::vector<std::uint8_t> raw = {0x04, 0x10, 1, 2, 3};
    auto r = over(raw);
    CHECK(!r.next().has_value());
    CHECK(r.error().find("claims 16") != std::string::npos);
}

TEST(der_decodes_object_identifiers_including_the_packed_first_two_arcs) {
    // 1.2.840.113549.1.1.11, sha256WithRSAEncryption.
    const std::vector<std::uint8_t> content = {0x2a, 0x86, 0x48, 0x86, 0xf7,
                                               0x0d, 0x01, 0x01, 0x0b};
    CHECK_EQ(der::oid_to_string(bytes_view(content.data(), content.size())),
             std::string("1.2.840.113549.1.1.11"));
    CHECK_EQ(der::oid_label("1.2.840.113549.1.1.11"), std::string("sha256WithRSAEncryption"));

    const std::vector<std::uint8_t> cn = {0x55, 0x04, 0x03};  // 2.5.4.3
    CHECK_EQ(der::oid_to_string(bytes_view(cn.data(), cn.size())), std::string("2.5.4.3"));
    CHECK_EQ(der::oid_label("2.5.4.3"), std::string("CN"));
    // An unknown identifier keeps its dotted form rather than disappearing.
    CHECK_EQ(der::oid_label("1.3.9.9.9"), std::string("1.3.9.9.9"));
}

TEST(der_rejects_a_malformed_object_identifier) {
    const std::vector<std::uint8_t> unfinished = {0x2a, 0x86};  // ends mid arc
    CHECK_EQ(der::oid_to_string(bytes_view(unfinished.data(), unfinished.size())), std::string());
    const std::vector<std::uint8_t> padded = {0x2a, 0x80, 0x01};  // non-minimal arc
    CHECK_EQ(der::oid_to_string(bytes_view(padded.data(), padded.size())), std::string());
}

// RFC 5280 section 4.1.2.5.1: a two digit year of 50 or above means the
// twentieth century. Getting this backwards makes an expired certificate look
// valid for another seventy five years.
TEST(der_applies_the_rfc5280_century_rule_to_a_two_digit_year) {
    auto at = [](const char* s, std::uint32_t tag) {
        static std::vector<std::uint8_t> buf;
        buf.assign(s, s + std::char_traits<char>::length(s));
        der::tlv t;
        t.number = tag;
        t.content = bytes_view(buf.data(), buf.size());
        return der::parse_time(t);
    };
    auto y2049 = at("490101000000Z", der::tag::utc_time);
    REQUIRE(y2049.ok());
    CHECK_EQ(der::format_time(*y2049), std::string("2049-01-01 00:00:00Z"));

    auto y1950 = at("500101000000Z", der::tag::utc_time);
    REQUIRE(y1950.ok());
    CHECK_EQ(der::format_time(*y1950), std::string("1950-01-01 00:00:00Z"));

    auto g = at("20260819123456Z", der::tag::generalized_time);
    REQUIRE(g.ok());
    CHECK_EQ(der::format_time(*g), std::string("2026-08-19 12:34:56Z"));
}

TEST(der_rejects_a_time_without_seconds_and_an_impossible_date) {
    auto at = [](const char* s, std::uint32_t tag) {
        static std::vector<std::uint8_t> buf;
        buf.assign(s, s + std::char_traits<char>::length(s));
        der::tlv t;
        t.number = tag;
        t.content = bytes_view(buf.data(), buf.size());
        return der::parse_time(t);
    };
    CHECK(!at("2601011234Z", der::tag::utc_time).ok());        // no seconds
    CHECK(!at("260101123456", der::tag::utc_time).ok());       // no Z
    CHECK(!at("260231123456Z", der::tag::utc_time).ok());      // 31 February
    CHECK(!at("261301123456Z", der::tag::utc_time).ok());      // month 13
}

TEST(der_enforces_minimal_integers_and_the_strict_boolean_encoding) {
    const std::vector<std::uint8_t> padded = {0x00, 0x05};
    CHECK(!der::parse_integer(bytes_view(padded.data(), padded.size())).ok());

    const std::vector<std::uint8_t> needed = {0x00, 0x80};  // 128, the zero is required
    auto ok = der::parse_integer(bytes_view(needed.data(), needed.size()));
    REQUIRE(ok.ok());
    CHECK_EQ(*ok, std::int64_t(128));

    const std::vector<std::uint8_t> negative = {0xff, 0x7f};  // -129
    auto neg = der::parse_integer(bytes_view(negative.data(), negative.size()));
    REQUIRE(neg.ok());
    CHECK_EQ(*neg, std::int64_t(-129));

    const std::vector<std::uint8_t> loose_true = {0x01};
    CHECK(!der::parse_boolean(bytes_view(loose_true.data(), loose_true.size())).ok());
    const std::vector<std::uint8_t> der_true = {0xff};
    auto b = der::parse_boolean(bytes_view(der_true.data(), der_true.size()));
    REQUIRE(b.ok());
    CHECK(*b);
}

TEST(der_reads_a_bit_string_and_reports_its_unused_bits) {
    const std::vector<std::uint8_t> content = {0x03, 0xb8};  // three unused bits
    std::uint8_t unused = 0;
    auto payload = der::parse_bit_string(bytes_view(content.data(), content.size()), unused);
    REQUIRE(payload.ok());
    CHECK_EQ(int(unused), 3);
    CHECK_EQ(to_hex(*payload), std::string("b8"));

    const std::vector<std::uint8_t> bad = {0x09, 0x00};
    std::uint8_t u2 = 0;
    CHECK(!der::parse_bit_string(bytes_view(bad.data(), bad.size()), u2).ok());
}
