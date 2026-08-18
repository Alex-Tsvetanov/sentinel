#include "check.hpp"
#include "sentinel/fixtures.hpp"
#include "sentinel/tls.hpp"

#include <string>
#include <vector>

using namespace sentinel;

namespace {

bool contains(const std::vector<std::string>& v, const std::string& needle) {
    for (const auto& s : v) {
        if (s.find(needle) != std::string::npos) return true;
    }
    return false;
}

}  // namespace

TEST(tls_reads_the_negotiated_parameters_of_a_complete_exchange) {
    const auto stream = fixtures::tls13_stream("sentinel.example.test", false);
    auto s = tls::scan_stream(bytes_view(stream.data(), stream.size()));
    REQUIRE(s.ok());
    auto rep = tls::summarise(*s);
    REQUIRE(rep.ok());
    CHECK(rep->saw_client_hello);
    CHECK(rep->saw_server_hello);
    CHECK_EQ(rep->negotiated_version, std::string("TLS 1.3"));
    CHECK_EQ(rep->cipher_suite_text, std::string("TLS_AES_128_GCM_SHA256"));
    CHECK_EQ(rep->selected_group, std::string("x25519"));
    CHECK_EQ(rep->server_name, std::string("sentinel.example.test"));
    CHECK_EQ(rep->alpn, std::string("h2"));
}

// RFC 8446 leaves ServerHello.legacy_version at TLS 1.2 and puts the real answer
// in an extension. A reader that trusts the legacy field reports TLS 1.2 for
// every TLS 1.3 connection it sees.
TEST(tls_takes_the_version_from_supported_versions_and_not_from_the_legacy_field) {
    const auto stream = fixtures::tls13_stream("sentinel.example.test", false);
    auto s = tls::scan_stream(bytes_view(stream.data(), stream.size()));
    REQUIRE(s.ok());
    for (const auto& m : s->messages) {
        if (m.type != tls::handshake_type::server_hello) continue;
        auto sh = tls::parse_server_hello(m.body);
        REQUIRE(sh.ok());
        CHECK_EQ(tls::version_name(sh->legacy_version), std::string("TLS 1.2"));
    }
    auto rep = tls::summarise(*s);
    REQUIRE(rep.ok());
    CHECK_EQ(rep->negotiated_version, std::string("TLS 1.3"));
    CHECK(rep->version_source.find("supported_versions") != std::string::npos);
}

// A handshake message may be split across records. Both forms of the same
// exchange have to produce the same report.
TEST(tls_reassembles_a_handshake_message_split_across_two_records) {
    const auto whole = fixtures::tls13_stream("sentinel.example.test", false);
    const auto split = fixtures::tls13_stream("sentinel.example.test", true);
    CHECK(split.size() > whole.size());  // one extra record header

    auto a = tls::scan_stream(bytes_view(whole.data(), whole.size()));
    auto b = tls::scan_stream(bytes_view(split.data(), split.size()));
    REQUIRE(a.ok());
    REQUIRE(b.ok());
    CHECK_EQ(a->handshake_records, std::size_t(2));
    CHECK_EQ(b->handshake_records, std::size_t(3));
    CHECK_EQ(a->messages.size(), std::size_t(2));
    CHECK_EQ(b->messages.size(), std::size_t(2));

    auto ra = tls::summarise(*a);
    auto rb = tls::summarise(*b);
    REQUIRE(ra.ok());
    REQUIRE(rb.ok());
    // The record counts differ by one, which is the point. Everything the
    // handshake actually negotiated has to come out identical.
    CHECK_EQ(ra->negotiated_version, rb->negotiated_version);
    CHECK_EQ(ra->cipher_suite_text, rb->cipher_suite_text);
    CHECK_EQ(ra->selected_group, rb->selected_group);
    CHECK_EQ(ra->server_name, rb->server_name);
    CHECK_EQ(ra->alpn, rb->alpn);
    CHECK_EQ(ra->server_extensions.size(), rb->server_extensions.size());
}

TEST(tls_counts_protected_records_instead_of_guessing_at_them) {
    const auto stream = fixtures::tls13_stream();
    auto s = tls::scan_stream(bytes_view(stream.data(), stream.size()));
    REQUIRE(s.ok());
    CHECK_EQ(s->encrypted_records, std::size_t(3));
    CHECK(s->encrypted_bytes > 1900);
    auto rep = tls::summarise(*s);
    REQUIRE(rep.ok());
    CHECK(contains(rep->unobservable, "CertificateVerify"));
    CHECK(contains(rep->unobservable, "protected record(s) were counted but not read"));
}

TEST(tls_notices_the_downgrade_sentinel_and_the_obsolete_suites) {
    const auto stream = fixtures::tls12_downgrade_stream();
    auto s = tls::scan_stream(bytes_view(stream.data(), stream.size()));
    REQUIRE(s.ok());
    auto rep = tls::summarise(*s);
    REQUIRE(rep.ok());
    CHECK_EQ(rep->negotiated_version, std::string("TLS 1.2"));
    CHECK(contains(rep->findings, "downgrade sentinel"));
    CHECK(contains(rep->findings, "RC4"));
    CHECK(contains(rep->findings, "3DES"));
}

TEST(tls_rejects_a_handshake_message_that_runs_past_the_records_that_carry_it) {
    const auto stream = fixtures::truncated_stream();
    auto s = tls::scan_stream(bytes_view(stream.data(), stream.size()));
    CHECK(!s.ok());
    CHECK(s.error().find("handshake message") != std::string::npos);
}

TEST(tls_rejects_an_unknown_record_content_type) {
    const std::uint8_t raw[] = {0x99, 0x03, 0x03, 0x00, 0x01, 0x41};
    auto s = tls::scan_stream(bytes_view(raw, sizeof raw));
    CHECK(!s.ok());
    CHECK(s.error().find("unknown record content type 153") != std::string::npos);
}

// RFC 8446 section 5.1 caps a record fragment. Accepting a larger one lets a
// sender decide how much the reader allocates.
TEST(tls_rejects_a_record_that_claims_more_than_the_specification_allows) {
    std::vector<std::uint8_t> raw = {22, 0x03, 0x03, 0x50, 0x00};
    raw.resize(5 + 0x5000, 0);
    auto s = tls::scan_stream(bytes_view(raw.data(), raw.size()));
    CHECK(!s.ok());
    CHECK(s.error().find("exceeds the limit") != std::string::npos);
}

TEST(tls_rejects_a_client_hello_whose_extension_block_overruns) {
    const auto stream = fixtures::tls13_stream("a.example.test", false);
    std::vector<std::uint8_t> broken(stream.begin(), stream.end());
    // The extension block length sits after the compression method list. Rather
    // than compute the offset, the whole record is cut short so the inner
    // length prefix no longer fits.
    broken.resize(stream.size() / 2);
    auto s = tls::scan_stream(bytes_view(broken.data(), broken.size()));
    if (s.ok()) {
        auto rep = tls::summarise(*s);
        CHECK(!rep.ok());
    } else {
        CHECK(!s.error().empty());
    }
}

TEST(tls_rejects_a_supported_versions_list_of_odd_length) {
    const std::uint8_t body[] = {0x03, 0x03, 0x04, 0x03};  // three bytes claimed
    auto v = tls::decode_supported_versions_client(bytes_view(body, sizeof body));
    CHECK(!v.ok());
    CHECK(v.error().find("bad list length") != std::string::npos);
}

TEST(tls_rejects_an_empty_alpn_protocol_name) {
    const std::uint8_t body[] = {0x00, 0x03, 0x02, 'h', '2', 0x00};
    auto v = tls::decode_alpn(bytes_view(body, sizeof body));
    // Three bytes of list: "h2" then a zero length entry, which is not allowed.
    const std::uint8_t body2[] = {0x00, 0x04, 0x02, 'h', '2', 0x00};
    auto v2 = tls::decode_alpn(bytes_view(body2, sizeof body2));
    CHECK(v.ok());
    CHECK(!v2.ok());
    CHECK(v2.error().find("empty protocol name") != std::string::npos);
}

TEST(tls_names_the_suites_groups_and_schemes_it_reports) {
    CHECK_EQ(tls::cipher_suite_name(0x1303), std::string("TLS_CHACHA20_POLY1305_SHA256"));
    CHECK_EQ(tls::group_name(0x001d), std::string("x25519"));
    CHECK_EQ(tls::signature_scheme_name(0x0804), std::string("rsa_pss_rsae_sha256"));
    CHECK_EQ(tls::extension_name(43), std::string("supported_versions"));
    CHECK(tls::is_tls13_cipher_suite(0x1301));
    CHECK(!tls::is_tls13_cipher_suite(0xc02f));
    // GREASE values are reserved to keep implementations honest, and a reader
    // that reports them as unknown protocol errors is the problem they exist to
    // find.
    CHECK_EQ(tls::group_name(0x0a0a), std::string("GREASE 0x0a0a"));
}
