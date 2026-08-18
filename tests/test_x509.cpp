#include "check.hpp"
#include "sentinel/fixtures.hpp"
#include "sentinel/x509.hpp"

#include <string>
#include <vector>

using namespace sentinel;

namespace {

constexpr std::int64_t reference_time = 1'776'000'000;  // a fixed point, so tests do not drift

bytes_view view(const std::vector<std::uint8_t>& v) { return bytes_view(v.data(), v.size()); }

bool has_dns(const x509::certificate& c, const std::string& name) {
    for (const auto& g : c.subject_alt_names) {
        if (g.kind == x509::general_name_kind::dns && g.value == name) return true;
    }
    return false;
}

}  // namespace

TEST(x509_decodes_the_fields_of_a_generated_authority_certificate) {
    const auto pki = fixtures::build_pki(reference_time);
    auto root = x509::parse_certificate(view(pki.root_der));
    REQUIRE(root.ok());
    CHECK_EQ(root->version, 3);
    CHECK_EQ(root->serial_hex, std::string("01"));
    CHECK_EQ(root->subject.text(),
             std::string("CN=Sentinel Test Root CA, O=Sentinel Course Project, C=BG"));
    CHECK(root->self_issued());
    CHECK(root->constraints.present);
    CHECK(root->constraints.is_ca);
    CHECK(root->constraints.critical);
    CHECK(root->constraints.has_path_len);
    CHECK_EQ(root->constraints.path_len, std::int64_t(1));
    CHECK(root->usage.present);
    CHECK(root->usage.has(x509::ku_key_cert_sign));
    CHECK(root->usage.has(x509::ku_crl_sign));
    CHECK(!root->usage.has(x509::ku_digital_signature));
    CHECK_EQ(root->signature_algorithm, std::string("sha256WithRSAEncryption"));
    CHECK_EQ(root->public_key_algorithm, std::string("rsaEncryption"));
    CHECK(root->tbs.size() > 100);
}

TEST(x509_decodes_alternative_names_key_usage_and_extended_key_usage_of_an_end_entity) {
    const auto pki = fixtures::build_pki(reference_time);
    REQUIRE(!pki.cases.empty());
    auto leaf = x509::parse_certificate(view(pki.cases[0].der[0]));
    REQUIRE(leaf.ok());
    CHECK_EQ(leaf->serial_hex, std::string("1001"));
    CHECK(!leaf->constraints.is_ca);
    CHECK(has_dns(*leaf, "sentinel.example.test"));
    CHECK(has_dns(*leaf, "*.svc.example.test"));
    CHECK(leaf->usage.has(x509::ku_digital_signature));
    CHECK(leaf->usage.has(x509::ku_key_encipherment));
    CHECK_EQ(leaf->extended_key_usage.size(), std::size_t(2));
    CHECK_EQ(leaf->extended_key_usage[0], std::string("serverAuth"));
    CHECK(leaf->unhandled_critical.empty());
    CHECK(!leaf->subject_key_id_hex.empty());
    CHECK(!leaf->authority_key_id_hex.empty());
    CHECK(leaf->valid.not_before < reference_time);
    CHECK(leaf->valid.not_after > reference_time);
}

TEST(x509_records_a_critical_extension_it_cannot_process) {
    const auto pki = fixtures::build_pki(reference_time);
    const fixtures::chain_case* target = nullptr;
    for (const auto& c : pki.cases) {
        if (c.name == "unrecognised critical extension") target = &c;
    }
    REQUIRE(target != nullptr);
    auto leaf = x509::parse_certificate(view(target->der[0]));
    REQUIRE(leaf.ok());
    REQUIRE(leaf->unhandled_critical.size() == 1);
    CHECK_EQ(leaf->unhandled_critical[0], std::string("2.5.29.54"));
}

TEST(x509_reads_the_name_constraints_of_a_constrained_authority) {
    const auto pki = fixtures::build_pki(reference_time);
    const fixtures::chain_case* target = nullptr;
    for (const auto& c : pki.cases) {
        if (c.name == "name inside the permitted subtree") target = &c;
    }
    REQUIRE(target != nullptr);
    auto ca = x509::parse_certificate(view(target->der[1]));
    REQUIRE(ca.ok());
    CHECK(ca->constrained_names.present);
    CHECK(ca->constrained_names.critical);
    REQUIRE(ca->constrained_names.permitted.size() == 1);
    CHECK_EQ(ca->constrained_names.permitted[0].value, std::string("inside.example.test"));
    CHECK(ca->constrained_names.excluded.empty());
}

TEST(x509_refuses_a_truncated_certificate) {
    const auto pki = fixtures::build_pki(reference_time);
    std::vector<std::uint8_t> cut(pki.root_der.begin(),
                                  pki.root_der.begin() + static_cast<long>(pki.root_der.size() / 3));
    auto c = x509::parse_certificate(view(cut));
    CHECK(!c.ok());
    CHECK(!c.error().empty());
}

TEST(x509_refuses_bytes_that_are_not_a_certificate) {
    const std::vector<std::uint8_t> junk = {0x01, 0x02, 0x03, 0x04};
    CHECK(!x509::parse_certificate(view(junk)).ok());
    CHECK(!x509::parse_certificate(bytes_view()).ok());
}

// RFC 6125 section 6.4.3. Each of these is a real disagreement between
// implementations, which is why they are pinned down here one at a time.
TEST(x509_host_matching_follows_the_wildcard_rules) {
    CHECK(x509::host_matches("example.test", "example.test"));
    CHECK(x509::host_matches("EXAMPLE.test", "example.TEST"));  // case insensitive
    CHECK(x509::host_matches("*.example.test", "a.example.test"));
    CHECK(x509::host_matches("www*.example.test", "www17.example.test"));

    CHECK(!x509::host_matches("*.example.test", "example.test"));    // needs a label
    CHECK(!x509::host_matches("*.example.test", "a.b.example.test"));  // never spans a dot
    CHECK(!x509::host_matches("*.test", "example.test"));             // too few labels behind it
    CHECK(!x509::host_matches("*", "example.test"));
    CHECK(!x509::host_matches("*.*.example.test", "a.b.example.test"));  // one wildcard only
    CHECK(!x509::host_matches("a.*.example.test", "a.b.example.test"));  // leftmost label only
    CHECK(!x509::host_matches("", "example.test"));
}

// RFC 5280 section 4.2.1.10. The subtree boundary has to fall on a label break,
// otherwise notexample.test appears to be inside example.test.
TEST(x509_dns_subtree_containment_stops_at_a_label_boundary) {
    CHECK(x509::dns_within_subtree("example.test", "example.test"));
    CHECK(x509::dns_within_subtree("example.test", "host.example.test"));
    CHECK(x509::dns_within_subtree("example.test", "a.b.example.test"));
    CHECK(!x509::dns_within_subtree("example.test", "notexample.test"));
    CHECK(!x509::dns_within_subtree("example.test", "example.test.evil"));
    CHECK(!x509::dns_within_subtree("host.example.test", "example.test"));
    CHECK(x509::dns_within_subtree("", "anything.at.all"));  // an empty base covers everything
}

TEST(x509_distinguished_names_compare_after_folding_case_and_spacing) {
    const auto pki = fixtures::build_pki(reference_time);
    auto root = x509::parse_certificate(view(pki.root_der));
    auto inter = x509::parse_certificate(view(pki.intermediate_der));
    REQUIRE(root.ok());
    REQUIRE(inter.ok());
    CHECK_EQ(inter->issuer.canonical(), root->subject.canonical());
    CHECK(inter->issuer.canonical() != inter->subject.canonical());
    REQUIRE(root->subject.find("CN") != nullptr);
    CHECK_EQ(*root->subject.find("CN"), std::string("Sentinel Test Root CA"));
    CHECK(root->subject.find("OU") == nullptr);
}
