#include "check.hpp"
#include "sentinel/chain.hpp"
#include "sentinel/fixtures.hpp"

#include <string>
#include <vector>

using namespace sentinel;

namespace {

constexpr std::int64_t reference_time = 1'776'000'000;

bytes_view view(const std::vector<std::uint8_t>& v) { return bytes_view(v.data(), v.size()); }

// The parsed certificates hold views into the DER buffers, so the fixture has to
// outlive them. Keeping both in one object makes that impossible to get wrong.
struct harness {
    fixtures::pki pki;
    chain::trust_store store;

    explicit harness(std::int64_t now) : pki(fixtures::build_pki(now)) {
        auto root = x509::parse_certificate(view(pki.root_der));
        if (root) store.anchors.push_back(*root);
        store.revoked_serials = pki.revoked_serials;
        store.revocation_data_current = true;
    }

    std::vector<x509::certificate> parse(const fixtures::chain_case& c) const {
        std::vector<x509::certificate> out;
        for (const auto& der : c.der) {
            auto p = x509::parse_certificate(view(der));
            if (p) out.push_back(*p);
        }
        return out;
    }

    chain::report run(const fixtures::chain_case& c, std::int64_t at) const {
        chain::options opt;
        opt.at_time = at;
        opt.server_name = c.server_name;
        return chain::validate(parse(c), store, opt);
    }
};

const fixtures::chain_case& case_named(const harness& h, const std::string& name) {
    for (const auto& c : h.pki.cases) {
        if (c.name == name) return c;
    }
    static fixtures::chain_case none;
    return none;
}

std::string first_failure(const chain::report& r) {
    for (const auto& c : r.checks) {
        if (c.result == chain::status::failed) return c.name;
    }
    return {};
}

}  // namespace

// Every generated case, checked against the verdict written down when the case
// was built. A case that accepts a chain it should refuse is a security defect,
// not a numeric discrepancy, so all of them are asserted together.
TEST(chain_every_generated_case_produces_the_verdict_it_was_built_for) {
    const harness h(reference_time);
    CHECK(h.pki.cases.size() >= 12);
    for (const auto& c : h.pki.cases) {
        const auto rep = h.run(c, reference_time);
        if (rep.accepted != c.expect_accepted) {
            failures_.push_back({__FILE__, __LINE__,
                                 "case \"" + c.name + "\" expected " +
                                     (c.expect_accepted ? "accepted" : "rejected") + ", got " +
                                     (rep.accepted ? "accepted" : "rejected")});
        }
    }
}

TEST(chain_accepts_a_well_formed_path_and_names_every_certificate_on_it) {
    const harness h(reference_time);
    const auto rep = h.run(case_named(h, "well formed chain"), reference_time);
    CHECK(rep.accepted);
    REQUIRE(rep.path.size() == 3);
    CHECK(rep.path[0].find("sentinel.example.test") != std::string::npos);
    CHECK(rep.path[1].find("Issuing CA") != std::string::npos);
    CHECK(rep.path[2].find("Root CA") != std::string::npos);
    CHECK_EQ(rep.count(chain::status::failed), std::size_t(0));
    CHECK(rep.count(chain::status::passed) >= 7);
}

// The whole point of the report. A check that did not run must say so rather
// than be counted as a pass.
TEST(chain_reports_signature_verification_as_skipped_and_says_why) {
    const harness h(reference_time);
    const auto rep = h.run(case_named(h, "well formed chain"), reference_time);
    bool found = false;
    for (const auto& c : rep.checks) {
        if (c.name != "signature verification") continue;
        found = true;
        CHECK(c.result == chain::status::skipped);
        CHECK(c.detail.find("no cryptographic backend") != std::string::npos);
        CHECK(c.detail.find("2 issuer signature(s)") != std::string::npos);
    }
    CHECK(found);
    CHECK(rep.count(chain::status::skipped) >= 1);
}

TEST(chain_refuses_an_expired_certificate_and_names_the_check_that_failed) {
    const harness h(reference_time);
    const auto rep = h.run(case_named(h, "expired end entity certificate"), reference_time);
    CHECK(!rep.accepted);
    CHECK_EQ(first_failure(rep), std::string("validity window"));
}

TEST(chain_refuses_a_host_name_that_no_alternative_name_covers) {
    const harness h(reference_time);
    const auto rep = h.run(case_named(h, "host name not covered by the certificate"), reference_time);
    CHECK(!rep.accepted);
    CHECK_EQ(first_failure(rep), std::string("host name match"));
}

TEST(chain_refuses_an_issuer_that_is_not_a_certification_authority) {
    const harness h(reference_time);
    const auto rep =
        h.run(case_named(h, "issuer is not marked as a certification authority"), reference_time);
    CHECK(!rep.accepted);
    CHECK_EQ(first_failure(rep), std::string("basic constraints"));
}

TEST(chain_enforces_the_path_length_constraint_of_the_issuing_authority) {
    const harness h(reference_time);
    const auto rep =
        h.run(case_named(h, "path longer than pathLenConstraint allows"), reference_time);
    CHECK(!rep.accepted);
    CHECK_EQ(first_failure(rep), std::string("path length constraint"));
}

TEST(chain_refuses_a_certificate_that_may_not_be_used_for_server_authentication) {
    const harness h(reference_time);
    const auto rep =
        h.run(case_named(h, "extended key usage without server authentication"), reference_time);
    CHECK(!rep.accepted);
    CHECK_EQ(first_failure(rep), std::string("extended key usage"));
}

TEST(chain_refuses_a_certificate_whose_serial_is_on_the_revocation_list) {
    const harness h(reference_time);
    const auto rep =
        h.run(case_named(h, "serial number on the local revocation list"), reference_time);
    CHECK(!rep.accepted);
    CHECK_EQ(first_failure(rep), std::string("revocation"));
}

// RFC 5280 section 6.1: a critical extension the verifier does not understand
// means the path is refused, not that the extension is ignored.
TEST(chain_refuses_a_path_carrying_a_critical_extension_it_does_not_process) {
    const harness h(reference_time);
    const auto rep = h.run(case_named(h, "unrecognised critical extension"), reference_time);
    CHECK(!rep.accepted);
    CHECK_EQ(first_failure(rep), std::string("critical extensions"));
}

TEST(chain_applies_the_name_constraints_of_an_intermediate_authority) {
    const harness h(reference_time);
    const auto inside = h.run(case_named(h, "name inside the permitted subtree"), reference_time);
    CHECK(inside.accepted);
    const auto outside = h.run(case_named(h, "name outside the permitted subtree"), reference_time);
    CHECK(!outside.accepted);
    CHECK_EQ(first_failure(outside), std::string("name constraints"));
}

TEST(chain_reports_that_no_path_reaches_a_trust_anchor) {
    const harness h(reference_time);
    const auto rep = h.run(case_named(h, "no path to a trust anchor"), reference_time);
    CHECK(!rep.accepted);
    CHECK_EQ(rep.paths_considered, std::size_t(0));
    REQUIRE(!rep.rejected.empty());
    CHECK(rep.rejected[0].find("no issuer certificate found") != std::string::npos);
}

// Both answers to a missing revocation source are defensible, so the policy is a
// parameter. What is not acceptable is reporting a pass for a check that could
// not be carried out.
TEST(chain_revocation_policy_decides_what_a_missing_source_means) {
    harness h(reference_time);
    h.store.revocation_data_current = false;
    const auto& c = case_named(h, "well formed chain");
    const auto certs = h.parse(c);

    chain::options open;
    open.at_time = reference_time;
    open.server_name = c.server_name;
    open.on_missing_revocation = chain::revocation_policy::fail_open;
    const auto lenient = chain::validate(certs, h.store, open);
    CHECK(lenient.accepted);

    chain::options closed = open;
    closed.on_missing_revocation = chain::revocation_policy::fail_closed;
    const auto strict = chain::validate(certs, h.store, closed);
    CHECK(!strict.accepted);
    CHECK_EQ(first_failure(strict), std::string("revocation"));
}

TEST(chain_the_same_certificate_passes_before_and_fails_after_its_expiry) {
    const harness h(reference_time);
    const auto& c = case_named(h, "well formed chain");
    CHECK(h.run(c, reference_time).accepted);
    // Ninety days on, past the eighty day validity window of the end entity.
    const auto later = h.run(c, reference_time + 90 * 86400);
    CHECK(!later.accepted);
    CHECK_EQ(first_failure(later), std::string("validity window"));
}

TEST(chain_rendering_lists_the_verdict_the_path_and_every_check) {
    const harness h(reference_time);
    const auto text = chain::render(h.run(case_named(h, "well formed chain"), reference_time));
    CHECK(text.find("ACCEPTED") != std::string::npos);
    CHECK(text.find("[PASS] validity window") != std::string::npos);
    CHECK(text.find("[SKIP] signature verification") != std::string::npos);
    CHECK(text.find("Sentinel Test Root CA") != std::string::npos);
}

TEST(chain_refuses_an_empty_certificate_list) {
    const harness h(reference_time);
    chain::options opt;
    opt.at_time = reference_time;
    const auto rep = chain::validate({}, h.store, opt);
    CHECK(!rep.accepted);
    REQUIRE(!rep.checks.empty());
    CHECK_EQ(rep.checks[0].detail, std::string("no certificate was presented"));
}
