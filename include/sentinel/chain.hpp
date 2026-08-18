// Certificate path building and validation.
//
// The algorithm is the one in RFC 5280 section 6, reduced to the checks that can
// be carried out without a cryptographic backend, plus an explicit statement of
// the one check that cannot. Signature verification needs a maths library this
// project deliberately does not depend on, so it is reported as skipped rather
// than quietly left out. A report that hides a check it did not run is worse
// than no report.
#pragma once

#include <cstdint>
#include <set>
#include <string>
#include <vector>

#include "sentinel/x509.hpp"

namespace sentinel::chain {

enum class status { passed, failed, skipped };

struct check {
    std::string name;
    status result = status::passed;
    std::string detail;
};

// What to do when there is no revocation information for a certificate. Both
// answers are defensible and both are wrong in some deployment, which is exactly
// why the choice is a parameter and not a default buried in the code.
enum class revocation_policy { fail_open, fail_closed };

struct trust_store {
    std::vector<x509::certificate> anchors;
    // Serial numbers as printed by the parser, lower case hex without leading
    // zero bytes. This is a locally administered list, not a CRL fetched over
    // the network: nothing in this project opens an outbound connection.
    std::set<std::string> revoked_serials;
    bool revocation_data_current = false;

    bool is_anchor(const x509::certificate& c) const;
};

struct options {
    std::int64_t at_time = 0;  // seconds since the Unix epoch
    std::string server_name;   // empty means the name check does not apply
    std::size_t max_path_length = 8;
    bool require_server_auth = true;
    revocation_policy on_missing_revocation = revocation_policy::fail_open;
};

struct report {
    bool accepted = false;
    std::vector<std::string> path;      // leaf first, trust anchor last
    std::vector<check> checks;
    std::vector<std::string> rejected;  // one line per candidate path that failed
    std::size_t paths_considered = 0;

    std::size_t count(status s) const;
};

// presented[0] is the certificate being validated. The rest are whatever the
// peer supplied, in any order, and any of them may be unused.
report validate(const std::vector<x509::certificate>& presented, const trust_store& store,
                const options& opt);

std::string render(const report& r);

}  // namespace sentinel::chain
