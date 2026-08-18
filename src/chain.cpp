#include "sentinel/chain.hpp"

#include <algorithm>
#include <functional>

#include "sentinel/der.hpp"

namespace sentinel::chain {
namespace {

using cert_ptr = const x509::certificate*;

const char* status_text(status s) {
    switch (s) {
        case status::passed: return "PASS";
        case status::failed: return "FAIL";
        default: return "SKIP";
    }
}

struct evaluator {
    const trust_store& store;
    const options& opt;
    std::vector<check> checks;
    bool failed = false;

    void pass(std::string name, std::string detail) {
        checks.push_back({std::move(name), status::passed, std::move(detail)});
    }
    void fail(std::string name, std::string detail) {
        checks.push_back({std::move(name), status::failed, std::move(detail)});
        failed = true;
    }
    void skip(std::string name, std::string detail) {
        checks.push_back({std::move(name), status::skipped, std::move(detail)});
    }

    void run(const std::vector<cert_ptr>& path);

    void check_names(const std::vector<cert_ptr>& path);
    void check_validity(const std::vector<cert_ptr>& path);
    void check_basic_constraints(const std::vector<cert_ptr>& path);
    void check_key_usage(const std::vector<cert_ptr>& path);
    void check_extended_key_usage(const std::vector<cert_ptr>& path);
    void check_host_name(const std::vector<cert_ptr>& path);
    void check_name_constraints(const std::vector<cert_ptr>& path);
    void check_critical_extensions(const std::vector<cert_ptr>& path);
    void check_revocation(const std::vector<cert_ptr>& path);
    void check_signatures(const std::vector<cert_ptr>& path);
};

void evaluator::check_names(const std::vector<cert_ptr>& path) {
    for (std::size_t i = 0; i + 1 < path.size(); ++i) {
        if (path[i]->issuer.canonical() != path[i + 1]->subject.canonical()) {
            fail("issuer name chaining", "the issuer of " + path[i]->subject.text() +
                                             " does not match the subject of " +
                                             path[i + 1]->subject.text());
            return;
        }
    }
    pass("issuer name chaining",
         std::to_string(path.size()) + " certificate(s) link subject to issuer without a gap");
}

void evaluator::check_validity(const std::vector<cert_ptr>& path) {
    for (cert_ptr c : path) {
        if (opt.at_time < c->valid.not_before) {
            fail("validity window", c->subject.text() + " is not valid before " +
                                        der::format_time(c->valid.not_before));
            return;
        }
        if (opt.at_time > c->valid.not_after) {
            fail("validity window", c->subject.text() + " expired on " +
                                        der::format_time(c->valid.not_after));
            return;
        }
    }
    pass("validity window",
         "every certificate on the path covers " + der::format_time(opt.at_time));
}

void evaluator::check_basic_constraints(const std::vector<cert_ptr>& path) {
    std::string detail;
    for (std::size_t i = 1; i < path.size(); ++i) {
        cert_ptr c = path[i];
        if (!c->constraints.present || !c->constraints.is_ca) {
            fail("basic constraints", c->subject.text() +
                                          " signs another certificate but is not marked as a "
                                          "certification authority");
            return;
        }
        if (!c->constraints.critical) {
            detail += c->subject.text() + " has a non-critical basicConstraints; ";
        }
        // RFC 5280 section 4.2.1.9: pathLenConstraint bounds the number of
        // non-self-issued intermediates that may follow this certificate.
        if (c->constraints.has_path_len) {
            std::size_t intermediates = 0;
            for (std::size_t j = 1; j < i; ++j) {
                if (!path[j]->self_issued()) ++intermediates;
            }
            if (static_cast<std::int64_t>(intermediates) > c->constraints.path_len) {
                fail("path length constraint",
                     c->subject.text() + " allows " + std::to_string(c->constraints.path_len) +
                         " intermediate(s) below it, the path has " +
                         std::to_string(intermediates));
                return;
            }
        }
    }
    if (path[0]->constraints.present && path[0]->constraints.is_ca && path.size() > 1) {
        detail += "the end entity certificate is itself marked as a certification authority; ";
    }
    pass("basic constraints",
         detail.empty() ? "every issuer on the path is a certification authority" : detail);
    if (path.size() > 1) {
        pass("path length constraint", "no pathLenConstraint on the path is exceeded");
    }
}

void evaluator::check_key_usage(const std::vector<cert_ptr>& path) {
    for (std::size_t i = 1; i < path.size(); ++i) {
        cert_ptr c = path[i];
        if (c->usage.present && !c->usage.has(x509::ku_key_cert_sign)) {
            fail("key usage", c->subject.text() +
                                  " signs certificates but its keyUsage does not include "
                                  "keyCertSign, it has: " +
                                  c->usage.text());
            return;
        }
    }
    const x509::key_usage& leaf = path[0]->usage;
    if (leaf.present && !leaf.has(x509::ku_digital_signature) &&
        !leaf.has(x509::ku_key_encipherment) && !leaf.has(x509::ku_key_agreement)) {
        fail("key usage", "the end entity key usage " + leaf.text() +
                              " permits none of digitalSignature, keyEncipherment or keyAgreement");
        return;
    }
    pass("key usage", "end entity: " + leaf.text() +
                          (path.size() > 1 ? "; every issuer permits keyCertSign" : ""));
}

void evaluator::check_extended_key_usage(const std::vector<cert_ptr>& path) {
    const auto& eku = path[0]->extended_key_usage;
    if (eku.empty()) {
        skip("extended key usage",
             "the end entity certificate carries no extKeyUsage, so it is unconstrained");
        return;
    }
    const bool ok = std::find(eku.begin(), eku.end(), "serverAuth") != eku.end() ||
                    std::find(eku.begin(), eku.end(), "anyExtendedKeyUsage") != eku.end();
    std::string listed;
    for (const auto& p : eku) listed += (listed.empty() ? "" : ", ") + p;
    if (opt.require_server_auth && !ok) {
        fail("extended key usage",
             "server authentication was required, the certificate permits only: " + listed);
        return;
    }
    pass("extended key usage", listed);
}

void evaluator::check_host_name(const std::vector<cert_ptr>& path) {
    if (opt.server_name.empty()) {
        skip("host name match", "no server name was supplied to check against");
        return;
    }
    std::vector<std::string> dns;
    for (const auto& g : path[0]->subject_alt_names) {
        if (g.kind == x509::general_name_kind::dns) dns.push_back(g.value);
    }
    if (!dns.empty()) {
        for (const auto& pattern : dns) {
            if (x509::host_matches(pattern, opt.server_name)) {
                pass("host name match", opt.server_name + " matches the dNSName " + pattern);
                return;
            }
        }
        std::string listed;
        for (const auto& d : dns) listed += (listed.empty() ? "" : ", ") + d;
        fail("host name match", opt.server_name + " matches none of the dNSName entries: " + listed);
        return;
    }
    // RFC 6125 deprecates the common name fallback. It is applied here so that
    // certificates without a subjectAltName can still be reported on, but the
    // report says plainly that the fallback was used.
    if (const std::string* cn = path[0]->subject.find("CN")) {
        if (x509::host_matches(*cn, opt.server_name)) {
            pass("host name match", opt.server_name + " matches the common name " + *cn +
                                        "; there is no subjectAltName, which RFC 6125 deprecates");
            return;
        }
        fail("host name match", opt.server_name + " does not match the common name " + *cn);
        return;
    }
    fail("host name match", "the certificate carries neither a dNSName nor a common name");
}

void evaluator::check_name_constraints(const std::vector<cert_ptr>& path) {
    bool any = false;
    std::vector<std::string> subject_names;
    for (const auto& g : path[0]->subject_alt_names) {
        if (g.kind == x509::general_name_kind::dns) subject_names.push_back(g.value);
    }
    if (subject_names.empty() && !opt.server_name.empty()) subject_names.push_back(opt.server_name);

    for (std::size_t i = 1; i < path.size(); ++i) {
        const auto& nc = path[i]->constrained_names;
        if (!nc.present) continue;
        any = true;
        for (const auto& name : subject_names) {
            for (const auto& ex : nc.excluded) {
                if (ex.kind != x509::general_name_kind::dns) continue;
                if (x509::dns_within_subtree(ex.value, name)) {
                    fail("name constraints", name + " falls inside the excluded subtree " +
                                                 ex.value + " of " + path[i]->subject.text());
                    return;
                }
            }
            bool has_dns_permitted = false, allowed = false;
            for (const auto& pm : nc.permitted) {
                if (pm.kind != x509::general_name_kind::dns) continue;
                has_dns_permitted = true;
                if (x509::dns_within_subtree(pm.value, name)) allowed = true;
            }
            if (has_dns_permitted && !allowed) {
                fail("name constraints", name + " falls outside every permitted subtree of " +
                                             path[i]->subject.text());
                return;
            }
        }
    }
    if (!any) {
        skip("name constraints", "no certification authority on the path constrains names");
        return;
    }
    pass("name constraints", "every subject name stays inside the permitted subtrees");
}

void evaluator::check_critical_extensions(const std::vector<cert_ptr>& path) {
    for (cert_ptr c : path) {
        if (!c->unhandled_critical.empty()) {
            std::string listed;
            for (const auto& e : c->unhandled_critical) listed += (listed.empty() ? "" : ", ") + e;
            fail("critical extensions", c->subject.text() +
                                            " carries a critical extension this verifier does not "
                                            "process: " +
                                            listed);
            return;
        }
    }
    pass("critical extensions", "every critical extension on the path is understood");
}

void evaluator::check_revocation(const std::vector<cert_ptr>& path) {
    for (cert_ptr c : path) {
        if (store.revoked_serials.count(c->serial_hex)) {
            fail("revocation", c->subject.text() + " has serial " + c->serial_hex +
                                   ", which is on the local revocation list");
            return;
        }
    }
    if (!store.revocation_data_current) {
        // The policy is stated in the report either way. Failing open and calling
        // it a pass would be the dishonest option.
        if (opt.on_missing_revocation == revocation_policy::fail_closed) {
            fail("revocation",
                 "no current revocation data and the policy is fail closed, so the path is refused");
        } else {
            skip("revocation",
                 "no current revocation data and the policy is fail open, so revocation was not "
                 "established either way");
        }
        return;
    }
    pass("revocation", "no certificate on the path is on the local revocation list");
}

void evaluator::check_signatures(const std::vector<cert_ptr>& path) {
    // Stated once, plainly. The default build of this project has no third party
    // dependency at all, and the arithmetic behind a signature check belongs in a
    // reviewed cryptographic library rather than in a course project.
    skip("signature verification",
         "not performed: no cryptographic backend is compiled in, so the " +
             std::to_string(path.size() - 1) +
             " issuer signature(s) on this path were not checked");
}

void evaluator::run(const std::vector<cert_ptr>& path) {
    checks.clear();
    failed = false;
    check_names(path);
    check_validity(path);
    check_basic_constraints(path);
    check_key_usage(path);
    check_extended_key_usage(path);
    check_host_name(path);
    check_name_constraints(path);
    check_critical_extensions(path);
    check_revocation(path);
    check_signatures(path);
}

}  // namespace

bool trust_store::is_anchor(const x509::certificate& c) const {
    const std::string key = c.subject.canonical();
    for (const auto& a : anchors) {
        if (a.subject.canonical() == key && a.serial_hex == c.serial_hex) return true;
    }
    return false;
}

std::size_t report::count(status s) const {
    std::size_t n = 0;
    for (const auto& c : checks) {
        if (c.result == s) ++n;
    }
    return n;
}

report validate(const std::vector<x509::certificate>& presented, const trust_store& store,
                const options& opt) {
    report rep;
    if (presented.empty()) {
        rep.checks.push_back({"input", status::failed, "no certificate was presented"});
        return rep;
    }

    evaluator ev{store, opt, {}, false};
    std::vector<cert_ptr> path{&presented[0]};
    bool have_first_complete = false;

    // Depth first search over the candidate issuers. Every complete path is
    // evaluated, not only the first one found, because the first path to a trust
    // anchor is often not the one that validates.
    const std::function<void()> search = [&]() {
        if (rep.accepted) return;
        cert_ptr cur = path.back();
        if (store.is_anchor(*cur)) {
            ++rep.paths_considered;
            ev.run(path);
            if (!ev.failed) {
                rep.accepted = true;
                rep.checks = ev.checks;
                for (cert_ptr c : path) rep.path.push_back(c->subject.text());
                return;
            }
            if (!have_first_complete) {
                have_first_complete = true;
                rep.checks = ev.checks;
                for (cert_ptr c : path) rep.path.push_back(c->subject.text());
            }
            for (const auto& c : ev.checks) {
                if (c.result == status::failed) {
                    rep.rejected.push_back("path via " + cur->subject.text() + ": " + c.detail);
                    break;
                }
            }
            return;
        }
        if (path.size() >= opt.max_path_length) {
            rep.rejected.push_back("path through " + cur->subject.text() +
                                   " hit the length limit of " +
                                   std::to_string(opt.max_path_length));
            return;
        }

        const std::string wanted = cur->issuer.canonical();
        bool any_candidate = false;
        auto try_candidate = [&](const x509::certificate& cand) {
            if (rep.accepted) return;
            if (cand.subject.canonical() != wanted) return;
            for (cert_ptr on : path) {
                if (on == &cand) return;  // a cross signed pair must not loop
            }
            any_candidate = true;
            path.push_back(&cand);
            search();
            path.pop_back();
        };
        // Trust anchors first: the shortest path to a root is the common case and
        // trying it first keeps the search cheap.
        for (const auto& a : store.anchors) try_candidate(a);
        for (const auto& p : presented) try_candidate(p);

        if (!any_candidate) {
            rep.rejected.push_back("no issuer certificate found for " + cur->issuer.text());
        }
    };
    search();

    if (rep.checks.empty()) {
        rep.checks.push_back(
            {"path building", status::failed, "no path from the end entity to a trust anchor"});
    }
    return rep;
}

std::string render(const report& r) {
    std::string out;
    out += "  verdict                     : ";
    out += r.accepted ? "ACCEPTED" : "REJECTED";
    out += "\n";
    out += "  candidate paths evaluated   : " + std::to_string(r.paths_considered) + "\n";
    if (!r.path.empty()) {
        out += "  path (end entity first):\n";
        for (std::size_t i = 0; i < r.path.size(); ++i) {
            out += "      " + std::to_string(i) + ". " + r.path[i] + "\n";
        }
    }
    out += "  checks:\n";
    for (const auto& c : r.checks) {
        out += "      [" + std::string(status_text(c.result)) + "] " + c.name + "\n";
        if (!c.detail.empty()) out += "             " + c.detail + "\n";
    }
    out += "  summary: " + std::to_string(r.count(status::passed)) + " passed, " +
           std::to_string(r.count(status::failed)) + " failed, " +
           std::to_string(r.count(status::skipped)) + " skipped\n";
    if (!r.rejected.empty()) {
        out += "  rejected candidates:\n";
        for (const auto& s : r.rejected) out += "      " + s + "\n";
    }
    return out;
}

}  // namespace sentinel::chain
