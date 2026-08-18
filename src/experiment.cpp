#include "sentinel/experiment.hpp"

#include <algorithm>
#include <cstdio>
#include <thread>

#include "sentinel/chain.hpp"
#include "sentinel/fixtures.hpp"
#include "sentinel/harness.hpp"
#include "sentinel/tls.hpp"
#include "sentinel/x509.hpp"

namespace sentinel::experiment {
namespace {

std::string fixed(double v, int decimals) {
    char buf[64];
    std::snprintf(buf, sizeof buf, "%.*f", decimals, v);
    return buf;
}

std::string pad(const std::string& s, std::size_t width, bool right = false) {
    if (s.size() >= width) return s;
    const std::string fill(width - s.size(), ' ');
    return right ? fill + s : s + fill;
}

bytes_view view(const std::vector<std::uint8_t>& v) { return bytes_view(v.data(), v.size()); }

}  // namespace

double sample_set::median() const {
    if (values.empty()) return 0.0;
    std::vector<double> v = values;
    std::sort(v.begin(), v.end());
    const std::size_t n = v.size();
    return n % 2 ? v[n / 2] : (v[n / 2 - 1] + v[n / 2]) / 2.0;
}

double sample_set::lowest() const {
    return values.empty() ? 0.0 : *std::min_element(values.begin(), values.end());
}

double sample_set::highest() const {
    return values.empty() ? 0.0 : *std::max_element(values.begin(), values.end());
}

double sample_set::relative_spread() const {
    const double m = median();
    if (m == 0.0) return 0.0;
    return (highest() - lowest()) / m;
}

// ---------------------------------------------------------------------------
// Parsing and validation
// ---------------------------------------------------------------------------

throughput_row measure_tls_parse(std::int64_t budget_ns, int repetitions) {
    throughput_row row;
    row.name = "TLS 1.3 handshake scan and report";
    const auto stream = fixtures::tls13_stream();

    for (int rep = 0; rep < repetitions; ++rep) {
        std::uint64_t ops = 0;
        const std::int64_t start = admission::now_ns();
        std::int64_t elapsed = 0;
        while (elapsed < budget_ns) {
            for (int i = 0; i < 64; ++i) {
                auto s = tls::scan_stream(view(stream));
                if (s) {
                    auto r = tls::summarise(*s);
                    if (r) ++ops;
                }
            }
            elapsed = admission::now_ns() - start;
        }
        if (ops == 0) continue;
        row.ns_per_operation.values.push_back(static_cast<double>(elapsed) /
                                              static_cast<double>(ops));
        row.operations = ops;
    }
    row.bytes = stream.size();
    const double ns = row.ns_per_operation.median();
    if (ns > 0) {
        row.mib_per_second = static_cast<double>(row.bytes) / (ns * 1e-9) / (1024.0 * 1024.0);
    }
    return row;
}

throughput_row measure_certificate_parse(std::int64_t budget_ns, int repetitions) {
    throughput_row row;
    row.name = "X.509 certificate decode";
    const auto pki = fixtures::build_pki(1'776'000'000);
    const auto& der = pki.cases[0].der[0];

    for (int rep = 0; rep < repetitions; ++rep) {
        std::uint64_t ops = 0;
        const std::int64_t start = admission::now_ns();
        std::int64_t elapsed = 0;
        while (elapsed < budget_ns) {
            for (int i = 0; i < 256; ++i) {
                auto c = x509::parse_certificate(view(der));
                if (c) ++ops;
            }
            elapsed = admission::now_ns() - start;
        }
        if (ops == 0) continue;
        row.ns_per_operation.values.push_back(static_cast<double>(elapsed) /
                                              static_cast<double>(ops));
        row.operations = ops;
    }
    row.bytes = der.size();
    const double ns = row.ns_per_operation.median();
    if (ns > 0) {
        row.mib_per_second = static_cast<double>(row.bytes) / (ns * 1e-9) / (1024.0 * 1024.0);
    }
    return row;
}

throughput_row measure_chain_validation(std::int64_t budget_ns, int repetitions) {
    throughput_row row;
    row.name = "certificate path build and validate, three certificates";
    const std::int64_t reference = 1'776'000'000;
    const auto pki = fixtures::build_pki(reference);
    chain::trust_store store;
    if (auto root = x509::parse_certificate(view(pki.root_der))) store.anchors.push_back(*root);
    store.revoked_serials = pki.revoked_serials;
    store.revocation_data_current = true;

    const auto& c = pki.cases[0];
    std::vector<x509::certificate> presented;
    for (const auto& der : c.der) {
        if (auto p = x509::parse_certificate(view(der))) presented.push_back(*p);
    }
    chain::options opt;
    opt.at_time = reference;
    opt.server_name = c.server_name;

    for (int rep = 0; rep < repetitions; ++rep) {
        std::uint64_t ops = 0;
        const std::int64_t start = admission::now_ns();
        std::int64_t elapsed = 0;
        while (elapsed < budget_ns) {
            for (int i = 0; i < 64; ++i) {
                const auto r = chain::validate(presented, store, opt);
                if (r.accepted) ++ops;
            }
            elapsed = admission::now_ns() - start;
        }
        if (ops == 0) continue;
        row.ns_per_operation.values.push_back(static_cast<double>(elapsed) /
                                              static_cast<double>(ops));
        row.operations = ops;
    }
    row.bytes = 0;
    return row;
}

// ---------------------------------------------------------------------------
// Admission
// ---------------------------------------------------------------------------

std::vector<admission::config> standard_configurations() {
    std::vector<admission::config> out;
    admission::config baseline;  // nothing switched on
    out.push_back(baseline);

    admission::config accounting;
    accounting.accounting = true;
    out.push_back(accounting);

    admission::config rate = accounting;
    rate.rate_limit = true;
    rate.bucket_capacity = 4096;
    // Deliberately above the rate the harness can offer from one address. The
    // figure being measured is what the limiter costs when it admits, not what a
    // refusal costs, and on loopback every client shares one source address, so a
    // limit that bites would throttle the honest clients along with the flood.
    // A limiter that does bite is exercised in the tests instead.
    rate.refill_per_second = 2'000'000;
    out.push_back(rate);

    admission::config cookie = accounting;
    cookie.cookies = true;
    out.push_back(cookie);

    admission::config work = cookie;
    work.proof_of_work = true;
    work.difficulty_bits = 12;
    out.push_back(work);

    admission::config all = work;
    all.rate_limit = rate.rate_limit;
    all.bucket_capacity = rate.bucket_capacity;
    all.refill_per_second = rate.refill_per_second;
    all.degrade = true;
    out.push_back(all);
    return out;
}

decision_cost measure_decision_cost(const admission::config& cfg, std::int64_t budget_ns,
                                    int repetitions) {
    decision_cost out;
    out.configuration = cfg.label();
    out.difficulty_bits = cfg.proof_of_work ? cfg.difficulty_bits : 0;

    // The client side cost of the proof, measured separately because it is paid
    // by the other party and shows up as latency, not as server load.
    if (cfg.proof_of_work) {
        const std::int64_t start = admission::now_ns();
        std::uint64_t attempts = 0;
        int solved = 0;
        for (int i = 0; i < 16; ++i) {
            admission::challenge ch{static_cast<std::uint64_t>(i) * 0x9e3779b9ULL,
                                    cfg.difficulty_bits};
            std::uint64_t nonce = 0;
            bool found = false;
            attempts += admission::solve_challenge(ch, 1u << 26, nonce, found);
            if (found) ++solved;
        }
        const double total_ms = static_cast<double>(admission::now_ns() - start) / 1e6;
        if (solved > 0) {
            out.proof_solve_ms = total_ms / solved;
            out.proof_attempts = attempts / static_cast<std::uint64_t>(solved);
        }
    }

    for (int rep = 0; rep < repetitions; ++rep) {
        admission::controller c(cfg, admission::cookie_key{0x1122334455667788ULL,
                                                           0x99aabbccddeeff00ULL});
        // A proof is solved once and reused, so that the timing measures the
        // server side verification and not the client side search.
        std::uint64_t reusable_proof = 0;
        std::uint32_t reusable_cookie = 0;
        const std::int64_t now = admission::now_ns();
        if (cfg.cookies) {
            admission::request warm;
            warm.src = 1;
            warm.nonce = 1;
            const auto d = c.admit(warm, now);
            reusable_cookie = d.cookie;
            if (cfg.proof_of_work) {
                admission::challenge ch{d.challenge_seed, d.difficulty_bits};
                bool found = false;
                admission::solve_challenge(ch, 1u << 26, reusable_proof, found);
            }
        }

        // The timestamp handed to the controller advances by a microsecond per
        // decision. A frozen clock would empty the token bucket after its
        // capacity and turn the rest of the run into a measurement of the
        // refusal path, which is not the quantity wanted here. The step is small
        // enough that the whole repetition stays inside two cookie time slots.
        constexpr std::int64_t step_ns = 1000;
        constexpr std::uint64_t iteration_cap = 1'000'000;

        std::uint64_t ops = 0;
        std::uint64_t not_admitted = 0;
        const std::int64_t start = admission::now_ns();
        std::int64_t elapsed = 0;
        while (elapsed < budget_ns && ops < iteration_cap) {
            for (int i = 0; i < 256; ++i) {
                admission::request r;
                r.src = 1;
                r.nonce = 1;
                r.cookie = reusable_cookie;
                r.proof = reusable_proof;
                r.second_attempt = cfg.cookies;
                const auto d = c.admit(r, now + static_cast<std::int64_t>(ops) * step_ns);
                if (d.conn_id) c.release(d.conn_id);
                if (d.result != admission::verdict::accept) ++not_admitted;
                ++ops;
            }
            elapsed = admission::now_ns() - start;
        }
        if (ops == 0) continue;
        out.decisions_not_admitted += not_admitted;
        out.ns_per_decision.values.push_back(static_cast<double>(elapsed) /
                                             static_cast<double>(ops));
    }
    return out;
}

load_row run_load(const admission::config& cfg, const load_params& p) {
    load_row row;
    row.configuration = cfg.label();

    for (int rep = 0; rep < p.repetitions; ++rep) {
        harness::server_options opt;
        opt.admission = cfg;
        opt.admission.table_capacity = p.table_capacity;
        opt.hold_ns = p.hold_ns;
        harness::server server(opt);
        if (!server.start()) continue;

        std::vector<std::thread> threads;
        std::vector<harness::client_result> honest(static_cast<std::size_t>(p.honest_threads));
        std::vector<harness::client_result> flood(static_cast<std::size_t>(p.flood_threads));

        const std::int64_t start = admission::now_ns();
        for (int i = 0; i < p.honest_threads; ++i) {
            threads.emplace_back([&, i] {
                harness::client_options c;
                c.port = server.port();
                c.duration_ns = p.duration_ns;
                c.answer_challenge = true;
                c.seed = 0x1000 + static_cast<std::uint64_t>(i);
                honest[static_cast<std::size_t>(i)] = harness::run_client(c);
            });
        }
        for (int i = 0; i < p.flood_threads; ++i) {
            threads.emplace_back([&, i] {
                harness::client_options c;
                c.port = server.port();
                c.duration_ns = p.duration_ns;
                c.answer_challenge = false;  // the defining behaviour of the flood
                c.seed = 0x2000 + static_cast<std::uint64_t>(i);
                flood[static_cast<std::size_t>(i)] = harness::run_client(c);
            });
        }
        for (auto& t : threads) t.join();
        const double seconds = static_cast<double>(admission::now_ns() - start) / 1e9;
        server.stop();

        std::vector<double> latency;
        std::uint64_t admitted = 0, refused = 0;
        for (const auto& r : honest) {
            admitted += r.admitted;
            refused += r.refused;
            latency.insert(latency.end(), r.latency_us.begin(), r.latency_us.end());
        }
        for (const auto& r : flood) refused += r.refused;

        const auto st = server.stats();
        row.admitted_per_second.values.push_back(static_cast<double>(admitted) / seconds);
        row.decisions_per_second.values.push_back(static_cast<double>(st.offered) / seconds);
        row.p50_us.values.push_back(harness::percentile(latency, 0.50));
        row.p95_us.values.push_back(harness::percentile(latency, 0.95));
        row.admitted = admitted;
        row.refused = refused;
        row.offered = st.offered;
        row.peak_table = std::max(row.peak_table, server.peak_table());
        row.state_bytes = std::max(row.state_bytes, st.state_bytes);
    }
    return row;
}

std::vector<load_row> run_load_sweep(const load_params& p) {
    std::vector<load_row> rows;
    for (const auto& cfg : standard_configurations()) rows.push_back(run_load(cfg, p));
    return rows;
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

std::string render_throughput(const std::vector<throughput_row>& rows) {
    std::string out;
    out += "  " + pad("operation", 52) + pad("ns/op", 12, true) + pad("ops/s", 14, true) +
           pad("spread", 10, true) + "\n";
    out += "  " + std::string(88, '-') + "\n";
    for (const auto& r : rows) {
        const double ns = r.ns_per_operation.median();
        out += "  " + pad(r.name, 58) + pad(fixed(ns, 1), 12, true) +
               pad(ns > 0 ? fixed(1e9 / ns, 0) : std::string("n/a"), 14, true) +
               pad(fixed(r.ns_per_operation.relative_spread() * 100.0, 1) + "%", 10, true) + "\n";
        if (r.mib_per_second > 0) {
            out += "  " + pad("", 58) + pad(fixed(r.mib_per_second, 1) + " MiB/s over " +
                                                std::to_string(r.bytes) + " bytes",
                                            36, true) +
                   "\n";
        }
    }
    return out;
}

std::string render_decision_costs(const std::vector<decision_cost>& rows) {
    std::string out;
    out += "  " + pad("configuration", 64) + pad("ns/decision", 14, true) +
           pad("spread", 10, true) + pad("client proof", 16, true) + "\n";
    out += "  " + std::string(104, '-') + "\n";
    for (const auto& r : rows) {
        std::string proof = "none";
        if (r.difficulty_bits > 0) {
            proof = fixed(r.proof_solve_ms, 2) + " ms";
        }
        out += "  " + pad(r.configuration, 64) +
               pad(fixed(r.ns_per_decision.median(), 1), 14, true) +
               pad(fixed(r.ns_per_decision.relative_spread() * 100.0, 1) + "%", 10, true) +
               pad(proof, 16, true) + "\n";
        if (r.difficulty_bits > 0) {
            out += "  " + pad("", 64) +
                   pad(std::to_string(r.proof_attempts) + " hashes at " +
                           std::to_string(r.difficulty_bits) + " bits",
                       40, true) +
                   "\n";
        }
    }
    return out;
}

std::string render_load(const std::vector<load_row>& rows) {
    std::string out;
    out += "  " + pad("configuration", 64) + pad("admitted/s", 13, true) + pad("p50 us", 11, true) +
           pad("p95 us", 11, true) + pad("decisions/s", 13, true) + pad("peak tbl", 10, true) +
           pad("state B", 10, true) + "\n";
    out += "  " + std::string(132, '-') + "\n";
    double baseline = 0;
    for (const auto& r : rows) {
        if (baseline == 0) baseline = r.admitted_per_second.median();
        out += "  " + pad(r.configuration, 64) +
               pad(fixed(r.admitted_per_second.median(), 0), 13, true) +
               pad(fixed(r.p50_us.median(), 1), 11, true) +
               pad(fixed(r.p95_us.median(), 1), 11, true) +
               pad(fixed(r.decisions_per_second.median(), 0), 13, true) +
               pad(std::to_string(r.peak_table), 10, true) +
               pad(std::to_string(r.state_bytes), 10, true) + "\n";
    }
    if (baseline > 0) {
        out += "\n  relative to the baseline configuration:\n";
        for (const auto& r : rows) {
            const double ratio = r.admitted_per_second.median() / baseline * 100.0;
            out += "      " + pad(r.configuration, 64) + pad(fixed(ratio, 1) + "%", 10, true) +
                   " of baseline throughput\n";
        }
    }
    return out;
}

std::string machine_description() {
    std::string out;
    out += "compiler        : ";
#if defined(__clang__)
    out += "clang " + std::to_string(__clang_major__) + "." + std::to_string(__clang_minor__) + "." +
           std::to_string(__clang_patchlevel__);
#elif defined(__GNUC__)
    out += "gcc " + std::to_string(__GNUC__) + "." + std::to_string(__GNUC_MINOR__) + "." +
           std::to_string(__GNUC_PATCHLEVEL__);
#elif defined(_MSC_VER)
    out += "msvc " + std::to_string(_MSC_VER);
#else
    out += "unknown";
#endif
    out += "\n  platform        : ";
#if defined(_WIN32)
    out += "Windows";
#elif defined(__APPLE__)
    out += "macOS";
#elif defined(__linux__)
    out += "Linux";
#else
    out += "unknown";
#endif
    out += "\n  hardware threads: " + std::to_string(std::thread::hardware_concurrency());
    out += "\n  build type      : ";
#if defined(NDEBUG)
    out += "optimised, assertions off";
#else
    out += "assertions on";
#endif
    out += "\n  clock           : std::chrono::steady_clock, ";
    out += std::to_string(static_cast<long long>(std::chrono::steady_clock::period::den /
                                                 std::chrono::steady_clock::period::num));
    out += " ticks per second";
    return out;
}

}  // namespace sentinel::experiment
