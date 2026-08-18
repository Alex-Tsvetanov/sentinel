// The measurements.
//
// Every number this project reports comes from one of the functions below, run
// on the machine that reports it. Nothing here has a default value that stands
// in for a measurement, and no function returns an estimate.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "sentinel/admission.hpp"

namespace sentinel::experiment {

// A repeated timing. The median is reported and the spread is reported with it,
// because a median on its own hides a run that went wrong.
struct sample_set {
    std::vector<double> values;
    double median() const;
    double lowest() const;
    double highest() const;
    // Spread as a fraction of the median, the quantity the validity rule in the
    // method uses to decide whether a set of repetitions may be reported.
    double relative_spread() const;
};

struct throughput_row {
    std::string name;
    std::uint64_t operations = 0;
    std::uint64_t bytes = 0;
    sample_set ns_per_operation;
    double mib_per_second = 0;
};

throughput_row measure_tls_parse(std::int64_t budget_ns, int repetitions);
throughput_row measure_chain_validation(std::int64_t budget_ns, int repetitions);
throughput_row measure_certificate_parse(std::int64_t budget_ns, int repetitions);

// The cost of one admission decision inside the process, with no socket in the
// way. This is the overhead the mechanism itself adds.
struct decision_cost {
    std::string configuration;
    sample_set ns_per_decision;
    double proof_solve_ms = 0;      // client side, zero when no proof is demanded
    std::uint64_t proof_attempts = 0;
    std::uint8_t difficulty_bits = 0;
    // Decisions in the timed loop that were not admissions. Any value other than
    // zero means the row timed a mixture of the accept path and a refusal path,
    // and the number is printed rather than quietly averaged in.
    std::uint64_t decisions_not_admitted = 0;
};

std::vector<admission::config> standard_configurations();
decision_cost measure_decision_cost(const admission::config& cfg, std::int64_t budget_ns,
                                    int repetitions);

// The end to end experiment: real connections over loopback, honest clients and
// flood clients at the same time.
struct load_params {
    std::int64_t duration_ns = 400'000'000;
    int honest_threads = 2;
    int flood_threads = 4;
    int repetitions = 3;
    std::int64_t hold_ns = 20'000'000;
    std::size_t table_capacity = 2048;
};

struct load_row {
    std::string configuration;
    sample_set admitted_per_second;
    sample_set p50_us;
    sample_set p95_us;
    sample_set decisions_per_second;
    std::uint64_t admitted = 0;
    std::uint64_t offered = 0;
    std::uint64_t refused = 0;
    std::size_t peak_table = 0;
    std::size_t state_bytes = 0;
};

load_row run_load(const admission::config& cfg, const load_params& p);
std::vector<load_row> run_load_sweep(const load_params& p);

std::string render_throughput(const std::vector<throughput_row>& rows);
std::string render_decision_costs(const std::vector<decision_cost>& rows);
std::string render_load(const std::vector<load_row>& rows);

// The machine the numbers were taken on, read at run time rather than written
// down, so a result copied from another machine cannot pass as this one.
std::string machine_description();

}  // namespace sentinel::experiment
