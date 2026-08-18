// Connection admission control for a server under flood conditions.
//
// Four mechanisms, each switchable on its own, because the question this project
// asks is not which one is best but what each one costs:
//
//   1. a token bucket per source,
//   2. a stateless cryptographic cookie in the manner of RFC 4987, so that no
//      state is allocated before the client has proved it can receive,
//   3. a proof of work challenge that moves cost to the client,
//   4. a connection table with accounting and eviction, which is what makes the
//      other three measurable.
//
// The graceful degradation policy sits on top and tightens the first three as
// the table fills.
//
// None of this is an attack tool. It is the receiving side of a flood, and the
// load in the experiments comes from this project's own loopback harness.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace sentinel::admission {

// A source address folded to 64 bits. Which bits go in is the caller's business:
// the experiments use the peer address and port, and a deployment would use the
// address alone so that one host cannot buy more allowance by opening more ports.
using source_id = std::uint64_t;

std::int64_t now_ns();

// ---------------------------------------------------------------------------
// Token bucket
// ---------------------------------------------------------------------------

struct token_bucket {
    double capacity = 0;
    double refill_per_second = 0;
    double tokens = 0;
    std::int64_t last_ns = 0;

    void refill(std::int64_t at_ns);
    bool try_consume(std::int64_t at_ns, double n = 1.0);
    bool idle(std::int64_t at_ns) const;
};

class rate_limiter {
public:
    rate_limiter(double capacity, double refill_per_second, std::size_t max_sources);

    bool allow(source_id src, std::int64_t at_ns, double scale = 1.0);
    std::size_t tracked() const { return buckets_.size(); }
    std::size_t evictions() const { return evictions_; }

private:
    void make_room(std::int64_t at_ns);

    double capacity_;
    double refill_;
    std::size_t max_sources_;
    std::size_t evictions_ = 0;
    std::unordered_map<source_id, token_bucket> buckets_;
};

// ---------------------------------------------------------------------------
// Stateless cookie
// ---------------------------------------------------------------------------

struct cookie_key {
    std::uint64_t k0 = 0;
    std::uint64_t k1 = 0;
};

cookie_key random_cookie_key();

// The cookie binds the source, the value the client chose, and a coarse time
// slot. The server keeps nothing: it recomputes the cookie when the client
// echoes it back, which is the property RFC 4987 is after.
std::uint32_t make_cookie(const cookie_key& key, source_id src, std::uint64_t client_nonce,
                          std::uint32_t slot);
std::uint32_t time_slot(std::int64_t at_ns, std::int64_t slot_ns);
bool verify_cookie(const cookie_key& key, source_id src, std::uint64_t client_nonce,
                   std::uint32_t cookie, std::uint32_t current_slot, std::uint32_t tolerance);

// ---------------------------------------------------------------------------
// Proof of work
// ---------------------------------------------------------------------------

struct challenge {
    std::uint64_t seed = 0;
    std::uint8_t difficulty_bits = 0;
};

bool proof_is_valid(const challenge& c, std::uint64_t nonce);
// Searches for a nonce. Returns the number of attempts, and sets found to false
// if the budget ran out first.
std::uint64_t solve_challenge(const challenge& c, std::uint64_t max_attempts, std::uint64_t& nonce,
                              bool& found);

// ---------------------------------------------------------------------------
// Connection accounting
// ---------------------------------------------------------------------------

class conn_table {
public:
    explicit conn_table(std::size_t capacity) : capacity_(capacity) {}

    // Returns 0 when there is no room even after eviction.
    std::uint64_t open(source_id src, std::int64_t at_ns);
    bool establish(std::uint64_t id);
    bool close(std::uint64_t id);
    std::size_t expire_half_open(std::int64_t at_ns, std::int64_t max_age_ns);

    std::size_t size() const { return entries_.size(); }
    std::size_t capacity() const { return capacity_; }
    std::size_t half_open() const { return entries_.size() - established_; }
    std::size_t established() const { return established_; }
    std::size_t evictions() const { return evictions_; }
    std::size_t peak() const { return peak_; }
    double occupancy() const {
        return capacity_ ? static_cast<double>(entries_.size()) / static_cast<double>(capacity_) : 1.0;
    }
    // Bytes of state held per connection, so the memory cost of a mechanism can
    // be stated rather than estimated.
    static std::size_t bytes_per_entry();

private:
    struct entry {
        source_id src = 0;
        std::int64_t opened_ns = 0;
        bool established = false;
    };
    std::size_t capacity_;
    std::size_t established_ = 0;
    std::size_t evictions_ = 0;
    std::size_t peak_ = 0;
    std::uint64_t next_id_ = 1;
    std::unordered_map<std::uint64_t, entry> entries_;
};

// ---------------------------------------------------------------------------
// Degradation policy
// ---------------------------------------------------------------------------

enum class pressure { normal, elevated, critical };
pressure pressure_for(double occupancy);
const char* pressure_name(pressure p);

// ---------------------------------------------------------------------------
// The controller
// ---------------------------------------------------------------------------

struct config {
    bool rate_limit = false;
    bool cookies = false;
    bool proof_of_work = false;
    bool accounting = false;
    bool degrade = false;

    double bucket_capacity = 64;
    double refill_per_second = 20000;
    std::size_t max_tracked_sources = 8192;
    std::size_t table_capacity = 8192;
    std::uint8_t difficulty_bits = 10;
    std::int64_t cookie_slot_ns = 2'000'000'000;
    std::uint32_t cookie_slot_tolerance = 1;

    std::string label() const;
};

enum class verdict {
    accept,
    challenge,      // no state allocated, the client must come back with the cookie
    reject_rate,
    reject_cookie,
    reject_proof,
    reject_full,
};

const char* verdict_name(verdict v);

struct request {
    source_id src = 0;
    std::uint64_t nonce = 0;      // chosen by the client, echoed in the cookie
    std::uint32_t cookie = 0;     // returned by the client on the second attempt
    std::uint64_t proof = 0;      // proof of work nonce, when one was demanded
    bool second_attempt = false;
};

struct decision {
    verdict result = verdict::accept;
    const char* reason = "";
    std::uint32_t cookie = 0;
    std::uint64_t challenge_seed = 0;
    std::uint8_t difficulty_bits = 0;
    std::uint64_t conn_id = 0;
};

struct stats {
    std::uint64_t offered = 0;
    std::uint64_t accepted = 0;
    std::uint64_t challenged = 0;
    std::uint64_t rejected_rate = 0;
    std::uint64_t rejected_cookie = 0;
    std::uint64_t rejected_proof = 0;
    std::uint64_t rejected_full = 0;
    std::size_t peak_table = 0;
    std::size_t evictions = 0;
    std::size_t tracked_sources = 0;
    std::size_t state_bytes = 0;
};

// One accept loop owns one controller. Nothing here takes a lock: a shared
// counter behind a mutex would put the measurement inside the thing being
// measured.
class controller {
public:
    controller(const config& cfg, cookie_key key);

    decision admit(const request& req, std::int64_t at_ns);
    void release(std::uint64_t conn_id);

    const config& settings() const { return cfg_; }
    stats snapshot() const;
    conn_table& table() { return table_; }
    pressure current_pressure() const;

private:
    std::uint8_t effective_difficulty(pressure p) const;

    config cfg_;
    cookie_key key_;
    rate_limiter limiter_;
    conn_table table_;
    stats stats_;
};

}  // namespace sentinel::admission
