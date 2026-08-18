#include "sentinel/admission.hpp"

#include <algorithm>
#include <chrono>
#include <random>

#include "sentinel/siphash.hpp"

namespace sentinel::admission {

std::int64_t now_ns() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

// ---------------------------------------------------------------------------

void token_bucket::refill(std::int64_t at_ns) {
    if (last_ns == 0) {
        last_ns = at_ns;
        return;
    }
    const double elapsed = static_cast<double>(at_ns - last_ns) * 1e-9;
    if (elapsed <= 0) return;
    tokens = std::min(capacity, tokens + elapsed * refill_per_second);
    last_ns = at_ns;
}

bool token_bucket::try_consume(std::int64_t at_ns, double n) {
    refill(at_ns);
    if (tokens < n) return false;
    tokens -= n;
    return true;
}

bool token_bucket::idle(std::int64_t at_ns) const {
    if (refill_per_second <= 0) return false;
    const double elapsed = static_cast<double>(at_ns - last_ns) * 1e-9;
    return tokens + elapsed * refill_per_second >= capacity;
}

rate_limiter::rate_limiter(double capacity, double refill_per_second, std::size_t max_sources)
    : capacity_(capacity), refill_(refill_per_second), max_sources_(max_sources) {}

// A source whose bucket has refilled to the brim is indistinguishable from one
// that has never been seen, so its entry carries no information and can go.
// ponytail: this is a linear sweep, run only when the table is full. If the
// source count ever gets large enough for that to show up in a profile, the
// replacement is a bounded LRU, not a cleverer sweep.
void rate_limiter::make_room(std::int64_t at_ns) {
    for (auto it = buckets_.begin(); it != buckets_.end();) {
        if (it->second.idle(at_ns)) {
            it = buckets_.erase(it);
            ++evictions_;
        } else {
            ++it;
        }
    }
    if (buckets_.size() >= max_sources_ && !buckets_.empty()) {
        // Everything is active. Drop one entry so the table stays bounded; the
        // source loses its history and starts again with a full bucket, which
        // errs towards admitting rather than refusing.
        buckets_.erase(buckets_.begin());
        ++evictions_;
    }
}

bool rate_limiter::allow(source_id src, std::int64_t at_ns, double scale) {
    auto it = buckets_.find(src);
    if (it == buckets_.end()) {
        if (buckets_.size() >= max_sources_) make_room(at_ns);
        token_bucket b;
        b.capacity = capacity_;
        b.refill_per_second = refill_;
        b.tokens = capacity_;
        b.last_ns = at_ns;
        it = buckets_.emplace(src, b).first;
    }
    return it->second.try_consume(at_ns, scale);
}

// ---------------------------------------------------------------------------

cookie_key random_cookie_key() {
    std::random_device rd;
    auto draw = [&rd] {
        return (static_cast<std::uint64_t>(rd()) << 32) ^ rd();
    };
    return cookie_key{draw(), draw()};
}

std::uint32_t time_slot(std::int64_t at_ns, std::int64_t slot_ns) {
    if (slot_ns <= 0) return 0;
    return static_cast<std::uint32_t>(at_ns / slot_ns);
}

std::uint32_t make_cookie(const cookie_key& key, source_id src, std::uint64_t client_nonce,
                          std::uint32_t slot) {
    // Two rounds so that neither the source nor the client value can be varied
    // independently of the other without changing the result.
    const std::uint64_t mixed = siphash24_u64(src ^ (static_cast<std::uint64_t>(slot) << 32),
                                              key.k0, key.k1);
    const std::uint64_t full = siphash24_u64(client_nonce ^ mixed, key.k0, key.k1);
    // Truncated to 32 bits, the width a sequence number field offers. A guess
    // succeeds with probability 2^-32 per try, which is the same bound the
    // mechanism has in the transport it is modelled on.
    return static_cast<std::uint32_t>(full ^ (full >> 32));
}

bool verify_cookie(const cookie_key& key, source_id src, std::uint64_t client_nonce,
                   std::uint32_t cookie, std::uint32_t current_slot, std::uint32_t tolerance) {
    // The slot has to be allowed to lag, otherwise every client whose reply
    // crosses a slot boundary is refused.
    for (std::uint32_t back = 0; back <= tolerance; ++back) {
        if (back > current_slot) break;
        if (make_cookie(key, src, client_nonce, current_slot - back) == cookie) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------

namespace {
constexpr std::uint64_t pow_key1 = 0x9e3779b97f4a7c15ULL;
}

bool proof_is_valid(const challenge& c, std::uint64_t nonce) {
    if (c.difficulty_bits == 0) return true;
    if (c.difficulty_bits >= 64) return false;
    const std::uint64_t h = siphash24_u64(nonce, c.seed, pow_key1);
    return (h >> (64 - c.difficulty_bits)) == 0;
}

std::uint64_t solve_challenge(const challenge& c, std::uint64_t max_attempts, std::uint64_t& nonce,
                             bool& found) {
    found = false;
    for (std::uint64_t i = 0; i < max_attempts; ++i) {
        if (proof_is_valid(c, i)) {
            nonce = i;
            found = true;
            return i + 1;
        }
    }
    nonce = 0;
    return max_attempts;
}

// ---------------------------------------------------------------------------

std::size_t conn_table::bytes_per_entry() {
    // The payload plus the key. A hash table has per-node overhead on top of
    // this; the figure below is the part the design controls.
    return sizeof(entry) + sizeof(std::uint64_t);
}

std::uint64_t conn_table::open(source_id src, std::int64_t at_ns) {
    if (entries_.size() >= capacity_) {
        // Full. Drop the oldest connection that has not completed: an incomplete
        // connection is the cheaper thing to lose, and under a flood it is
        // overwhelmingly likely to be part of the flood.
        std::uint64_t oldest = 0;
        std::int64_t oldest_ns = 0;
        for (const auto& [id, e] : entries_) {
            if (e.established) continue;
            if (oldest == 0 || e.opened_ns < oldest_ns) {
                oldest = id;
                oldest_ns = e.opened_ns;
            }
        }
        if (oldest == 0) return 0;  // everything is established, refuse instead
        entries_.erase(oldest);
        ++evictions_;
    }
    const std::uint64_t id = next_id_++;
    entries_.emplace(id, entry{src, at_ns, false});
    peak_ = std::max(peak_, entries_.size());
    return id;
}

bool conn_table::establish(std::uint64_t id) {
    auto it = entries_.find(id);
    if (it == entries_.end() || it->second.established) return false;
    it->second.established = true;
    ++established_;
    return true;
}

bool conn_table::close(std::uint64_t id) {
    auto it = entries_.find(id);
    if (it == entries_.end()) return false;
    if (it->second.established) --established_;
    entries_.erase(it);
    return true;
}

std::size_t conn_table::expire_half_open(std::int64_t at_ns, std::int64_t max_age_ns) {
    std::size_t removed = 0;
    for (auto it = entries_.begin(); it != entries_.end();) {
        if (!it->second.established && at_ns - it->second.opened_ns > max_age_ns) {
            it = entries_.erase(it);
            ++removed;
            ++evictions_;
        } else {
            ++it;
        }
    }
    return removed;
}

// ---------------------------------------------------------------------------

pressure pressure_for(double occupancy) {
    if (occupancy >= 0.85) return pressure::critical;
    if (occupancy >= 0.50) return pressure::elevated;
    return pressure::normal;
}

const char* pressure_name(pressure p) {
    switch (p) {
        case pressure::normal: return "normal";
        case pressure::elevated: return "elevated";
        default: return "critical";
    }
}

const char* verdict_name(verdict v) {
    switch (v) {
        case verdict::accept: return "accept";
        case verdict::challenge: return "challenge";
        case verdict::reject_rate: return "reject (rate)";
        case verdict::reject_cookie: return "reject (cookie)";
        case verdict::reject_proof: return "reject (proof)";
        default: return "reject (table full)";
    }
}

std::string config::label() const {
    if (!rate_limit && !cookies && !proof_of_work && !accounting && !degrade) {
        return "baseline, no mechanism";
    }
    std::string s;
    auto add = [&s](const char* n) {
        if (!s.empty()) s += " + ";
        s += n;
    };
    if (accounting) add("accounting");
    if (rate_limit) add("rate limit");
    if (cookies) add("cookie");
    if (proof_of_work) add("proof of work");
    if (degrade) add("degradation");
    return s;
}

controller::controller(const config& cfg, cookie_key key)
    : cfg_(cfg),
      key_(key),
      limiter_(cfg.bucket_capacity, cfg.refill_per_second, cfg.max_tracked_sources),
      table_(cfg.table_capacity) {}

pressure controller::current_pressure() const {
    if (!cfg_.accounting) return pressure::normal;
    return pressure_for(table_.occupancy());
}

std::uint8_t controller::effective_difficulty(pressure p) const {
    if (!cfg_.degrade) return cfg_.difficulty_bits;
    switch (p) {
        case pressure::normal: return cfg_.difficulty_bits;
        case pressure::elevated: return static_cast<std::uint8_t>(cfg_.difficulty_bits + 2);
        default: return static_cast<std::uint8_t>(cfg_.difficulty_bits + 4);
    }
}

decision controller::admit(const request& req, std::int64_t at_ns) {
    ++stats_.offered;
    decision d;
    const pressure p = current_pressure();

    // 1. Rate limiting first: it is the cheapest test, and under degradation it
    // costs a source two tokens instead of one.
    if (cfg_.rate_limit) {
        const double cost = (cfg_.degrade && p != pressure::normal) ? 2.0 : 1.0;
        if (!limiter_.allow(req.src, at_ns, cost)) {
            ++stats_.rejected_rate;
            d.result = verdict::reject_rate;
            d.reason = "the source has spent its allowance";
            return d;
        }
    }

    // 2. The cookie. On a first attempt nothing is allocated: the client is sent
    // a value it must return, which proves it can receive at the address it
    // claimed. This is the whole point of the mechanism.
    const std::uint32_t slot = time_slot(at_ns, cfg_.cookie_slot_ns);
    if (cfg_.cookies && !req.second_attempt) {
        ++stats_.challenged;
        d.result = verdict::challenge;
        d.reason = "return the cookie to be admitted; no state was allocated";
        d.cookie = make_cookie(key_, req.src, req.nonce, slot);
        d.challenge_seed = cfg_.proof_of_work ? (d.cookie | (static_cast<std::uint64_t>(slot) << 32))
                                              : 0;
        d.difficulty_bits = cfg_.proof_of_work ? effective_difficulty(p) : 0;
        return d;
    }
    if (cfg_.cookies) {
        if (!verify_cookie(key_, req.src, req.nonce, req.cookie, slot, cfg_.cookie_slot_tolerance)) {
            ++stats_.rejected_cookie;
            d.result = verdict::reject_cookie;
            d.reason = "the cookie does not belong to this source, value and time slot";
            return d;
        }
    }

    // 3. Proof of work, verified in a single hash.
    if (cfg_.proof_of_work && req.second_attempt) {
        challenge c;
        c.seed = req.cookie | (static_cast<std::uint64_t>(slot) << 32);
        c.difficulty_bits = effective_difficulty(p);
        if (!proof_is_valid(c, req.proof)) {
            // The seed may have been issued in the previous slot, exactly as with
            // the cookie, so the tolerated slots are tried before refusing.
            bool ok = false;
            for (std::uint32_t back = 1; back <= cfg_.cookie_slot_tolerance && !ok; ++back) {
                if (back > slot) break;
                challenge older = c;
                older.seed = req.cookie | (static_cast<std::uint64_t>(slot - back) << 32);
                ok = proof_is_valid(older, req.proof);
            }
            if (!ok) {
                ++stats_.rejected_proof;
                d.result = verdict::reject_proof;
                d.reason = "the proof of work does not meet the required difficulty";
                return d;
            }
        }
    }

    // 4. Only now is state allocated.
    if (cfg_.accounting) {
        // Under critical pressure the server stops taking new half open
        // connections from clients that have not already proved liveness. This
        // is the degradation policy: shed the cheapest traffic first.
        if (cfg_.degrade && p == pressure::critical && cfg_.cookies && !req.second_attempt) {
            ++stats_.rejected_full;
            d.result = verdict::reject_full;
            d.reason = "under critical pressure, only clients that returned a cookie are admitted";
            return d;
        }
        const std::uint64_t id = table_.open(req.src, at_ns);
        if (id == 0) {
            ++stats_.rejected_full;
            d.result = verdict::reject_full;
            d.reason = "the connection table is full of established connections";
            return d;
        }
        table_.establish(id);
        d.conn_id = id;
    }
    ++stats_.accepted;
    d.result = verdict::accept;
    d.reason = "admitted";
    return d;
}

void controller::release(std::uint64_t conn_id) {
    if (conn_id) table_.close(conn_id);
}

stats controller::snapshot() const {
    stats s = stats_;
    s.peak_table = table_.peak();
    s.evictions = table_.evictions() + limiter_.evictions();
    s.tracked_sources = limiter_.tracked();
    s.state_bytes = table_.size() * conn_table::bytes_per_entry() +
                    limiter_.tracked() * (sizeof(token_bucket) + sizeof(source_id));
    return s;
}

}  // namespace sentinel::admission
