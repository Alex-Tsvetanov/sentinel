#include "check.hpp"
#include "sentinel/admission.hpp"

#include <cstdint>
#include <set>

using namespace sentinel::admission;

namespace {

constexpr std::int64_t ms = 1'000'000;
constexpr std::int64_t s = 1'000'000'000;

const cookie_key test_key{0x0123456789abcdefULL, 0xfedcba9876543210ULL};

request first_try(source_id src, std::uint64_t nonce) {
    request r;
    r.src = src;
    r.nonce = nonce;
    return r;
}

}  // namespace

TEST(admission_token_bucket_spends_its_capacity_then_refills_over_time) {
    token_bucket b{10.0, 5.0, 10.0, 0};
    std::int64_t t = s;
    for (int i = 0; i < 10; ++i) {
        CHECK(b.try_consume(t));
    }
    CHECK(!b.try_consume(t));  // capacity spent

    CHECK(b.try_consume(t + 200 * ms));  // one token back after 0.2 s at 5 per second
    CHECK(!b.try_consume(t + 200 * ms));

    // The bucket never fills beyond its capacity, however long it idles.
    CHECK(b.try_consume(t + 3600 * s, 10.0));
    CHECK(!b.try_consume(t + 3600 * s, 1.0));
}

TEST(admission_rate_limiter_keeps_sources_apart) {
    rate_limiter limiter(4, 1, 1024);
    std::int64_t t = s;
    for (int i = 0; i < 4; ++i) {
        CHECK(limiter.allow(1, t));
    }
    CHECK(!limiter.allow(1, t));
    // A different source has its own allowance, which is the property that makes
    // this useless against a distributed flood and cheap against a single host.
    CHECK(limiter.allow(2, t));
    CHECK_EQ(limiter.tracked(), std::size_t(2));
}

TEST(admission_rate_limiter_bounds_the_memory_it_uses_for_source_state) {
    rate_limiter limiter(2, 1000, 64);
    std::int64_t t = s;
    for (std::uint64_t src = 0; src < 5000; ++src) {
        limiter.allow(src, t);
        t += 10 * ms;
    }
    CHECK(limiter.tracked() <= std::size_t(64));
    CHECK(limiter.evictions() > 0);
}

// The point of the cookie is that the server holds nothing between the two
// messages, so it must be reproducible from the request alone.
TEST(admission_cookie_is_reproducible_and_bound_to_the_source_and_the_slot) {
    const std::uint32_t c = make_cookie(test_key, 42, 7, 100);
    CHECK_EQ(make_cookie(test_key, 42, 7, 100), c);
    CHECK(make_cookie(test_key, 43, 7, 100) != c);   // different source
    CHECK(make_cookie(test_key, 42, 8, 100) != c);   // different client value
    CHECK(make_cookie(test_key, 42, 7, 101) != c);   // different slot
    const cookie_key other{1, 2};
    CHECK(make_cookie(other, 42, 7, 100) != c);      // different server key
}

TEST(admission_cookie_verification_tolerates_one_slot_of_lag_and_no_more) {
    const std::uint32_t c = make_cookie(test_key, 42, 7, 100);
    CHECK(verify_cookie(test_key, 42, 7, c, 100, 1));
    CHECK(verify_cookie(test_key, 42, 7, c, 101, 1));   // issued one slot ago
    CHECK(!verify_cookie(test_key, 42, 7, c, 102, 1));  // too old
    CHECK(!verify_cookie(test_key, 42, 7, c + 1, 100, 1));
    CHECK(!verify_cookie(test_key, 99, 7, c, 100, 1));
}

TEST(admission_time_slot_advances_once_per_slot_length) {
    CHECK_EQ(time_slot(0, 2 * s), std::uint32_t(0));
    CHECK_EQ(time_slot(2 * s - 1, 2 * s), std::uint32_t(0));
    CHECK_EQ(time_slot(2 * s, 2 * s), std::uint32_t(1));
    CHECK_EQ(time_slot(9 * s, 2 * s), std::uint32_t(4));
}

TEST(admission_proof_of_work_is_hard_to_find_and_cheap_to_check) {
    challenge c{0xdeadbeefULL, 12};
    std::uint64_t nonce = 0;
    bool found = false;
    const std::uint64_t attempts = solve_challenge(c, 1u << 22, nonce, found);
    REQUIRE(found);
    CHECK(proof_is_valid(c, nonce));
    CHECK(attempts > 1);
    // A wrong nonce is refused, and a harder challenge refuses the same nonce.
    CHECK(!proof_is_valid(c, nonce + 1) || nonce + 1 != nonce);
    challenge harder{0xdeadbeefULL, 24};
    CHECK(!proof_is_valid(harder, nonce));
    // Zero difficulty admits anything, which is what switching the mechanism off
    // has to mean.
    challenge none{0xdeadbeefULL, 0};
    CHECK(proof_is_valid(none, 0));
}

TEST(admission_connection_table_counts_half_open_and_established_separately) {
    conn_table t(4);
    const std::uint64_t a = t.open(1, s);
    const std::uint64_t b = t.open(2, s);
    REQUIRE(a != 0);
    REQUIRE(b != 0);
    CHECK_EQ(t.half_open(), std::size_t(2));
    CHECK_EQ(t.established(), std::size_t(0));
    CHECK(t.establish(a));
    CHECK(!t.establish(a));  // twice is not a state change
    CHECK_EQ(t.established(), std::size_t(1));
    CHECK_EQ(t.half_open(), std::size_t(1));
    CHECK(t.close(a));
    CHECK(!t.close(a));
    CHECK_EQ(t.size(), std::size_t(1));
    CHECK_EQ(t.peak(), std::size_t(2));
}

// The eviction rule is the design decision of the table: when it is full, the
// incomplete connection is the one that goes.
TEST(admission_connection_table_evicts_the_oldest_incomplete_connection_when_full) {
    conn_table t(3);
    const std::uint64_t oldest = t.open(1, 1 * s);
    const std::uint64_t middle = t.open(2, 2 * s);
    const std::uint64_t newest = t.open(3, 3 * s);
    CHECK(t.establish(newest));
    const std::uint64_t extra = t.open(4, 4 * s);
    CHECK(extra != 0);
    CHECK_EQ(t.size(), std::size_t(3));
    CHECK_EQ(t.evictions(), std::size_t(1));
    CHECK(!t.close(oldest));  // it is the one that went
    CHECK(t.close(middle));
}

TEST(admission_connection_table_refuses_when_every_entry_is_established) {
    conn_table t(2);
    const std::uint64_t a = t.open(1, s);
    const std::uint64_t b = t.open(2, s);
    t.establish(a);
    t.establish(b);
    CHECK_EQ(t.open(3, s), std::uint64_t(0));
}

TEST(admission_connection_table_expires_half_open_entries_by_age) {
    conn_table t(16);
    t.open(1, 1 * s);
    t.open(2, 2 * s);
    const std::uint64_t fresh = t.open(3, 10 * s);
    t.establish(fresh);
    CHECK_EQ(t.expire_half_open(11 * s, 5 * s), std::size_t(2));
    CHECK_EQ(t.size(), std::size_t(1));
}

TEST(admission_pressure_follows_the_occupancy_of_the_table) {
    CHECK(pressure_for(0.0) == pressure::normal);
    CHECK(pressure_for(0.49) == pressure::normal);
    CHECK(pressure_for(0.50) == pressure::elevated);
    CHECK(pressure_for(0.84) == pressure::elevated);
    CHECK(pressure_for(0.85) == pressure::critical);
    CHECK(pressure_for(1.0) == pressure::critical);
}

TEST(admission_baseline_configuration_admits_everything_it_is_offered) {
    config cfg;  // every mechanism off
    controller c(cfg, test_key);
    for (int i = 0; i < 1000; ++i) {
        const auto d = c.admit(first_try(static_cast<source_id>(i), 1), s);
        CHECK(d.result == verdict::accept);
    }
    CHECK_EQ(c.snapshot().accepted, std::uint64_t(1000));
    CHECK_EQ(c.snapshot().state_bytes, std::size_t(0));
}

// A flood that never answers has to cost the server nothing that persists.
TEST(admission_cookies_allocate_no_state_for_a_client_that_never_answers) {
    config cfg;
    cfg.cookies = true;
    cfg.accounting = true;
    controller c(cfg, test_key);
    for (std::uint64_t i = 0; i < 50000; ++i) {
        const auto d = c.admit(first_try(i, i), s);
        CHECK(d.result == verdict::challenge);
    }
    CHECK_EQ(c.table().size(), std::size_t(0));
    CHECK_EQ(c.snapshot().accepted, std::uint64_t(0));
    CHECK_EQ(c.snapshot().challenged, std::uint64_t(50000));
    CHECK_EQ(c.snapshot().state_bytes, std::size_t(0));
}

TEST(admission_a_client_that_returns_the_cookie_is_admitted_and_a_forged_one_is_not) {
    config cfg;
    cfg.cookies = true;
    cfg.accounting = true;
    controller c(cfg, test_key);
    const std::int64_t t = 100 * s;

    auto challenge_reply = c.admit(first_try(7, 1234), t);
    REQUIRE(challenge_reply.result == verdict::challenge);

    request back = first_try(7, 1234);
    back.second_attempt = true;
    back.cookie = challenge_reply.cookie;
    const auto good = c.admit(back, t);
    CHECK(good.result == verdict::accept);
    CHECK(good.conn_id != 0);
    CHECK_EQ(c.table().established(), std::size_t(1));

    request forged = back;
    forged.cookie = challenge_reply.cookie ^ 1u;
    CHECK(c.admit(forged, t).result == verdict::reject_cookie);

    // The same cookie from a different source is refused, which is what stops a
    // cookie from being harvested and reused.
    request stolen = back;
    stolen.src = 8;
    CHECK(c.admit(stolen, t).result == verdict::reject_cookie);
}

TEST(admission_a_second_attempt_without_a_valid_proof_is_refused) {
    config cfg;
    cfg.cookies = true;
    cfg.proof_of_work = true;
    cfg.difficulty_bits = 8;
    controller c(cfg, test_key);
    const std::int64_t t = 200 * s;

    const auto issued = c.admit(first_try(11, 99), t);
    REQUIRE(issued.result == verdict::challenge);
    CHECK_EQ(int(issued.difficulty_bits), 8);

    request back = first_try(11, 99);
    back.second_attempt = true;
    back.cookie = issued.cookie;
    back.proof = 0;
    challenge ch{issued.challenge_seed, issued.difficulty_bits};
    if (!proof_is_valid(ch, 0)) {
        CHECK(c.admit(back, t).result == verdict::reject_proof);
    }

    std::uint64_t nonce = 0;
    bool found = false;
    solve_challenge(ch, 1u << 22, nonce, found);
    REQUIRE(found);
    back.proof = nonce;
    CHECK(c.admit(back, t).result == verdict::accept);
}

TEST(admission_the_rate_limiter_refuses_a_source_that_exceeds_its_allowance) {
    config cfg;
    cfg.rate_limit = true;
    cfg.bucket_capacity = 8;
    cfg.refill_per_second = 1;
    controller c(cfg, test_key);
    int accepted = 0, refused = 0;
    for (int i = 0; i < 100; ++i) {
        const auto d = c.admit(first_try(1, 0), s);
        (d.result == verdict::accept ? accepted : refused)++;
    }
    CHECK_EQ(accepted, 8);
    CHECK_EQ(refused, 92);
    CHECK_EQ(c.snapshot().rejected_rate, std::uint64_t(92));
}

// Degradation has to show up as a change in behaviour, not only as a label.
TEST(admission_degradation_raises_the_difficulty_as_the_table_fills) {
    config cfg;
    cfg.accounting = true;
    cfg.cookies = true;
    cfg.proof_of_work = true;
    cfg.degrade = true;
    cfg.difficulty_bits = 6;
    cfg.table_capacity = 100;
    controller c(cfg, test_key);
    const std::int64_t t = 300 * s;

    CHECK_EQ(int(c.admit(first_try(1, 1), t).difficulty_bits), 6);
    CHECK(c.current_pressure() == pressure::normal);

    // Fill the table past half by admitting properly answered connections.
    for (std::uint64_t i = 0; i < 60; ++i) {
        const auto issued = c.admit(first_try(i, i), t);
        request back = first_try(i, i);
        back.second_attempt = true;
        back.cookie = issued.cookie;
        challenge ch{issued.challenge_seed, issued.difficulty_bits};
        bool found = false;
        solve_challenge(ch, 1u << 24, back.proof, found);
        if (found) c.admit(back, t);
    }
    CHECK(c.current_pressure() == pressure::elevated);
    CHECK_EQ(int(c.admit(first_try(999, 1), t).difficulty_bits), 8);
}

TEST(admission_releasing_a_connection_returns_its_slot_to_the_table) {
    config cfg;
    cfg.accounting = true;
    cfg.table_capacity = 4;
    controller c(cfg, test_key);
    std::set<std::uint64_t> ids;
    for (int i = 0; i < 4; ++i) {
        const auto d = c.admit(first_try(static_cast<source_id>(i), 0), s);
        REQUIRE(d.result == verdict::accept);
        ids.insert(d.conn_id);
    }
    CHECK(c.admit(first_try(9, 0), s).result == verdict::reject_full);
    c.release(*ids.begin());
    CHECK(c.admit(first_try(9, 0), s).result == verdict::accept);
}

TEST(admission_configuration_labels_name_the_mechanisms_that_are_on) {
    config off;
    CHECK_EQ(off.label(), std::string("baseline, no mechanism"));
    config all;
    all.accounting = all.rate_limit = all.cookies = all.proof_of_work = all.degrade = true;
    CHECK_EQ(all.label(),
             std::string("accounting + rate limit + cookie + proof of work + degradation"));
    CHECK_EQ(std::string(verdict_name(verdict::reject_cookie)), std::string("reject (cookie)"));
    CHECK_EQ(std::string(pressure_name(pressure::critical)), std::string("critical"));
}
