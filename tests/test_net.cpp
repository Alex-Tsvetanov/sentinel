#include "check.hpp"
#include "sentinel/harness.hpp"
#include "sentinel/net.hpp"

#include <thread>

using namespace sentinel;

namespace {
constexpr std::int64_t ms = 1'000'000;
}

TEST(net_listener_binds_loopback_and_carries_a_message_both_ways) {
    net::initialise();
    net::listener l;
    REQUIRE(l.open(0));
    CHECK(l.port() != 0);

    std::thread server([&l] {
        auto c = l.accept();
        if (!c) return;
        std::uint8_t buf[4]{};
        if (c->recv_exact(buf, sizeof buf)) {
            for (auto& b : buf) b = static_cast<std::uint8_t>(b + 1);
            c->send_all(buf, sizeof buf);
        }
        c->close();
    });

    auto client = net::connect_loopback(l.port());
    REQUIRE(client.has_value());
    const std::uint8_t out[4] = {1, 2, 3, 4};
    CHECK(client->send_all(out, sizeof out));
    std::uint8_t in[4]{};
    CHECK(client->recv_exact(in, sizeof in));
    CHECK_EQ(int(in[0]), 2);
    CHECK_EQ(int(in[3]), 5);
    client->close();
    server.join();
    l.close();
}

TEST(net_connecting_to_a_port_nobody_listens_on_fails_rather_than_blocking) {
    net::initialise();
    // Bind then close, so the port is known to be free at this instant.
    net::listener l;
    REQUIRE(l.open(0));
    const std::uint16_t port = l.port();
    l.close();
    auto c = net::connect_loopback(port);
    CHECK(!c.has_value());
}

TEST(harness_messages_survive_a_round_trip_through_their_byte_form) {
    harness::wire_request in;
    in.nonce = 0x0123456789abcdefULL;
    in.cookie = 0xdeadbeef;
    in.proof = 0xfedcba9876543210ULL;
    in.second_attempt = true;
    std::uint8_t buf[harness::request_bytes];
    harness::encode(in, buf);
    harness::wire_request out;
    harness::decode(buf, out);
    CHECK_EQ(out.nonce, in.nonce);
    CHECK_EQ(out.cookie, in.cookie);
    CHECK_EQ(out.proof, in.proof);
    CHECK(out.second_attempt);

    harness::wire_reply r_in;
    r_in.result = 3;
    r_in.cookie = 0x11223344;
    r_in.seed = 0x5566778899aabbccULL;
    r_in.difficulty = 17;
    std::uint8_t rbuf[harness::reply_bytes];
    harness::encode(r_in, rbuf);
    harness::wire_reply r_out;
    harness::decode(rbuf, r_out);
    CHECK_EQ(r_out.result, r_in.result);
    CHECK_EQ(r_out.cookie, r_in.cookie);
    CHECK_EQ(r_out.seed, r_in.seed);
    CHECK_EQ(r_out.difficulty, r_in.difficulty);
}

// End to end over real sockets: with no mechanism on, every offered connection
// is admitted, which is the baseline every other measurement is compared with.
TEST(harness_baseline_server_admits_every_connection_it_is_offered) {
    harness::server_options opt;
    opt.admission.accounting = true;
    opt.hold_ns = 0;
    harness::server s(opt);
    REQUIRE(s.start());

    harness::client_options c;
    c.port = s.port();
    c.duration_ns = 2000 * ms;
    c.max_connections = 40;
    const auto result = harness::run_client(c);
    s.stop();

    CHECK_EQ(result.attempts, std::uint64_t(40));
    CHECK_EQ(result.admitted, std::uint64_t(40));
    CHECK_EQ(result.refused, std::uint64_t(0));
    CHECK_EQ(result.challenged, std::uint64_t(0));
    CHECK(result.latency_us.size() == 40);
    CHECK(harness::percentile(result.latency_us, 0.5) > 0.0);
}

// The property the cookie exists for, observed over sockets rather than argued
// about: a source that never answers leaves nothing behind on the server.
TEST(harness_a_client_that_never_answers_the_cookie_leaves_no_state_behind) {
    harness::server_options opt;
    opt.admission.cookies = true;
    opt.admission.accounting = true;
    opt.hold_ns = 60'000'000'000;  // a minute, so nothing expires during the test
    harness::server s(opt);
    REQUIRE(s.start());

    harness::client_options flood;
    flood.port = s.port();
    flood.duration_ns = 2000 * ms;
    flood.max_connections = 60;
    flood.answer_challenge = false;
    const auto flooded = harness::run_client(flood);

    harness::client_options honest = flood;
    honest.answer_challenge = true;
    honest.max_connections = 10;
    honest.seed = 12345;
    const auto completed = harness::run_client(honest);
    s.stop();

    CHECK_EQ(flooded.challenged, std::uint64_t(60));
    CHECK_EQ(flooded.admitted, std::uint64_t(0));
    CHECK_EQ(completed.admitted, std::uint64_t(10));

    const auto st = s.stats();
    CHECK_EQ(st.challenged, std::uint64_t(70));  // every first attempt
    CHECK_EQ(st.accepted, std::uint64_t(10));    // only the ones that answered
    // Sixty unanswered attempts cost the table nothing at all.
    CHECK(s.peak_table() <= std::size_t(10));
}

TEST(harness_rate_limiting_refuses_a_single_source_that_goes_too_fast) {
    harness::server_options opt;
    opt.admission.rate_limit = true;
    opt.admission.bucket_capacity = 5;
    opt.admission.refill_per_second = 1;
    harness::server s(opt);
    REQUIRE(s.start());

    harness::client_options c;
    c.port = s.port();
    c.duration_ns = 3000 * ms;
    c.max_connections = 30;
    const auto result = harness::run_client(c);
    s.stop();

    // The loopback client and the server share one address, so the whole run
    // draws on one bucket.
    CHECK(result.admitted >= std::uint64_t(5));
    CHECK(result.admitted <= std::uint64_t(10));
    CHECK(result.refused >= std::uint64_t(20));
    CHECK(s.stats().rejected_rate >= std::uint64_t(20));
}

TEST(harness_percentiles_are_reported_only_when_there_are_samples) {
    CHECK_EQ(harness::percentile({}, 0.5), 0.0);
    CHECK_EQ(harness::percentile({5.0}, 0.95), 5.0);
    CHECK_EQ(harness::percentile({1.0, 2.0, 3.0, 4.0}, 0.0), 1.0);
    CHECK_EQ(harness::percentile({1.0, 2.0, 3.0, 4.0}, 1.0), 4.0);
    CHECK_EQ(harness::percentile({1.0, 2.0, 3.0, 4.0}, 0.5), 2.5);
}
