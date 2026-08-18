// The loopback load harness: a server that applies the admission layer to real
// TCP connections, and a client that generates them.
//
// The load in every experiment in this project comes from here. It reaches the
// loopback interface of the machine it runs on and nothing else. There is no
// mode in which it can be pointed at another host, and that is a property of the
// listener, which binds 127.0.0.1, not a promise in a comment.
#pragma once

#include <atomic>
#include <cstdint>
#include <deque>
#include <thread>
#include <vector>

#include "sentinel/admission.hpp"
#include "sentinel/net.hpp"

namespace sentinel::harness {

// Fixed size messages, written big endian by hand so that two machines with
// different word orders would agree.
inline constexpr std::size_t request_bytes = 21;
inline constexpr std::size_t reply_bytes = 14;

struct wire_request {
    std::uint64_t nonce = 0;
    std::uint32_t cookie = 0;
    std::uint64_t proof = 0;
    bool second_attempt = false;
};

struct wire_reply {
    std::uint8_t result = 0;  // admission::verdict
    std::uint32_t cookie = 0;
    std::uint64_t seed = 0;
    std::uint8_t difficulty = 0;
};

void encode(const wire_request& r, std::uint8_t* out);
void decode(const std::uint8_t* in, wire_request& r);
void encode(const wire_reply& r, std::uint8_t* out);
void decode(const std::uint8_t* in, wire_reply& r);

struct server_options {
    admission::config admission;
    // How long an admitted connection keeps its entry in the accounting table.
    // The socket itself closes at once; this models the state a real server
    // holds after admitting, which is what puts the table under pressure.
    std::int64_t hold_ns = 50'000'000;
};

class server {
public:
    explicit server(const server_options& opt);
    ~server();
    server(const server&) = delete;
    server& operator=(const server&) = delete;

    bool start();
    void stop();
    std::uint16_t port() const { return listener_.port(); }

    // Valid once stop() has returned, which is when the accept thread has been
    // joined. Reading them while it runs would race with it.
    admission::stats stats() const;
    std::uint64_t connections_served() const { return served_; }
    std::size_t peak_table() const { return peak_table_; }

private:
    void run();

    server_options opt_;
    net::listener listener_;
    admission::controller controller_;
    std::thread thread_;
    std::atomic<bool> running_{false};
    std::deque<std::pair<std::uint64_t, std::int64_t>> held_;
    std::uint64_t served_ = 0;
    std::size_t peak_table_ = 0;
};

struct client_options {
    std::uint16_t port = 0;
    std::int64_t duration_ns = 0;
    std::uint64_t max_connections = 0;  // zero means no limit beyond the duration
    bool answer_challenge = true;       // a flood client never answers
    std::uint64_t seed = 1;
    std::uint64_t proof_budget = 1u << 24;
};

struct client_result {
    std::uint64_t attempts = 0;
    std::uint64_t admitted = 0;
    std::uint64_t challenged = 0;
    std::uint64_t refused = 0;
    std::uint64_t connect_failures = 0;
    std::uint64_t proof_attempts = 0;
    std::vector<double> latency_us;  // one entry per admitted connection
};

client_result run_client(const client_options& opt);

// Percentile over a copy of the samples. Returns zero for an empty set rather
// than inventing a value.
double percentile(std::vector<double> samples, double p);

}  // namespace sentinel::harness
