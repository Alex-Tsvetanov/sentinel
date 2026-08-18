#include "sentinel/harness.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>

namespace sentinel::harness {
namespace {

void put64(std::uint8_t* p, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) p[i] = static_cast<std::uint8_t>(v >> (56 - 8 * i));
}
std::uint64_t get64(const std::uint8_t* p) {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
    return v;
}
void put32(std::uint8_t* p, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) p[i] = static_cast<std::uint8_t>(v >> (24 - 8 * i));
}
std::uint32_t get32(const std::uint8_t* p) {
    std::uint32_t v = 0;
    for (int i = 0; i < 4; ++i) v = (v << 8) | p[i];
    return v;
}

// A cheap deterministic sequence for the client side. Nothing here needs to be
// unpredictable: the client is the party proving liveness, not the one being
// protected.
std::uint64_t next_value(std::uint64_t& state) {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    return state;
}

}  // namespace

void encode(const wire_request& r, std::uint8_t* out) {
    put64(out, r.nonce);
    put32(out + 8, r.cookie);
    put64(out + 12, r.proof);
    out[20] = r.second_attempt ? 1 : 0;
}

void decode(const std::uint8_t* in, wire_request& r) {
    r.nonce = get64(in);
    r.cookie = get32(in + 8);
    r.proof = get64(in + 12);
    r.second_attempt = in[20] != 0;
}

void encode(const wire_reply& r, std::uint8_t* out) {
    out[0] = r.result;
    put32(out + 1, r.cookie);
    put64(out + 5, r.seed);
    out[13] = r.difficulty;
}

void decode(const std::uint8_t* in, wire_reply& r) {
    r.result = in[0];
    r.cookie = get32(in + 1);
    r.seed = get64(in + 5);
    r.difficulty = in[13];
}

server::server(const server_options& opt)
    : opt_(opt), controller_(opt.admission, admission::random_cookie_key()) {}

server::~server() { stop(); }

bool server::start() {
    if (!listener_.open(0)) return false;
    running_ = true;
    thread_ = std::thread([this] { run(); });
    return true;
}

void server::stop() {
    if (!running_.exchange(false)) {
        if (thread_.joinable()) thread_.join();
        return;
    }
    // Unblock the accept call by connecting to it once, which is the portable
    // way to wake a blocking accept without a signal.
    listener_.close();
    if (thread_.joinable()) thread_.join();
}

void server::run() {
    std::uint8_t req_buf[request_bytes];
    std::uint8_t rep_buf[reply_bytes];
    while (running_) {
        auto conn = listener_.accept();
        if (!conn) break;

        const std::int64_t at = admission::now_ns();
        // Entries whose dwell time has passed go back before the new decision is
        // taken, so occupancy reflects the moment being measured.
        while (!held_.empty() && held_.front().second <= at) {
            controller_.release(held_.front().first);
            held_.pop_front();
        }

        if (!conn->recv_exact(req_buf, request_bytes)) continue;
        wire_request wr;
        decode(req_buf, wr);

        admission::request r;
        r.src = conn->peer_id() >> 32 << 32;  // address only, so one host is one source
        r.nonce = wr.nonce;
        r.cookie = wr.cookie;
        r.proof = wr.proof;
        r.second_attempt = wr.second_attempt;

        const auto d = controller_.admit(r, at);
        wire_reply reply;
        reply.result = static_cast<std::uint8_t>(d.result);
        reply.cookie = d.cookie;
        reply.seed = d.challenge_seed;
        reply.difficulty = d.difficulty_bits;
        encode(reply, rep_buf);
        conn->send_all(rep_buf, reply_bytes);

        if (d.conn_id) held_.emplace_back(d.conn_id, at + opt_.hold_ns);
        peak_table_ = std::max(peak_table_, controller_.table().size());
        ++served_;
        // The server closes first. The client is then the passive side of the
        // close and does not hold its ephemeral port afterwards, which is what
        // keeps a long run from exhausting the port range.
        conn->close();
    }
}

admission::stats server::stats() const { return controller_.snapshot(); }

client_result run_client(const client_options& opt) {
    client_result out;
    net::initialise();
    const std::int64_t deadline = admission::now_ns() + opt.duration_ns;
    std::uint64_t state = opt.seed | 1;
    std::uint8_t req_buf[request_bytes];
    std::uint8_t rep_buf[reply_bytes];

    while (admission::now_ns() < deadline) {
        if (opt.max_connections && out.attempts >= opt.max_connections) break;
        ++out.attempts;
        const std::int64_t started = admission::now_ns();
        const std::uint64_t nonce = next_value(state);

        auto conn = net::connect_loopback(opt.port);
        if (!conn) {
            ++out.connect_failures;
            continue;
        }
        wire_request wr;
        wr.nonce = nonce;
        encode(wr, req_buf);
        if (!conn->send_all(req_buf, request_bytes) || !conn->recv_exact(rep_buf, reply_bytes)) {
            ++out.connect_failures;
            continue;
        }
        wire_reply reply;
        decode(rep_buf, reply);
        conn->drain();
        conn->close();

        auto verdict = static_cast<admission::verdict>(reply.result);
        if (verdict == admission::verdict::challenge) {
            ++out.challenged;
            if (!opt.answer_challenge) continue;  // this is what a flood source does

            wire_request second;
            second.nonce = nonce;
            second.cookie = reply.cookie;
            second.second_attempt = true;
            if (reply.difficulty > 0) {
                admission::challenge ch{reply.seed, reply.difficulty};
                bool found = false;
                out.proof_attempts +=
                    admission::solve_challenge(ch, opt.proof_budget, second.proof, found);
                if (!found) {
                    ++out.refused;
                    continue;
                }
            }
            auto again = net::connect_loopback(opt.port);
            if (!again) {
                ++out.connect_failures;
                continue;
            }
            encode(second, req_buf);
            if (!again->send_all(req_buf, request_bytes) ||
                !again->recv_exact(rep_buf, reply_bytes)) {
                ++out.connect_failures;
                continue;
            }
            decode(rep_buf, reply);
            again->drain();
            again->close();
            verdict = static_cast<admission::verdict>(reply.result);
        }

        if (verdict == admission::verdict::accept) {
            ++out.admitted;
            out.latency_us.push_back(static_cast<double>(admission::now_ns() - started) / 1000.0);
        } else {
            ++out.refused;
        }
    }
    return out;
}

double percentile(std::vector<double> samples, double p) {
    if (samples.empty()) return 0.0;
    std::sort(samples.begin(), samples.end());
    const double pos = p * static_cast<double>(samples.size() - 1);
    const std::size_t lo = static_cast<std::size_t>(pos);
    const std::size_t hi = std::min(lo + 1, samples.size() - 1);
    const double frac = pos - static_cast<double>(lo);
    return samples[lo] * (1.0 - frac) + samples[hi] * frac;
}

}  // namespace sentinel::harness
