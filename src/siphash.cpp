#include "sentinel/siphash.hpp"

#include <cstdio>
#include <string>

namespace sentinel {
namespace {

inline std::uint64_t rotl(std::uint64_t x, int b) {
    return (x << b) | (x >> (64 - b));
}

struct state {
    std::uint64_t v0, v1, v2, v3;

    void round() {
        v0 += v1;
        v1 = rotl(v1, 13);
        v1 ^= v0;
        v0 = rotl(v0, 32);
        v2 += v3;
        v3 = rotl(v3, 16);
        v3 ^= v2;
        v0 += v3;
        v3 = rotl(v3, 21);
        v3 ^= v0;
        v2 += v1;
        v1 = rotl(v1, 17);
        v1 ^= v2;
        v2 = rotl(v2, 32);
    }

    void absorb(std::uint64_t m) {
        v3 ^= m;
        round();
        round();  // the 2 of SipHash-2-4
        v0 ^= m;
    }

    std::uint64_t finish() {
        v2 ^= 0xff;
        round();
        round();
        round();
        round();  // the 4 of SipHash-2-4
        return v0 ^ v1 ^ v2 ^ v3;
    }
};

state init(std::uint64_t k0, std::uint64_t k1) {
    return {k0 ^ 0x736f6d6570736575ULL, k1 ^ 0x646f72616e646f6dULL,
            k0 ^ 0x6c7967656e657261ULL, k1 ^ 0x7465646279746573ULL};
}

}  // namespace

std::uint64_t siphash24(bytes_view msg, std::uint64_t k0, std::uint64_t k1) {
    state s = init(k0, k1);
    const std::size_t n = msg.size();
    std::size_t i = 0;
    for (; i + 8 <= n; i += 8) {
        std::uint64_t m = 0;
        for (int b = 7; b >= 0; --b) m = (m << 8) | msg[i + static_cast<std::size_t>(b)];
        s.absorb(m);
    }
    // Final partial word, with the message length modulo 256 in the top byte.
    std::uint64_t tail = static_cast<std::uint64_t>(n & 0xff) << 56;
    for (std::size_t b = n - i; b-- > 0;) {
        tail |= static_cast<std::uint64_t>(msg[i + b]) << (8 * b);
    }
    s.absorb(tail);
    return s.finish();
}

std::uint64_t siphash24_u64(std::uint64_t msg, std::uint64_t k0, std::uint64_t k1) {
    state s = init(k0, k1);
    s.absorb(msg);
    s.absorb(8ULL << 56);  // length byte, no remaining input
    return s.finish();
}

std::string to_hex(bytes_view b, std::size_t max_bytes) {
    const std::size_t n = (max_bytes && b.size() > max_bytes) ? max_bytes : b.size();
    std::string out;
    out.reserve(n * 2 + 4);
    char buf[3];
    for (std::size_t i = 0; i < n; ++i) {
        std::snprintf(buf, sizeof buf, "%02x", b[i]);
        out += buf;
    }
    if (n < b.size()) out += "...";
    return out;
}

}  // namespace sentinel
