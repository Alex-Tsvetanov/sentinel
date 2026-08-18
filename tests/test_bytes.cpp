#include "check.hpp"
#include "sentinel/bytes.hpp"
#include "sentinel/siphash.hpp"

#include <cstdint>
#include <vector>

using namespace sentinel;

TEST(bytes_reader_reads_big_endian_fields) {
    const std::uint8_t raw[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a};
    byte_reader r{bytes_view(raw, sizeof raw)};
    CHECK_EQ(int(r.u8()), 0x01);
    CHECK_EQ(int(r.u16()), 0x0203);
    CHECK_EQ(int(r.u24()), 0x040506);
    CHECK_EQ(static_cast<std::uint64_t>(r.u32()), 0x0708090aULL);
    CHECK(r.ok());
    CHECK_EQ(r.remaining(), std::size_t(0));
}

TEST(bytes_reader_refuses_to_read_past_the_end) {
    const std::uint8_t raw[] = {0xaa, 0xbb};
    byte_reader r{bytes_view(raw, sizeof raw)};
    (void)r.u32();
    CHECK(!r.ok());
    CHECK(r.error().find("need 4") != std::string::npos);
    CHECK(r.error().find("offset 0") != std::string::npos);
}

TEST(bytes_reader_keeps_the_first_failure_reason) {
    const std::uint8_t raw[] = {0xaa};
    byte_reader r{bytes_view(raw, sizeof raw)};
    (void)r.u16();
    const std::string first = r.error();
    (void)r.u32();
    CHECK_EQ(r.error(), first);
}

TEST(bytes_reader_takes_length_prefixed_vectors) {
    const std::uint8_t raw[] = {0x03, 'a', 'b', 'c', 0x00, 0x02, 'd', 'e'};
    byte_reader r{bytes_view(raw, sizeof raw)};
    const bytes_view a = r.take_u8_prefixed();
    const bytes_view b = r.take_u16_prefixed();
    REQUIRE(r.ok());
    CHECK_EQ(a.size(), std::size_t(3));
    CHECK_EQ(b.size(), std::size_t(2));
    CHECK_EQ(to_hex(a), std::string("616263"));
    CHECK_EQ(to_hex(b), std::string("6465"));
}

TEST(bytes_reader_rejects_a_length_prefix_longer_than_the_buffer) {
    const std::uint8_t raw[] = {0x00, 0x40, 'x'};  // claims 64 bytes, one present
    byte_reader r{bytes_view(raw, sizeof raw)};
    const bytes_view v = r.take_u16_prefixed();
    CHECK(!r.ok());
    CHECK_EQ(v.size(), std::size_t(0));
}

// Reference vectors from the SipHash paper: key 00..0f, message 00..(n-1).
TEST(siphash24_matches_the_published_reference_vectors) {
    const std::uint64_t k0 = 0x0706050403020100ULL;
    const std::uint64_t k1 = 0x0f0e0d0c0b0a0908ULL;
    const std::uint64_t expected[] = {
        0x726fdb47dd0e0e31ULL, 0x74f839c593dc67fdULL, 0x0d6c8009d9a94f5aULL,
        0x85676696d7fb7e2dULL, 0xcf2794e0277187b7ULL, 0x18765564cd99a68dULL,
        0xcbc9466e58fee3ceULL, 0xab0200f58b01d137ULL, 0x93f5f5799a932462ULL,
    };
    std::vector<std::uint8_t> msg;
    for (std::size_t i = 0; i < sizeof expected / sizeof expected[0]; ++i) {
        CHECK_EQ(siphash24(bytes_view(msg.data(), msg.size()), k0, k1), expected[i]);
        msg.push_back(static_cast<std::uint8_t>(i));
    }
}

TEST(siphash24_u64_agrees_with_the_general_case) {
    const std::uint64_t k0 = 0xdeadbeefcafef00dULL, k1 = 0x0123456789abcdefULL;
    for (std::uint64_t v : {0ULL, 1ULL, 0x0102030405060708ULL, ~0ULL}) {
        std::uint8_t le[8];
        for (int i = 0; i < 8; ++i) le[i] = static_cast<std::uint8_t>(v >> (8 * i));
        CHECK_EQ(siphash24_u64(v, k0, k1), siphash24(bytes_view(le, 8), k0, k1));
    }
}
