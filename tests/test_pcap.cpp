#include "check.hpp"
#include "sentinel/fixtures.hpp"
#include "sentinel/pcap.hpp"
#include "sentinel/tls.hpp"

#include <algorithm>
#include <string>
#include <vector>

using namespace sentinel;

TEST(pcap_round_trips_a_generated_tls_stream_through_ethernet_frames) {
    const auto tls = fixtures::tls13_stream("sentinel.example.test", false);
    const auto cap_bytes = fixtures::tls_stream_as_pcap(tls, 400);
    CHECK(cap_bytes.size() > tls.size());

    auto cap = pcap::parse(bytes_view(cap_bytes.data(), cap_bytes.size()));
    REQUIRE(cap.ok());
    CHECK(!cap->swapped);
    CHECK_EQ(cap->version_major, std::uint16_t(2));
    CHECK(cap->network == pcap::linktype::ethernet);
    CHECK(cap->packets.size() >= 2);

    auto extracted = pcap::extract_tcp_payloads(*cap);
    REQUIRE(extracted.ok());
    CHECK_EQ(extracted->size(), tls.size());
    CHECK(std::equal(extracted->begin(), extracted->end(), tls.begin()));

    auto scan = tls::scan_stream(bytes_view(extracted->data(), extracted->size()));
    REQUIRE(scan.ok());
    auto rep = tls::summarise(*scan);
    REQUIRE(rep.ok());
    CHECK_EQ(rep->negotiated_version, std::string("TLS 1.3"));
    CHECK_EQ(rep->server_name, std::string("sentinel.example.test"));
}

TEST(pcap_tls_stream_from_pcap_matches_direct_scan) {
    const auto tls = fixtures::tls13_stream("pcap.example.test", true);
    const auto cap_bytes = fixtures::tls_stream_as_pcap(tls, 256);
    auto from_pcap = pcap::tls_stream_from_pcap(bytes_view(cap_bytes.data(), cap_bytes.size()));
    REQUIRE(from_pcap.ok());

    auto a = tls::summarise(*tls::scan_stream(bytes_view(tls.data(), tls.size())));
    auto b = tls::summarise(*tls::scan_stream(bytes_view(from_pcap->data(), from_pcap->size())));
    REQUIRE(a.ok());
    REQUIRE(b.ok());
    CHECK_EQ(a->negotiated_version, b->negotiated_version);
    CHECK_EQ(a->cipher_suite_text, b->cipher_suite_text);
    CHECK_EQ(a->selected_group, b->selected_group);
    CHECK_EQ(a->server_name, b->server_name);
}

TEST(pcap_refuses_unrecognised_magic) {
    const std::uint8_t junk[24] = {};
    auto cap = pcap::parse(bytes_view(junk, sizeof junk));
    CHECK(!cap.ok());
    CHECK(cap.error().find("magic") != std::string::npos);
}

TEST(pcap_refuses_nanosecond_variant) {
    std::vector<std::uint8_t> hdr(24, 0);
    // 0xa1b23c4d little-endian on disk.
    hdr[0] = 0x4d;
    hdr[1] = 0x3c;
    hdr[2] = 0xb2;
    hdr[3] = 0xa1;
    auto cap = pcap::parse(bytes_view(hdr.data(), hdr.size()));
    CHECK(!cap.ok());
    CHECK(cap.error().find("nanosecond") != std::string::npos);
}

TEST(pcap_refuses_truncated_global_header) {
    const std::uint8_t short_hdr[8] = {0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00};
    CHECK(!pcap::parse(bytes_view(short_hdr, sizeof short_hdr)).ok());
}
