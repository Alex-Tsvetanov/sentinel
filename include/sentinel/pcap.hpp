// Classic pcap (libpcap savefile) reader, implemented in-tree.
//
// Enough of the file format to pull TLS record bytes out of a capture that this
// project wrote itself. There is no link against libpcap: the on-disk layout is
// small and stable, and linking a capture library would contradict the build
// promise. This is not a general reassembly engine; payloads are concatenated
// in file order for IPv4/TCP packets on the link types listed below.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "sentinel/bytes.hpp"

namespace sentinel::pcap {

// Link-layer header types from the tcpdump.org LINKTYPE registry that this
// reader understands. Anything else is refused with a clear reason.
enum class linktype : std::uint32_t {
    ethernet = 1,   // LINKTYPE_ETHERNET
    raw = 101,      // LINKTYPE_RAW (IPv4 or IPv6 directly)
    linux_sll = 113,
};

struct packet {
    std::uint32_t ts_sec = 0;
    std::uint32_t ts_usec = 0;
    std::vector<std::uint8_t> data;  // link-layer frame as stored
};

struct file {
    bool swapped = false;  // true when the file was written in the opposite endianness
    std::uint16_t version_major = 0;
    std::uint16_t version_minor = 0;
    std::uint32_t snaplen = 0;
    linktype network = linktype::ethernet;
    std::vector<packet> packets;
};

// Parses a classic pcap buffer (magic 0xa1b2c3d4 or the swapped 0xd4c3b2a1).
// Nanosecond variants (0xa1b23c4d) are refused rather than misread.
result<file> parse(bytes_view bytes);

// Reads a whole file into memory. Used by tests and the demo; the filesystem is
// otherwise unused by the analysis layers.
result<std::vector<std::uint8_t>> read_file(const std::string& path);

// Concatenates IPv4 TCP payloads in capture order. Enough for an ordered
// single-flow fixture; not a substitute for full TCP reassembly.
result<std::vector<std::uint8_t>> extract_tcp_payloads(const file& cap);

// Convenience: parse then extract.
result<std::vector<std::uint8_t>> tls_stream_from_pcap(bytes_view pcap_bytes);

}  // namespace sentinel::pcap
