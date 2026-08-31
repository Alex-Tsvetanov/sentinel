#include "sentinel/pcap.hpp"

#include <fstream>

namespace sentinel::pcap {
namespace {

std::uint16_t rd16(const std::uint8_t* p, bool swap) {
    const std::uint16_t v = static_cast<std::uint16_t>(p[0] | (p[1] << 8));
    if (!swap) return v;
    return static_cast<std::uint16_t>((v << 8) | (v >> 8));
}

std::uint32_t rd32(const std::uint8_t* p, bool swap) {
    const std::uint32_t v = static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
                            (static_cast<std::uint32_t>(p[2]) << 16) |
                            (static_cast<std::uint32_t>(p[3]) << 24);
    if (!swap) return v;
    return (v << 24) | ((v << 8) & 0x00ff0000u) | ((v >> 8) & 0x0000ff00u) | (v >> 24);
}

std::uint16_t be16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}

result<bytes_view> ipv4_tcp_payload(bytes_view ip_packet) {
    if (ip_packet.size() < 20) {
        return result<bytes_view>::failure("IPv4 header is truncated");
    }
    const std::uint8_t vihl = ip_packet[0];
    if ((vihl >> 4) != 4) {
        return result<bytes_view>::failure("not an IPv4 packet");
    }
    const std::size_t ihl = static_cast<std::size_t>(vihl & 0x0f) * 4;
    if (ihl < 20 || ip_packet.size() < ihl) {
        return result<bytes_view>::failure("IPv4 header length is invalid");
    }
    if (ip_packet[9] != 6) {  // TCP
        return result<bytes_view>::failure("not a TCP packet");
    }
    const std::size_t total = be16(ip_packet.data() + 2);
    if (total < ihl || total > ip_packet.size()) {
        return result<bytes_view>::failure("IPv4 total length is inconsistent");
    }
    bytes_view tcp = ip_packet.subspan(ihl, total - ihl);
    if (tcp.size() < 20) {
        return result<bytes_view>::failure("TCP header is truncated");
    }
    const std::size_t data_off = static_cast<std::size_t>((tcp[12] >> 4) * 4);
    if (data_off < 20 || data_off > tcp.size()) {
        return result<bytes_view>::failure("TCP data offset is invalid");
    }
    return tcp.subspan(data_off);
}

result<bytes_view> frame_to_ip(bytes_view frame, linktype lt) {
    switch (lt) {
        case linktype::ethernet: {
            if (frame.size() < 14) {
                return result<bytes_view>::failure("Ethernet frame is truncated");
            }
            const std::uint16_t ethertype = be16(frame.data() + 12);
            if (ethertype != 0x0800) {
                return result<bytes_view>::failure("Ethernet ethertype is not IPv4");
            }
            return frame.subspan(14);
        }
        case linktype::raw:
            return frame;
        case linktype::linux_sll: {
            // Linux cooked capture: 16-byte header, protocol at offset 14.
            if (frame.size() < 16) {
                return result<bytes_view>::failure("Linux cooked frame is truncated");
            }
            const std::uint16_t proto = be16(frame.data() + 14);
            if (proto != 0x0800) {
                return result<bytes_view>::failure("Linux cooked protocol is not IPv4");
            }
            return frame.subspan(16);
        }
    }
    return result<bytes_view>::failure("unsupported link type");
}

}  // namespace

result<std::vector<std::uint8_t>> read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return result<std::vector<std::uint8_t>>::failure("cannot open " + path);
    }
    in.seekg(0, std::ios::end);
    const auto n = in.tellg();
    if (n < 0) {
        return result<std::vector<std::uint8_t>>::failure("cannot size " + path);
    }
    in.seekg(0, std::ios::beg);
    std::vector<std::uint8_t> buf(static_cast<std::size_t>(n));
    if (!buf.empty()) {
        in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
        if (!in) {
            return result<std::vector<std::uint8_t>>::failure("short read of " + path);
        }
    }
    return buf;
}

result<file> parse(bytes_view bytes) {
    if (bytes.size() < 24) {
        return result<file>::failure("pcap file shorter than the 24-byte global header");
    }
    const std::uint32_t magic = static_cast<std::uint32_t>(bytes[0]) |
                                (static_cast<std::uint32_t>(bytes[1]) << 8) |
                                (static_cast<std::uint32_t>(bytes[2]) << 16) |
                                (static_cast<std::uint32_t>(bytes[3]) << 24);
    bool swap = false;
    if (magic == 0xa1b2c3d4u) {
        swap = false;
    } else if (magic == 0xd4c3b2a1u) {
        swap = true;
    } else if (magic == 0xa1b23c4du || magic == 0x4d3cb2a1u) {
        return result<file>::failure("nanosecond pcap variant is not supported");
    } else {
        return result<file>::failure("unrecognised pcap magic");
    }

    file out;
    out.swapped = swap;
    out.version_major = rd16(bytes.data() + 4, swap);
    out.version_minor = rd16(bytes.data() + 6, swap);
    out.snaplen = rd32(bytes.data() + 16, swap);
    const std::uint32_t network = rd32(bytes.data() + 20, swap);
    if (network != static_cast<std::uint32_t>(linktype::ethernet) &&
        network != static_cast<std::uint32_t>(linktype::raw) &&
        network != static_cast<std::uint32_t>(linktype::linux_sll)) {
        return result<file>::failure("unsupported pcap network link type " +
                                     std::to_string(network));
    }
    out.network = static_cast<linktype>(network);
    if (out.version_major != 2) {
        return result<file>::failure("unsupported pcap major version " +
                                     std::to_string(out.version_major));
    }

    std::size_t off = 24;
    while (off < bytes.size()) {
        if (bytes.size() - off < 16) {
            return result<file>::failure("truncated pcap packet header");
        }
        packet pkt;
        pkt.ts_sec = rd32(bytes.data() + off, swap);
        pkt.ts_usec = rd32(bytes.data() + off + 4, swap);
        const std::uint32_t incl = rd32(bytes.data() + off + 8, swap);
        const std::uint32_t orig = rd32(bytes.data() + off + 12, swap);
        (void)orig;
        off += 16;
        if (incl > out.snaplen && out.snaplen != 0) {
            return result<file>::failure("packet incl_len exceeds snaplen");
        }
        if (bytes.size() - off < incl) {
            return result<file>::failure("truncated pcap packet data");
        }
        pkt.data.assign(bytes.begin() + static_cast<std::ptrdiff_t>(off),
                        bytes.begin() + static_cast<std::ptrdiff_t>(off + incl));
        off += incl;
        out.packets.push_back(std::move(pkt));
    }
    return out;
}

result<std::vector<std::uint8_t>> extract_tcp_payloads(const file& cap) {
    std::vector<std::uint8_t> out;
    for (std::size_t i = 0; i < cap.packets.size(); ++i) {
        const auto& pkt = cap.packets[i];
        auto ip = frame_to_ip(bytes_view(pkt.data.data(), pkt.data.size()), cap.network);
        if (!ip) {
            // Non-IPv4/TCP frames are skipped rather than failing the whole file:
            // a capture may contain ARP or other noise around the TLS flow.
            continue;
        }
        auto payload = ipv4_tcp_payload(*ip);
        if (!payload) continue;
        out.insert(out.end(), payload->begin(), payload->end());
    }
    if (out.empty()) {
        return result<std::vector<std::uint8_t>>::failure(
            "no IPv4 TCP payload bytes found in the capture");
    }
    return out;
}

result<std::vector<std::uint8_t>> tls_stream_from_pcap(bytes_view pcap_bytes) {
    auto cap = parse(pcap_bytes);
    if (!cap) return result<std::vector<std::uint8_t>>::failure(cap.error());
    return extract_tcp_payloads(*cap);
}

}  // namespace sentinel::pcap
