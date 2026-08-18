#include "sentinel/der.hpp"

#include <chrono>
#include <cstdio>
#include <map>

namespace sentinel::der {

void reader::fail(std::string why) {
    if (!failed_) {
        failed_ = true;
        error_ = std::move(why) + " at offset " + std::to_string(pos_);
    }
}

std::optional<tlv> reader::next() {
    if (failed_) return std::nullopt;
    if (pos_ >= buf_.size()) {
        fail("no element left");
        return std::nullopt;
    }
    const std::size_t start = pos_;
    const std::uint8_t id = buf_[pos_++];
    tlv t;
    t.cls = static_cast<tag_class>(id >> 6);
    t.constructed = (id & 0x20) != 0;
    t.number = id & 0x1f;
    if (t.number == 0x1f) {
        // Nothing in a conforming certificate uses the high tag number form, and
        // accepting it only widens the surface for no benefit.
        fail("high tag number form is not accepted");
        return std::nullopt;
    }

    if (pos_ >= buf_.size()) {
        fail("truncated before the length byte");
        return std::nullopt;
    }
    const std::uint8_t first = buf_[pos_++];
    std::size_t len = 0;
    if (first < 0x80) {
        len = first;
    } else if (first == 0x80) {
        fail("indefinite length is not valid DER");
        return std::nullopt;
    } else if (first == 0xff) {
        fail("reserved length byte 0xff");
        return std::nullopt;
    } else {
        const std::size_t n = first & 0x7f;
        if (n > sizeof(std::size_t)) {
            fail("length field of " + std::to_string(n) + " bytes is out of range");
            return std::nullopt;
        }
        if (buf_.size() - pos_ < n) {
            fail("truncated inside a multi-byte length");
            return std::nullopt;
        }
        if (buf_[pos_] == 0) {
            fail("non-minimal length encoding, leading zero byte");
            return std::nullopt;
        }
        for (std::size_t i = 0; i < n; ++i) len = (len << 8) | buf_[pos_ + i];
        pos_ += n;
        if (len < 0x80) {
            fail("non-minimal length encoding, long form used for a short length");
            return std::nullopt;
        }
    }

    if (buf_.size() - pos_ < len) {
        fail("element claims " + std::to_string(len) + " byte(s), " +
             std::to_string(buf_.size() - pos_) + " left");
        return std::nullopt;
    }
    t.content = buf_.subspan(pos_, len);
    pos_ += len;
    t.whole = buf_.subspan(start, pos_ - start);
    return t;
}

std::optional<tlv> reader::next(std::uint32_t universal_tag) {
    const std::size_t before = pos_;
    auto t = next();
    if (!t) return std::nullopt;
    if (!t->is(universal_tag)) {
        pos_ = before;
        fail("expected universal tag " + std::to_string(universal_tag) + ", found class " +
             std::to_string(static_cast<int>(t->cls)) + " tag " + std::to_string(t->number));
        return std::nullopt;
    }
    return t;
}

std::string oid_to_string(bytes_view content) {
    if (content.empty()) return {};
    std::string out;
    // The first byte packs the first two arcs: 40 * a + b.
    const unsigned first = content[0];
    const unsigned a = first >= 80 ? 2 : first / 40;
    const unsigned b = first >= 80 ? first - 80 : first % 40;
    out = std::to_string(a) + "." + std::to_string(b);

    std::uint64_t acc = 0;
    bool in_progress = false;
    for (std::size_t i = 1; i < content.size(); ++i) {
        const std::uint8_t c = content[i];
        if (!in_progress && c == 0x80) return {};  // non-minimal arc encoding
        if (acc > (~0ULL >> 7)) return {};         // would overflow
        acc = (acc << 7) | (c & 0x7f);
        in_progress = (c & 0x80) != 0;
        if (!in_progress) {
            out += "." + std::to_string(acc);
            acc = 0;
        }
    }
    if (in_progress) return {};  // ended mid-arc
    return out;
}

std::string oid_label(const std::string& dotted) {
    static const std::map<std::string, const char*> known = {
        {"2.5.4.3", "CN"},
        {"2.5.4.4", "SN"},
        {"2.5.4.6", "C"},
        {"2.5.4.7", "L"},
        {"2.5.4.8", "ST"},
        {"2.5.4.9", "STREET"},
        {"2.5.4.10", "O"},
        {"2.5.4.11", "OU"},
        {"2.5.4.5", "serialNumber"},
        {"0.9.2342.19200300.100.1.25", "DC"},
        {"1.2.840.113549.1.9.1", "emailAddress"},
        {"2.5.29.14", "subjectKeyIdentifier"},
        {"2.5.29.15", "keyUsage"},
        {"2.5.29.17", "subjectAltName"},
        {"2.5.29.19", "basicConstraints"},
        {"2.5.29.30", "nameConstraints"},
        {"2.5.29.31", "cRLDistributionPoints"},
        {"2.5.29.32", "certificatePolicies"},
        {"2.5.29.35", "authorityKeyIdentifier"},
        {"2.5.29.37", "extKeyUsage"},
        {"1.3.6.1.5.5.7.1.1", "authorityInfoAccess"},
        {"1.3.6.1.5.5.7.3.1", "serverAuth"},
        {"1.3.6.1.5.5.7.3.2", "clientAuth"},
        {"1.3.6.1.5.5.7.3.3", "codeSigning"},
        {"1.3.6.1.5.5.7.3.4", "emailProtection"},
        {"1.3.6.1.5.5.7.3.8", "timeStamping"},
        {"1.3.6.1.5.5.7.3.9", "OCSPSigning"},
        {"2.5.29.37.0", "anyExtendedKeyUsage"},
        {"1.2.840.113549.1.1.1", "rsaEncryption"},
        {"1.2.840.113549.1.1.11", "sha256WithRSAEncryption"},
        {"1.2.840.113549.1.1.12", "sha384WithRSAEncryption"},
        {"1.2.840.113549.1.1.13", "sha512WithRSAEncryption"},
        {"1.2.840.113549.1.1.10", "rsassaPss"},
        {"1.2.840.10045.2.1", "id-ecPublicKey"},
        {"1.2.840.10045.4.3.2", "ecdsa-with-SHA256"},
        {"1.2.840.10045.4.3.3", "ecdsa-with-SHA384"},
        {"1.2.840.10045.3.1.7", "prime256v1"},
        {"1.3.101.112", "Ed25519"},
    };
    const auto it = known.find(dotted);
    return it != known.end() ? it->second : dotted;
}

result<std::int64_t> parse_integer(bytes_view content) {
    if (content.empty()) return result<std::int64_t>::failure("empty INTEGER");
    if (content.size() > 8) {
        return result<std::int64_t>::failure("INTEGER of " + std::to_string(content.size()) +
                                             " bytes does not fit in 64 bits");
    }
    if (content.size() > 1) {
        // DER forbids a redundant leading 0x00 or 0xff byte.
        const bool redundant = (content[0] == 0x00 && (content[1] & 0x80) == 0) ||
                               (content[0] == 0xff && (content[1] & 0x80) != 0);
        if (redundant) return result<std::int64_t>::failure("non-minimal INTEGER encoding");
    }
    std::int64_t v = (content[0] & 0x80) ? -1 : 0;
    for (std::uint8_t b : content) v = (v << 8) | b;
    return v;
}

std::string integer_to_hex(bytes_view content) {
    // Serial numbers are habitually shown as hex because they are frequently
    // twenty bytes long, which no integer type holds.
    std::size_t start = 0;
    while (start + 1 < content.size() && content[start] == 0) ++start;
    return to_hex(content.subspan(start));
}

result<bool> parse_boolean(bytes_view content) {
    if (content.size() != 1) return result<bool>::failure("BOOLEAN must be one byte");
    if (content[0] != 0x00 && content[0] != 0xff) {
        return result<bool>::failure("DER BOOLEAN true must be 0xff");
    }
    return content[0] != 0;
}

result<bytes_view> parse_bit_string(bytes_view content, std::uint8_t& unused_bits) {
    if (content.empty()) return result<bytes_view>::failure("empty BIT STRING");
    unused_bits = content[0];
    if (unused_bits > 7) return result<bytes_view>::failure("BIT STRING unused bit count above 7");
    if (content.size() == 1 && unused_bits != 0) {
        return result<bytes_view>::failure("empty BIT STRING with unused bits");
    }
    return content.subspan(1);
}

namespace {

bool digits(bytes_view b, std::size_t at, std::size_t n, int& out) {
    if (at + n > b.size()) return false;
    int v = 0;
    for (std::size_t i = 0; i < n; ++i) {
        const std::uint8_t c = b[at + i];
        if (c < '0' || c > '9') return false;
        v = v * 10 + (c - '0');
    }
    out = v;
    return true;
}

}  // namespace

result<std::int64_t> parse_time(const tlv& t) {
    const bool utc = t.is(tag::utc_time);
    if (!utc && !t.is(tag::generalized_time)) {
        return result<std::int64_t>::failure("not a time value");
    }
    const bytes_view b = t.content;
    // RFC 5280 section 4.1.2.5 requires seconds and the Z suffix in both forms.
    const std::size_t want = utc ? 13u : 15u;
    if (b.size() != want || b[b.size() - 1] != 'Z') {
        return result<std::int64_t>::failure(
            std::string(utc ? "UTCTime" : "GeneralizedTime") +
            " must be YYYYMMDDHHMMSSZ with seconds present, per RFC 5280");
    }
    int year = 0, mon = 0, day = 0, hh = 0, mm = 0, ss = 0;
    std::size_t p = 0;
    if (utc) {
        int yy = 0;
        if (!digits(b, p, 2, yy)) return result<std::int64_t>::failure("bad year");
        // RFC 5280: two-digit years of 50 and above mean the twentieth century.
        year = yy >= 50 ? 1900 + yy : 2000 + yy;
        p = 2;
    } else {
        if (!digits(b, p, 4, year)) return result<std::int64_t>::failure("bad year");
        p = 4;
    }
    if (!digits(b, p, 2, mon) || !digits(b, p + 2, 2, day) || !digits(b, p + 4, 2, hh) ||
        !digits(b, p + 6, 2, mm) || !digits(b, p + 8, 2, ss)) {
        return result<std::int64_t>::failure("non-numeric field in the time value");
    }
    if (mon < 1 || mon > 12 || day < 1 || day > 31 || hh > 23 || mm > 59 || ss > 60) {
        return result<std::int64_t>::failure("time field out of range");
    }
    const std::chrono::year_month_day ymd{std::chrono::year{year},
                                          std::chrono::month{static_cast<unsigned>(mon)},
                                          std::chrono::day{static_cast<unsigned>(day)}};
    if (!ymd.ok()) return result<std::int64_t>::failure("calendar date does not exist");
    const auto days = std::chrono::sys_days{ymd}.time_since_epoch().count();
    return static_cast<std::int64_t>(days) * 86400 + hh * 3600 + mm * 60 + ss;
}

std::string format_time(std::int64_t seconds) {
    const auto days = static_cast<int>(seconds >= 0 ? seconds / 86400 : (seconds - 86399) / 86400);
    std::int64_t rem = seconds - static_cast<std::int64_t>(days) * 86400;
    const std::chrono::year_month_day ymd{
        std::chrono::sys_days{std::chrono::days{days}}};
    char buf[32];
    std::snprintf(buf, sizeof buf, "%04d-%02u-%02u %02d:%02d:%02dZ",
                  static_cast<int>(ymd.year()), static_cast<unsigned>(ymd.month()),
                  static_cast<unsigned>(ymd.day()), static_cast<int>(rem / 3600),
                  static_cast<int>(rem / 60 % 60), static_cast<int>(rem % 60));
    return buf;
}

result<std::string> parse_string(const tlv& t) {
    switch (t.number) {
        case tag::utf8_string:
        case tag::printable_string:
        case tag::ia5_string:
        case tag::t61_string:
            return std::string(reinterpret_cast<const char*>(t.content.data()), t.content.size());
        case tag::bmp_string: {
            // Two bytes per character, big endian. Only the Basic Multilingual
            // Plane appears in practice, and it is transcoded to UTF-8 here.
            if (t.content.size() % 2 != 0) {
                return result<std::string>::failure("BMPString of odd length");
            }
            std::string out;
            for (std::size_t i = 0; i < t.content.size(); i += 2) {
                const unsigned cp =
                    static_cast<unsigned>(t.content[i]) << 8 | t.content[i + 1];
                if (cp < 0x80) {
                    out += static_cast<char>(cp);
                } else if (cp < 0x800) {
                    out += static_cast<char>(0xc0 | (cp >> 6));
                    out += static_cast<char>(0x80 | (cp & 0x3f));
                } else {
                    out += static_cast<char>(0xe0 | (cp >> 12));
                    out += static_cast<char>(0x80 | ((cp >> 6) & 0x3f));
                    out += static_cast<char>(0x80 | (cp & 0x3f));
                }
            }
            return out;
        }
        default:
            return result<std::string>::failure("tag " + std::to_string(t.number) +
                                                " is not a string type this decoder reads");
    }
}

}  // namespace sentinel::der
