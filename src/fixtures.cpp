#include "sentinel/fixtures.hpp"

#include <chrono>
#include <cstdio>
#include <string>

#include "sentinel/siphash.hpp"
#include "sentinel/tls.hpp"

namespace sentinel::fixtures {
namespace {

using bytes = std::vector<std::uint8_t>;

// ---------------------------------------------------------------------------
// A byte writer for the TLS side. Length prefixes are written by measuring the
// block after it is built, which is the only way to get them right without
// counting by hand.
// ---------------------------------------------------------------------------

void put_u8(bytes& b, std::uint8_t v) { b.push_back(v); }
void put_u16(bytes& b, std::uint16_t v) {
    b.push_back(static_cast<std::uint8_t>(v >> 8));
    b.push_back(static_cast<std::uint8_t>(v));
}
void put(bytes& b, const bytes& v) { b.insert(b.end(), v.begin(), v.end()); }

bytes u8_prefixed(const bytes& body) {
    bytes out;
    put_u8(out, static_cast<std::uint8_t>(body.size()));
    put(out, body);
    return out;
}
bytes u16_prefixed(const bytes& body) {
    bytes out;
    put_u16(out, static_cast<std::uint16_t>(body.size()));
    put(out, body);
    return out;
}
bytes u24_prefixed(const bytes& body) {
    bytes out;
    out.push_back(static_cast<std::uint8_t>(body.size() >> 16));
    out.push_back(static_cast<std::uint8_t>(body.size() >> 8));
    out.push_back(static_cast<std::uint8_t>(body.size()));
    put(out, body);
    return out;
}

bytes u16_list(const std::vector<std::uint16_t>& v) {
    bytes out;
    for (std::uint16_t x : v) put_u16(out, x);
    return out;
}

// Deterministic filler where real traffic would carry random or key material.
// A fixture that changes between runs cannot be used as a regression test.
bytes filler(const std::string& label, std::size_t n) {
    bytes out;
    out.reserve(n);
    const std::uint64_t k0 = 0x5345'4e54'494e'454cULL;  // "SENTINEL"
    std::uint64_t h = siphash24(bytes_view(reinterpret_cast<const std::uint8_t*>(label.data()),
                                           label.size()),
                                k0, 0x0102030405060708ULL);
    while (out.size() < n) {
        h = siphash24_u64(h, k0, 0x0102030405060708ULL);
        for (int i = 0; i < 8 && out.size() < n; ++i) {
            out.push_back(static_cast<std::uint8_t>(h >> (8 * i)));
        }
    }
    return out;
}

bytes extension(std::uint16_t type, const bytes& body) {
    bytes out;
    put_u16(out, type);
    put(out, u16_prefixed(body));
    return out;
}

bytes ext_server_name(const std::string& host) {
    bytes entry;
    put_u8(entry, 0);  // host_name
    bytes name(host.begin(), host.end());
    put(entry, u16_prefixed(name));
    return extension(tls::ext_server_name, u16_prefixed(entry));
}

bytes ext_alpn(const std::vector<std::string>& protocols) {
    bytes list;
    for (const auto& p : protocols) {
        bytes one(p.begin(), p.end());
        put(list, u8_prefixed(one));
    }
    return extension(tls::ext_alpn, u16_prefixed(list));
}

bytes ext_key_share_client(const std::vector<std::pair<std::uint16_t, std::size_t>>& shares) {
    bytes list;
    for (const auto& [group, len] : shares) {
        put_u16(list, group);
        put(list, u16_prefixed(filler("share" + std::to_string(group), len)));
    }
    return extension(tls::ext_key_share, u16_prefixed(list));
}

bytes ext_key_share_server(std::uint16_t group, std::size_t len) {
    bytes body;
    put_u16(body, group);
    put(body, u16_prefixed(filler("server share", len)));
    return extension(tls::ext_key_share, body);
}

bytes record(tls::content_type type, const bytes& fragment) {
    bytes out;
    put_u8(out, static_cast<std::uint8_t>(type));
    put_u16(out, 0x0303);  // legacy_record_version, fixed at TLS 1.2 by RFC 8446
    put(out, u16_prefixed(fragment));
    return out;
}

bytes handshake(tls::handshake_type type, const bytes& body) {
    bytes out;
    put_u8(out, static_cast<std::uint8_t>(type));
    put(out, u24_prefixed(body));
    return out;
}

bytes client_hello_body(const std::string& server_name, bool offer_tls13,
                        const std::vector<std::uint16_t>& suites) {
    bytes body;
    put_u16(body, 0x0303);  // legacy_version, always TLS 1.2 on the wire
    put(body, filler("client random", 32));
    put(body, u8_prefixed(filler("legacy session id", 32)));
    put(body, u16_prefixed(u16_list(suites)));
    put(body, u8_prefixed({0x00}));  // null compression only

    bytes ext;
    put(ext, ext_server_name(server_name));
    put(ext, extension(tls::ext_ec_point_formats, u8_prefixed({0x00})));
    put(ext, extension(tls::ext_supported_groups,
                       u16_prefixed(u16_list({0x001d, 0x0017, 0x0018, 0x0100}))));
    put(ext, extension(tls::ext_signature_algorithms,
                       u16_prefixed(u16_list({0x0403, 0x0804, 0x0805, 0x0806, 0x0401, 0x0807}))));
    put(ext, ext_alpn({"h2", "http/1.1"}));
    if (offer_tls13) {
        put(ext, extension(tls::ext_supported_versions, u8_prefixed(u16_list({0x0304, 0x0303}))));
        put(ext, ext_key_share_client({{0x001d, 32}, {0x0017, 65}}));
        put(ext, extension(tls::ext_psk_key_exchange_modes, u8_prefixed({0x01})));
    } else {
        put(ext, extension(tls::ext_session_ticket, {}));
    }
    put(ext, extension(tls::ext_extended_master_secret, {}));
    put(body, u16_prefixed(ext));
    return body;
}

bytes server_hello_body(std::uint16_t suite, bool tls13, const std::uint8_t* random_tail) {
    bytes body;
    put_u16(body, 0x0303);
    bytes random = filler("server random", 32);
    if (random_tail) {
        for (int i = 0; i < 8; ++i) random[24 + static_cast<std::size_t>(i)] = random_tail[i];
    }
    put(body, random);
    put(body, u8_prefixed(filler("legacy session id", 32)));
    put_u16(body, suite);
    put_u8(body, 0x00);

    bytes ext;
    if (tls13) {
        put(ext, extension(tls::ext_supported_versions, u16_list({0x0304})));
        put(ext, ext_key_share_server(0x001d, 32));
    } else {
        put(ext, extension(tls::ext_ec_point_formats, u8_prefixed({0x00})));
        put(ext, extension(tls::ext_renegotiation_info, u8_prefixed({})));
    }
    put(ext, ext_alpn({"h2"}));
    put(body, u16_prefixed(ext));
    return body;
}

}  // namespace

std::vector<std::uint8_t> tls13_stream(const std::string& server_name, bool split_server_hello) {
    bytes out;
    const bytes ch = handshake(tls::handshake_type::client_hello,
                               client_hello_body(server_name, true,
                                                 {0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0x00ff}));
    put(out, record(tls::content_type::handshake, ch));

    const bytes sh =
        handshake(tls::handshake_type::server_hello, server_hello_body(0x1301, true, nullptr));
    if (split_server_hello && sh.size() > 20) {
        // One handshake message across two records. Legal, and the case a reader
        // that treats one record as one message gets wrong.
        const std::size_t cut = sh.size() / 2;
        put(out, record(tls::content_type::handshake, bytes(sh.begin(), sh.begin() + static_cast<long>(cut))));
        put(out, record(tls::content_type::handshake, bytes(sh.begin() + static_cast<long>(cut), sh.end())));
    } else {
        put(out, record(tls::content_type::handshake, sh));
    }

    put(out, record(tls::content_type::change_cipher_spec, {0x01}));
    // From here the exchange is protected. EncryptedExtensions, Certificate,
    // CertificateVerify and Finished are inside these records and unreadable.
    put(out, record(tls::content_type::application_data, filler("encrypted extensions", 512)));
    put(out, record(tls::content_type::application_data, filler("certificate", 1400)));
    put(out, record(tls::content_type::application_data, filler("finished", 64)));
    return out;
}

std::vector<std::uint8_t> tls12_downgrade_stream() {
    bytes out;
    const bytes ch = handshake(tls::handshake_type::client_hello,
                               client_hello_body("legacy.example.test", true,
                                                 {0x1301, 0xc02f, 0x0005, 0x000a}));
    put(out, record(tls::content_type::handshake, ch));
    // RFC 8446 section 4.1.3 downgrade sentinel for TLS 1.2.
    const std::uint8_t sentinel_tls12[8] = {0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01};
    const bytes sh = handshake(tls::handshake_type::server_hello,
                               server_hello_body(0xc02f, false, sentinel_tls12));
    put(out, record(tls::content_type::handshake, sh));
    put(out, record(tls::content_type::application_data, filler("tls12 payload", 256)));
    return out;
}

std::vector<std::uint8_t> truncated_stream() {
    bytes ch = handshake(tls::handshake_type::client_hello,
                         client_hello_body("truncated.example.test", true, {0x1301}));
    ch.resize(ch.size() - 40);  // the record is intact, the message inside it is not
    return record(tls::content_type::handshake, ch);
}

// ---------------------------------------------------------------------------
// DER encoding for the certificate hierarchy.
// ---------------------------------------------------------------------------

namespace {

bytes der_tlv(std::uint8_t id, const bytes& content) {
    bytes out;
    out.push_back(id);
    const std::size_t n = content.size();
    if (n < 0x80) {
        out.push_back(static_cast<std::uint8_t>(n));
    } else {
        bytes len;
        for (std::size_t v = n; v; v >>= 8) len.insert(len.begin(), static_cast<std::uint8_t>(v));
        out.push_back(static_cast<std::uint8_t>(0x80 | len.size()));
        put(out, len);
    }
    put(out, content);
    return out;
}

bytes der_seq(const bytes& c) { return der_tlv(0x30, c); }
bytes der_set(const bytes& c) { return der_tlv(0x31, c); }
bytes der_null() { return {0x05, 0x00}; }

bytes der_oid(const std::string& dotted) {
    std::vector<std::uint64_t> arcs;
    std::uint64_t cur = 0;
    bool any = false;
    for (char c : dotted) {
        if (c == '.') {
            arcs.push_back(cur);
            cur = 0;
            any = false;
        } else {
            cur = cur * 10 + static_cast<std::uint64_t>(c - '0');
            any = true;
        }
    }
    if (any) arcs.push_back(cur);
    bytes content;
    content.push_back(static_cast<std::uint8_t>(arcs[0] * 40 + arcs[1]));
    for (std::size_t i = 2; i < arcs.size(); ++i) {
        bytes base128;
        std::uint64_t v = arcs[i];
        do {
            base128.insert(base128.begin(), static_cast<std::uint8_t>(v & 0x7f));
            v >>= 7;
        } while (v);
        for (std::size_t j = 0; j + 1 < base128.size(); ++j) base128[j] |= 0x80;
        put(content, base128);
    }
    return der_tlv(0x06, content);
}

bytes der_integer(std::int64_t v) {
    bytes content;
    bool started = false;
    for (int shift = 56; shift >= 0; shift -= 8) {
        const std::uint8_t b = static_cast<std::uint8_t>(v >> shift);
        if (!started && b == 0 && shift > 0) continue;
        started = true;
        content.push_back(b);
    }
    if (content.empty()) content.push_back(0);
    if (content[0] & 0x80) content.insert(content.begin(), 0x00);
    return der_tlv(0x02, content);
}

bytes der_bit_string(const bytes& payload, std::uint8_t unused = 0) {
    bytes content;
    content.push_back(unused);
    put(content, payload);
    return der_tlv(0x03, content);
}

bytes der_octet_string(const bytes& payload) { return der_tlv(0x04, payload); }
bytes der_boolean(bool v) { return {0x01, 0x01, static_cast<std::uint8_t>(v ? 0xff : 0x00)}; }

bytes der_utf8(const std::string& s) {
    return der_tlv(0x0c, bytes(s.begin(), s.end()));
}
bytes der_printable(const std::string& s) {
    return der_tlv(0x13, bytes(s.begin(), s.end()));
}

bytes der_utc_time(std::int64_t seconds) {
    const auto days = static_cast<int>(seconds >= 0 ? seconds / 86400 : (seconds - 86399) / 86400);
    const std::int64_t rem = seconds - static_cast<std::int64_t>(days) * 86400;
    const std::chrono::year_month_day ymd{std::chrono::sys_days{std::chrono::days{days}}};
    char buf[16];
    std::snprintf(buf, sizeof buf, "%02d%02u%02u%02d%02d%02dZ",
                  static_cast<int>(ymd.year()) % 100, static_cast<unsigned>(ymd.month()),
                  static_cast<unsigned>(ymd.day()), static_cast<int>(rem / 3600),
                  static_cast<int>(rem / 60 % 60), static_cast<int>(rem % 60));
    return der_tlv(0x17, bytes(buf, buf + 13));
}

struct dn_spec {
    std::string country = "BG";
    std::string organisation = "Sentinel Course Project";
    std::string common_name;
};

bytes der_name(const dn_spec& d) {
    auto rdn = [](const std::string& oid, const bytes& value) {
        bytes atv = der_oid(oid);
        put(atv, value);
        return der_set(der_seq(atv));
    };
    bytes content;
    put(content, rdn("2.5.4.6", der_printable(d.country)));
    put(content, rdn("2.5.4.10", der_utf8(d.organisation)));
    put(content, rdn("2.5.4.3", der_utf8(d.common_name)));
    return der_seq(content);
}

bytes der_extension(const std::string& oid, bool critical, const bytes& value) {
    bytes c = der_oid(oid);
    if (critical) put(c, der_boolean(true));
    put(c, der_octet_string(value));
    return der_seq(c);
}

bytes encode_key_usage(std::uint16_t bits) {
    int highest = -1;
    for (int i = 0; i < 16; ++i) {
        if ((bits >> i) & 1u) highest = i;
    }
    if (highest < 0) return der_bit_string({}, 0);
    const std::size_t nbytes = static_cast<std::size_t>(highest) / 8 + 1;
    bytes payload(nbytes, 0);
    for (int i = 0; i <= highest; ++i) {
        if ((bits >> i) & 1u) {
            payload[static_cast<std::size_t>(i) / 8] |=
                static_cast<std::uint8_t>(1u << (7 - i % 8));
        }
    }
    const std::uint8_t unused = static_cast<std::uint8_t>(nbytes * 8 - static_cast<std::size_t>(highest) - 1);
    return der_bit_string(payload, unused);
}

// A SubjectPublicKeyInfo shaped like an RSA key. The modulus is deterministic
// filler, not a key: no private key exists, nothing signs, nothing verifies.
bytes synthetic_spki(const std::string& label) {
    bytes alg = der_oid("1.2.840.113549.1.1.1");
    put(alg, der_null());
    bytes modulus = filler("modulus " + label, 256);
    modulus[0] |= 0x80;  // a real modulus has its top bit set
    bytes modulus_int;
    modulus_int.push_back(0x00);  // keep the INTEGER positive
    put(modulus_int, modulus);
    bytes key = der_tlv(0x02, modulus_int);
    put(key, der_integer(65537));
    bytes spki = der_seq(alg);
    put(spki, der_bit_string(der_seq(key)));
    return der_seq(spki);
}

struct cert_spec {
    std::uint64_t serial = 1;
    dn_spec subject;
    dn_spec issuer;
    std::int64_t not_before = 0;
    std::int64_t not_after = 0;
    bool is_ca = false;
    bool emit_basic_constraints = true;
    bool has_path_len = false;
    std::int64_t path_len = 0;
    std::uint16_t key_usage_bits = 0;
    std::vector<std::string> dns_names;
    std::vector<std::string> eku_oids;
    std::vector<std::string> permitted_dns;
    std::vector<std::string> excluded_dns;
    bool unhandled_critical_extension = false;
};

bytes encode_certificate(const cert_spec& s) {
    const bytes sig_alg = [] {
        bytes a = der_oid("1.2.840.113549.1.1.11");  // sha256WithRSAEncryption
        put(a, der_null());
        return der_seq(a);
    }();

    bytes tbs;
    put(tbs, der_tlv(0xa0, der_integer(2)));  // [0] EXPLICIT version, v3
    put(tbs, der_integer(static_cast<std::int64_t>(s.serial)));
    put(tbs, sig_alg);
    put(tbs, der_name(s.issuer));
    {
        bytes v = der_utc_time(s.not_before);
        put(v, der_utc_time(s.not_after));
        put(tbs, der_seq(v));
    }
    put(tbs, der_name(s.subject));
    put(tbs, synthetic_spki(s.subject.common_name));

    bytes exts;
    if (s.emit_basic_constraints) {
        bytes bc;
        if (s.is_ca) put(bc, der_boolean(true));
        if (s.has_path_len) put(bc, der_integer(s.path_len));
        put(exts, der_extension("2.5.29.19", true, der_seq(bc)));
    }
    if (s.key_usage_bits) {
        put(exts, der_extension("2.5.29.15", true, encode_key_usage(s.key_usage_bits)));
    }
    if (!s.dns_names.empty()) {
        bytes names;
        for (const auto& d : s.dns_names) {
            put(names, der_tlv(0x82, bytes(d.begin(), d.end())));  // [2] dNSName
        }
        put(exts, der_extension("2.5.29.17", false, der_seq(names)));
    }
    if (!s.eku_oids.empty()) {
        bytes purposes;
        for (const auto& o : s.eku_oids) put(purposes, der_oid(o));
        put(exts, der_extension("2.5.29.37", false, der_seq(purposes)));
    }
    if (!s.permitted_dns.empty() || !s.excluded_dns.empty()) {
        bytes nc;
        auto subtrees = [](const std::vector<std::string>& v) {
            bytes acc;
            for (const auto& d : v) {
                put(acc, der_seq(der_tlv(0x82, bytes(d.begin(), d.end()))));
            }
            return acc;
        };
        if (!s.permitted_dns.empty()) put(nc, der_tlv(0xa0, subtrees(s.permitted_dns)));
        if (!s.excluded_dns.empty()) put(nc, der_tlv(0xa1, subtrees(s.excluded_dns)));
        put(exts, der_extension("2.5.29.30", true, der_seq(nc)));
    }
    {
        // Subject and authority key identifiers, derived from the names so the
        // fixture stays deterministic.
        put(exts, der_extension("2.5.29.14", false,
                                der_octet_string(filler("ski " + s.subject.common_name, 20))));
        bytes aki = der_tlv(0x80, filler("ski " + s.issuer.common_name, 20));
        put(exts, der_extension("2.5.29.35", false, der_seq(aki)));
    }
    if (s.unhandled_critical_extension) {
        // inhibitAnyPolicy. Real, standard, critical, and genuinely not processed
        // by this validator, which is exactly the case RFC 5280 section 6.1 says
        // must lead to rejection.
        put(exts, der_extension("2.5.29.54", true, der_integer(0)));
    }
    put(tbs, der_tlv(0xa3, der_seq(exts)));

    bytes cert = der_seq(tbs);
    put(cert, sig_alg);
    // Placeholder in place of a signature. See the header comment: no key
    // material exists, and the validator reports signature verification as
    // skipped rather than pretending to have checked this.
    put(cert, der_bit_string(filler("signature " + s.subject.common_name +
                                        std::to_string(s.serial),
                                    256)));
    return der_seq(cert);
}

constexpr std::int64_t day = 86400;

// Bit mask helpers so the specs below read as their RFC 5280 names.
constexpr std::uint16_t ku(int bit) { return static_cast<std::uint16_t>(1u << bit); }
const std::uint16_t ku_ca = ku(5) | ku(6);           // keyCertSign, cRLSign
const std::uint16_t ku_server = ku(0) | ku(2);       // digitalSignature, keyEncipherment
const std::string eku_server_auth = "1.3.6.1.5.5.7.3.1";
const std::string eku_client_auth = "1.3.6.1.5.5.7.3.2";
const std::string eku_code_signing = "1.3.6.1.5.5.7.3.3";

}  // namespace

pki build_pki(std::int64_t now) {
    pki out;
    const dn_spec root_dn{"BG", "Sentinel Course Project", "Sentinel Test Root CA"};
    const dn_spec inter_dn{"BG", "Sentinel Course Project", "Sentinel Test Issuing CA"};

    cert_spec root;
    root.serial = 0x01;
    root.subject = root_dn;
    root.issuer = root_dn;
    root.not_before = now - 365 * day;
    root.not_after = now + 3650 * day;
    root.is_ca = true;
    root.has_path_len = true;
    root.path_len = 1;
    root.key_usage_bits = ku_ca;
    out.root_der = encode_certificate(root);

    cert_spec inter;
    inter.serial = 0x10;
    inter.subject = inter_dn;
    inter.issuer = root_dn;
    inter.not_before = now - 200 * day;
    inter.not_after = now + 1000 * day;
    inter.is_ca = true;
    inter.has_path_len = true;
    inter.path_len = 0;
    inter.key_usage_bits = ku_ca;
    out.intermediate_der = encode_certificate(inter);

    auto server_leaf = [&](std::uint64_t serial, const std::string& cn,
                           const std::vector<std::string>& dns) {
        cert_spec c;
        c.serial = serial;
        c.subject = {"BG", "Sentinel Course Project", cn};
        c.issuer = inter_dn;
        c.not_before = now - 10 * day;
        c.not_after = now + 80 * day;
        c.key_usage_bits = ku_server;
        c.dns_names = dns;
        c.eku_oids = {eku_server_auth, eku_client_auth};
        return c;
    };

    // 1. The case everything else is measured against.
    {
        auto leaf = server_leaf(0x1001, "sentinel.example.test",
                                {"sentinel.example.test", "*.svc.example.test"});
        out.cases.push_back({"well formed chain",
                             "sentinel.example.test",
                             {encode_certificate(leaf), out.intermediate_der},
                             true,
                             "accepted: every check that can run without a cryptographic "
                             "backend passes"});
    }
    // 2. The wildcard, which must match one label and only one.
    {
        auto leaf = server_leaf(0x1002, "wildcard.example.test", {"*.svc.example.test"});
        const bytes der = encode_certificate(leaf);
        out.cases.push_back({"wildcard matches a single label",
                             "api.svc.example.test",
                             {der, out.intermediate_der},
                             true,
                             "accepted: *.svc.example.test covers api.svc.example.test"});
        out.cases.push_back({"wildcard does not span a dot",
                             "a.b.svc.example.test",
                             {der, out.intermediate_der},
                             false,
                             "rejected: a wildcard label never matches across a dot"});
    }
    // 3. Expired.
    {
        auto leaf = server_leaf(0x1003, "expired.example.test", {"expired.example.test"});
        leaf.not_before = now - 400 * day;
        leaf.not_after = now - 30 * day;
        out.cases.push_back({"expired end entity certificate",
                             "expired.example.test",
                             {encode_certificate(leaf), out.intermediate_der},
                             false,
                             "rejected: the validity window closed before the reference time"});
    }
    // 4. Name mismatch.
    {
        auto leaf = server_leaf(0x1004, "other.example.test", {"other.example.test"});
        out.cases.push_back({"host name not covered by the certificate",
                             "sentinel.example.test",
                             {encode_certificate(leaf), out.intermediate_der},
                             false,
                             "rejected: no dNSName covers the requested host"});
    }
    // 5. An issuer that is not a certification authority.
    {
        cert_spec bad_ca;
        bad_ca.serial = 0x20;
        bad_ca.subject = {"BG", "Sentinel Course Project", "Sentinel Not A CA"};
        bad_ca.issuer = root_dn;
        bad_ca.not_before = now - 100 * day;
        bad_ca.not_after = now + 100 * day;
        bad_ca.is_ca = false;
        bad_ca.key_usage_bits = ku_server;
        auto leaf = server_leaf(0x1005, "under-non-ca.example.test", {"under-non-ca.example.test"});
        leaf.issuer = bad_ca.subject;
        out.cases.push_back({"issuer is not marked as a certification authority",
                             "under-non-ca.example.test",
                             {encode_certificate(leaf), encode_certificate(bad_ca)},
                             false,
                             "rejected: basicConstraints on the issuer does not say cA"});
    }
    // 6. pathLenConstraint exceeded: root allows one intermediate, this path has two.
    {
        const dn_spec sub_dn{"BG", "Sentinel Course Project", "Sentinel Test Sub CA"};
        cert_spec sub;
        sub.serial = 0x30;
        sub.subject = sub_dn;
        sub.issuer = inter_dn;
        sub.not_before = now - 100 * day;
        sub.not_after = now + 500 * day;
        sub.is_ca = true;
        sub.key_usage_bits = ku_ca;
        auto leaf = server_leaf(0x1006, "deep.example.test", {"deep.example.test"});
        leaf.issuer = sub_dn;
        out.cases.push_back({"path longer than pathLenConstraint allows",
                             "deep.example.test",
                             {encode_certificate(leaf), encode_certificate(sub),
                              out.intermediate_der},
                             false,
                             "rejected: the issuing authority permits no intermediate below it"});
    }
    // 7. Extended key usage that excludes server authentication.
    {
        auto leaf = server_leaf(0x1007, "codesign.example.test", {"codesign.example.test"});
        leaf.eku_oids = {eku_code_signing};
        out.cases.push_back({"extended key usage without server authentication",
                             "codesign.example.test",
                             {encode_certificate(leaf), out.intermediate_der},
                             false,
                             "rejected: the key may only be used for code signing"});
    }
    // 8. Revoked.
    {
        auto leaf = server_leaf(0x1008, "revoked.example.test", {"revoked.example.test"});
        out.revoked_serials.insert("1008");
        out.cases.push_back({"serial number on the local revocation list",
                             "revoked.example.test",
                             {encode_certificate(leaf), out.intermediate_der},
                             false,
                             "rejected: the serial number appears on the revocation list"});
    }
    // 9. A critical extension the verifier does not process.
    {
        auto leaf = server_leaf(0x1009, "critical.example.test", {"critical.example.test"});
        leaf.unhandled_critical_extension = true;
        out.cases.push_back({"unrecognised critical extension",
                             "critical.example.test",
                             {encode_certificate(leaf), out.intermediate_der},
                             false,
                             "rejected: RFC 5280 section 6.1 forbids ignoring a critical "
                             "extension that is not understood"});
    }
    // 10. Name constraints on the issuing authority.
    {
        const dn_spec nc_dn{"BG", "Sentinel Course Project", "Sentinel Constrained CA"};
        cert_spec nc;
        nc.serial = 0x40;
        nc.subject = nc_dn;
        nc.issuer = root_dn;
        nc.not_before = now - 100 * day;
        nc.not_after = now + 500 * day;
        nc.is_ca = true;
        nc.has_path_len = true;
        nc.path_len = 0;
        nc.key_usage_bits = ku_ca;
        nc.permitted_dns = {"inside.example.test"};
        const bytes nc_der = encode_certificate(nc);

        auto good = server_leaf(0x100a, "host.inside.example.test", {"host.inside.example.test"});
        good.issuer = nc_dn;
        out.cases.push_back({"name inside the permitted subtree",
                             "host.inside.example.test",
                             {encode_certificate(good), nc_der},
                             true,
                             "accepted: the name falls inside the permitted subtree"});

        auto bad = server_leaf(0x100b, "host.outside.example.test", {"host.outside.example.test"});
        bad.issuer = nc_dn;
        out.cases.push_back({"name outside the permitted subtree",
                             "host.outside.example.test",
                             {encode_certificate(bad), nc_der},
                             false,
                             "rejected: the issuing authority may not certify this name"});
    }
    // 11. Nothing links the end entity to a trust anchor.
    {
        const dn_spec unknown{"BG", "Somebody Else", "Unknown Issuing CA"};
        auto leaf = server_leaf(0x100c, "orphan.example.test", {"orphan.example.test"});
        leaf.issuer = unknown;
        out.cases.push_back({"no path to a trust anchor",
                             "orphan.example.test",
                             {encode_certificate(leaf)},
                             false,
                             "rejected: no certificate presented or trusted issues this one"});
    }
    return out;
}

}  // namespace sentinel::fixtures
