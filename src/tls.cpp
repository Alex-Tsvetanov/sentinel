#include "sentinel/tls.hpp"

#include <algorithm>
#include <cstdio>
#include <map>

namespace sentinel::tls {
namespace {

std::string hex16(std::uint16_t v) {
    char b[8];
    std::snprintf(b, sizeof b, "0x%04x", v);
    return b;
}

const extension* find_in(const std::vector<extension>& v, std::uint16_t type) {
    for (const auto& e : v) {
        if (e.type == type) return &e;
    }
    return nullptr;
}

result<std::vector<extension>> parse_extensions(bytes_view body) {
    std::vector<extension> out;
    byte_reader r{body};
    while (r.remaining() > 0) {
        extension e;
        e.type = r.u16();
        e.body = r.take_u16_prefixed();
        if (!r.ok()) return result<std::vector<extension>>::failure("extension list: " + r.error());
        out.push_back(e);
    }
    return out;
}

}  // namespace

const extension* client_hello::find(std::uint16_t type) const { return find_in(extensions, type); }
const extension* server_hello::find(std::uint16_t type) const { return find_in(extensions, type); }

bool server_hello::downgrade_sentinel_tls12() const {
    static const std::uint8_t s[8] = {0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01};
    return random.size() == 32 && std::equal(s, s + 8, random.data() + 24);
}

bool server_hello::downgrade_sentinel_tls11_or_below() const {
    static const std::uint8_t s[8] = {0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x00};
    return random.size() == 32 && std::equal(s, s + 8, random.data() + 24);
}

result<record> parse_record(byte_reader& r) {
    record rec;
    const std::uint8_t t = r.u8();
    rec.legacy_version = r.u16();
    rec.fragment = r.take_u16_prefixed();
    if (!r.ok()) return result<record>::failure("record header: " + r.error());
    switch (t) {
        case 20:
        case 21:
        case 22:
        case 23:
            rec.type = static_cast<content_type>(t);
            break;
        default:
            return result<record>::failure("unknown record content type " + std::to_string(t));
    }
    // RFC 8446 section 5.1 caps the plaintext fragment at 2^14 and the protected
    // record at 2^14 + 256. Anything larger is either corruption or an attempt to
    // make the reader allocate, and it is rejected before anything is copied.
    const std::size_t cap =
        rec.type == content_type::application_data ? (1u << 14) + 256 : (1u << 14);
    if (rec.fragment.size() > cap) {
        return result<record>::failure("record fragment of " +
                                       std::to_string(rec.fragment.size()) +
                                       " bytes exceeds the limit of " + std::to_string(cap));
    }
    return rec;
}

result<scan> scan_stream(bytes_view buf) {
    scan s;
    s.total_bytes = buf.size();
    byte_reader r{buf};
    while (r.remaining() > 0) {
        auto rec = parse_record(r);
        if (!rec) return result<scan>::failure(rec.error());
        ++s.records;
        switch (rec->type) {
            case content_type::handshake:
                ++s.handshake_records;
                // Handshake messages may be split across records and several may
                // share one, so the fragments are concatenated first and only then
                // cut into messages.
                s.handshake_bytes.insert(s.handshake_bytes.end(), rec->fragment.begin(),
                                         rec->fragment.end());
                break;
            case content_type::application_data:
                // Everything after the server changes keys is protected. A passive
                // observer counts it and says so, rather than guessing at it.
                ++s.encrypted_records;
                s.encrypted_bytes += rec->fragment.size();
                break;
            case content_type::change_cipher_spec:
                ++s.change_cipher_spec_records;
                break;
            case content_type::alert:
                ++s.alert_records;
                break;
        }
    }
    if (!r.ok()) return result<scan>::failure(r.error());

    byte_reader hr{bytes_view(s.handshake_bytes.data(), s.handshake_bytes.size())};
    while (hr.remaining() > 0) {
        message m;
        m.type = static_cast<handshake_type>(hr.u8());
        m.body = hr.take_u24_prefixed();
        if (!hr.ok()) return result<scan>::failure("handshake message: " + hr.error());
        s.messages.push_back(m);
    }
    return s;
}

result<client_hello> parse_client_hello(bytes_view body) {
    client_hello ch;
    byte_reader r{body};
    ch.legacy_version = r.u16();
    ch.random = r.take(32);
    ch.session_id = r.take_u8_prefixed();
    const bytes_view suites = r.take_u16_prefixed();
    const bytes_view comp = r.take_u8_prefixed();
    if (!r.ok()) return result<client_hello>::failure("ClientHello: " + r.error());
    if (suites.size() % 2 != 0) {
        return result<client_hello>::failure("ClientHello: cipher suite list has an odd length");
    }
    for (std::size_t i = 0; i < suites.size(); i += 2) {
        ch.cipher_suites.push_back(static_cast<std::uint16_t>(suites[i] << 8 | suites[i + 1]));
    }
    ch.compression_methods.assign(comp.begin(), comp.end());

    // The extension block is optional in the wire format, present in practice.
    if (r.remaining() > 0) {
        const bytes_view ext = r.take_u16_prefixed();
        if (!r.ok()) return result<client_hello>::failure("ClientHello: " + r.error());
        auto parsed = parse_extensions(ext);
        if (!parsed) return result<client_hello>::failure("ClientHello: " + parsed.error());
        ch.extensions = std::move(*parsed);
    }
    if (r.remaining() > 0) {
        return result<client_hello>::failure("ClientHello: " + std::to_string(r.remaining()) +
                                             " trailing byte(s) after the extension block");
    }
    return ch;
}

result<server_hello> parse_server_hello(bytes_view body) {
    server_hello sh;
    byte_reader r{body};
    sh.legacy_version = r.u16();
    sh.random = r.take(32);
    sh.session_id = r.take_u8_prefixed();
    sh.cipher_suite = r.u16();
    sh.compression_method = r.u8();
    if (!r.ok()) return result<server_hello>::failure("ServerHello: " + r.error());
    if (r.remaining() > 0) {
        const bytes_view ext = r.take_u16_prefixed();
        if (!r.ok()) return result<server_hello>::failure("ServerHello: " + r.error());
        auto parsed = parse_extensions(ext);
        if (!parsed) return result<server_hello>::failure("ServerHello: " + parsed.error());
        sh.extensions = std::move(*parsed);
    }
    if (r.remaining() > 0) {
        return result<server_hello>::failure("ServerHello: " + std::to_string(r.remaining()) +
                                             " trailing byte(s) after the extension block");
    }
    return sh;
}

result<std::vector<std::uint16_t>> decode_u16_vector_u16_len(bytes_view body) {
    byte_reader r{body};
    const bytes_view v = r.take_u16_prefixed();
    if (!r.ok()) return result<std::vector<std::uint16_t>>::failure(r.error());
    if (r.remaining() != 0) {
        return result<std::vector<std::uint16_t>>::failure("trailing bytes after the list");
    }
    if (v.size() % 2 != 0) {
        return result<std::vector<std::uint16_t>>::failure("list length is not a multiple of two");
    }
    std::vector<std::uint16_t> out;
    for (std::size_t i = 0; i < v.size(); i += 2) {
        out.push_back(static_cast<std::uint16_t>(v[i] << 8 | v[i + 1]));
    }
    return out;
}

result<std::vector<std::uint16_t>> decode_supported_versions_client(bytes_view body) {
    byte_reader r{body};
    const bytes_view v = r.take_u8_prefixed();
    if (!r.ok()) return result<std::vector<std::uint16_t>>::failure(r.error());
    if (v.empty() || v.size() % 2 != 0) {
        return result<std::vector<std::uint16_t>>::failure("supported_versions: bad list length");
    }
    std::vector<std::uint16_t> out;
    for (std::size_t i = 0; i < v.size(); i += 2) {
        out.push_back(static_cast<std::uint16_t>(v[i] << 8 | v[i + 1]));
    }
    return out;
}

result<std::uint16_t> decode_supported_versions_server(bytes_view body) {
    if (body.size() != 2) {
        return result<std::uint16_t>::failure(
            "supported_versions from a server must be two bytes");
    }
    return static_cast<std::uint16_t>(body[0] << 8 | body[1]);
}

result<std::vector<key_share_entry>> decode_key_share_client(bytes_view body) {
    byte_reader r{body};
    const bytes_view list = r.take_u16_prefixed();
    if (!r.ok()) return result<std::vector<key_share_entry>>::failure("key_share: " + r.error());
    std::vector<key_share_entry> out;
    byte_reader lr{list};
    while (lr.remaining() > 0) {
        key_share_entry e;
        e.group = lr.u16();
        e.key_exchange = lr.take_u16_prefixed();
        if (!lr.ok()) {
            return result<std::vector<key_share_entry>>::failure("key_share: " + lr.error());
        }
        out.push_back(e);
    }
    return out;
}

result<key_share_entry> decode_key_share_server(bytes_view body) {
    byte_reader r{body};
    key_share_entry e;
    e.group = r.u16();
    // A HelloRetryRequest carries the group alone, with no key.
    if (r.remaining() == 0) {
        if (!r.ok()) return result<key_share_entry>::failure("key_share: " + r.error());
        return e;
    }
    e.key_exchange = r.take_u16_prefixed();
    if (!r.ok() || r.remaining() != 0) {
        return result<key_share_entry>::failure("key_share: malformed server share");
    }
    return e;
}

result<std::vector<std::string>> decode_server_name(bytes_view body) {
    byte_reader r{body};
    const bytes_view list = r.take_u16_prefixed();
    if (!r.ok()) return result<std::vector<std::string>>::failure("server_name: " + r.error());
    std::vector<std::string> out;
    byte_reader lr{list};
    while (lr.remaining() > 0) {
        const std::uint8_t kind = lr.u8();
        const bytes_view name = lr.take_u16_prefixed();
        if (!lr.ok()) return result<std::vector<std::string>>::failure("server_name: " + lr.error());
        if (kind == 0) {  // host_name, the only kind ever defined
            out.emplace_back(reinterpret_cast<const char*>(name.data()), name.size());
        }
    }
    return out;
}

result<std::vector<std::string>> decode_alpn(bytes_view body) {
    byte_reader r{body};
    const bytes_view list = r.take_u16_prefixed();
    if (!r.ok()) return result<std::vector<std::string>>::failure("alpn: " + r.error());
    std::vector<std::string> out;
    byte_reader lr{list};
    while (lr.remaining() > 0) {
        const bytes_view p = lr.take_u8_prefixed();
        if (!lr.ok()) return result<std::vector<std::string>>::failure("alpn: " + lr.error());
        if (p.empty()) return result<std::vector<std::string>>::failure("alpn: empty protocol name");
        out.emplace_back(reinterpret_cast<const char*>(p.data()), p.size());
    }
    return out;
}

std::string version_name(std::uint16_t v) {
    switch (v) {
        case 0x0300: return "SSL 3.0";
        case 0x0301: return "TLS 1.0";
        case 0x0302: return "TLS 1.1";
        case 0x0303: return "TLS 1.2";
        case 0x0304: return "TLS 1.3";
        default:
            if ((v & 0x0f0f) == 0x0a0a) return "GREASE " + hex16(v);
            return "unknown " + hex16(v);
    }
}

std::string cipher_suite_name(std::uint16_t v) {
    static const std::map<std::uint16_t, const char*> names = {
        {0x1301, "TLS_AES_128_GCM_SHA256"},
        {0x1302, "TLS_AES_256_GCM_SHA384"},
        {0x1303, "TLS_CHACHA20_POLY1305_SHA256"},
        {0x1304, "TLS_AES_128_CCM_SHA256"},
        {0x1305, "TLS_AES_128_CCM_8_SHA256"},
        {0xc02b, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
        {0xc02c, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"},
        {0xc02f, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
        {0xc030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
        {0xcca8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"},
        {0xcca9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"},
        {0x009c, "TLS_RSA_WITH_AES_128_GCM_SHA256"},
        {0x009d, "TLS_RSA_WITH_AES_256_GCM_SHA384"},
        {0x002f, "TLS_RSA_WITH_AES_128_CBC_SHA"},
        {0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA"},
        {0x000a, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"},
        {0x0005, "TLS_RSA_WITH_RC4_128_SHA"},
        {0x0004, "TLS_RSA_WITH_RC4_128_MD5"},
        {0x00ff, "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"},
    };
    const auto it = names.find(v);
    if (it != names.end()) return it->second;
    if ((v & 0x0f0f) == 0x0a0a) return "GREASE " + hex16(v);
    return "unknown " + hex16(v);
}

bool is_tls13_cipher_suite(std::uint16_t v) { return v >= 0x1301 && v <= 0x1305; }

std::string group_name(std::uint16_t v) {
    switch (v) {
        case 0x0017: return "secp256r1";
        case 0x0018: return "secp384r1";
        case 0x0019: return "secp521r1";
        case 0x001d: return "x25519";
        case 0x001e: return "x448";
        case 0x0100: return "ffdhe2048";
        case 0x0101: return "ffdhe3072";
        case 0x0102: return "ffdhe4096";
        case 0x0103: return "ffdhe6144";
        case 0x0104: return "ffdhe8192";
        default:
            if ((v & 0x0f0f) == 0x0a0a) return "GREASE " + hex16(v);
            return "unknown " + hex16(v);
    }
}

std::string signature_scheme_name(std::uint16_t v) {
    switch (v) {
        case 0x0201: return "rsa_pkcs1_sha1";
        case 0x0203: return "ecdsa_sha1";
        case 0x0401: return "rsa_pkcs1_sha256";
        case 0x0403: return "ecdsa_secp256r1_sha256";
        case 0x0501: return "rsa_pkcs1_sha384";
        case 0x0503: return "ecdsa_secp384r1_sha384";
        case 0x0601: return "rsa_pkcs1_sha512";
        case 0x0603: return "ecdsa_secp521r1_sha512";
        case 0x0804: return "rsa_pss_rsae_sha256";
        case 0x0805: return "rsa_pss_rsae_sha384";
        case 0x0806: return "rsa_pss_rsae_sha512";
        case 0x0807: return "ed25519";
        case 0x0808: return "ed448";
        case 0x0809: return "rsa_pss_pss_sha256";
        case 0x080a: return "rsa_pss_pss_sha384";
        case 0x080b: return "rsa_pss_pss_sha512";
        default:
            if ((v & 0x0f0f) == 0x0a0a) return "GREASE " + hex16(v);
            return "unknown " + hex16(v);
    }
}

std::string extension_name(std::uint16_t v) {
    switch (v) {
        case ext_server_name: return "server_name";
        case ext_status_request: return "status_request";
        case ext_supported_groups: return "supported_groups";
        case ext_ec_point_formats: return "ec_point_formats";
        case ext_signature_algorithms: return "signature_algorithms";
        case ext_alpn: return "application_layer_protocol_negotiation";
        case ext_signed_certificate_timestamp: return "signed_certificate_timestamp";
        case ext_padding: return "padding";
        case ext_extended_master_secret: return "extended_master_secret";
        case ext_compress_certificate: return "compress_certificate";
        case ext_record_size_limit: return "record_size_limit";
        case ext_session_ticket: return "session_ticket";
        case ext_pre_shared_key: return "pre_shared_key";
        case ext_early_data: return "early_data";
        case ext_supported_versions: return "supported_versions";
        case ext_cookie: return "cookie";
        case ext_psk_key_exchange_modes: return "psk_key_exchange_modes";
        case ext_certificate_authorities: return "certificate_authorities";
        case ext_signature_algorithms_cert: return "signature_algorithms_cert";
        case ext_key_share: return "key_share";
        case ext_renegotiation_info: return "renegotiation_info";
        default:
            if ((v & 0x0f0f) == 0x0a0a) return "GREASE " + hex16(v);
            return "extension " + hex16(v);
    }
}

namespace {

std::vector<std::string> map_names(const std::vector<std::uint16_t>& v,
                                   std::string (*f)(std::uint16_t)) {
    std::vector<std::string> out;
    out.reserve(v.size());
    for (std::uint16_t x : v) out.push_back(f(x));
    return out;
}

}  // namespace

result<handshake_report> summarise(const scan& s) {
    handshake_report rep;
    rep.records = s.records;
    rep.encrypted_records = s.encrypted_records;
    rep.encrypted_bytes = s.encrypted_bytes;

    for (const auto& m : s.messages) {
        if (m.type == handshake_type::client_hello) {
            auto ch = parse_client_hello(m.body);
            if (!ch) return result<handshake_report>::failure(ch.error());
            rep.saw_client_hello = true;
            rep.client_cipher_suites = map_names(ch->cipher_suites, cipher_suite_name);
            for (const auto& e : ch->extensions) rep.client_extensions.push_back(extension_name(e.type));

            if (const extension* e = ch->find(ext_supported_versions)) {
                auto v = decode_supported_versions_client(e->body);
                if (!v) return result<handshake_report>::failure(v.error());
                rep.client_versions = map_names(*v, version_name);
            }
            if (const extension* e = ch->find(ext_supported_groups)) {
                auto v = decode_u16_vector_u16_len(e->body);
                if (!v) return result<handshake_report>::failure("supported_groups: " + v.error());
                rep.client_groups = map_names(*v, group_name);
            }
            if (const extension* e = ch->find(ext_signature_algorithms)) {
                auto v = decode_u16_vector_u16_len(e->body);
                if (!v) {
                    return result<handshake_report>::failure("signature_algorithms: " + v.error());
                }
                rep.client_signature_schemes = map_names(*v, signature_scheme_name);
            }
            if (const extension* e = ch->find(ext_key_share)) {
                auto v = decode_key_share_client(e->body);
                if (!v) return result<handshake_report>::failure(v.error());
                for (const auto& k : *v) {
                    rep.client_key_shares.push_back(group_name(k.group) + " (" +
                                                    std::to_string(k.key_exchange.size()) + " B)");
                }
            }
            if (const extension* e = ch->find(ext_server_name)) {
                auto v = decode_server_name(e->body);
                if (!v) return result<handshake_report>::failure(v.error());
                if (!v->empty()) rep.server_name = (*v)[0];
            }
            if (const extension* e = ch->find(ext_alpn)) {
                auto v = decode_alpn(e->body);
                if (!v) return result<handshake_report>::failure(v.error());
                rep.client_alpn = *v;
            }
        } else if (m.type == handshake_type::server_hello) {
            auto sh = parse_server_hello(m.body);
            if (!sh) return result<handshake_report>::failure(sh.error());
            rep.saw_server_hello = true;
            rep.cipher_suite = sh->cipher_suite;
            rep.cipher_suite_text = cipher_suite_name(sh->cipher_suite);
            for (const auto& e : sh->extensions) rep.server_extensions.push_back(extension_name(e.type));

            // RFC 8446 puts the real version in supported_versions and leaves the
            // legacy field at TLS 1.2 for middlebox tolerance. Reading the legacy
            // field alone is the classic way to misreport a TLS 1.3 connection.
            if (const extension* e = sh->find(ext_supported_versions)) {
                auto v = decode_supported_versions_server(e->body);
                if (!v) return result<handshake_report>::failure(v.error());
                rep.negotiated_version = version_name(*v);
                rep.version_source = "ServerHello supported_versions extension";
            } else {
                rep.negotiated_version = version_name(sh->legacy_version);
                rep.version_source = "ServerHello legacy_version, no supported_versions extension";
            }
            if (const extension* e = sh->find(ext_key_share)) {
                auto v = decode_key_share_server(e->body);
                if (!v) return result<handshake_report>::failure(v.error());
                rep.selected_group = group_name(v->group);
                if (v->key_exchange.empty()) rep.selected_group += " (HelloRetryRequest, no key)";
            }
            if (const extension* e = sh->find(ext_alpn)) {
                auto v = decode_alpn(e->body);
                if (!v) return result<handshake_report>::failure(v.error());
                if (!v->empty()) rep.alpn = (*v)[0];
            }
            if (sh->downgrade_sentinel_tls12()) {
                rep.findings.push_back(
                    "ServerHello.random carries the RFC 8446 downgrade sentinel for TLS 1.2");
            }
            if (sh->downgrade_sentinel_tls11_or_below()) {
                rep.findings.push_back(
                    "ServerHello.random carries the RFC 8446 downgrade sentinel for TLS 1.1 or below");
            }
        }
    }

    if (!rep.saw_client_hello && !rep.saw_server_hello) {
        return result<handshake_report>::failure("no ClientHello and no ServerHello in the stream");
    }

    // Policy observations. NIST SP 800-52 Rev. 2 is written as configuration
    // requirements, which makes statements of this kind mechanically checkable.
    if (rep.saw_server_hello) {
        if (rep.negotiated_version != "TLS 1.3" && rep.negotiated_version != "TLS 1.2") {
            rep.findings.push_back("negotiated version " + rep.negotiated_version +
                                   " is below the TLS 1.2 floor of NIST SP 800-52 Rev. 2");
        }
        if (rep.negotiated_version == "TLS 1.3" && !is_tls13_cipher_suite(rep.cipher_suite)) {
            rep.findings.push_back("cipher suite " + rep.cipher_suite_text +
                                   " is not one of the five defined for TLS 1.3");
        }
    }
    for (const auto& name : rep.client_cipher_suites) {
        if (name.find("RC4") != std::string::npos || name.find("3DES") != std::string::npos ||
            name.find("MD5") != std::string::npos) {
            rep.findings.push_back("client offered the obsolete suite " + name);
        }
    }
    if (rep.saw_client_hello && rep.server_name == "not sent") {
        rep.findings.push_back(
            "client sent no server_name, so a name-based check against the certificate has nothing "
            "to compare against");
    }

    // The boundary of passive observation. This list is the honest part of the
    // report: it names what the observer did not see instead of leaving the
    // reader to assume it saw everything.
    rep.unobservable.push_back(
        "EncryptedExtensions, Certificate, CertificateVerify and Finished: protected under the "
        "handshake traffic keys from the ServerHello onwards");
    rep.unobservable.push_back(
        "the server certificate chain, so a chain check needs the certificates from another source");
    rep.unobservable.push_back("client certificate, if one was requested and sent");
    rep.unobservable.push_back("session resumption tickets and any early data payload");
    if (s.encrypted_records > 0) {
        rep.unobservable.push_back(std::to_string(s.encrypted_bytes) + " byte(s) in " +
                                   std::to_string(s.encrypted_records) +
                                   " protected record(s) were counted but not read");
    }
    return rep;
}

namespace {

void put_list(std::string& out, const char* label, const std::vector<std::string>& v) {
    if (v.empty()) return;
    out += "  ";
    out += label;
    out += ":\n";
    for (const auto& s : v) out += "      " + s + "\n";
}

}  // namespace

std::string render(const handshake_report& rep) {
    std::string out;
    out += "  records seen                : " + std::to_string(rep.records) + " (" +
           std::to_string(rep.encrypted_records) + " protected, " +
           std::to_string(rep.encrypted_bytes) + " protected bytes)\n";
    out += "  ClientHello observed        : " + std::string(rep.saw_client_hello ? "yes" : "no") + "\n";
    out += "  ServerHello observed        : " + std::string(rep.saw_server_hello ? "yes" : "no") + "\n";
    out += "  negotiated version          : " + rep.negotiated_version + "\n";
    out += "  version read from           : " + rep.version_source + "\n";
    out += "  negotiated cipher suite     : " + rep.cipher_suite_text + "\n";
    out += "  negotiated group            : " + rep.selected_group + "\n";
    out += "  server_name from client     : " + rep.server_name + "\n";
    out += "  negotiated ALPN             : " + rep.alpn + "\n";
    put_list(out, "client offered versions", rep.client_versions);
    put_list(out, "client offered cipher suites", rep.client_cipher_suites);
    put_list(out, "client offered groups", rep.client_groups);
    put_list(out, "client key shares", rep.client_key_shares);
    put_list(out, "client signature schemes", rep.client_signature_schemes);
    put_list(out, "client offered ALPN", rep.client_alpn);
    put_list(out, "ClientHello extensions", rep.client_extensions);
    put_list(out, "ServerHello extensions", rep.server_extensions);
    put_list(out, "findings", rep.findings);
    put_list(out, "not observable by a passive reader", rep.unobservable);
    return out;
}

}  // namespace sentinel::tls
