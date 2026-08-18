#include "sentinel/x509.hpp"

#include <algorithm>
#include <cctype>

namespace sentinel::x509 {
namespace {

std::string lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// Whitespace collapsed and case folded, which is the practical reading of the
// X.520 caseIgnoreMatch rule that RFC 5280 section 7.1 points at for name
// chaining. Two names that differ only in spacing must chain.
std::string fold(const std::string& s) {
    std::string out;
    bool space = false;
    for (char c : s) {
        if (std::isspace(static_cast<unsigned char>(c))) {
            space = !out.empty();
            continue;
        }
        if (space) out += ' ';
        space = false;
        out += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return out;
}

result<std::vector<general_name>> parse_general_names(bytes_view content) {
    std::vector<general_name> out;
    der::reader r{content};
    while (!r.empty()) {
        auto t = r.next();
        if (!t) return result<std::vector<general_name>>::failure("GeneralName: " + r.error());
        general_name g;
        auto as_text = [&] {
            return std::string(reinterpret_cast<const char*>(t->content.data()), t->content.size());
        };
        switch (t->number) {
            case 1: g.kind = general_name_kind::rfc822; g.value = as_text(); break;
            case 2: g.kind = general_name_kind::dns; g.value = lower(as_text()); break;
            case 6: g.kind = general_name_kind::uri; g.value = as_text(); break;
            case 7: {
                g.kind = general_name_kind::ip;
                const bytes_view b = t->content;
                if (b.size() == 4) {
                    g.value = std::to_string(b[0]) + "." + std::to_string(b[1]) + "." +
                              std::to_string(b[2]) + "." + std::to_string(b[3]);
                } else {
                    g.value = to_hex(b);
                }
                break;
            }
            case 8: g.kind = general_name_kind::registered_id; g.value = der::oid_to_string(t->content); break;
            case 4: g.kind = general_name_kind::directory; g.value = to_hex(t->content, 16); break;
            default: g.kind = general_name_kind::other; g.value = to_hex(t->content, 16); break;
        }
        out.push_back(std::move(g));
    }
    return out;
}

result<distinguished_name> parse_name(const der::tlv& seq) {
    distinguished_name dn;
    der::reader rdns{seq.content};
    while (!rdns.empty()) {
        auto rdn = rdns.next(der::tag::set);
        if (!rdn) return result<distinguished_name>::failure("RDN: " + rdns.error());
        der::reader atvs{rdn->content};
        while (!atvs.empty()) {
            auto atv = atvs.next(der::tag::sequence);
            if (!atv) return result<distinguished_name>::failure("attribute: " + atvs.error());
            der::reader f{atv->content};
            auto oid = f.next(der::tag::oid);
            if (!oid) return result<distinguished_name>::failure("attribute type: " + f.error());
            auto val = f.next();
            if (!val) return result<distinguished_name>::failure("attribute value: " + f.error());
            attribute a;
            a.type = der::oid_to_string(oid->content);
            if (a.type.empty()) {
                return result<distinguished_name>::failure("malformed attribute type identifier");
            }
            a.label = der::oid_label(a.type);
            auto s = der::parse_string(*val);
            a.value = s ? *s : "<" + to_hex(val->content, 12) + ">";
            dn.attributes.push_back(std::move(a));
        }
    }
    return dn;
}

}  // namespace

std::string general_name::kind_text() const {
    switch (kind) {
        case general_name_kind::rfc822: return "rfc822Name";
        case general_name_kind::dns: return "dNSName";
        case general_name_kind::directory: return "directoryName";
        case general_name_kind::uri: return "uniformResourceIdentifier";
        case general_name_kind::ip: return "iPAddress";
        case general_name_kind::registered_id: return "registeredID";
        default: return "otherName";
    }
}

std::string distinguished_name::text() const {
    std::string out;
    // Printed most specific first, which is how a reader expects to see it and
    // the reverse of the encoding order.
    for (std::size_t i = attributes.size(); i-- > 0;) {
        if (!out.empty()) out += ", ";
        out += attributes[i].label + "=" + attributes[i].value;
    }
    return out.empty() ? "<empty>" : out;
}

std::string distinguished_name::canonical() const {
    std::string out;
    for (const auto& a : attributes) {
        out += a.type;
        out += '=';
        out += fold(a.value);
        out += '\x1f';
    }
    return out;
}

const std::string* distinguished_name::find(const std::string& label) const {
    for (std::size_t i = attributes.size(); i-- > 0;) {
        if (attributes[i].label == label) return &attributes[i].value;
    }
    return nullptr;
}

std::string key_usage::text() const {
    if (!present) return "absent";
    static const char* names[] = {"digitalSignature", "nonRepudiation", "keyEncipherment",
                                  "dataEncipherment", "keyAgreement",   "keyCertSign",
                                  "cRLSign",          "encipherOnly",   "decipherOnly"};
    std::string out;
    for (int i = 0; i < 9; ++i) {
        if ((bits >> i) & 1u) {
            if (!out.empty()) out += ", ";
            out += names[i];
        }
    }
    return out.empty() ? "none" : out;
}

std::string certificate::summary() const {
    std::string out = subject.text();
    out += " [serial " + serial_hex + ", " + der::format_time(valid.not_before) + " .. " +
           der::format_time(valid.not_after) + "]";
    return out;
}

result<certificate> parse_certificate(bytes_view der_bytes) {
    certificate c;
    der::reader top{der_bytes};
    auto cert = top.next(der::tag::sequence);
    if (!cert) return result<certificate>::failure("Certificate: " + top.error());

    der::reader body{cert->content};
    auto tbs = body.next(der::tag::sequence);
    if (!tbs) return result<certificate>::failure("TBSCertificate: " + body.error());
    c.tbs = tbs->whole;

    auto sigalg = body.next(der::tag::sequence);
    if (!sigalg) return result<certificate>::failure("signatureAlgorithm: " + body.error());
    {
        der::reader a{sigalg->content};
        auto oid = a.next(der::tag::oid);
        if (!oid) return result<certificate>::failure("signatureAlgorithm: " + a.error());
        c.outer_signature_algorithm = der::oid_label(der::oid_to_string(oid->content));
    }
    auto sigval = body.next(der::tag::bit_string);
    if (!sigval) return result<certificate>::failure("signatureValue: " + body.error());
    std::uint8_t unused = 0;
    auto sig = der::parse_bit_string(sigval->content, unused);
    if (!sig) return result<certificate>::failure("signatureValue: " + sig.error());
    c.signature = *sig;

    der::reader t{tbs->content};
    auto first = t.next();
    if (!first) return result<certificate>::failure("TBSCertificate: " + t.error());
    if (first->is_context(0)) {
        der::reader v{first->content};
        auto ver = v.next(der::tag::integer);
        if (!ver) return result<certificate>::failure("version: " + v.error());
        auto n = der::parse_integer(ver->content);
        if (!n) return result<certificate>::failure("version: " + n.error());
        if (*n < 0 || *n > 2) {
            return result<certificate>::failure("version value " + std::to_string(*n) +
                                                " is outside v1 to v3");
        }
        c.version = static_cast<int>(*n) + 1;
        first = t.next(der::tag::integer);
        if (!first) return result<certificate>::failure("serialNumber: " + t.error());
    } else if (!first->is(der::tag::integer)) {
        return result<certificate>::failure("expected a version tag or a serial number");
    }
    c.serial_hex = der::integer_to_hex(first->content);

    auto inner_alg = t.next(der::tag::sequence);
    if (!inner_alg) return result<certificate>::failure("signature: " + t.error());
    {
        der::reader a{inner_alg->content};
        auto oid = a.next(der::tag::oid);
        if (!oid) return result<certificate>::failure("signature: " + a.error());
        c.signature_algorithm = der::oid_label(der::oid_to_string(oid->content));
    }

    auto issuer = t.next(der::tag::sequence);
    if (!issuer) return result<certificate>::failure("issuer: " + t.error());
    auto issuer_dn = parse_name(*issuer);
    if (!issuer_dn) return result<certificate>::failure("issuer: " + issuer_dn.error());
    c.issuer = std::move(*issuer_dn);

    auto valid_seq = t.next(der::tag::sequence);
    if (!valid_seq) return result<certificate>::failure("validity: " + t.error());
    {
        der::reader v{valid_seq->content};
        auto nb = v.next();
        auto na = nb ? v.next() : std::nullopt;
        if (!nb || !na) return result<certificate>::failure("validity: " + v.error());
        auto a = der::parse_time(*nb);
        auto b = der::parse_time(*na);
        if (!a) return result<certificate>::failure("notBefore: " + a.error());
        if (!b) return result<certificate>::failure("notAfter: " + b.error());
        c.valid.not_before = *a;
        c.valid.not_after = *b;
    }

    auto subject = t.next(der::tag::sequence);
    if (!subject) return result<certificate>::failure("subject: " + t.error());
    auto subject_dn = parse_name(*subject);
    if (!subject_dn) return result<certificate>::failure("subject: " + subject_dn.error());
    c.subject = std::move(*subject_dn);

    auto spki = t.next(der::tag::sequence);
    if (!spki) return result<certificate>::failure("subjectPublicKeyInfo: " + t.error());
    {
        der::reader s{spki->content};
        auto alg = s.next(der::tag::sequence);
        if (!alg) return result<certificate>::failure("public key algorithm: " + s.error());
        der::reader a{alg->content};
        auto oid = a.next(der::tag::oid);
        if (!oid) return result<certificate>::failure("public key algorithm: " + a.error());
        c.public_key_algorithm = der::oid_label(der::oid_to_string(oid->content));
        auto key = s.next(der::tag::bit_string);
        if (!key) return result<certificate>::failure("subjectPublicKey: " + s.error());
        std::uint8_t unused_key_bits = 0;
        auto k = der::parse_bit_string(key->content, unused_key_bits);
        if (!k) return result<certificate>::failure("subjectPublicKey: " + k.error());
        c.public_key_bits = k->size() * 8 - unused_key_bits;
    }

    // The two unique identifier fields are v2 leftovers. They are skipped rather
    // than decoded, but they must be skipped correctly or the extension block is
    // read from the wrong place.
    while (!t.empty()) {
        auto e = t.next();
        if (!e) return result<certificate>::failure("TBSCertificate tail: " + t.error());
        if (e->is_context(1) || e->is_context(2)) continue;
        if (!e->is_context(3)) {
            return result<certificate>::failure("unexpected element in the TBSCertificate tail");
        }
        if (c.version != 3) {
            return result<certificate>::failure("extensions are present in a v" +
                                                std::to_string(c.version) + " certificate");
        }
        der::reader ex_outer{e->content};
        auto ex_seq = ex_outer.next(der::tag::sequence);
        if (!ex_seq) return result<certificate>::failure("extensions: " + ex_outer.error());
        der::reader ex{ex_seq->content};
        while (!ex.empty()) {
            auto one = ex.next(der::tag::sequence);
            if (!one) return result<certificate>::failure("extension: " + ex.error());
            der::reader f{one->content};
            auto oid = f.next(der::tag::oid);
            if (!oid) return result<certificate>::failure("extension id: " + f.error());
            const std::string dotted = der::oid_to_string(oid->content);
            bool critical = false;
            auto nxt = f.next();
            if (!nxt) return result<certificate>::failure("extension body: " + f.error());
            if (nxt->is(der::tag::boolean)) {
                auto b = der::parse_boolean(nxt->content);
                if (!b) return result<certificate>::failure("extension critical flag: " + b.error());
                critical = *b;
                nxt = f.next();
                if (!nxt) return result<certificate>::failure("extension body: " + f.error());
            }
            if (!nxt->is(der::tag::octet_string)) {
                return result<certificate>::failure("extension value is not an OCTET STRING");
            }
            const bytes_view value = nxt->content;
            bool understood = true;

            if (dotted == "2.5.29.19") {
                c.constraints.present = true;
                c.constraints.critical = critical;
                der::reader v{value};
                auto seq = v.next(der::tag::sequence);
                if (!seq) return result<certificate>::failure("basicConstraints: " + v.error());
                der::reader b{seq->content};
                while (!b.empty()) {
                    auto item = b.next();
                    if (!item) return result<certificate>::failure("basicConstraints: " + b.error());
                    if (item->is(der::tag::boolean)) {
                        auto ca = der::parse_boolean(item->content);
                        if (!ca) return result<certificate>::failure("basicConstraints cA: " + ca.error());
                        c.constraints.is_ca = *ca;
                    } else if (item->is(der::tag::integer)) {
                        auto n = der::parse_integer(item->content);
                        if (!n || *n < 0) {
                            return result<certificate>::failure("basicConstraints pathLenConstraint");
                        }
                        c.constraints.has_path_len = true;
                        c.constraints.path_len = *n;
                    }
                }
            } else if (dotted == "2.5.29.15") {
                c.usage.present = true;
                c.usage.critical = critical;
                der::reader v{value};
                auto bs = v.next(der::tag::bit_string);
                if (!bs) return result<certificate>::failure("keyUsage: " + v.error());
                std::uint8_t unused_bits = 0;
                auto payload = der::parse_bit_string(bs->content, unused_bits);
                if (!payload) return result<certificate>::failure("keyUsage: " + payload.error());
                // Bit zero is the most significant bit of the first byte.
                for (std::size_t i = 0; i < payload->size() && i < 2; ++i) {
                    for (int bit = 0; bit < 8; ++bit) {
                        const std::size_t index = i * 8 + static_cast<std::size_t>(bit);
                        if (index >= payload->size() * 8 - unused_bits) break;
                        if (((*payload)[i] >> (7 - bit)) & 1u) {
                            c.usage.bits |= static_cast<std::uint16_t>(1u << index);
                        }
                    }
                }
            } else if (dotted == "2.5.29.17") {
                der::reader v{value};
                auto seq = v.next(der::tag::sequence);
                if (!seq) return result<certificate>::failure("subjectAltName: " + v.error());
                auto names = parse_general_names(seq->content);
                if (!names) return result<certificate>::failure("subjectAltName: " + names.error());
                c.subject_alt_names = std::move(*names);
            } else if (dotted == "2.5.29.37") {
                der::reader v{value};
                auto seq = v.next(der::tag::sequence);
                if (!seq) return result<certificate>::failure("extKeyUsage: " + v.error());
                der::reader k{seq->content};
                while (!k.empty()) {
                    auto purpose = k.next(der::tag::oid);
                    if (!purpose) return result<certificate>::failure("extKeyUsage: " + k.error());
                    c.extended_key_usage.push_back(der::oid_label(der::oid_to_string(purpose->content)));
                }
            } else if (dotted == "2.5.29.30") {
                c.constrained_names.present = true;
                c.constrained_names.critical = critical;
                der::reader v{value};
                auto seq = v.next(der::tag::sequence);
                if (!seq) return result<certificate>::failure("nameConstraints: " + v.error());
                der::reader s{seq->content};
                while (!s.empty()) {
                    auto side = s.next();
                    if (!side) return result<certificate>::failure("nameConstraints: " + s.error());
                    // Each GeneralSubtree wraps the base name and two defaults
                    // that RFC 5280 requires to be absent.
                    der::reader subtrees{side->content};
                    std::vector<general_name> collected;
                    while (!subtrees.empty()) {
                        auto sub = subtrees.next(der::tag::sequence);
                        if (!sub) return result<certificate>::failure("GeneralSubtree: " + subtrees.error());
                        auto base = parse_general_names(sub->content);
                        if (!base) return result<certificate>::failure("GeneralSubtree: " + base.error());
                        if (!base->empty()) collected.push_back((*base)[0]);
                    }
                    if (side->is_context(0)) {
                        c.constrained_names.permitted = std::move(collected);
                    } else if (side->is_context(1)) {
                        c.constrained_names.excluded = std::move(collected);
                    }
                }
            } else if (dotted == "2.5.29.14") {
                der::reader v{value};
                auto os = v.next(der::tag::octet_string);
                if (!os) return result<certificate>::failure("subjectKeyIdentifier: " + v.error());
                c.subject_key_id_hex = to_hex(os->content);
            } else if (dotted == "2.5.29.35") {
                der::reader v{value};
                auto seq = v.next(der::tag::sequence);
                if (!seq) return result<certificate>::failure("authorityKeyIdentifier: " + v.error());
                der::reader a{seq->content};
                while (!a.empty()) {
                    auto item = a.next();
                    if (!item) break;
                    if (item->is_context(0)) c.authority_key_id_hex = to_hex(item->content);
                }
            } else {
                understood = false;
            }

            // RFC 5280 section 6.1: a path must be rejected when a certificate on
            // it carries a critical extension the verifier does not process.
            if (!understood && critical) {
                c.unhandled_critical.push_back(der::oid_label(dotted));
            }
        }
    }
    return c;
}

bool host_matches(const std::string& pattern, const std::string& host) {
    const std::string p = lower(pattern);
    const std::string h = lower(host);
    if (p.empty() || h.empty()) return false;
    const std::size_t star = p.find('*');
    if (star == std::string::npos) return p == h;
    // One wildcard, in the leftmost label only. Anything else is refused rather
    // than interpreted, because the interpretations differ between libraries and
    // the disagreement is exactly where certificate confusion lives.
    if (p.find('*', star + 1) != std::string::npos) return false;
    const std::size_t first_dot = p.find('.');
    if (first_dot == std::string::npos || star > first_dot) return false;
    // A wildcard needs at least two labels behind it, so that *.com cannot match.
    const std::string suffix = p.substr(first_dot);
    if (std::count(suffix.begin(), suffix.end(), '.') < 2) return false;

    const std::size_t host_dot = h.find('.');
    if (host_dot == std::string::npos) return false;
    if (h.substr(host_dot) != suffix) return false;

    // The wildcard never spans a dot, and the fixed parts of the label around it
    // must still match.
    const std::string plabel = p.substr(0, first_dot);
    const std::string hlabel = h.substr(0, host_dot);
    const std::string before = plabel.substr(0, star);
    const std::string after = plabel.substr(star + 1);
    if (hlabel.size() < before.size() + after.size()) return false;
    return hlabel.compare(0, before.size(), before) == 0 &&
           hlabel.compare(hlabel.size() - after.size(), after.size(), after) == 0;
}

bool dns_within_subtree(const std::string& base, const std::string& host) {
    const std::string b = lower(base);
    const std::string h = lower(host);
    if (b.empty()) return true;  // an empty base covers every name
    if (h == b) return true;
    if (h.size() <= b.size()) return false;
    // RFC 5280 section 4.2.1.10: example.com covers host.example.com but not
    // notexample.com, so the character before the suffix has to be a label break.
    if (h.compare(h.size() - b.size(), b.size(), b) != 0) return false;
    const char sep = h[h.size() - b.size() - 1];
    return sep == '.' || b[0] == '.';
}

}  // namespace sentinel::x509
