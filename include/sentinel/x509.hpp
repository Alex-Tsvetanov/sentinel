// X.509 version 3 certificates, decoded from DER.
//
// The structure follows ITU-T X.509 as profiled for the internet by RFC 5280.
// Only the fields the chain validator needs are decoded, and everything decoded
// is decoded honestly: an unrecognised critical extension is recorded rather
// than ignored, because ignoring it is precisely the mistake RFC 5280 section
// 6.1 forbids.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "sentinel/bytes.hpp"
#include "sentinel/der.hpp"

namespace sentinel::x509 {

struct attribute {
    std::string type;   // dotted object identifier
    std::string label;  // CN, O, C and so on, or the dotted form when unknown
    std::string value;
};

struct distinguished_name {
    std::vector<attribute> attributes;

    std::string text() const;       // human readable, most specific first
    std::string canonical() const;  // case folded and whitespace collapsed, for comparison
    const std::string* find(const std::string& label) const;
    bool empty() const { return attributes.empty(); }
};

enum class general_name_kind {
    other,
    rfc822,
    dns,
    directory,
    uri,
    ip,
    registered_id,
};

struct general_name {
    general_name_kind kind = general_name_kind::other;
    std::string value;
    std::string kind_text() const;
};

struct validity {
    std::int64_t not_before = 0;
    std::int64_t not_after = 0;
};

struct basic_constraints {
    bool present = false;
    bool critical = false;
    bool is_ca = false;
    bool has_path_len = false;
    std::int64_t path_len = 0;
};

// Bit positions from RFC 5280 section 4.2.1.3.
enum key_usage_bit {
    ku_digital_signature = 0,
    ku_non_repudiation = 1,
    ku_key_encipherment = 2,
    ku_data_encipherment = 3,
    ku_key_agreement = 4,
    ku_key_cert_sign = 5,
    ku_crl_sign = 6,
    ku_encipher_only = 7,
    ku_decipher_only = 8,
};

struct key_usage {
    bool present = false;
    bool critical = false;
    std::uint16_t bits = 0;

    bool has(key_usage_bit b) const { return (bits >> b) & 1u; }
    std::string text() const;
};

struct name_constraints {
    bool present = false;
    bool critical = false;
    std::vector<general_name> permitted;
    std::vector<general_name> excluded;
};

struct certificate {
    int version = 1;  // 1, 2 or 3
    std::string serial_hex;
    std::string signature_algorithm;      // from the inner AlgorithmIdentifier
    std::string outer_signature_algorithm;
    distinguished_name issuer;
    distinguished_name subject;
    validity valid;
    std::string public_key_algorithm;
    std::size_t public_key_bits = 0;
    std::vector<general_name> subject_alt_names;
    basic_constraints constraints;
    key_usage usage;
    name_constraints constrained_names;
    std::vector<std::string> extended_key_usage;      // labels, serverAuth and so on
    std::vector<std::string> unhandled_critical;      // critical and not understood
    std::string subject_key_id_hex;
    std::string authority_key_id_hex;

    bytes_view tbs;        // exact bytes a signature would be computed over
    bytes_view signature;  // signature value, unused without a crypto backend

    bool self_issued() const { return issuer.canonical() == subject.canonical(); }
    std::string summary() const;
};

result<certificate> parse_certificate(bytes_view der_bytes);

// RFC 6125 style host name matching, with the wildcard rules that actually
// apply: at most one wildcard, leftmost label only, and it never spans a dot.
bool host_matches(const std::string& pattern, const std::string& host);

// True when host falls inside the dNSName subtree base, per RFC 5280 section
// 4.2.1.10, where an empty base matches everything.
bool dns_within_subtree(const std::string& base, const std::string& host);

}  // namespace sentinel::x509
