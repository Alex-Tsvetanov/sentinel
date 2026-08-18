// TLS 1.3 record layer and handshake parsing, over a plain byte buffer.
//
// The input is a span of bytes. Where those bytes came from is not this layer's
// business: a file written by a capture tool, a socket, or a fixture built in
// the test suite all look the same here. That is deliberate, and it is why the
// project needs no packet capture library to be useful or testable.
//
// Structure per RFC 8446. Nothing in the parsed structures owns its bytes; every
// field is a view into the caller's buffer.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "sentinel/bytes.hpp"

namespace sentinel::tls {

enum class content_type : std::uint8_t {
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,
};

enum class handshake_type : std::uint8_t {
    client_hello = 1,
    server_hello = 2,
    new_session_ticket = 4,
    end_of_early_data = 5,
    encrypted_extensions = 8,
    certificate = 11,
    certificate_request = 13,
    certificate_verify = 15,
    finished = 20,
    key_update = 24,
};

// Extension numbers used by the report. Others are shown by number.
enum : std::uint16_t {
    ext_server_name = 0,
    ext_status_request = 5,
    ext_supported_groups = 10,
    ext_ec_point_formats = 11,
    ext_signature_algorithms = 13,
    ext_alpn = 16,
    ext_signed_certificate_timestamp = 18,
    ext_padding = 21,
    ext_extended_master_secret = 23,
    ext_compress_certificate = 27,
    ext_record_size_limit = 28,
    ext_session_ticket = 35,
    ext_pre_shared_key = 41,
    ext_early_data = 42,
    ext_supported_versions = 43,
    ext_cookie = 44,
    ext_psk_key_exchange_modes = 45,
    ext_certificate_authorities = 47,
    ext_signature_algorithms_cert = 50,
    ext_key_share = 51,
    ext_renegotiation_info = 65281,
};

struct record {
    content_type type{};
    std::uint16_t legacy_version = 0;
    bytes_view fragment;
};

struct extension {
    std::uint16_t type = 0;
    bytes_view body;
};

struct key_share_entry {
    std::uint16_t group = 0;
    bytes_view key_exchange;
};

struct client_hello {
    std::uint16_t legacy_version = 0;
    bytes_view random;
    bytes_view session_id;
    std::vector<std::uint16_t> cipher_suites;
    std::vector<std::uint8_t> compression_methods;
    std::vector<extension> extensions;

    const extension* find(std::uint16_t type) const;
};

struct server_hello {
    std::uint16_t legacy_version = 0;
    bytes_view random;
    bytes_view session_id;
    std::uint16_t cipher_suite = 0;
    std::uint8_t compression_method = 0;
    std::vector<extension> extensions;

    const extension* find(std::uint16_t type) const;

    // RFC 8446 section 4.1.3: a TLS 1.3 server that has fallen back to an older
    // version writes a fixed value into the last eight bytes of ServerHello.random
    // so the client can notice the downgrade. A passive observer can notice it too.
    bool downgrade_sentinel_tls12() const;
    bool downgrade_sentinel_tls11_or_below() const;
};

struct message {
    handshake_type type{};
    bytes_view body;
};

// The result of walking a byte stream: the records that were seen, the handshake
// messages reassembled out of them, and a count of what could not be read
// because it was encrypted.
struct scan {
    std::vector<std::uint8_t> handshake_bytes;  // owns the reassembled stream
    std::vector<message> messages;              // views into handshake_bytes
    std::size_t records = 0;
    std::size_t handshake_records = 0;
    std::size_t encrypted_records = 0;
    std::size_t change_cipher_spec_records = 0;
    std::size_t alert_records = 0;
    std::size_t encrypted_bytes = 0;
    std::size_t total_bytes = 0;
};

result<record> parse_record(byte_reader& r);
result<scan> scan_stream(bytes_view buf);

result<client_hello> parse_client_hello(bytes_view body);
result<server_hello> parse_server_hello(bytes_view body);

result<std::vector<std::uint16_t>> decode_u16_vector_u16_len(bytes_view body);
result<std::vector<std::uint16_t>> decode_supported_versions_client(bytes_view body);
result<std::uint16_t> decode_supported_versions_server(bytes_view body);
result<std::vector<key_share_entry>> decode_key_share_client(bytes_view body);
result<key_share_entry> decode_key_share_server(bytes_view body);
result<std::vector<std::string>> decode_server_name(bytes_view body);
result<std::vector<std::string>> decode_alpn(bytes_view body);

std::string version_name(std::uint16_t v);
std::string cipher_suite_name(std::uint16_t v);
std::string group_name(std::uint16_t v);
std::string signature_scheme_name(std::uint16_t v);
std::string extension_name(std::uint16_t v);
bool is_tls13_cipher_suite(std::uint16_t v);

// What the observer actually established, and what it explicitly could not.
struct handshake_report {
    bool saw_client_hello = false;
    bool saw_server_hello = false;

    std::string negotiated_version = "unknown";
    std::string version_source = "not observed";
    std::uint16_t cipher_suite = 0;
    std::string cipher_suite_text = "unknown";
    std::string selected_group = "not observed";
    std::string server_name = "not sent";
    std::string alpn = "not observed";

    std::vector<std::string> client_versions;
    std::vector<std::string> client_cipher_suites;
    std::vector<std::string> client_groups;
    std::vector<std::string> client_key_shares;
    std::vector<std::string> client_signature_schemes;
    std::vector<std::string> client_alpn;
    std::vector<std::string> client_extensions;
    std::vector<std::string> server_extensions;

    std::vector<std::string> findings;   // policy observations, worst first
    std::vector<std::string> unobservable;

    std::size_t records = 0;
    std::size_t encrypted_records = 0;
    std::size_t encrypted_bytes = 0;
};

result<handshake_report> summarise(const scan& s);
std::string render(const handshake_report& rep);

}  // namespace sentinel::tls
