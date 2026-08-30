// Optional cryptographic backend for X.509 signature verification.
//
// The default build prefers to stay free of third-party code. When the platform
// provides OpenSSL/libcrypto and CMake finds it with find_package(OpenSSL QUIET),
// this layer calls that library to verify issuer signatures. When it does not,
// every call reports that verification was skipped. Nothing here invents a
// result that was not produced by a real verify operation.
#pragma once

#include <string>

#include "sentinel/bytes.hpp"
#include "sentinel/x509.hpp"

namespace sentinel::crypto {

// True only when a system cryptographic library was linked into this build.
bool available();

// Human-readable backend identity, e.g. "OpenSSL 3.0.13", or "none".
std::string backend_name();

enum class verify_status { passed, failed, skipped };

struct verify_result {
    verify_status status = verify_status::skipped;
    std::string detail;
};

// Verifies that subject.signature is the issuer's signature over subject.tbs,
// using issuer.public_key_info and subject.signature_algorithm. Reports skipped
// when no backend is compiled in; never reports passed without a successful
// library verify call.
verify_result verify_certificate_signature(const x509::certificate& subject,
                                           const x509::certificate& issuer);

}  // namespace sentinel::crypto
