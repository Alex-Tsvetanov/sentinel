#include "sentinel/crypto.hpp"

#include <sstream>

#if defined(SENTINEL_HAS_OPENSSL) && SENTINEL_HAS_OPENSSL
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/x509.h>
#endif

namespace sentinel::crypto {

bool available() {
#if defined(SENTINEL_HAS_OPENSSL) && SENTINEL_HAS_OPENSSL
    return true;
#else
    return false;
#endif
}

std::string backend_name() {
#if defined(SENTINEL_HAS_OPENSSL) && SENTINEL_HAS_OPENSSL
    return OPENSSL_VERSION_TEXT;
#else
    return "none";
#endif
}

#if defined(SENTINEL_HAS_OPENSSL) && SENTINEL_HAS_OPENSSL
namespace {

const EVP_MD* digest_for_algorithm(const std::string& alg) {
    // Labels produced by der::oid_label for the algorithms the fixture signs with.
    if (alg == "sha256WithRSAEncryption") return EVP_sha256();
    if (alg == "sha384WithRSAEncryption") return EVP_sha384();
    if (alg == "sha512WithRSAEncryption") return EVP_sha512();
    if (alg == "ecdsa-with-SHA256") return EVP_sha256();
    if (alg == "ecdsa-with-SHA384") return EVP_sha384();
    return nullptr;
}

}  // namespace
#endif

verify_result verify_certificate_signature(const x509::certificate& subject,
                                           const x509::certificate& issuer) {
#if !(defined(SENTINEL_HAS_OPENSSL) && SENTINEL_HAS_OPENSSL)
    (void)subject;
    (void)issuer;
    return {verify_status::skipped,
            "not performed: no cryptographic backend is compiled in"};
#else
    if (subject.tbs.empty()) {
        return {verify_status::failed, "subject TBSCertificate is empty"};
    }
    if (subject.signature.empty()) {
        return {verify_status::failed, "subject signatureValue is empty"};
    }
    if (issuer.public_key_info.empty()) {
        return {verify_status::failed, "issuer subjectPublicKeyInfo is empty"};
    }
    if (subject.signature_algorithm != subject.outer_signature_algorithm) {
        return {verify_status::failed,
                "inner and outer signatureAlgorithm disagree (" + subject.signature_algorithm +
                    " vs " + subject.outer_signature_algorithm + ")"};
    }

    const EVP_MD* md = digest_for_algorithm(subject.signature_algorithm);
    if (!md) {
        return {verify_status::failed,
                "signature algorithm " + subject.signature_algorithm +
                    " is not supported by this backend"};
    }

    const unsigned char* p = issuer.public_key_info.data();
    EVP_PKEY* pkey = d2i_PUBKEY(nullptr, &p, static_cast<long>(issuer.public_key_info.size()));
    if (!pkey) {
        return {verify_status::failed, "failed to decode issuer subjectPublicKeyInfo"};
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return {verify_status::failed, "EVP_MD_CTX_new failed"};
    }

    verify_result out;
    if (EVP_DigestVerifyInit(ctx, nullptr, md, nullptr, pkey) != 1) {
        out = {verify_status::failed, "EVP_DigestVerifyInit failed"};
    } else if (EVP_DigestVerifyUpdate(ctx, subject.tbs.data(), subject.tbs.size()) != 1) {
        out = {verify_status::failed, "EVP_DigestVerifyUpdate failed"};
    } else {
        const int rc =
            EVP_DigestVerifyFinal(ctx, subject.signature.data(), subject.signature.size());
        if (rc == 1) {
            std::ostringstream detail;
            detail << "issuer signature over TBSCertificate verifies with " << backend_name()
                   << " (" << subject.signature_algorithm << ")";
            out = {verify_status::passed, detail.str()};
        } else if (rc == 0) {
            out = {verify_status::failed, "issuer signature does not verify"};
        } else {
            out = {verify_status::failed, "EVP_DigestVerifyFinal failed"};
        }
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return out;
#endif
}

}  // namespace sentinel::crypto
