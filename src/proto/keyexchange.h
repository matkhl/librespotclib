#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <optional>

namespace librespotc::proto {

// Subset of keyexchange messages.

std::vector<uint8_t> encode_client_hello(
    const std::vector<uint8_t>& gc,        // DH public key (big-endian)
    const std::vector<uint8_t>& client_nonce, // 16 bytes
    uint64_t spotify_version = 0x10800000000ULL); // arbitrary modern version

struct ApChallenge {
    std::vector<uint8_t> gs;            // server DH public
    std::vector<uint8_t> gs_signature;  // RSA-PKCS1v15-SHA1 of gs
};

struct ApResponse {
    std::optional<ApChallenge> challenge;
    // login_failed details if upgrade/failure
    int32_t error_code = 0;
    bool has_failure = false;
    std::string error_desc;
    bool upgrade_required = false;
};

// Parse an APResponseMessage payload (without the 4-byte length prefix).
ApResponse decode_ap_response(const uint8_t* data, size_t len);

// hmac = challenge to send back in ClientResponsePlaintext
std::vector<uint8_t> encode_client_response_plaintext(
    const std::vector<uint8_t>& hmac);

} // namespace librespotc::proto
