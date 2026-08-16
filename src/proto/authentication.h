#pragma once
#include <cstdint>
#include <vector>
#include <string>

namespace librespotc::proto {

enum class AuthType : int32_t {
    USER_PASS = 0,
    STORED_SPOTIFY = 1,
    SPOTIFY_TOKEN = 3,
};

// Encode ClientResponseEncrypted.
// device_id: stable per-installation identifier (lowercase hex SHA-1 of device name OK).
std::vector<uint8_t> encode_client_response_encrypted(
    const std::string& username,
    AuthType type,
    const std::vector<uint8_t>& auth_data,
    const std::string& device_id);

struct ApWelcome {
    std::string canonical_username;
    int32_t reusable_auth_credentials_type = 0;
    std::vector<uint8_t> reusable_auth_credentials;
};

struct AuthFailure {
    int32_t error_code = 0;
    std::string error_desc;
};

ApWelcome decode_ap_welcome(const uint8_t* data, size_t len);
AuthFailure decode_auth_failure(const uint8_t* data, size_t len);

} // namespace librespotc::proto
