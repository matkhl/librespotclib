#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace librespotc::crypto {

std::string b64_encode(const uint8_t* data, size_t len);
inline std::string b64_encode(const std::vector<uint8_t>& v) {
    return b64_encode(v.data(), v.size());
}
// Returns empty vector on parse failure.
std::vector<uint8_t> b64_decode(const std::string& s);

// URL-decode application/x-www-form-urlencoded value.
std::string url_decode(const std::string& s);

} // namespace librespotc::crypto
