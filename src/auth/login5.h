#pragma once
#include <cstdint>
#include <chrono>
#include <mutex>
#include <string>
#include <vector>

namespace librespotc::auth {

class Login5Provider {
public:
    Login5Provider(std::string client_id,
                   std::string device_id,
                   std::string username,
                   std::vector<uint8_t> stored_credential_blob);

    // Returns access_token (refreshes if missing/expired). Empty on failure.
    // Requires a working client_token (passed in as header value).
    std::string access_token(const std::string& client_token);
    void invalidate();

private:
    std::string client_id_;
    std::string device_id_;
    std::string username_;
    std::vector<uint8_t> stored_blob_;

    std::mutex m_;
    std::string current_;
    std::chrono::steady_clock::time_point expiry_;
    bool fetch_locked(const std::string& client_token, std::string& err);
};

} // namespace librespotc::auth
