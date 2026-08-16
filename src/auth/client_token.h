#pragma once
#include <string>
#include <chrono>
#include <mutex>

namespace librespotc::auth {

class ClientTokenProvider {
public:
    ClientTokenProvider(std::string client_id,
                        std::string device_id,
                        std::string client_version = "1.2.52.442");

    // Returns current token (refreshes if missing/expired). Empty string on failure.
    std::string token();
    void invalidate();

private:
    std::string client_id_;
    std::string device_id_;
    std::string client_version_;
    std::mutex m_;
    std::string current_;
    std::chrono::steady_clock::time_point expiry_;

    bool fetch_locked(std::string& err);
};

} // namespace librespotc::auth
