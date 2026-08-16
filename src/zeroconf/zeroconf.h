#pragma once
#include <cstdint>
#include <string>
#include <mutex>
#include <condition_variable>
#include <memory>

#include "http_server.h"
#include "../auth/blob.h"

namespace librespotc::zeroconf {

struct Config {
    std::string device_name;
    std::string device_id;       // lowercase hex SHA-1 of something stable
    std::string device_type;     // "Speaker"
    std::string client_id;       // optional
    uint16_t    port = 0;        // 0 = OS-assigned
};

// Spawns HTTP server + mDNS advertise. Blocks `wait_for_credentials` until
// the Spotify app POSTs /addUser with a decryptable blob.
class ZeroconfService {
public:
    explicit ZeroconfService(const Config& cfg);
    ~ZeroconfService();

    bool start();
    void stop();

    // Block up to timeout_ms (0 = forever). On success populates `out`.
    bool wait_for_credentials(auth::Credentials& out, uint32_t timeout_ms = 0);

    uint16_t local_port() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace librespotc::zeroconf
