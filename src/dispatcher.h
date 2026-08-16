#pragma once
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "connection/ap_codec.h"

namespace librespotc {

// Mercury request/response correlator.
struct MercuryPending {
    std::vector<std::vector<uint8_t>> parts;       // accumulated complete parts
    std::vector<uint8_t>              partial;     // partial-part buffer for flag=2 last
    bool done = false;
    int  status_code = 0;
    std::string uri;
    std::mutex m;
    std::condition_variable cv;
};

struct MercuryResponse {
    int status_code = 0;
    std::string uri;
    std::vector<std::vector<uint8_t>> parts; // [0] = body (header stripped)
};

struct AudioKeyPending {
    bool   done = false;
    bool   ok = false;
    uint8_t key[16]{};
    std::string error;
    std::mutex m;
    std::condition_variable cv;
};

// Owns the post-handshake packet pump. Spawn one per Session.
class Dispatcher {
public:
    explicit Dispatcher(connection::ApCodec& codec);
    ~Dispatcher();

    void start();
    void stop();

    // Mercury GET. Blocks up to timeout_ms (0 = forever). Returns false on timeout/error.
    bool mercury_get(const std::string& uri, MercuryResponse& out, uint32_t timeout_ms = 5000);

    // Audio key request.
    bool audio_key_request(const uint8_t track_id[16],
                           const uint8_t file_id[20],
                           uint8_t out_key[16],
                           uint32_t timeout_ms = 5000);
    bool audio_key_request_ex(const uint8_t track_id[16],
                              const uint8_t file_id[20],
                              uint8_t out_key[16],
                              std::string& error,
                              uint32_t timeout_ms = 5000);

    bool alive() const { return alive_; }
    std::string last_error() const { std::lock_guard<std::mutex> g(err_m_); return last_err_; }

private:
    connection::ApCodec& codec_;
    std::thread thr_;
    std::atomic<bool> running_{false};
    std::atomic<bool> alive_{true};

    std::mutex send_m_; // serialize codec sends

    // Mercury
    std::mutex mercury_m_;
    uint64_t mercury_seq_ = 1;
    std::map<uint64_t, std::shared_ptr<MercuryPending>> mercury_;

    // Audio key
    std::mutex akey_m_;
    uint32_t akey_seq_ = 0;
    std::map<uint32_t, std::shared_ptr<AudioKeyPending>> akey_;

    mutable std::mutex err_m_;
    std::string last_err_;
    void set_err(const std::string& s);

    void run_loop();
    void handle_mercury(uint8_t cmd, std::vector<uint8_t>& data);
    void handle_audio_key(uint8_t cmd, std::vector<uint8_t>& data);
};

} // namespace librespotc
