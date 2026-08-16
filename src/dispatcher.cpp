#include "dispatcher.h"
#include "proto/pb_codec.h"

#include <cstdio>
#include <cstring>

namespace librespotc {

static uint16_t read_u16_be(const uint8_t* p) {
    return ((uint16_t)p[0] << 8) | p[1];
}
static uint32_t read_u32_be(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}
static uint64_t read_u64_be(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
    return v;
}
static void write_u16_be(uint8_t* p, uint16_t v) { p[0]=(uint8_t)(v>>8); p[1]=(uint8_t)v; }
static void write_u32_be(uint8_t* p, uint32_t v) {
    p[0]=(uint8_t)(v>>24); p[1]=(uint8_t)(v>>16); p[2]=(uint8_t)(v>>8); p[3]=(uint8_t)v;
}
static void write_u64_be(uint8_t* p, uint64_t v) {
    for (int i = 7; i >= 0; --i) { p[i] = (uint8_t)(v & 0xff); v >>= 8; }
}

Dispatcher::Dispatcher(connection::ApCodec& codec) : codec_(codec) {}
Dispatcher::~Dispatcher() { stop(); }

void Dispatcher::start() {
    running_ = true;
    thr_ = std::thread([this]{ run_loop(); });
}

void Dispatcher::stop() {
    running_ = false;
    if (thr_.joinable()) thr_.join();
}

void Dispatcher::set_err(const std::string& s) {
    std::lock_guard<std::mutex> g(err_m_);
    last_err_ = s;
    std::fprintf(stderr, "[dispatcher] %s\n", s.c_str());
}

void Dispatcher::run_loop() {
    using namespace connection;
    while (running_) {
        uint8_t cmd = 0;
        std::vector<uint8_t> body;
        bool ok;
        {
            std::lock_guard<std::mutex> g(send_m_);
            // recv is itself blocking and not protected by send_m_, but Shannon
            // recv cipher state is separate from send so it's safe to run
            // concurrently with sends — release the lock immediately.
        }
        ok = codec_.recv(cmd, body);
        if (!ok) {
            alive_ = false;
            set_err("codec recv failed");
            // wake any waiters
            {
                std::lock_guard<std::mutex> g(mercury_m_);
                for (auto& kv : mercury_) {
                    std::lock_guard<std::mutex> gp(kv.second->m);
                    kv.second->done = true;
                    kv.second->status_code = -1;
                    kv.second->cv.notify_all();
                }
            }
            {
                std::lock_guard<std::mutex> g(akey_m_);
                for (auto& kv : akey_) {
                    std::lock_guard<std::mutex> gp(kv.second->m);
                    kv.second->done = true;
                    kv.second->ok = false;
                    kv.second->cv.notify_all();
                }
            }
            return;
        }

        switch (cmd) {
            case cmd::MERCURY_REQ:
            case cmd::MERCURY_SUB:
            case cmd::MERCURY_UNSUB:
            case cmd::MERCURY_EVENT:
                handle_mercury(cmd, body);
                break;
            case cmd::AES_KEY:
            case cmd::AES_KEY_ERROR:
                handle_audio_key(cmd, body);
                break;
            case cmd::PING: {
                // Reply PONG with the same payload (server timestamp, 4 bytes
                // BE). Sending zeros makes Spotify's AP treat the keepalive
                // as failed and idle-kill the socket within ~3 minutes, which
                // surfaces as repeated Reconnecting/Reconnected churn.
                std::lock_guard<std::mutex> g(send_m_);
                codec_.send(cmd::PONG, body.data(), body.size());
                break;
            }
            case cmd::PONG_ACK:
            case cmd::COUNTRY_CODE:
            case cmd::LICENSE_VERSION:
            case cmd::PRODUCT_INFO:
            case cmd::LEGACY_WELCOME:
            case cmd::SECRET_BLOCK:
                // ignore
                break;
            default:
                // ignore unknown for now
                break;
        }
    }
}

void Dispatcher::handle_mercury(uint8_t /*cmd*/, std::vector<uint8_t>& data) {
    if (data.size() < 5) return;
    size_t p = 0;
    uint16_t seq_len = read_u16_be(data.data() + p); p += 2;
    if (p + seq_len > data.size()) return;
    uint64_t seq = 0;
    if (seq_len == 8) seq = read_u64_be(data.data() + p);
    else {
        // librespot encodes seq as 8 BE bytes; accept other widths defensively
        for (size_t i = 0; i < seq_len; ++i) seq = (seq << 8) | data[p + i];
    }
    p += seq_len;
    if (p + 3 > data.size()) return;
    uint8_t  flags = data[p++];
    uint16_t parts = read_u16_be(data.data() + p); p += 2;

    std::shared_ptr<MercuryPending> pen;
    {
        std::lock_guard<std::mutex> g(mercury_m_);
        auto it = mercury_.find(seq);
        if (it != mercury_.end()) pen = it->second;
    }
    if (!pen) return; // unexpected or pubsub event we don't track

    for (uint16_t i = 0; i < parts; ++i) {
        if (p + 2 > data.size()) return;
        uint16_t sz = read_u16_be(data.data() + p); p += 2;
        if (p + sz > data.size()) return;
        std::vector<uint8_t> part(data.begin() + p, data.begin() + p + sz);
        p += sz;
        if (!pen->partial.empty()) {
            pen->partial.insert(pen->partial.end(), part.begin(), part.end());
            part = std::move(pen->partial);
            pen->partial.clear();
        }
        if (i + 1 == parts && flags == 2) {
            pen->partial = std::move(part);
        } else {
            pen->parts.push_back(std::move(part));
        }
    }

    if (flags == 1) {
        // Final. Decode header (parts[0]) for status_code+uri, then signal.
        if (!pen->parts.empty()) {
            auto& hdr_bytes = pen->parts[0];
            proto::Reader r(hdr_bytes.data(), hdr_bytes.size());
            int32_t status = 0;
            std::string uri;
            while (!r.at_end()) {
                uint32_t f, wt;
                if (!r.read_tag(f, wt)) break;
                if (f == 1 && wt == proto::WIRE_LEN) uri = r.read_string();
                else if (f == 4 && wt == proto::WIRE_VARINT) {
                    uint64_t v = r.read_varint();
                    // sint32 zigzag
                    status = (int32_t)((v >> 1) ^ (uint64_t)(-(int64_t)(v & 1)));
                } else r.skip_field(wt);
            }
            pen->uri = std::move(uri);
            pen->status_code = status;
        }
        {
            std::lock_guard<std::mutex> g(pen->m);
            pen->done = true;
            pen->cv.notify_all();
        }
        std::lock_guard<std::mutex> g(mercury_m_);
        mercury_.erase(seq);
    }
}

void Dispatcher::handle_audio_key(uint8_t cmd, std::vector<uint8_t>& data) {
    using namespace connection;
    if (data.size() < 4) return;
    uint32_t seq = read_u32_be(data.data());
    std::shared_ptr<AudioKeyPending> pen;
    {
        std::lock_guard<std::mutex> g(akey_m_);
        auto it = akey_.find(seq);
        if (it != akey_.end()) { pen = it->second; akey_.erase(it); }
    }
    if (!pen) return;
    if (cmd == cmd::AES_KEY && data.size() >= 4 + 16) {
        std::memcpy(pen->key, data.data() + 4, 16);
        pen->ok = true;
    } else {
        pen->ok = false;
        if (cmd == cmd::AES_KEY_ERROR && data.size() >= 6) {
            char buf[80];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                        "AES_KEY_ERROR bytes=%02x %02x",
                        data[4], data[5]);
            pen->error = buf;
            std::fprintf(stderr, "[audio_key] %s\n", pen->error.c_str());
        } else if (cmd == cmd::AES_KEY_ERROR) {
            pen->error = "AES_KEY_ERROR truncated";
            std::fprintf(stderr, "[audio_key] %s (len=%zu)\n",
                         pen->error.c_str(), data.size());
        } else {
            pen->error = "unexpected key packet";
        }
    }
    std::lock_guard<std::mutex> g(pen->m);
    pen->done = true;
    pen->cv.notify_all();
}

bool Dispatcher::mercury_get(const std::string& uri, MercuryResponse& out, uint32_t timeout_ms) {
    if (!alive_) return false;

    auto pen = std::make_shared<MercuryPending>();
    uint64_t seq;
    {
        std::lock_guard<std::mutex> g(mercury_m_);
        seq = mercury_seq_++;
        mercury_[seq] = pen;
    }

    // Build header proto: uri(1, LEN, string), method(3, LEN, "GET")
    proto::Writer hdr;
    hdr.write_string(1, uri);
    hdr.write_string(3, "GET");

    std::vector<uint8_t> packet;
    // seq_length(2) || seq(8) || flags(1) || part_count(2) || header_len(2) || header
    packet.resize(2 + 8 + 1 + 2 + 2 + hdr.size());
    uint8_t* p = packet.data();
    write_u16_be(p, 8); p += 2;
    write_u64_be(p, seq); p += 8;
    *p++ = 1;             // FINAL
    write_u16_be(p, 1);   // 1 part (the header)
    p += 2;
    write_u16_be(p, (uint16_t)hdr.size()); p += 2;
    std::memcpy(p, hdr.data(), hdr.size());

    {
        std::lock_guard<std::mutex> g(send_m_);
        if (!codec_.send(connection::cmd::MERCURY_REQ, packet)) {
            std::lock_guard<std::mutex> g2(mercury_m_);
            mercury_.erase(seq);
            return false;
        }
    }

    std::unique_lock<std::mutex> lk(pen->m);
    auto ok = pen->cv.wait_for(lk, std::chrono::milliseconds(timeout_ms),
                               [&]{ return pen->done; });
    if (!ok) {
        std::lock_guard<std::mutex> g(mercury_m_);
        mercury_.erase(seq);
        return false;
    }
    if (pen->status_code < 0) return false;
    out.status_code = pen->status_code;
    out.uri = pen->uri;
    // parts[0] is header, payload is parts[1..]
    if (!pen->parts.empty()) {
        out.parts.assign(pen->parts.begin() + 1, pen->parts.end());
    }
    return true;
}

bool Dispatcher::audio_key_request(const uint8_t track_id[16],
                                   const uint8_t file_id[20],
                                   uint8_t out_key[16],
                                   uint32_t timeout_ms) {
    std::string error;
    return audio_key_request_ex(track_id, file_id, out_key, error, timeout_ms);
}

bool Dispatcher::audio_key_request_ex(const uint8_t track_id[16],
                                      const uint8_t file_id[20],
                                      uint8_t out_key[16],
                                      std::string& error,
                                      uint32_t timeout_ms) {
    error.clear();
    if (!alive_) return false;
    auto pen = std::make_shared<AudioKeyPending>();
    uint32_t seq;
    {
        std::lock_guard<std::mutex> g(akey_m_);
        seq = akey_seq_++;
        akey_[seq] = pen;
    }

    uint8_t payload[20 + 16 + 4 + 2];
    std::memcpy(payload,        file_id, 20);
    std::memcpy(payload + 20,   track_id, 16);
    write_u32_be(payload + 36,  seq);
    payload[40] = 0; payload[41] = 0;

    {
        std::lock_guard<std::mutex> g(send_m_);
        if (!codec_.send(connection::cmd::REQUEST_KEY, payload, sizeof(payload))) {
            std::lock_guard<std::mutex> g2(akey_m_);
            akey_.erase(seq);
            error = "send failed";
            return false;
        }
    }

    std::unique_lock<std::mutex> lk(pen->m);
    auto ok = pen->cv.wait_for(lk, std::chrono::milliseconds(timeout_ms),
                               [&]{ return pen->done; });
    if (!ok) {
        std::lock_guard<std::mutex> g(akey_m_);
        akey_.erase(seq);
        error = "timeout";
        return false;
    }
    if (!pen->ok) {
        error = pen->error.empty() ? "rejected" : pen->error;
        return false;
    }
    std::memcpy(out_key, pen->key, 16);
    return true;
}

} // namespace librespotc
