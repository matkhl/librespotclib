#include "login5.h"
#include "hashcash.h"

#include "../proto/pb_codec.h"
#include "../net/http_fetch.h"

#include <cstdio>
#include <cstring>

namespace librespotc::auth {

// Encode LoginRequest with stored_credential and optional hashcash solutions.
//
// Fields:
//   client_info=1 submessage: client_id=1 string, device_id=2 string
//   login_context=2 bytes
//   challenge_solutions=3 submessage: solutions=1 repeated ChallengeSolution
//     ChallengeSolution.hashcash=1 HashcashSolution: suffix=1 bytes, duration=2 Duration
//       Duration.seconds=1 int64, Duration.nanos=2 int32
//   stored_credential=100 submessage: username=1 string, data=2 bytes
struct HashcashSolutionBytes {
    std::vector<uint8_t> suffix; // 16
    int64_t duration_seconds = 0;
    int32_t duration_nanos = 0;
};

static std::vector<uint8_t> encode_login_request(
    const std::string& client_id,
    const std::string& device_id,
    const std::string& username,
    const std::vector<uint8_t>& stored_blob,
    const std::vector<uint8_t>& login_context,
    const std::vector<HashcashSolutionBytes>& solutions) {

    proto::Writer w;
    w.write_submessage(1, [&](proto::Writer& ci) {
        ci.write_string(1, client_id);
        ci.write_string(2, device_id);
    });
    if (!login_context.empty()) {
        w.write_bytes(2, login_context);
    }
    if (!solutions.empty()) {
        w.write_submessage(3, [&](proto::Writer& cs) {
            for (auto& s : solutions) {
                cs.write_submessage(1, [&](proto::Writer& sol) {
                    sol.write_submessage(1, [&](proto::Writer& hc) {
                        hc.write_bytes(1, s.suffix);
                        hc.write_submessage(2, [&](proto::Writer& dur) {
                            // proto3 int64/int32 use varint
                            dur.write_tag(1, proto::WIRE_VARINT);
                            dur.write_varint((uint64_t)s.duration_seconds);
                            dur.write_tag(2, proto::WIRE_VARINT);
                            dur.write_varint((uint64_t)(int64_t)s.duration_nanos);
                        });
                    });
                });
            }
        });
    }
    w.write_submessage(100, [&](proto::Writer& sc) {
        sc.write_string(1, username);
        sc.write_bytes(2, stored_blob);
    });
    return w.take();
}

struct LoginParse {
    int kind = -1; // 0=ok, 1=challenges, 2=error
    std::string access_token;
    int32_t expires_in = 0;
    std::vector<uint8_t> login_context;
    std::vector<uint8_t> challenge_prefix;
    int32_t challenge_length = 0;
    int32_t error_code = 0;
};

static LoginParse parse_login_response(const uint8_t* data, size_t len) {
    LoginParse lp;
    try {
        proto::Reader r(data, len);
        while (!r.at_end()) {
            uint32_t f, wt;
            if (!r.read_tag(f, wt)) break;
            if (f == 1 && wt == proto::WIRE_LEN) {
                // LoginOk: username=1, access_token=2, stored_credential=3, expires_in=4
                auto sub = r.read_len_delim();
                while (!sub.at_end()) {
                    uint32_t sf, swt;
                    if (!sub.read_tag(sf, swt)) break;
                    if (sf == 2 && swt == proto::WIRE_LEN) lp.access_token = sub.read_string();
                    else if (sf == 4 && swt == proto::WIRE_VARINT) lp.expires_in = (int32_t)sub.read_varint();
                    else sub.skip_field(swt);
                }
                lp.kind = 0;
            } else if (f == 2 && wt == proto::WIRE_VARINT) {
                lp.error_code = (int32_t)r.read_varint();
                lp.kind = 2;
            } else if (f == 3 && wt == proto::WIRE_LEN) {
                // Challenges: challenges=1 repeated Challenge { hashcash=1 { prefix=1, length=2 } }
                auto sub = r.read_len_delim();
                while (!sub.at_end()) {
                    uint32_t sf, swt;
                    if (!sub.read_tag(sf, swt)) break;
                    if (sf == 1 && swt == proto::WIRE_LEN) {
                        auto ch = sub.read_len_delim();
                        while (!ch.at_end()) {
                            uint32_t cf, cwt;
                            if (!ch.read_tag(cf, cwt)) break;
                            if (cf == 1 && cwt == proto::WIRE_LEN) {
                                auto hc = ch.read_len_delim();
                                while (!hc.at_end()) {
                                    uint32_t hf, hwt;
                                    if (!hc.read_tag(hf, hwt)) break;
                                    if (hf == 1 && hwt == proto::WIRE_LEN) lp.challenge_prefix = hc.read_bytes();
                                    else if (hf == 2 && hwt == proto::WIRE_VARINT) lp.challenge_length = (int32_t)hc.read_varint();
                                    else hc.skip_field(hwt);
                                }
                            } else ch.skip_field(cwt);
                        }
                    } else sub.skip_field(swt);
                }
                lp.kind = 1;
            } else if (f == 5 && wt == proto::WIRE_LEN) {
                lp.login_context = r.read_bytes();
            } else r.skip_field(wt);
        }
    } catch (...) { lp.kind = -1; }
    return lp;
}

Login5Provider::Login5Provider(std::string client_id,
                               std::string device_id,
                               std::string username,
                               std::vector<uint8_t> stored_blob)
    : client_id_(std::move(client_id)),
      device_id_(std::move(device_id)),
      username_(std::move(username)),
      stored_blob_(std::move(stored_blob)) {}

bool Login5Provider::fetch_locked(const std::string& client_token, std::string& err) {
    std::vector<HashcashSolutionBytes> solutions;
    std::vector<uint8_t> login_context;
    for (int attempt = 0; attempt < 3; ++attempt) {
        auto body = encode_login_request(client_id_, device_id_, username_, stored_blob_,
                                         login_context, solutions);
        std::map<std::string,std::string> hdrs;
        hdrs["Accept"] = "application/x-protobuf";
        hdrs["client-token"] = client_token;
        auto r = net::https_post("https://login5.spotify.com/v3/login",
                                 "application/x-protobuf",
                                 body.data(), body.size(), hdrs);
        if (r.status != 200) {
            err = "HTTP " + std::to_string(r.status);
            std::fprintf(stderr, "[login5] %s body=%.200s\n", err.c_str(),
                         std::string((const char*)r.body.data(),
                                     std::min<size_t>(r.body.size(), 200)).c_str());
            return false;
        }
        auto lp = parse_login_response(r.body.data(), r.body.size());
        if (lp.kind == 0) {
            current_ = lp.access_token;
            expiry_ = std::chrono::steady_clock::now()
                    + std::chrono::seconds(lp.expires_in > 60 ? lp.expires_in - 60 : 3000);
            std::fprintf(stderr, "[login5] granted access_token (len=%zu, expires=%ds)\n",
                         lp.access_token.size(), lp.expires_in);
            return true;
        }
        if (lp.kind == 2) {
            err = "LoginError=" + std::to_string(lp.error_code);
            std::fprintf(stderr, "[login5] %s\n", err.c_str());
            return false;
        }
        if (lp.kind == 1) {
            std::fprintf(stderr, "[login5] hashcash challenge length=%d, prefix_len=%zu\n",
                         lp.challenge_length, lp.challenge_prefix.size());
            uint8_t suffix[16];
            auto t0 = std::chrono::steady_clock::now();
            if (!solve_hash_cash(lp.login_context.data(), lp.login_context.size(),
                                 lp.challenge_prefix.data(), lp.challenge_prefix.size(),
                                 lp.challenge_length, suffix)) {
                err = "hashcash timeout";
                return false;
            }
            auto t1 = std::chrono::steady_clock::now();
            auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
            int64_t secs = ns / 1000000000LL;
            int32_t nanos = (int32_t)(ns % 1000000000LL);

            HashcashSolutionBytes sol;
            sol.suffix.assign(suffix, suffix + 16);
            sol.duration_seconds = secs;
            sol.duration_nanos   = nanos;
            solutions.push_back(std::move(sol));
            login_context = std::move(lp.login_context);
            continue;
        }
        err = "parse failed";
        return false;
    }
    err = "max challenge attempts exceeded";
    return false;
}

std::string Login5Provider::access_token(const std::string& client_token) {
    std::lock_guard<std::mutex> g(m_);
    if (!current_.empty() && std::chrono::steady_clock::now() < expiry_) return current_;
    std::string err;
    if (fetch_locked(client_token, err)) return current_;
    return {};
}

void Login5Provider::invalidate() {
    std::lock_guard<std::mutex> g(m_);
    current_.clear();
    expiry_ = {};
}

} // namespace librespotc::auth
