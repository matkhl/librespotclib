#include "client_token.h"
#include "hashcash.h"

#include "../proto/pb_codec.h"
#include "../net/http_fetch.h"

#include <cstdio>
#include <cstring>

namespace librespotc::auth {

// proto field numbers from clienttoken_http.proto / connectivity.proto.

static std::vector<uint8_t> encode_client_data_request(
    const std::string& client_version,
    const std::string& client_id,
    const std::string& device_id) {

    proto::Writer w;
    // request_type = REQUEST_CLIENT_DATA_REQUEST = 1
    w.write_enum(1, 1);
    // client_data (field 2, submessage)
    w.write_submessage(2, [&](proto::Writer& cd) {
        cd.write_string(1, client_version);
        cd.write_string(2, client_id);
        // connectivity_sdk_data = oneof data (field 3)
        cd.write_submessage(3, [&](proto::Writer& csd) {
            // platform_specific_data (field 1, submessage)
            csd.write_submessage(1, [&](proto::Writer& psd) {
                // desktop_windows (field 4 within oneof)
                psd.write_submessage(4, [&](proto::Writer& w64) {
                    w64.write_int32(1, 10);        // os_version
                    w64.write_int32(3, 26100);     // os_build (Win11)
                    w64.write_int32(4, 2);         // platform_id (Win32NT)
                    w64.write_int32(6, 9);         // unknown_value_6
                    w64.write_int32(7, 34404);     // image_file_machine (x64)
                    w64.write_int32(8, 34404);     // pe_machine
                    w64.write_bool(10, true);      // unknown_value_10
                });
            });
            csd.write_string(2, device_id);
        });
    });
    return w.take();
}

static std::vector<uint8_t> encode_challenge_answer(
    const std::string& state,
    const std::string& hashcash_suffix_hex_upper) {

    proto::Writer w;
    w.write_enum(1, 2); // REQUEST_CHALLENGE_ANSWERS_REQUEST = 2
    w.write_submessage(3, [&](proto::Writer& ca) {
        ca.write_string(1, state);
        ca.write_submessage(2, [&](proto::Writer& ans) {
            ans.write_enum(1, 3); // CHALLENGE_HASH_CASH = 3
            ans.write_submessage(4, [&](proto::Writer& hc) {
                hc.write_string(1, hashcash_suffix_hex_upper);
            });
        });
    });
    return w.take();
}

static std::string to_upper_hex(const uint8_t* p, size_t n) {
    static const char* H = "0123456789ABCDEF";
    std::string s(n*2, '0');
    for (size_t i = 0; i < n; ++i) {
        s[2*i]   = H[p[i] >> 4];
        s[2*i+1] = H[p[i] & 0xf];
    }
    return s;
}

static std::vector<uint8_t> hex_upper_decode(const std::string& s) {
    auto hv = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + c - 'a';
        if (c >= 'A' && c <= 'F') return 10 + c - 'A';
        return -1;
    };
    std::vector<uint8_t> out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i + 1 < s.size(); i += 2) {
        int hi = hv(s[i]), lo = hv(s[i+1]);
        if (hi < 0 || lo < 0) return {};
        out.push_back((uint8_t)((hi << 4) | lo));
    }
    return out;
}

// Parse ClientTokenResponse → granted token (out_token) OR a challenge.
// Returns:  0 = granted, 1 = challenge, -1 = error
struct ParseResult {
    int kind = -1;
    std::string token;
    int32_t expires_after = 0;
    int32_t refresh_after = 0;
    std::string challenge_state;
    std::string challenge_prefix_hex;
    int32_t     challenge_length = 0;
};

static ParseResult parse_response(const uint8_t* data, size_t len) {
    ParseResult pr;
    try {
        proto::Reader r(data, len);
        int32_t resp_type = 0;
        while (!r.at_end()) {
            uint32_t f, wt;
            if (!r.read_tag(f, wt)) break;
            if (f == 1 && wt == proto::WIRE_VARINT) resp_type = (int32_t)r.read_varint();
            else if (f == 2 && wt == proto::WIRE_LEN) {
                // GrantedTokenResponse: token=1 string, expires=2 int32, refresh=3 int32, domains=4 repeated
                auto sub = r.read_len_delim();
                while (!sub.at_end()) {
                    uint32_t sf, swt;
                    if (!sub.read_tag(sf, swt)) break;
                    if (sf == 1 && swt == proto::WIRE_LEN) pr.token = sub.read_string();
                    else if (sf == 2 && swt == proto::WIRE_VARINT) pr.expires_after = (int32_t)sub.read_varint();
                    else if (sf == 3 && swt == proto::WIRE_VARINT) pr.refresh_after = (int32_t)sub.read_varint();
                    else sub.skip_field(swt);
                }
                pr.kind = 0;
            } else if (f == 3 && wt == proto::WIRE_LEN) {
                // ChallengesResponse: state=1, challenges=2 repeated Challenge
                auto sub = r.read_len_delim();
                while (!sub.at_end()) {
                    uint32_t sf, swt;
                    if (!sub.read_tag(sf, swt)) break;
                    if (sf == 1 && swt == proto::WIRE_LEN) pr.challenge_state = sub.read_string();
                    else if (sf == 2 && swt == proto::WIRE_LEN) {
                        auto ch = sub.read_len_delim();
                        while (!ch.at_end()) {
                            uint32_t cf, cwt;
                            if (!ch.read_tag(cf, cwt)) break;
                            if (cf == 4 && cwt == proto::WIRE_LEN) {
                                // HashCashParameters: length=1, prefix=2
                                auto hc = ch.read_len_delim();
                                while (!hc.at_end()) {
                                    uint32_t hf, hwt;
                                    if (!hc.read_tag(hf, hwt)) break;
                                    if (hf == 1 && hwt == proto::WIRE_VARINT) pr.challenge_length = (int32_t)hc.read_varint();
                                    else if (hf == 2 && hwt == proto::WIRE_LEN) pr.challenge_prefix_hex = hc.read_string();
                                    else hc.skip_field(hwt);
                                }
                            } else ch.skip_field(cwt);
                        }
                    } else sub.skip_field(swt);
                }
                pr.kind = 1;
            } else r.skip_field(wt);
        }
        (void)resp_type;
    } catch (...) { pr.kind = -1; }
    return pr;
}

ClientTokenProvider::ClientTokenProvider(std::string client_id,
                                         std::string device_id,
                                         std::string client_version)
    : client_id_(std::move(client_id)),
      device_id_(std::move(device_id)),
      client_version_(std::move(client_version)) {}

bool ClientTokenProvider::fetch_locked(std::string& err) {
    auto body = encode_client_data_request(client_version_, client_id_, device_id_);
    auto r = net::https_post("https://clienttoken.spotify.com/v1/clienttoken",
                             "application/x-protobuf", body.data(), body.size(),
                             {{"Accept", "application/x-protobuf"}});
    if (r.status != 200) {
        err = "HTTP " + std::to_string(r.status);
        std::fprintf(stderr, "[client_token] %s\n", err.c_str());
        return false;
    }
    auto pr = parse_response(r.body.data(), r.body.size());
    if (pr.kind == 0) {
        current_ = pr.token;
        expiry_ = std::chrono::steady_clock::now()
                + std::chrono::seconds(pr.refresh_after > 0 ? pr.refresh_after : 7200);
        std::fprintf(stderr, "[client_token] granted (len=%zu, refresh=%ds)\n",
                     pr.token.size(), pr.refresh_after);
        return true;
    }
    if (pr.kind == 1) {
        std::fprintf(stderr, "[client_token] hashcash challenge (length=%d)\n", pr.challenge_length);
        auto prefix = hex_upper_decode(pr.challenge_prefix_hex);
        if (prefix.empty()) { err = "bad challenge prefix"; return false; }
        uint8_t suffix[16];
        if (!solve_hash_cash(nullptr, 0, prefix.data(), prefix.size(),
                             pr.challenge_length, suffix)) {
            err = "hashcash timeout"; return false;
        }
        auto suffix_hex = to_upper_hex(suffix, 16);
        auto answer = encode_challenge_answer(pr.challenge_state, suffix_hex);
        auto r2 = net::https_post("https://clienttoken.spotify.com/v1/clienttoken",
                                  "application/x-protobuf", answer.data(), answer.size(),
                                  {{"Accept", "application/x-protobuf"}});
        if (r2.status != 200) {
            err = "answer HTTP " + std::to_string(r2.status);
            std::fprintf(stderr, "[client_token] %s\n", err.c_str());
            return false;
        }
        auto pr2 = parse_response(r2.body.data(), r2.body.size());
        if (pr2.kind == 0) {
            current_ = pr2.token;
            expiry_ = std::chrono::steady_clock::now()
                    + std::chrono::seconds(pr2.refresh_after > 0 ? pr2.refresh_after : 7200);
            std::fprintf(stderr, "[client_token] granted after challenge (len=%zu)\n", pr2.token.size());
            return true;
        }
        err = "answer not granted";
        return false;
    }
    err = "parse failed";
    return false;
}

std::string ClientTokenProvider::token() {
    std::lock_guard<std::mutex> g(m_);
    if (!current_.empty() && std::chrono::steady_clock::now() < expiry_) return current_;
    std::string err;
    if (fetch_locked(err)) return current_;
    return {};
}

void ClientTokenProvider::invalidate() {
    std::lock_guard<std::mutex> g(m_);
    current_.clear();
    expiry_ = {};
}

} // namespace librespotc::auth
