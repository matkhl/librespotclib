#include "spotify_id.h"
#include <cstring>

namespace librespotc {

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    return -1;
}

bool SpotifyId::from_base16(const std::string& s, SpotifyId& out) {
    if (s.size() != 32) return false;
    for (size_t i = 0; i < 16; ++i) {
        int hi = hexval(s[2*i]);
        int lo = hexval(s[2*i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.bytes[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

bool SpotifyId::from_base62(const std::string& s, SpotifyId& out) {
    if (s.size() != 22) return false;
    // Compute u128 := sum(s_i * 62^(21-i)) using base-256 limb arithmetic.
    uint8_t r[16] = {0};
    for (char c : s) {
        int v;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'z') v = 10 + (c - 'a');
        else if (c >= 'A' && c <= 'Z') v = 36 + (c - 'A');
        else return false;
        // r = r * 62 + v
        uint32_t carry = (uint32_t)v;
        for (int i = 15; i >= 0; --i) {
            uint32_t cur = (uint32_t)r[i] * 62u + carry;
            r[i] = (uint8_t)(cur & 0xff);
            carry = cur >> 8;
        }
        if (carry != 0) return false; // overflow — invalid id
    }
    std::memcpy(out.bytes.data(), r, 16);
    return true;
}

bool SpotifyId::from_raw_bytes(const uint8_t* data, size_t len, SpotifyId& out) {
    if (len != 16) return false;
    std::memcpy(out.bytes.data(), data, 16);
    return true;
}

bool SpotifyId::from_uri(const std::string& uri, SpotifyId& out) {
    // Strip optional prefix "spotify:track:" / "spotify:episode:" / etc.
    std::string s = uri;
    auto lastColon = s.rfind(':');
    if (lastColon != std::string::npos) s = s.substr(lastColon + 1);
    if (s.size() == 22) return from_base62(s, out);
    if (s.size() == 32) return from_base16(s, out);
    return false;
}

static std::string hex_of(const uint8_t* p, size_t n) {
    static const char* H = "0123456789abcdef";
    std::string out(n * 2, '0');
    for (size_t i = 0; i < n; ++i) {
        out[2*i]   = H[p[i] >> 4];
        out[2*i+1] = H[p[i] & 0xf];
    }
    return out;
}

std::string SpotifyId::to_base16() const { return hex_of(bytes.data(), bytes.size()); }

std::string SpotifyId::to_base62() const {
    static const char* B62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    uint8_t tmp[16];
    std::memcpy(tmp, bytes.data(), 16);
    std::string s(22, '0');
    for (int i = 21; i >= 0; --i) {
        uint32_t carry = 0;
        for (int j = 0; j < 16; ++j) {
            uint32_t cur = (carry << 8) | tmp[j];
            tmp[j] = (uint8_t)(cur / 62);
            carry  = cur % 62;
        }
        s[i] = B62[carry];
    }
    return s;
}
std::string FileId::to_base16()    const { return hex_of(bytes.data(), bytes.size()); }

bool FileId::from_raw_bytes(const uint8_t* data, size_t len, FileId& out) {
    if (len != 20) return false;
    std::memcpy(out.bytes.data(), data, 20);
    return true;
}

} // namespace librespotc
