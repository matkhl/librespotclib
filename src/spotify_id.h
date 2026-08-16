#pragma once
#include <cstdint>
#include <string>
#include <array>
#include <vector>

namespace librespotc {

// 128-bit Spotify ID. Stored as 16 raw bytes (big-endian numeric).
struct SpotifyId {
    std::array<uint8_t, 16> bytes{};

    // Accepts "spotify:track:<22b62>", bare 22-char base62, or 32-char hex.
    static bool from_uri(const std::string& uri, SpotifyId& out);
    static bool from_base62(const std::string& s, SpotifyId& out);
    static bool from_base16(const std::string& s, SpotifyId& out);
    static bool from_raw_bytes(const uint8_t* data, size_t len, SpotifyId& out);

    std::string to_base16() const;
    std::string to_base62() const;
};

struct FileId {
    std::array<uint8_t, 20> bytes{}; // SHA-1 sized — Spotify file_ids are 20 bytes
    static bool from_raw_bytes(const uint8_t* data, size_t len, FileId& out);
    std::string to_base16() const;
};

} // namespace librespotc
