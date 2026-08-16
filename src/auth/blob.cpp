#include "blob.h"

#include "../crypto/bcrypt_wrap.h"
#include "../crypto/base64.h"

#include <fstream>
#include <stdexcept>
#include <cstring>
#include <filesystem>

namespace librespotc::auth {

// Mirrors librespot Credentials::with_blob().
// Inner blob is base64-encoded ciphertext encrypted with AES-192-ECB.
// Key = SHA1(PBKDF2-HMAC-SHA1(SHA1(device_id), username, 256, 20)) || BE32(20)
// After decrypt, an undocumented byte-stream sentinel-xor unscramble, then
// parse: [u8 0x01][bytes][u8 0x02][int auth_type][u8 0x03][bytes auth_data]
//
// The "int" is a small custom varint:
//   lo = next byte
//   if (lo & 0x80) == 0: value = lo
//   else: hi = next byte; value = (lo & 0x7f) | (hi << 7)

static uint32_t read_int(const uint8_t*& p, const uint8_t* end) {
    if (p >= end) throw std::runtime_error("blob: truncated int");
    uint32_t lo = *p++;
    if ((lo & 0x80) == 0) return lo;
    if (p >= end) throw std::runtime_error("blob: truncated int hi");
    uint32_t hi = *p++;
    return (lo & 0x7f) | (hi << 7);
}

static std::vector<uint8_t> read_bytes(const uint8_t*& p, const uint8_t* end) {
    uint32_t len = read_int(p, end);
    if (p + len > end) throw std::runtime_error("blob: truncated bytes");
    std::vector<uint8_t> r(p, p + len);
    p += len;
    return r;
}

Credentials parse_zeroconf_blob(const std::string& username,
                                const std::vector<uint8_t>& outer_decrypted,
                                const std::string& device_id) {
    // outer_decrypted is base64 text containing the AES-192 ciphertext
    std::string b64s(outer_decrypted.begin(), outer_decrypted.end());
    auto ct = crypto::b64_decode(b64s);
    if (ct.empty() || ct.size() % 16 != 0)
        throw std::runtime_error("blob: ciphertext size invalid");

    auto secret = crypto::sha1((const uint8_t*)device_id.data(), device_id.size());

    // PBKDF2-HMAC-SHA1(secret, username, 256, 20)
    auto kbase = crypto::pbkdf2_hmac_sha1(
        secret.data(), secret.size(),
        (const uint8_t*)username.data(), username.size(),
        0x100, 20);
    auto khash = crypto::sha1(kbase.data(), kbase.size());

    uint8_t key[24];
    std::memcpy(key, khash.data(), 20);
    key[20] = 0x00; key[21] = 0x00; key[22] = 0x00; key[23] = 0x14;

    auto data = ct;
    crypto::aes192_ecb_decrypt(key, data.data(), data.size());

    // The unscramble step from librespot:
    //   for i in 0..len-0x10:
    //     data[len-1-i] ^= data[len-1-i-0x10];
    size_t l = data.size();
    for (size_t i = 0; i + 0x10 < l; ++i) {
        data[l - 1 - i] ^= data[l - 1 - i - 0x10];
    }

    const uint8_t* p = data.data();
    const uint8_t* end = data.data() + data.size();
    if (p >= end) throw std::runtime_error("blob: empty after decrypt");

    // discard byte
    if (p < end) ++p;
    // discard varint-prefixed bytes
    (void)read_bytes(p, end);
    if (p < end) ++p;
    uint32_t auth_type = read_int(p, end);
    if (p < end) ++p;
    auto auth_data = read_bytes(p, end);

    Credentials c;
    c.username = username;
    c.auth_type = (int32_t)auth_type;
    c.auth_data = std::move(auth_data);
    return c;
}

static std::string cache_path(const std::string& dir) {
    std::filesystem::path p(dir);
    if (!dir.empty()) std::filesystem::create_directories(p);
    return (p / "credentials.dat").string();
}

bool save_to_cache(const std::string& cache_dir, const Credentials& c) {
    if (cache_dir.empty()) return false;
    std::ofstream f(cache_path(cache_dir), std::ios::binary | std::ios::trunc);
    if (!f) return false;
    uint32_t ulen = (uint32_t)c.username.size();
    uint32_t blen = (uint32_t)c.auth_data.size();
    f.write((const char*)&ulen, 4);
    f.write(c.username.data(), ulen);
    f.write((const char*)&c.auth_type, 4);
    f.write((const char*)&blen, 4);
    if (blen) f.write((const char*)c.auth_data.data(), blen);
    return (bool)f;
}

bool load_from_cache(const std::string& cache_dir, Credentials& out) {
    if (cache_dir.empty()) return false;
    std::ifstream f(cache_path(cache_dir), std::ios::binary);
    if (!f) return false;
    uint32_t ulen = 0, blen = 0;
    if (!f.read((char*)&ulen, 4)) return false;
    if (ulen > 256) return false;
    out.username.resize(ulen);
    if (ulen) f.read(out.username.data(), ulen);
    if (!f.read((char*)&out.auth_type, 4)) return false;
    if (!f.read((char*)&blen, 4)) return false;
    if (blen > (1u<<20)) return false;
    out.auth_data.resize(blen);
    if (blen) f.read((char*)out.auth_data.data(), blen);
    return (bool)f || f.eof();
}

} // namespace librespotc::auth
