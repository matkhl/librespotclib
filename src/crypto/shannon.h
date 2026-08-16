#pragma once
#include <cstdint>
#include <cstddef>

namespace librespotc::crypto {

// Shannon stream cipher (Spotify-specific).
// Ported from librespot-org/shannon crate v0.2.0 (Rust).
class Shannon {
public:
    explicit Shannon(const uint8_t* key, size_t key_len);

    // Reset to saved state and load nonce
    void nonce(const uint8_t* nonce_buf, size_t nonce_len);
    void nonce_u32(uint32_t n); // big-endian 4-byte nonce

    // In-place encrypt: XOR keystream + MAC plaintext
    void encrypt(uint8_t* buf, size_t len);
    // In-place decrypt: XOR keystream + MAC plaintext (post-XOR)
    void decrypt(uint8_t* buf, size_t len);

    // Produce MAC of MAC_LEN bytes (typically 4)
    void finish(uint8_t* mac_out, size_t mac_len);

    // Verify MAC, returns true if match
    bool check_mac(const uint8_t* expected, size_t mac_len);

private:
    static constexpr size_t N = 16;
    static constexpr uint32_t INITKONST = 0x6996c53au;
    static constexpr size_t KEYP = 13;

    uint32_t R[N]{};
    uint32_t CRC[N]{};
    uint32_t initR[N]{};
    uint32_t konst = INITKONST;
    uint32_t sbuf = 0;
    uint32_t mbuf = 0;
    size_t   nbuf = 0;

    void cycle();
    void diffuse();
    void loadkey(const uint8_t* key, size_t len);
    void savestate();
    void reloadstate();
    void genkonst();
    void crcfunc(uint32_t i);
    void macfunc(uint32_t i);

    template<bool Encrypt>
    void process(uint8_t* buf, size_t len);
};

} // namespace librespotc::crypto
