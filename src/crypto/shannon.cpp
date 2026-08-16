#include "shannon.h"
#include <cstring>

namespace librespotc::crypto {

static inline uint32_t rotl(uint32_t w, unsigned x) {
    return (w << x) | (w >> (32 - x));
}

static inline uint32_t sbox1(uint32_t w) {
    w ^= rotl(w, 5) | rotl(w, 7);
    w ^= rotl(w, 19) | rotl(w, 22);
    return w;
}

static inline uint32_t sbox2(uint32_t w) {
    w ^= rotl(w, 7) | rotl(w, 22);
    w ^= rotl(w, 5) | rotl(w, 19);
    return w;
}

static inline uint32_t read_u32_le(const uint8_t* p) {
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static inline void write_u32_le(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v       & 0xff);
    p[1] = (uint8_t)(v >>  8 & 0xff);
    p[2] = (uint8_t)(v >> 16 & 0xff);
    p[3] = (uint8_t)(v >> 24 & 0xff);
}

void Shannon::cycle() {
    uint32_t t = R[12] ^ R[13] ^ konst;
    t = sbox1(t) ^ rotl(R[0], 1);
    for (size_t i = 1; i < N; ++i) R[i-1] = R[i];
    R[N-1] = t;
    t = sbox2(R[2] ^ R[15]);
    R[0] ^= t;
    sbuf = t ^ R[8] ^ R[12];
}

void Shannon::diffuse() {
    for (size_t i = 0; i < N; ++i) cycle();
}

void Shannon::savestate() { std::memcpy(initR, R, sizeof(R)); }
void Shannon::reloadstate() { std::memcpy(R, initR, sizeof(R)); }
void Shannon::genkonst() { konst = R[0]; }

void Shannon::loadkey(const uint8_t* key, size_t len) {
    size_t i = 0;
    while (i + 4 <= len) {
        R[KEYP] ^= read_u32_le(key + i);
        cycle();
        i += 4;
    }
    if (i < len) {
        uint8_t xtra[4] = {0,0,0,0};
        for (size_t j = 0; j < len - i; ++j) xtra[j] = key[i+j];
        R[KEYP] ^= read_u32_le(xtra);
        cycle();
    }
    R[KEYP] ^= (uint32_t)len;
    cycle();
    std::memcpy(CRC, R, sizeof(R));
    diffuse();
    for (size_t j = 0; j < N; ++j) R[j] ^= CRC[j];
}

Shannon::Shannon(const uint8_t* key, size_t key_len) {
    // Fibonacci-initialized register
    R[0] = 1; R[1] = 1;
    for (size_t i = 2; i < N; ++i) R[i] = R[i-1] + R[i-2];
    loadkey(key, key_len);
    genkonst();
    savestate();
}

void Shannon::nonce(const uint8_t* nonce_buf, size_t len) {
    reloadstate();
    konst = INITKONST;
    loadkey(nonce_buf, len);
    genkonst();
    nbuf = 0;
}

void Shannon::nonce_u32(uint32_t n) {
    uint8_t b[4];
    b[0] = (uint8_t)(n >> 24);
    b[1] = (uint8_t)(n >> 16);
    b[2] = (uint8_t)(n >> 8);
    b[3] = (uint8_t)n;
    nonce(b, 4);
}

void Shannon::crcfunc(uint32_t i) {
    uint32_t t = CRC[0] ^ CRC[2] ^ CRC[15] ^ i;
    for (size_t j = 1; j < N; ++j) CRC[j-1] = CRC[j];
    CRC[N-1] = t;
}

void Shannon::macfunc(uint32_t i) {
    crcfunc(i);
    R[KEYP] ^= i;
}

template<bool Enc>
void Shannon::process(uint8_t* buf, size_t len) {
    size_t pos = 0;
    // handle previously buffered bytes
    if (nbuf != 0) {
        while (nbuf > 0 && pos < len) {
            uint8_t* b = &buf[pos];
            if constexpr (Enc) {
                mbuf ^= ((uint32_t)*b) << (32 - nbuf);
                *b ^= (uint8_t)((sbuf >> (32 - nbuf)) & 0xff);
            } else {
                *b ^= (uint8_t)((sbuf >> (32 - nbuf)) & 0xff);
                mbuf ^= ((uint32_t)*b) << (32 - nbuf);
            }
            nbuf -= 8;
            ++pos;
            if (nbuf == 0) {
                uint32_t m = mbuf;
                macfunc(m);
                mbuf = 0;
            }
        }
        if (pos >= len && nbuf > 0) return;
    }
    // handle whole words
    while (pos + 4 <= len) {
        cycle();
        uint32_t t = read_u32_le(buf + pos);
        if constexpr (Enc) {
            macfunc(t);
            t ^= sbuf;
        } else {
            t ^= sbuf;
            macfunc(t);
        }
        write_u32_le(buf + pos, t);
        pos += 4;
    }
    // trailing bytes
    if (pos < len) {
        cycle();
        mbuf = 0;
        nbuf = 32;
        while (pos < len) {
            uint8_t* b = &buf[pos];
            if constexpr (Enc) {
                mbuf ^= ((uint32_t)*b) << (32 - nbuf);
                *b ^= (uint8_t)((sbuf >> (32 - nbuf)) & 0xff);
            } else {
                *b ^= (uint8_t)((sbuf >> (32 - nbuf)) & 0xff);
                mbuf ^= ((uint32_t)*b) << (32 - nbuf);
            }
            nbuf -= 8;
            ++pos;
        }
    }
}

void Shannon::encrypt(uint8_t* buf, size_t len) { process<true>(buf, len); }
void Shannon::decrypt(uint8_t* buf, size_t len) { process<false>(buf, len); }

void Shannon::finish(uint8_t* mac_out, size_t mac_len) {
    if (nbuf != 0) {
        uint32_t m = mbuf;
        macfunc(m);
    }
    cycle();
    R[KEYP] ^= INITKONST ^ ((uint32_t)(nbuf) << 3);
    nbuf = 0;
    for (size_t i = 0; i < N; ++i) R[i] ^= CRC[i];
    diffuse();
    size_t pos = 0;
    while (pos + 4 <= mac_len) {
        cycle();
        write_u32_le(mac_out + pos, sbuf);
        pos += 4;
    }
    if (pos < mac_len) {
        cycle();
        for (size_t i = 0; pos < mac_len; ++pos, ++i) {
            mac_out[pos] = (uint8_t)((sbuf >> (8 * i)) & 0xff);
        }
    }
}

bool Shannon::check_mac(const uint8_t* expected, size_t mac_len) {
    uint8_t actual[64];
    if (mac_len > sizeof(actual)) return false;
    finish(actual, mac_len);
    uint8_t diff = 0;
    for (size_t i = 0; i < mac_len; ++i) diff |= actual[i] ^ expected[i];
    return diff == 0;
}

} // namespace librespotc::crypto
