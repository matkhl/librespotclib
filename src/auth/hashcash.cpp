#include "hashcash.h"
#include "../crypto/bcrypt_wrap.h"

#include <chrono>
#include <cstring>
#include <cstdio>

namespace librespotc::auth {

static int64_t read_i64_be(const uint8_t* p) {
    int64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | (uint64_t)p[i];
    return v;
}
static void write_i64_be(uint8_t* p, int64_t v) {
    for (int i = 7; i >= 0; --i) { p[i] = (uint8_t)(v & 0xff); v = (int64_t)((uint64_t)v >> 8); }
}

static int trailing_zeros_64(uint64_t v) {
    if (v == 0) return 64;
    int n = 0;
    while ((v & 1) == 0) { v >>= 1; ++n; }
    return n;
}

bool solve_hash_cash(const uint8_t* ctx, size_t ctx_len,
                     const uint8_t* prefix, size_t prefix_len,
                     int length, uint8_t suffix_out[16]) {
    auto start = std::chrono::steady_clock::now();
    constexpr int TIMEOUT_SEC = 10;

    // target = BigEndian::read_i64(sha1(ctx)[12..20])
    auto md = crypto::sha1(ctx, ctx_len);
    int64_t target = read_i64_be(md.data() + 12);

    int64_t counter = 0;
    while (true) {
        if (std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - start).count() >= TIMEOUT_SEC) {
            std::fprintf(stderr, "[hashcash] timeout (length=%d, %lld iters)\n",
                         length, (long long)counter);
            return false;
        }
        uint8_t suffix[16];
        write_i64_be(suffix + 0, target + counter);
        write_i64_be(suffix + 8, counter);

        // SHA1(prefix || suffix)
        std::vector<uint8_t> buf(prefix_len + 16);
        if (prefix_len) std::memcpy(buf.data(), prefix, prefix_len);
        std::memcpy(buf.data() + prefix_len, suffix, 16);
        auto h = crypto::sha1(buf.data(), buf.size());

        int64_t tail = read_i64_be(h.data() + 12);
        if ((uint64_t)tail == 0 ? 64 >= length : trailing_zeros_64((uint64_t)tail) >= length) {
            std::memcpy(suffix_out, suffix, 16);
            return true;
        }
        ++counter;
    }
}

} // namespace librespotc::auth
