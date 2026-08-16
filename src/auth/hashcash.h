#pragma once
#include <cstdint>

namespace librespotc::auth {

// Solve a Spotify hashcash challenge.
// ctx: variable-length context (login5: server's login_context bytes; client_token: empty)
// prefix: prefix bytes for hash input
// length: number of low-order zero bits required on last 8 bytes of SHA1
// suffix_out: 16 bytes filled with the found suffix
// Returns true on success, false on timeout (~10s).
bool solve_hash_cash(const uint8_t* ctx, size_t ctx_len,
                     const uint8_t* prefix, size_t prefix_len,
                     int length,
                     uint8_t suffix_out[16]);

} // namespace librespotc::auth
