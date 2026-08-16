#pragma once
#include <cstdint>
#include <cstddef>

namespace librespotc::audio {

// Spotify-fixed AES-CTR IV for audio file decryption.
extern const uint8_t AUDIO_IV[16];

// In-place AES-128-CTR over an entire file decrypted from offset 0.
// Use the existing crypto::aes128_ctr; this wrapper exists for clarity.
void decrypt_full(const uint8_t key[16], uint8_t* buf, size_t len);

} // namespace librespotc::audio
