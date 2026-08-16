#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>

namespace librespotc::crypto {

// Random bytes via BCryptGenRandom.
void random_bytes(uint8_t* out, size_t len);

// SHA-1 of input. Returns 20 bytes.
std::vector<uint8_t> sha1(const uint8_t* data, size_t len);

// HMAC-SHA1.
std::vector<uint8_t> hmac_sha1(const uint8_t* key, size_t key_len,
                               const uint8_t* data, size_t data_len);

// AES-128-CTR. iv is 16 bytes; counter increments per-block big-endian.
// Encrypts/decrypts in place (CTR is symmetric).
void aes128_ctr(const uint8_t key[16], const uint8_t iv[16],
                uint8_t* buf, size_t len);

// AES-128-CTR starting at a given byte offset into the keystream.
// Counter for first affected block = (iv as BE128) + (byte_offset / 16).
// Handles unaligned starts (XORs from offset%16 within first keystream block).
void aes128_ctr_at(const uint8_t key[16], const uint8_t iv[16],
                   uint64_t byte_offset, uint8_t* buf, size_t len);

// AES-192-ECB decrypt in place. No padding; len must be multiple of 16.
void aes192_ecb_decrypt(const uint8_t key[24], uint8_t* buf, size_t len);

// PBKDF2-HMAC-SHA1.
std::vector<uint8_t> pbkdf2_hmac_sha1(const uint8_t* password, size_t password_len,
                                      const uint8_t* salt, size_t salt_len,
                                      uint32_t iterations,
                                      size_t out_len);

// RSA PKCS#1 v1.5 SHA-1 signature verify.
// modulus_be: big-endian RSA modulus (typically 256 bytes = 2048-bit).
// exponent:   public exponent (typically 65537).
// hash:       20-byte SHA-1 digest of message.
// signature:  RSA signature (modulus-length bytes).
bool rsa_pkcs1v15_sha1_verify(const uint8_t* modulus_be, size_t modulus_len,
                              uint32_t exponent,
                              const uint8_t* hash, size_t hash_len,
                              const uint8_t* signature, size_t signature_len);

} // namespace librespotc::crypto
