#include "bcrypt_wrap.h"

#include <windows.h>
#include <bcrypt.h>

#include <cstring>
#include <stdexcept>

#pragma comment(lib, "bcrypt.lib")

namespace librespotc::crypto {

#ifndef NT_SUCCESS
#define NT_SUCCESS(x) (((NTSTATUS)(x)) >= 0)
#endif

void random_bytes(uint8_t* out, size_t len) {
    NTSTATUS s = BCryptGenRandom(nullptr, out, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!NT_SUCCESS(s)) throw std::runtime_error("BCryptGenRandom failed");
}

std::vector<uint8_t> sha1(const uint8_t* data, size_t len) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE h = nullptr;
    std::vector<uint8_t> out(20);
    NTSTATUS s = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA1_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(s)) throw std::runtime_error("BCryptOpenAlgorithmProvider SHA1");
    s = BCryptCreateHash(alg, &h, nullptr, 0, nullptr, 0, 0);
    if (NT_SUCCESS(s)) s = BCryptHashData(h, (PUCHAR)data, (ULONG)len, 0);
    if (NT_SUCCESS(s)) s = BCryptFinishHash(h, out.data(), (ULONG)out.size(), 0);
    if (h) BCryptDestroyHash(h);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    if (!NT_SUCCESS(s)) throw std::runtime_error("SHA1 hash failed");
    return out;
}

std::vector<uint8_t> hmac_sha1(const uint8_t* key, size_t key_len,
                               const uint8_t* data, size_t data_len) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE h = nullptr;
    std::vector<uint8_t> out(20);
    NTSTATUS s = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA1_ALGORITHM, nullptr,
                                             BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!NT_SUCCESS(s)) throw std::runtime_error("BCryptOpenAlgorithmProvider HMAC-SHA1");
    s = BCryptCreateHash(alg, &h, nullptr, 0, (PUCHAR)key, (ULONG)key_len, 0);
    if (NT_SUCCESS(s)) s = BCryptHashData(h, (PUCHAR)data, (ULONG)data_len, 0);
    if (NT_SUCCESS(s)) s = BCryptFinishHash(h, out.data(), (ULONG)out.size(), 0);
    if (h) BCryptDestroyHash(h);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    if (!NT_SUCCESS(s)) throw std::runtime_error("HMAC-SHA1 failed");
    return out;
}

// AES-ECB single-block encrypt helper, used to build CTR.
static void aes128_ecb_encrypt_block(BCRYPT_KEY_HANDLE key, const uint8_t in[16], uint8_t out[16]) {
    ULONG outLen = 0;
    NTSTATUS s = BCryptEncrypt(key, (PUCHAR)in, 16, nullptr, nullptr, 0,
                               out, 16, &outLen, 0);
    if (!NT_SUCCESS(s) || outLen != 16) throw std::runtime_error("AES ECB encrypt failed");
}

void aes128_ctr(const uint8_t key[16], const uint8_t iv[16],
                uint8_t* buf, size_t len) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE keyh = nullptr;
    NTSTATUS s = BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(s)) throw std::runtime_error("BCryptOpenAlgorithmProvider AES");
    // ECB mode for raw block encrypt
    s = BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
                          (PUCHAR)BCRYPT_CHAIN_MODE_ECB,
                          sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
    if (NT_SUCCESS(s))
        s = BCryptGenerateSymmetricKey(alg, &keyh, nullptr, 0,
                                       (PUCHAR)key, 16, 0);
    if (!NT_SUCCESS(s)) {
        if (alg) BCryptCloseAlgorithmProvider(alg, 0);
        throw std::runtime_error("AES key setup failed");
    }

    uint8_t counter[16];
    std::memcpy(counter, iv, 16);
    uint8_t keystream[16];
    size_t pos = 0;
    while (pos < len) {
        aes128_ecb_encrypt_block(keyh, counter, keystream);
        size_t chunk = (len - pos > 16) ? 16 : (len - pos);
        for (size_t i = 0; i < chunk; ++i) buf[pos + i] ^= keystream[i];
        pos += chunk;
        // increment counter (big-endian, full 128-bit)
        for (int i = 15; i >= 0; --i) {
            if (++counter[i] != 0) break;
        }
    }

    if (keyh) BCryptDestroyKey(keyh);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
}

void aes192_ecb_decrypt(const uint8_t key[24], uint8_t* buf, size_t len) {
    if (len % 16 != 0) throw std::runtime_error("AES ECB len not block-aligned");
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE keyh = nullptr;
    NTSTATUS s = BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(s)) throw std::runtime_error("BCryptOpenAlgorithmProvider AES-192");
    s = BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
                          (PUCHAR)BCRYPT_CHAIN_MODE_ECB,
                          sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
    if (NT_SUCCESS(s))
        s = BCryptGenerateSymmetricKey(alg, &keyh, nullptr, 0, (PUCHAR)key, 24, 0);
    if (NT_SUCCESS(s)) {
        ULONG out_len = 0;
        s = BCryptDecrypt(keyh, buf, (ULONG)len, nullptr, nullptr, 0,
                          buf, (ULONG)len, &out_len, 0);
    }
    if (keyh) BCryptDestroyKey(keyh);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    if (!NT_SUCCESS(s)) throw std::runtime_error("AES-192-ECB decrypt failed");
}

std::vector<uint8_t> pbkdf2_hmac_sha1(const uint8_t* password, size_t password_len,
                                      const uint8_t* salt, size_t salt_len,
                                      uint32_t iterations,
                                      size_t out_len) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    NTSTATUS s = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA1_ALGORITHM, nullptr,
                                             BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!NT_SUCCESS(s)) throw std::runtime_error("BCryptOpenAlgorithmProvider PBKDF2");
    std::vector<uint8_t> out(out_len);
    s = BCryptDeriveKeyPBKDF2(alg,
                              (PUCHAR)password, (ULONG)password_len,
                              (PUCHAR)salt, (ULONG)salt_len,
                              iterations,
                              out.data(), (ULONG)out.size(),
                              0);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (!NT_SUCCESS(s)) throw std::runtime_error("PBKDF2 failed");
    return out;
}

void aes128_ctr_at(const uint8_t key[16], const uint8_t iv[16],
                   uint64_t byte_offset, uint8_t* buf, size_t len) {
    if (len == 0) return;

    // Counter for first block = iv + (byte_offset / 16), big-endian add.
    uint8_t counter[16];
    std::memcpy(counter, iv, 16);
    uint64_t carry = byte_offset / 16;
    for (int i = 15; i >= 0 && carry != 0; --i) {
        uint64_t sum = (uint64_t)counter[i] + (carry & 0xff);
        counter[i] = (uint8_t)(sum & 0xff);
        carry = (carry >> 8) + (sum >> 8);
    }

    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE keyh = nullptr;
    NTSTATUS s = BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(s)) throw std::runtime_error("BCryptOpenAlgorithmProvider AES");
    s = BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
                          (PUCHAR)BCRYPT_CHAIN_MODE_ECB,
                          sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
    if (NT_SUCCESS(s))
        s = BCryptGenerateSymmetricKey(alg, &keyh, nullptr, 0, (PUCHAR)key, 16, 0);
    if (!NT_SUCCESS(s)) {
        if (alg) BCryptCloseAlgorithmProvider(alg, 0);
        throw std::runtime_error("AES key setup failed");
    }

    size_t skip = (size_t)(byte_offset % 16);
    size_t pos = 0;
    uint8_t keystream[16];

    while (pos < len) {
        ULONG out_len = 0;
        NTSTATUS es = BCryptEncrypt(keyh, (PUCHAR)counter, 16, nullptr, nullptr, 0,
                                    keystream, 16, &out_len, 0);
        if (!NT_SUCCESS(es) || out_len != 16) {
            BCryptDestroyKey(keyh);
            BCryptCloseAlgorithmProvider(alg, 0);
            throw std::runtime_error("AES CTR keystream gen failed");
        }
        size_t take_from = skip;
        size_t take_n = 16 - skip;
        if (take_n > len - pos) take_n = len - pos;
        for (size_t i = 0; i < take_n; ++i) buf[pos + i] ^= keystream[take_from + i];
        pos += take_n;
        skip = 0;
        for (int i = 15; i >= 0; --i) { if (++counter[i] != 0) break; }
    }

    BCryptDestroyKey(keyh);
    BCryptCloseAlgorithmProvider(alg, 0);
}

bool rsa_pkcs1v15_sha1_verify(const uint8_t* modulus_be, size_t modulus_len,
                              uint32_t exponent,
                              const uint8_t* hash, size_t hash_len,
                              const uint8_t* signature, size_t signature_len) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE key = nullptr;
    NTSTATUS s = BCryptOpenAlgorithmProvider(&alg, BCRYPT_RSA_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(s)) return false;

    // Build BCRYPT_RSAKEY_BLOB
    // Exponent as big-endian 4 bytes, trimmed of leading zeros (must be at least 1).
    uint8_t exp_be[4];
    exp_be[0] = (uint8_t)((exponent >> 24) & 0xff);
    exp_be[1] = (uint8_t)((exponent >> 16) & 0xff);
    exp_be[2] = (uint8_t)((exponent >>  8) & 0xff);
    exp_be[3] = (uint8_t)( exponent        & 0xff);
    size_t exp_lead = 0;
    while (exp_lead < 3 && exp_be[exp_lead] == 0) ++exp_lead;
    size_t exp_len = 4 - exp_lead;

    std::vector<uint8_t> blob(sizeof(BCRYPT_RSAKEY_BLOB) + exp_len + modulus_len);
    BCRYPT_RSAKEY_BLOB* h = (BCRYPT_RSAKEY_BLOB*)blob.data();
    h->Magic = BCRYPT_RSAPUBLIC_MAGIC;
    h->BitLength = (ULONG)(modulus_len * 8);
    h->cbPublicExp = (ULONG)exp_len;
    h->cbModulus = (ULONG)modulus_len;
    h->cbPrime1 = 0;
    h->cbPrime2 = 0;
    std::memcpy(blob.data() + sizeof(BCRYPT_RSAKEY_BLOB), exp_be + exp_lead, exp_len);
    std::memcpy(blob.data() + sizeof(BCRYPT_RSAKEY_BLOB) + exp_len, modulus_be, modulus_len);

    s = BCryptImportKeyPair(alg, nullptr, BCRYPT_RSAPUBLIC_BLOB, &key,
                            blob.data(), (ULONG)blob.size(), 0);
    bool ok = false;
    if (NT_SUCCESS(s)) {
        BCRYPT_PKCS1_PADDING_INFO pad{};
        pad.pszAlgId = BCRYPT_SHA1_ALGORITHM;
        s = BCryptVerifySignature(key, &pad,
                                  (PUCHAR)hash, (ULONG)hash_len,
                                  (PUCHAR)signature, (ULONG)signature_len,
                                  BCRYPT_PAD_PKCS1);
        ok = NT_SUCCESS(s);
    }
    if (key) BCryptDestroyKey(key);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

} // namespace librespotc::crypto
