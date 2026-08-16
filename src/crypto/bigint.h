#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>

namespace librespotc::crypto {

// Minimal unsigned big integer (little-endian 32-bit limbs).
// Sized for ~1024-bit DH; not constant-time, not for general crypto.
class BigUint {
public:
    BigUint() = default;
    static BigUint from_be(const uint8_t* data, size_t len);
    static BigUint from_le(const uint8_t* data, size_t len);
    static BigUint from_u32(uint32_t v);

    // Big-endian output, zero-trimmed leading bytes.
    std::vector<uint8_t> to_be() const;
    // Big-endian output, left-padded to fixed_len bytes.
    std::vector<uint8_t> to_be_padded(size_t fixed_len) const;

    bool is_zero() const;
    bool is_odd() const;
    size_t bit_length() const;

    void rshift1();
    int cmp(const BigUint& other) const; // -1, 0, 1

    // base^exp mod modulus
    static BigUint modexp(const BigUint& base, const BigUint& exp, const BigUint& mod);

private:
    // limbs[0] is least significant
    std::vector<uint32_t> limbs_;

    void trim();
    static BigUint mul(const BigUint& a, const BigUint& b);
    // a mod m. a is consumed.
    static BigUint mod(BigUint a, const BigUint& m);
    static void sub_inplace(BigUint& a, const BigUint& b); // requires a >= b
    static void shl_inplace(BigUint& a, size_t bits);
};

} // namespace librespotc::crypto
