#include "bigint.h"
#include <algorithm>
#include <cstring>

namespace librespotc::crypto {

void BigUint::trim() {
    while (!limbs_.empty() && limbs_.back() == 0) limbs_.pop_back();
}

BigUint BigUint::from_be(const uint8_t* data, size_t len) {
    BigUint r;
    r.limbs_.resize((len + 3) / 4, 0);
    // data[0] is most significant
    for (size_t i = 0; i < len; ++i) {
        size_t rev = len - 1 - i; // byte position from LSB
        r.limbs_[rev / 4] |= (uint32_t)data[i] << ((rev % 4) * 8);
    }
    r.trim();
    return r;
}

BigUint BigUint::from_le(const uint8_t* data, size_t len) {
    BigUint r;
    r.limbs_.resize((len + 3) / 4, 0);
    for (size_t i = 0; i < len; ++i) {
        r.limbs_[i / 4] |= (uint32_t)data[i] << ((i % 4) * 8);
    }
    r.trim();
    return r;
}

BigUint BigUint::from_u32(uint32_t v) {
    BigUint r;
    if (v) r.limbs_.push_back(v);
    return r;
}

std::vector<uint8_t> BigUint::to_be() const {
    if (limbs_.empty()) return {};
    size_t total = limbs_.size() * 4;
    std::vector<uint8_t> tmp(total);
    for (size_t i = 0; i < limbs_.size(); ++i) {
        uint32_t v = limbs_[i];
        tmp[total - 1 - i*4    ] = (uint8_t)(v & 0xff);
        tmp[total - 1 - i*4 - 1] = (uint8_t)((v >> 8) & 0xff);
        tmp[total - 1 - i*4 - 2] = (uint8_t)((v >> 16) & 0xff);
        tmp[total - 1 - i*4 - 3] = (uint8_t)((v >> 24) & 0xff);
    }
    size_t lead = 0;
    while (lead < tmp.size() - 1 && tmp[lead] == 0) ++lead;
    return std::vector<uint8_t>(tmp.begin() + lead, tmp.end());
}

std::vector<uint8_t> BigUint::to_be_padded(size_t fixed_len) const {
    auto v = to_be();
    if (v.size() >= fixed_len) {
        // already at or larger; truncate leading (should not happen if sized right)
        return std::vector<uint8_t>(v.end() - fixed_len, v.end());
    }
    std::vector<uint8_t> out(fixed_len, 0);
    std::memcpy(out.data() + (fixed_len - v.size()), v.data(), v.size());
    return out;
}

bool BigUint::is_zero() const { return limbs_.empty(); }
bool BigUint::is_odd() const  { return !limbs_.empty() && (limbs_[0] & 1u); }

size_t BigUint::bit_length() const {
    if (limbs_.empty()) return 0;
    uint32_t top = limbs_.back();
    size_t bits = (limbs_.size() - 1) * 32;
    while (top) { ++bits; top >>= 1; }
    return bits;
}

void BigUint::rshift1() {
    if (limbs_.empty()) return;
    for (size_t i = 0; i + 1 < limbs_.size(); ++i) {
        limbs_[i] = (limbs_[i] >> 1) | (limbs_[i+1] << 31);
    }
    limbs_.back() >>= 1;
    trim();
}

int BigUint::cmp(const BigUint& o) const {
    if (limbs_.size() != o.limbs_.size())
        return limbs_.size() < o.limbs_.size() ? -1 : 1;
    for (size_t i = limbs_.size(); i-- > 0; ) {
        if (limbs_[i] != o.limbs_[i])
            return limbs_[i] < o.limbs_[i] ? -1 : 1;
    }
    return 0;
}

BigUint BigUint::mul(const BigUint& a, const BigUint& b) {
    BigUint r;
    if (a.limbs_.empty() || b.limbs_.empty()) return r;
    r.limbs_.assign(a.limbs_.size() + b.limbs_.size(), 0);
    for (size_t i = 0; i < a.limbs_.size(); ++i) {
        uint64_t carry = 0;
        uint64_t ai = a.limbs_[i];
        for (size_t j = 0; j < b.limbs_.size(); ++j) {
            uint64_t cur = (uint64_t)r.limbs_[i+j] + ai * (uint64_t)b.limbs_[j] + carry;
            r.limbs_[i+j] = (uint32_t)cur;
            carry = cur >> 32;
        }
        r.limbs_[i + b.limbs_.size()] += (uint32_t)carry;
    }
    r.trim();
    return r;
}

void BigUint::sub_inplace(BigUint& a, const BigUint& b) {
    // a >= b assumed
    int64_t borrow = 0;
    for (size_t i = 0; i < a.limbs_.size(); ++i) {
        int64_t bv = (i < b.limbs_.size()) ? (int64_t)b.limbs_[i] : 0;
        int64_t cur = (int64_t)a.limbs_[i] - bv - borrow;
        if (cur < 0) { cur += (int64_t)1 << 32; borrow = 1; } else borrow = 0;
        a.limbs_[i] = (uint32_t)cur;
    }
    a.trim();
}

void BigUint::shl_inplace(BigUint& a, size_t bits) {
    if (a.is_zero() || bits == 0) return;
    size_t word_shift = bits / 32;
    size_t bit_shift  = bits % 32;
    if (word_shift) {
        a.limbs_.insert(a.limbs_.begin(), word_shift, 0u);
    }
    if (bit_shift) {
        uint32_t carry = 0;
        for (size_t i = word_shift; i < a.limbs_.size(); ++i) {
            uint32_t v = a.limbs_[i];
            a.limbs_[i] = (v << bit_shift) | carry;
            carry = v >> (32 - bit_shift);
        }
        if (carry) a.limbs_.push_back(carry);
    }
    a.trim();
}

BigUint BigUint::mod(BigUint a, const BigUint& m) {
    // long division by repeated shift-subtract.
    if (m.is_zero()) return BigUint{}; // undefined
    if (a.cmp(m) < 0) return a;
    size_t a_bits = a.bit_length();
    size_t m_bits = m.bit_length();
    if (a_bits < m_bits) return a;
    BigUint mshift = m;
    size_t shift = a_bits - m_bits;
    shl_inplace(mshift, shift);
    while (true) {
        if (a.cmp(mshift) >= 0) sub_inplace(a, mshift);
        if (shift == 0) break;
        mshift.rshift1();
        --shift;
    }
    return a;
}

BigUint BigUint::modexp(const BigUint& base, const BigUint& exp, const BigUint& m) {
    if (m.cmp(BigUint::from_u32(1)) == 0) return BigUint{};
    BigUint result = BigUint::from_u32(1);
    BigUint b = mod(base, m);
    BigUint e = exp;
    while (!e.is_zero()) {
        if (e.is_odd()) {
            result = mod(mul(result, b), m);
        }
        e.rshift1();
        if (e.is_zero()) break;
        b = mod(mul(b, b), m);
    }
    return result;
}

} // namespace librespotc::crypto
