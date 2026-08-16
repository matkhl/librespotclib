#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <string_view>
#include <cstring>
#include <stdexcept>

namespace librespotc::proto {

// Minimal protobuf wire-format encoder/decoder for the subset of messages
// librespotc needs. Hand-rolled to avoid pulling in libprotobuf.

constexpr uint32_t WIRE_VARINT = 0;
constexpr uint32_t WIRE_64BIT  = 1;
constexpr uint32_t WIRE_LEN    = 2;
constexpr uint32_t WIRE_32BIT  = 5;

class Writer {
public:
    void write_varint(uint64_t v) {
        while (v >= 0x80) {
            buf_.push_back((uint8_t)(v | 0x80));
            v >>= 7;
        }
        buf_.push_back((uint8_t)v);
    }
    void write_tag(uint32_t field, uint32_t wire) {
        write_varint(((uint64_t)field << 3) | wire);
    }
    void write_uint64(uint32_t field, uint64_t v) {
        write_tag(field, WIRE_VARINT);
        write_varint(v);
    }
    void write_int32(uint32_t field, int32_t v) {
        // proto2 int32 is varint (negative = 10-byte ext)
        write_tag(field, WIRE_VARINT);
        write_varint((uint64_t)(int64_t)v);
    }
    void write_uint32(uint32_t field, uint32_t v) {
        write_tag(field, WIRE_VARINT);
        write_varint((uint64_t)v);
    }
    void write_enum(uint32_t field, int32_t v) {
        write_tag(field, WIRE_VARINT);
        write_varint((uint64_t)(int64_t)v);
    }
    void write_bool(uint32_t field, bool v) {
        write_tag(field, WIRE_VARINT);
        write_varint(v ? 1 : 0);
    }
    void write_bytes(uint32_t field, const uint8_t* data, size_t len) {
        write_tag(field, WIRE_LEN);
        write_varint(len);
        buf_.insert(buf_.end(), data, data + len);
    }
    void write_bytes(uint32_t field, const std::vector<uint8_t>& v) {
        write_bytes(field, v.data(), v.size());
    }
    void write_string(uint32_t field, std::string_view s) {
        write_bytes(field, (const uint8_t*)s.data(), s.size());
    }
    void write_double(uint32_t field, double v) {
        write_tag(field, WIRE_64BIT);
        uint64_t bits;
        std::memcpy(&bits, &v, 8);
        for (int i = 0; i < 8; ++i) buf_.push_back((uint8_t)(bits >> (8*i)));
    }
    // Write a sub-message: callable receives an inner Writer; the result is
    // length-prefixed and emitted with the given field tag.
    template<typename F>
    void write_submessage(uint32_t field, F&& f) {
        Writer inner;
        f(inner);
        write_bytes(field, inner.data(), inner.size());
    }

    const uint8_t* data() const { return buf_.data(); }
    size_t size() const { return buf_.size(); }
    std::vector<uint8_t> take() { return std::move(buf_); }

private:
    std::vector<uint8_t> buf_;
};

class Reader {
public:
    Reader(const uint8_t* data, size_t len) : p_(data), end_(data + len) {}

    bool at_end() const { return p_ >= end_; }
    size_t remaining() const { return (size_t)(end_ - p_); }

    uint64_t read_varint() {
        uint64_t r = 0;
        int shift = 0;
        while (true) {
            if (p_ >= end_) throw std::runtime_error("varint truncated");
            uint8_t b = *p_++;
            r |= ((uint64_t)(b & 0x7f)) << shift;
            if ((b & 0x80) == 0) return r;
            shift += 7;
            if (shift >= 70) throw std::runtime_error("varint too long");
        }
    }

    // Read next tag. Returns false if at end.
    bool read_tag(uint32_t& field, uint32_t& wire) {
        if (at_end()) return false;
        uint64_t t = read_varint();
        wire  = (uint32_t)(t & 0x7);
        field = (uint32_t)(t >> 3);
        return true;
    }

    // Read length-delimited and return a Reader over its bytes.
    Reader read_len_delim() {
        uint64_t len = read_varint();
        if (len > remaining()) throw std::runtime_error("len-delim past end");
        Reader r(p_, (size_t)len);
        p_ += len;
        return r;
    }

    std::vector<uint8_t> read_bytes() {
        uint64_t len = read_varint();
        if (len > remaining()) throw std::runtime_error("bytes past end");
        std::vector<uint8_t> out(p_, p_ + len);
        p_ += len;
        return out;
    }

    std::string read_string() {
        uint64_t len = read_varint();
        if (len > remaining()) throw std::runtime_error("string past end");
        std::string out((const char*)p_, (size_t)len);
        p_ += len;
        return out;
    }

    // Skip an unknown field of given wire type.
    void skip_field(uint32_t wire) {
        switch (wire) {
            case WIRE_VARINT: (void)read_varint(); return;
            case WIRE_64BIT:
                if (remaining() < 8) throw std::runtime_error("trunc 64");
                p_ += 8; return;
            case WIRE_LEN: {
                uint64_t len = read_varint();
                if (len > remaining()) throw std::runtime_error("trunc len");
                p_ += len; return;
            }
            case WIRE_32BIT:
                if (remaining() < 4) throw std::runtime_error("trunc 32");
                p_ += 4; return;
            default:
                throw std::runtime_error("unknown wire type");
        }
    }

private:
    const uint8_t* p_;
    const uint8_t* end_;
};

} // namespace librespotc::proto
