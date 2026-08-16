#include "handshake.h"
#include "../crypto/bigint.h"
#include "../crypto/bcrypt_wrap.h"
#include "../net/tcp_socket.h"
#include "../proto/keyexchange.h"

#include <stdexcept>
#include <cstring>

namespace librespotc::handshake {

// 768-bit MODP prime (from RFC 2409 group 1, used by librespot DH)
static const uint8_t DH_PRIME_BE[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc9, 0x0f, 0xda, 0xa2, 0x21, 0x68, 0xc2, 0x34,
    0xc4, 0xc6, 0x62, 0x8b, 0x80, 0xdc, 0x1c, 0xd1, 0x29, 0x02, 0x4e, 0x08, 0x8a, 0x67, 0xcc, 0x74,
    0x02, 0x0b, 0xbe, 0xa6, 0x3b, 0x13, 0x9b, 0x22, 0x51, 0x4a, 0x08, 0x79, 0x8e, 0x34, 0x04, 0xdd,
    0xef, 0x95, 0x19, 0xb3, 0xcd, 0x3a, 0x43, 0x1b, 0x30, 0x2b, 0x0a, 0x6d, 0xf2, 0x5f, 0x14, 0x37,
    0x4f, 0xe1, 0x35, 0x6d, 0x6d, 0x51, 0xc2, 0x45, 0xe4, 0x85, 0xb5, 0x76, 0x62, 0x5e, 0x7e, 0xc6,
    0xf4, 0x4c, 0x42, 0xe9, 0xa6, 0x3a, 0x36, 0x20, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

// Spotify server's RSA public key (2048-bit) — used to verify gs_signature.
static const uint8_t SERVER_KEY[256] = {
    0xac, 0xe0, 0x46, 0x0b, 0xff, 0xc2, 0x30, 0xaf, 0xf4, 0x6b, 0xfe, 0xc3, 0xbf, 0xbf, 0x86, 0x3d,
    0xa1, 0x91, 0xc6, 0xcc, 0x33, 0x6c, 0x93, 0xa1, 0x4f, 0xb3, 0xb0, 0x16, 0x12, 0xac, 0xac, 0x6a,
    0xf1, 0x80, 0xe7, 0xf6, 0x14, 0xd9, 0x42, 0x9d, 0xbe, 0x2e, 0x34, 0x66, 0x43, 0xe3, 0x62, 0xd2,
    0x32, 0x7a, 0x1a, 0x0d, 0x92, 0x3b, 0xae, 0xdd, 0x14, 0x02, 0xb1, 0x81, 0x55, 0x05, 0x61, 0x04,
    0xd5, 0x2c, 0x96, 0xa4, 0x4c, 0x1e, 0xcc, 0x02, 0x4a, 0xd4, 0xb2, 0x0c, 0x00, 0x1f, 0x17, 0xed,
    0xc2, 0x2f, 0xc4, 0x35, 0x21, 0xc8, 0xf0, 0xcb, 0xae, 0xd2, 0xad, 0xd7, 0x2b, 0x0f, 0x9d, 0xb3,
    0xc5, 0x32, 0x1a, 0x2a, 0xfe, 0x59, 0xf3, 0x5a, 0x0d, 0xac, 0x68, 0xf1, 0xfa, 0x62, 0x1e, 0xfb,
    0x2c, 0x8d, 0x0c, 0xb7, 0x39, 0x2d, 0x92, 0x47, 0xe3, 0xd7, 0x35, 0x1a, 0x6d, 0xbd, 0x24, 0xc2,
    0xae, 0x25, 0x5b, 0x88, 0xff, 0xab, 0x73, 0x29, 0x8a, 0x0b, 0xcc, 0xcd, 0x0c, 0x58, 0x67, 0x31,
    0x89, 0xe8, 0xbd, 0x34, 0x80, 0x78, 0x4a, 0x5f, 0xc9, 0x6b, 0x89, 0x9d, 0x95, 0x6b, 0xfc, 0x86,
    0xd7, 0x4f, 0x33, 0xa6, 0x78, 0x17, 0x96, 0xc9, 0xc3, 0x2d, 0x0d, 0x32, 0xa5, 0xab, 0xcd, 0x05,
    0x27, 0xe2, 0xf7, 0x10, 0xa3, 0x96, 0x13, 0xc4, 0x2f, 0x99, 0xc0, 0x27, 0xbf, 0xed, 0x04, 0x9c,
    0x3c, 0x27, 0x58, 0x04, 0xb6, 0xb2, 0x19, 0xf9, 0xc1, 0x2f, 0x02, 0xe9, 0x48, 0x63, 0xec, 0xa1,
    0xb6, 0x42, 0xa0, 0x9d, 0x48, 0x25, 0xf8, 0xb3, 0x9d, 0xd0, 0xe8, 0x6a, 0xf9, 0x48, 0x4d, 0xa1,
    0xc2, 0xba, 0x86, 0x30, 0x42, 0xea, 0x9d, 0xb3, 0x08, 0x6c, 0x19, 0x0e, 0x48, 0xb3, 0x9d, 0x66,
    0xeb, 0x00, 0x06, 0xa2, 0x5a, 0xee, 0xa1, 0x1b, 0x13, 0x87, 0x3c, 0xd7, 0x19, 0xe6, 0x55, 0xbd,
};

// SPIRC client uses Spotify Desktop version as a u64. Matches librespot ::version::SPOTIFY_VERSION.
static constexpr uint64_t SPOTIFY_VERSION = 124200290ULL;

static uint32_t read_u32_be(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}

static void write_u32_be(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8);
    p[3] = (uint8_t)v;
}

HandshakeResult perform_handshake(net::TcpSocket& sock) {
    // 1) Generate DH local keypair.
    uint8_t priv_bytes[95];
    crypto::random_bytes(priv_bytes, sizeof(priv_bytes));
    auto private_key = crypto::BigUint::from_le(priv_bytes, sizeof(priv_bytes));
    auto generator = crypto::BigUint::from_u32(2);
    auto prime     = crypto::BigUint::from_be(DH_PRIME_BE, sizeof(DH_PRIME_BE));
    auto public_key = crypto::BigUint::modexp(generator, private_key, prime);
    std::vector<uint8_t> gc = public_key.to_be(); // big-endian, may be < 96 bytes

    // 2) Client nonce.
    std::vector<uint8_t> client_nonce(16);
    crypto::random_bytes(client_nonce.data(), client_nonce.size());

    // 3) Encode ClientHello and frame: [0x00, 0x04, BE32 total_size, packet]
    auto hello = proto::encode_client_hello(gc, client_nonce, SPOTIFY_VERSION);
    uint32_t total_size = (uint32_t)(2 + 4 + hello.size());

    std::vector<uint8_t> hello_frame;
    hello_frame.reserve(total_size);
    hello_frame.push_back(0x00);
    hello_frame.push_back(0x04);
    uint8_t sz[4]; write_u32_be(sz, total_size);
    hello_frame.insert(hello_frame.end(), sz, sz + 4);
    hello_frame.insert(hello_frame.end(), hello.begin(), hello.end());

    if (sock.send_all(hello_frame.data(), hello_frame.size()) < 0)
        throw std::runtime_error("send ClientHello failed");

    // 4) Receive APResponseMessage: [BE32 size_including_header][payload]
    uint8_t hdr[4];
    if (sock.recv_all(hdr, 4) < 0) throw std::runtime_error("recv APResponse hdr failed");
    uint32_t resp_size = read_u32_be(hdr);
    if (resp_size < 4 || resp_size > 65536)
        throw std::runtime_error("APResponse size invalid");
    std::vector<uint8_t> resp_body(resp_size - 4);
    if (sock.recv_all(resp_body.data(), resp_body.size()) < 0)
        throw std::runtime_error("recv APResponse body failed");

    // 5) Build accumulator = hello_frame || resp_size_hdr || resp_body
    std::vector<uint8_t> accumulator;
    accumulator.reserve(hello_frame.size() + 4 + resp_body.size());
    accumulator.insert(accumulator.end(), hello_frame.begin(), hello_frame.end());
    accumulator.insert(accumulator.end(), hdr, hdr + 4);
    accumulator.insert(accumulator.end(), resp_body.begin(), resp_body.end());

    // 6) Parse server response.
    auto resp = proto::decode_ap_response(resp_body.data(), resp_body.size());
    if (resp.has_failure) {
        throw std::runtime_error("AP login failed code=" + std::to_string(resp.error_code)
                                 + " " + resp.error_desc);
    }
    if (!resp.challenge) {
        throw std::runtime_error("AP response had no challenge");
    }
    const auto& gs = resp.challenge->gs;
    const auto& gs_sig = resp.challenge->gs_signature;
    if (gs.empty() || gs_sig.size() != 256) {
        throw std::runtime_error("AP response missing gs/gs_signature");
    }

    // 7) Verify server signature on gs with Spotify's RSA pubkey.
    auto gs_hash = crypto::sha1(gs.data(), gs.size());
    bool verified = crypto::rsa_pkcs1v15_sha1_verify(
        SERVER_KEY, sizeof(SERVER_KEY),
        65537,
        gs_hash.data(), gs_hash.size(),
        gs_sig.data(), gs_sig.size()
    );
    if (!verified) throw std::runtime_error("Server signature verification failed");

    // 8) Compute shared secret = gs^private mod prime
    auto remote_pub = crypto::BigUint::from_be(gs.data(), gs.size());
    auto shared = crypto::BigUint::modexp(remote_pub, private_key, prime);
    auto shared_secret = shared.to_be();

    // 9) Derive keys: HMAC-SHA1(shared, accumulator || i) for i=1..5
    std::vector<uint8_t> data;
    data.reserve(100);
    for (uint8_t i = 1; i <= 5; ++i) {
        std::vector<uint8_t> hmac_in = accumulator;
        hmac_in.push_back(i);
        auto h = crypto::hmac_sha1(shared_secret.data(), shared_secret.size(),
                                   hmac_in.data(), hmac_in.size());
        data.insert(data.end(), h.begin(), h.end());
    }
    auto challenge = crypto::hmac_sha1(data.data(), 0x14,
                                       accumulator.data(), accumulator.size());
    std::vector<uint8_t> send_key(data.begin() + 0x14, data.begin() + 0x34);
    std::vector<uint8_t> recv_key(data.begin() + 0x34, data.begin() + 0x54);

    // 10) Send ClientResponsePlaintext with challenge.
    auto resp_plain = proto::encode_client_response_plaintext(challenge);
    uint32_t cr_size = (uint32_t)(4 + resp_plain.size());
    std::vector<uint8_t> cr_frame(4);
    write_u32_be(cr_frame.data(), cr_size);
    cr_frame.insert(cr_frame.end(), resp_plain.begin(), resp_plain.end());
    if (sock.send_all(cr_frame.data(), cr_frame.size()) < 0)
        throw std::runtime_error("send ClientResponsePlaintext failed");

    // 11) Construct Shannon ciphers.
    HandshakeResult r;
    r.send_cipher = std::make_unique<crypto::Shannon>(send_key.data(), send_key.size());
    r.recv_cipher = std::make_unique<crypto::Shannon>(recv_key.data(), recv_key.size());
    return r;
}

} // namespace librespotc::handshake
