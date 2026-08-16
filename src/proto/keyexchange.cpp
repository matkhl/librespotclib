#include "keyexchange.h"
#include "pb_codec.h"

namespace librespotc::proto {

// Field numbers from deps/proto/keyexchange.proto
// ClientHello: build_info=10, cryptosuites_supported=30, login_crypto_hello=50,
//              client_nonce=60, padding=70, feature_set=80, powschemes_supported=40
// BuildInfo:   product=10, product_flags=20, platform=30, version=40
// LoginCryptoHelloUnion: diffie_hellman=10
// LoginCryptoDiffieHellmanHello: gc=10, server_keys_known=20

constexpr int PRODUCT_CLIENT = 0;
constexpr int PRODUCT_FLAG_NONE = 0;
constexpr int PLATFORM_WIN32_X86_64 = 0x27;
constexpr int CRYPTO_SUITE_SHANNON = 0;

std::vector<uint8_t> encode_client_hello(
    const std::vector<uint8_t>& gc,
    const std::vector<uint8_t>& client_nonce,
    uint64_t spotify_version) {

    Writer w;

    // build_info (field 10, submessage)
    w.write_submessage(10, [&](Writer& bi) {
        bi.write_enum(10, PRODUCT_CLIENT);
        bi.write_enum(20, PRODUCT_FLAG_NONE);
        bi.write_enum(30, PLATFORM_WIN32_X86_64);
        bi.write_uint64(40, spotify_version);
    });

    // cryptosuites_supported (field 30, repeated enum)
    w.write_enum(30, CRYPTO_SUITE_SHANNON);

    // login_crypto_hello (field 50, submessage)
    w.write_submessage(50, [&](Writer& lh) {
        // diffie_hellman (field 10, submessage)
        lh.write_submessage(10, [&](Writer& dh) {
            dh.write_bytes(10, gc);             // gc
            dh.write_uint32(20, 1);             // server_keys_known
        });
    });

    // client_nonce (field 60, bytes)
    w.write_bytes(60, client_nonce);
    // padding (field 70, bytes)
    uint8_t pad = 0x1e;
    w.write_bytes(70, &pad, 1);

    return w.take();
}

static void parse_login_crypto_challenge(Reader r, ApChallenge& out) {
    // LoginCryptoChallengeUnion: diffie_hellman=10
    while (!r.at_end()) {
        uint32_t f, wt;
        if (!r.read_tag(f, wt)) break;
        if (f == 10 && wt == WIRE_LEN) {
            Reader dh = r.read_len_delim();
            // LoginCryptoDiffieHellmanChallenge: gs=10, server_signature_key=20, gs_signature=30
            while (!dh.at_end()) {
                uint32_t df, dwt;
                if (!dh.read_tag(df, dwt)) break;
                if (df == 10 && dwt == WIRE_LEN) out.gs = dh.read_bytes();
                else if (df == 30 && dwt == WIRE_LEN) out.gs_signature = dh.read_bytes();
                else dh.skip_field(dwt);
            }
        } else {
            r.skip_field(wt);
        }
    }
}

static void parse_ap_challenge(Reader r, ApChallenge& out) {
    // APChallenge: login_crypto_challenge=10, fingerprint=20, pow=30, crypto=40,
    //              server_nonce=50, padding=60
    while (!r.at_end()) {
        uint32_t f, wt;
        if (!r.read_tag(f, wt)) break;
        if (f == 10 && wt == WIRE_LEN) {
            parse_login_crypto_challenge(r.read_len_delim(), out);
        } else {
            r.skip_field(wt);
        }
    }
}

static void parse_login_failed(Reader r, ApResponse& out) {
    // APLoginFailed: error_code=10, retry_delay=20, expiry=30, error_description=40
    while (!r.at_end()) {
        uint32_t f, wt;
        if (!r.read_tag(f, wt)) break;
        if (f == 10 && wt == WIRE_VARINT) out.error_code = (int32_t)r.read_varint();
        else if (f == 40 && wt == WIRE_LEN) out.error_desc = r.read_string();
        else r.skip_field(wt);
    }
}

ApResponse decode_ap_response(const uint8_t* data, size_t len) {
    Reader r(data, len);
    ApResponse out;
    while (!r.at_end()) {
        uint32_t f, wt;
        if (!r.read_tag(f, wt)) break;
        if (f == 10 && wt == WIRE_LEN) {
            ApChallenge c;
            parse_ap_challenge(r.read_len_delim(), c);
            out.challenge = std::move(c);
        } else if (f == 20 && wt == WIRE_LEN) {
            out.upgrade_required = true;
            r.skip_field(wt);
        } else if (f == 30 && wt == WIRE_LEN) {
            out.has_failure = true;
            parse_login_failed(r.read_len_delim(), out);
        } else {
            r.skip_field(wt);
        }
    }
    return out;
}

std::vector<uint8_t> encode_client_response_plaintext(const std::vector<uint8_t>& hmac) {
    Writer w;
    // login_crypto_response (10, submessage)
    w.write_submessage(10, [&](Writer& lr) {
        // diffie_hellman (10, submessage)
        lr.write_submessage(10, [&](Writer& dh) {
            dh.write_bytes(10, hmac); // hmac
        });
    });
    // pow_response (20, submessage) - empty union
    w.write_submessage(20, [&](Writer&) {});
    // crypto_response (30, submessage) - empty union
    w.write_submessage(30, [&](Writer&) {});
    return w.take();
}

} // namespace librespotc::proto
