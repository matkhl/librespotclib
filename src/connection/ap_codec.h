#pragma once
#include <cstdint>
#include <vector>
#include <memory>

#include "../crypto/shannon.h"

namespace librespotc::net { class TcpSocket; }

namespace librespotc::connection {

// Shannon-encrypted packet codec over the AP TCP connection.
// Each packet on the wire: [cmd:u8][len:u16 BE][payload:len][mac:4]
// Shannon nonces start at 0 per direction and increment per packet.
class ApCodec {
public:
    ApCodec(std::unique_ptr<crypto::Shannon> send_cipher,
            std::unique_ptr<crypto::Shannon> recv_cipher,
            net::TcpSocket& sock);

    // Send one packet. Returns true on success.
    bool send(uint8_t cmd, const uint8_t* payload, size_t len);
    bool send(uint8_t cmd, const std::vector<uint8_t>& payload) {
        return send(cmd, payload.data(), payload.size());
    }

    // Receive one packet. Blocks. Returns true on success.
    bool recv(uint8_t& cmd_out, std::vector<uint8_t>& payload_out);

private:
    std::unique_ptr<crypto::Shannon> send_;
    std::unique_ptr<crypto::Shannon> recv_;
    net::TcpSocket& sock_;
    uint32_t send_nonce_ = 0;
    uint32_t recv_nonce_ = 0;
};

// Common command bytes used in Spotify AP protocol.
namespace cmd {
    constexpr uint8_t SECRET_BLOCK         = 0x02;
    constexpr uint8_t PING                 = 0x04;
    constexpr uint8_t STREAM_CHUNK         = 0x08;
    constexpr uint8_t STREAM_CHUNK_RES     = 0x09;
    constexpr uint8_t CHANNEL_ERROR        = 0x0a;
    constexpr uint8_t CHANNEL_ABORT        = 0x0b;
    constexpr uint8_t REQUEST_KEY          = 0x0c;
    constexpr uint8_t AES_KEY              = 0x0d;
    constexpr uint8_t AES_KEY_ERROR        = 0x0e;
    constexpr uint8_t COUNTRY_CODE         = 0x1b;
    constexpr uint8_t PONG                 = 0x49;
    constexpr uint8_t PONG_ACK             = 0x4a;
    constexpr uint8_t PAUSE                = 0x4b;
    constexpr uint8_t PRODUCT_INFO         = 0x50;
    constexpr uint8_t LEGACY_WELCOME       = 0x69;
    constexpr uint8_t LICENSE_VERSION      = 0x76;
    constexpr uint8_t LOGIN                = 0xab;
    constexpr uint8_t AP_WELCOME           = 0xac;
    constexpr uint8_t AUTH_FAILURE         = 0xad;
    constexpr uint8_t MERCURY_REQ          = 0xb2;
    constexpr uint8_t MERCURY_SUB          = 0xb3;
    constexpr uint8_t MERCURY_UNSUB        = 0xb4;
    constexpr uint8_t MERCURY_EVENT        = 0xb5;
}

} // namespace librespotc::connection
