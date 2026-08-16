#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <memory>

#include "../crypto/shannon.h"

namespace librespotc::net { class TcpSocket; }

namespace librespotc::handshake {

struct HandshakeResult {
    std::unique_ptr<crypto::Shannon> send_cipher;
    std::unique_ptr<crypto::Shannon> recv_cipher;
};

// Performs full DH handshake over a connected socket.
// On success returns send/recv Shannon ciphers (nonces start at 0).
// On failure throws std::runtime_error.
HandshakeResult perform_handshake(net::TcpSocket& sock);

} // namespace librespotc::handshake
