#include "ap_codec.h"
#include "../net/tcp_socket.h"

#include <stdexcept>
#include <cstring>

namespace librespotc::connection {

ApCodec::ApCodec(std::unique_ptr<crypto::Shannon> s,
                 std::unique_ptr<crypto::Shannon> r,
                 net::TcpSocket& sock)
    : send_(std::move(s)), recv_(std::move(r)), sock_(sock) {}

bool ApCodec::send(uint8_t cmd, const uint8_t* payload, size_t len) {
    if (len > 0xffff) return false;
    std::vector<uint8_t> frame(3 + len);
    frame[0] = cmd;
    frame[1] = (uint8_t)((len >> 8) & 0xff);
    frame[2] = (uint8_t)( len       & 0xff);
    if (len) std::memcpy(frame.data() + 3, payload, len);

    send_->nonce_u32(send_nonce_++);
    send_->encrypt(frame.data(), frame.size());

    uint8_t mac[4];
    send_->finish(mac, 4);

    if (sock_.send_all(frame.data(), frame.size()) < 0) return false;
    if (sock_.send_all(mac, 4) < 0) return false;
    return true;
}

bool ApCodec::recv(uint8_t& cmd_out, std::vector<uint8_t>& payload_out) {
    recv_->nonce_u32(recv_nonce_++);

    uint8_t hdr[3];
    if (sock_.recv_all(hdr, 3) < 0) return false;
    recv_->decrypt(hdr, 3);
    cmd_out = hdr[0];
    uint16_t len = ((uint16_t)hdr[1] << 8) | hdr[2];

    payload_out.resize(len);
    if (len) {
        if (sock_.recv_all(payload_out.data(), len) < 0) return false;
        recv_->decrypt(payload_out.data(), len);
    }
    uint8_t mac[4];
    if (sock_.recv_all(mac, 4) < 0) return false;
    if (!recv_->check_mac(mac, 4)) return false;
    return true;
}

} // namespace librespotc::connection
