#pragma once
#include <cstdint>
#include <cstddef>
#include <string>

namespace librespotc::net {

class TcpSocket {
public:
    TcpSocket();
    ~TcpSocket();
    TcpSocket(const TcpSocket&) = delete;
    TcpSocket& operator=(const TcpSocket&) = delete;

    bool connect(const std::string& host, uint16_t port);
    void close();
    bool is_open() const;

    // Returns bytes written or -1 on error.
    int send_all(const uint8_t* data, size_t len);
    // Returns bytes read or -1 on error. Reads exactly len bytes (blocks).
    int recv_all(uint8_t* out, size_t len);

private:
    uintptr_t fd_ = (uintptr_t)-1; // SOCKET
    bool ws_started_ = false;
};

} // namespace librespotc::net
