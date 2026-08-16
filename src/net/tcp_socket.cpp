#include "tcp_socket.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")

namespace librespotc::net {

static int g_wsa_refcount = 0;

TcpSocket::TcpSocket() {
    WSADATA d{};
    if (g_wsa_refcount++ == 0) {
        WSAStartup(MAKEWORD(2, 2), &d);
    }
    ws_started_ = true;
}

TcpSocket::~TcpSocket() {
    close();
    if (ws_started_ && --g_wsa_refcount == 0) {
        WSACleanup();
    }
}

bool TcpSocket::connect(const std::string& host, uint16_t port) {
    close();
    addrinfo hints{}; hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    char port_s[8];
    _snprintf_s(port_s, sizeof(port_s), _TRUNCATE, "%u", (unsigned)port);
    if (getaddrinfo(host.c_str(), port_s, &hints, &res) != 0) return false;

    SOCKET s = INVALID_SOCKET;
    for (addrinfo* p = res; p != nullptr; p = p->ai_next) {
        s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s == INVALID_SOCKET) continue;
        if (::connect(s, p->ai_addr, (int)p->ai_addrlen) == 0) break;
        closesocket(s); s = INVALID_SOCKET;
    }
    freeaddrinfo(res);
    if (s == INVALID_SOCKET) return false;
    BOOL nodelay = TRUE;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char*)&nodelay, sizeof(nodelay));
    fd_ = (uintptr_t)s;
    return true;
}

void TcpSocket::close() {
    if (fd_ != (uintptr_t)-1) {
        closesocket((SOCKET)fd_);
        fd_ = (uintptr_t)-1;
    }
}

bool TcpSocket::is_open() const { return fd_ != (uintptr_t)-1; }

int TcpSocket::send_all(const uint8_t* data, size_t len) {
    size_t pos = 0;
    while (pos < len) {
        int n = ::send((SOCKET)fd_, (const char*)data + pos, (int)(len - pos), 0);
        if (n <= 0) return -1;
        pos += (size_t)n;
    }
    return (int)pos;
}

int TcpSocket::recv_all(uint8_t* out, size_t len) {
    size_t pos = 0;
    while (pos < len) {
        int n = ::recv((SOCKET)fd_, (char*)out + pos, (int)(len - pos), 0);
        if (n <= 0) return -1;
        pos += (size_t)n;
    }
    return (int)pos;
}

} // namespace librespotc::net
