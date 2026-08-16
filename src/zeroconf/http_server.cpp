#include "http_server.h"
#include "../crypto/base64.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <cstring>
#include <thread>
#include <vector>
#include <string>

#pragma comment(lib, "ws2_32.lib")

namespace librespotc::zeroconf {

static int g_wsa_refcount = 0;

HttpServer::HttpServer() {
    WSADATA d{};
    if (g_wsa_refcount++ == 0) WSAStartup(MAKEWORD(2,2), &d);
}
HttpServer::~HttpServer() {
    stop();
    if (--g_wsa_refcount == 0) WSACleanup();
}

bool HttpServer::start(uint16_t port) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return false;
    BOOL yes = TRUE;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    if (bind(s, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(s); return false;
    }
    if (listen(s, 16) == SOCKET_ERROR) { closesocket(s); return false; }

    int alen = sizeof(addr);
    getsockname(s, (sockaddr*)&addr, &alen);
    port_ = ntohs(addr.sin_port);
    listen_fd_ = (uintptr_t)s;
    return true;
}

void HttpServer::stop() {
    running_ = false;
    if (listen_fd_ != (uintptr_t)-1) {
        closesocket((SOCKET)listen_fd_);
        listen_fd_ = (uintptr_t)-1;
    }
}

static void parse_query(const std::string& q, std::map<std::string,std::string>& out) {
    size_t pos = 0;
    while (pos < q.size()) {
        size_t amp = q.find('&', pos);
        if (amp == std::string::npos) amp = q.size();
        size_t eq = q.find('=', pos);
        if (eq != std::string::npos && eq < amp) {
            out[crypto::url_decode(q.substr(pos, eq - pos))] =
                crypto::url_decode(q.substr(eq + 1, amp - eq - 1));
        } else if (amp > pos) {
            out[crypto::url_decode(q.substr(pos, amp - pos))] = "";
        }
        pos = amp + 1;
    }
}

static std::string recv_line(SOCKET s, std::string& spill) {
    while (true) {
        auto pos = spill.find("\r\n");
        if (pos != std::string::npos) {
            std::string r = spill.substr(0, pos);
            spill.erase(0, pos + 2);
            return r;
        }
        char buf[1024];
        int n = ::recv(s, buf, sizeof(buf), 0);
        if (n <= 0) return "";
        spill.append(buf, buf + n);
    }
}

static bool recv_n(SOCKET s, std::string& spill, size_t n, std::string& out) {
    while (spill.size() < n) {
        char buf[4096];
        int r = ::recv(s, buf, sizeof(buf), 0);
        if (r <= 0) return false;
        spill.append(buf, buf + r);
    }
    out.assign(spill.data(), n);
    spill.erase(0, n);
    return true;
}

static void handle_client(SOCKET cs, Handler handler) {
    std::string spill;

    // Request line
    std::string line = recv_line(cs, spill);
    if (line.empty()) { closesocket(cs); return; }
    HttpRequest req;
    {
        size_t sp1 = line.find(' ');
        size_t sp2 = (sp1 == std::string::npos) ? std::string::npos : line.find(' ', sp1+1);
        if (sp1 == std::string::npos || sp2 == std::string::npos) { closesocket(cs); return; }
        req.method = line.substr(0, sp1);
        std::string target = line.substr(sp1 + 1, sp2 - sp1 - 1);
        size_t qmark = target.find('?');
        if (qmark != std::string::npos) {
            req.path = target.substr(0, qmark);
            parse_query(target.substr(qmark + 1), req.query);
        } else {
            req.path = target;
        }
    }

    // Headers
    size_t content_length = 0;
    while (true) {
        std::string h = recv_line(cs, spill);
        if (h.empty()) break;
        if (h.size() >= 15) {
            // case-insensitive Content-Length match
            std::string lower; lower.reserve(h.size());
            for (char c : h) lower.push_back((char)tolower((unsigned char)c));
            if (lower.rfind("content-length:", 0) == 0) {
                content_length = (size_t)std::strtoul(lower.c_str() + 15, nullptr, 10);
            }
        }
    }

    if (content_length > 0) {
        if (!recv_n(cs, spill, content_length, req.body)) { closesocket(cs); return; }
        parse_query(req.body, req.form);
    }

    HttpResponse resp = handler ? handler(req) : HttpResponse{404, "Not Found", "text/plain", ""};

    char hdr[512];
    int hdr_len = _snprintf_s(hdr, sizeof(hdr), _TRUNCATE,
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n",
        resp.status, resp.status_text.c_str(),
        resp.content_type.c_str(),
        resp.body.size());
    if (hdr_len > 0) ::send(cs, hdr, hdr_len, 0);
    if (!resp.body.empty()) ::send(cs, resp.body.data(), (int)resp.body.size(), 0);

    shutdown(cs, SD_BOTH);
    closesocket(cs);
}

void HttpServer::run() {
    if (listen_fd_ == (uintptr_t)-1) return;
    running_ = true;
    while (running_) {
        sockaddr_in ca{}; int clen = sizeof(ca);
        SOCKET cs = accept((SOCKET)listen_fd_, (sockaddr*)&ca, &clen);
        if (cs == INVALID_SOCKET) {
            if (!running_) break;
            continue;
        }
        std::thread t(handle_client, cs, handler_);
        t.detach();
    }
}

} // namespace librespotc::zeroconf
