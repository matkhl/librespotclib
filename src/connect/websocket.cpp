#include "websocket.h"

#include <windows.h>
#include <winhttp.h>

#include <cstdio>
#include <vector>

#pragma comment(lib, "winhttp.lib")

namespace librespotc::connect {

static std::wstring to_w(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), n);
    return w;
}

WebSocket::WebSocket() = default;
WebSocket::~WebSocket() { close(); }

bool WebSocket::connect(const std::string& url,
                        const std::map<std::string, std::string>& extra_headers) {
    // WinHttpCrackUrl doesn't accept wss:// scheme. Substitute https:// so
    // it parses; the WebSocket upgrade happens later via SetOption.
    std::string crackable = url;
    if (crackable.rfind("wss://", 0) == 0) crackable.replace(0, 6, "https://");
    else if (crackable.rfind("ws://", 0) == 0) crackable.replace(0, 5, "http://");

    URL_COMPONENTSW comp{};
    comp.dwStructSize = sizeof(comp);
    wchar_t host[256] = {0}, path[2048] = {0};
    comp.lpszHostName = host;  comp.dwHostNameLength = sizeof(host)/sizeof(wchar_t);
    comp.lpszUrlPath  = path;  comp.dwUrlPathLength  = sizeof(path)/sizeof(wchar_t);
    auto wurl = to_w(crackable);
    if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &comp)) {
        std::fprintf(stderr, "[ws] CrackUrl failed\n"); return false;
    }

    hSession_ = WinHttpOpen(L"librespotc/1.0",
                            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession_) return false;
    hConn_ = WinHttpConnect(hSession_, host, comp.nPort, 0);
    if (!hConn_) { close(); return false; }

    DWORD flags = (comp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    hRequest_ = WinHttpOpenRequest(hConn_, L"GET", path, nullptr, WINHTTP_NO_REFERER,
                                   WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest_) { close(); return false; }

    // Mark for WebSocket upgrade
    if (!WinHttpSetOption(hRequest_, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, nullptr, 0)) {
        std::fprintf(stderr, "[ws] SetOption upgrade failed\n"); close(); return false;
    }

    std::wstring hdrs;
    for (auto& kv : extra_headers) {
        hdrs += to_w(kv.first) + L": " + to_w(kv.second) + L"\r\n";
    }

    BOOL ok = WinHttpSendRequest(hRequest_,
                                 hdrs.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : hdrs.c_str(),
                                 hdrs.empty() ? 0 : (DWORD)-1L,
                                 WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (ok) ok = WinHttpReceiveResponse(hRequest_, nullptr);
    if (!ok) {
        DWORD status = 0; DWORD sz = sizeof(status);
        WinHttpQueryHeaders(hRequest_, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz, WINHTTP_NO_HEADER_INDEX);
        std::fprintf(stderr, "[ws] send/recv response failed status=%lu\n", status);
        close(); return false;
    }

    DWORD status = 0; DWORD sz = sizeof(status);
    WinHttpQueryHeaders(hRequest_, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz, WINHTTP_NO_HEADER_INDEX);
    if (status != 101) {
        std::fprintf(stderr, "[ws] non-101 upgrade status=%lu\n", status);
        close(); return false;
    }

    hWebsocket_ = WinHttpWebSocketCompleteUpgrade(hRequest_, 0);
    if (!hWebsocket_) {
        std::fprintf(stderr, "[ws] CompleteUpgrade failed\n");
        close(); return false;
    }
    // Request handle no longer needed after upgrade completes
    WinHttpCloseHandle(hRequest_);
    hRequest_ = nullptr;
    open_ = true;
    return true;
}

bool WebSocket::send_text(const std::string& text) {
    if (!hWebsocket_) return false;
    DWORD rc = WinHttpWebSocketSend(hWebsocket_,
                                    WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE,
                                    (PVOID)text.data(), (DWORD)text.size());
    if (rc != NO_ERROR) {
        std::fprintf(stderr, "[ws] send failed rc=%lu\n", rc);
        return false;
    }
    return true;
}

bool WebSocket::recv(std::string& out, bool& is_text) {
    if (!hWebsocket_) return false;
    out.clear();
    is_text = true;
    constexpr DWORD CHUNK = 16 * 1024;
    std::vector<char> buf(CHUNK);
    while (true) {
        DWORD got = 0;
        WINHTTP_WEB_SOCKET_BUFFER_TYPE type{};
        DWORD rc = WinHttpWebSocketReceive(hWebsocket_, buf.data(), CHUNK, &got, &type);
        if (rc != NO_ERROR) {
            std::fprintf(stderr, "[ws] recv failed rc=%lu\n", rc);
            return false;
        }
        if (type == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE) {
            open_ = false;
            return false;
        }
        out.append(buf.data(), got);
        if (type == WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE) {
            is_text = true; return true;
        }
        if (type == WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE) {
            is_text = false; return true;
        }
        // _FRAGMENT types: keep looping to coalesce
    }
}

void WebSocket::close() {
    if (hWebsocket_) {
        WinHttpWebSocketClose(hWebsocket_, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, nullptr, 0);
        WinHttpCloseHandle(hWebsocket_);
        hWebsocket_ = nullptr;
    }
    if (hRequest_) { WinHttpCloseHandle(hRequest_); hRequest_ = nullptr; }
    if (hConn_)    { WinHttpCloseHandle(hConn_);    hConn_    = nullptr; }
    if (hSession_) { WinHttpCloseHandle(hSession_); hSession_ = nullptr; }
    open_ = false;
}

bool WebSocket::is_open() const { return open_; }

} // namespace librespotc::connect
