#include "apresolve.h"

#include <windows.h>
#include <winhttp.h>
#include <string>
#include <vector>
#include <stdexcept>

#include "../../deps/nlohmann/json.hpp"

#pragma comment(lib, "winhttp.lib")

namespace librespotc::net {

static std::wstring to_w(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), n);
    return w;
}

static std::string https_get(const std::wstring& host, const std::wstring& path) {
    std::string out;
    HINTERNET hSession = WinHttpOpen(L"librespotc/1.0",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS,
                                     0);
    if (!hSession) throw std::runtime_error("WinHttpOpen failed");

    HINTERNET hConn = WinHttpConnect(hSession, host.c_str(),
                                     INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConn) { WinHttpCloseHandle(hSession); throw std::runtime_error("WinHttpConnect failed"); }

    HINTERNET hReq = WinHttpOpenRequest(hConn, L"GET", path.c_str(),
                                        nullptr, WINHTTP_NO_REFERER,
                                        WINHTTP_DEFAULT_ACCEPT_TYPES,
                                        WINHTTP_FLAG_SECURE);
    if (!hReq) {
        WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSession);
        throw std::runtime_error("WinHttpOpenRequest failed");
    }

    BOOL ok = WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                 WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (ok) ok = WinHttpReceiveResponse(hReq, nullptr);

    if (ok) {
        DWORD avail = 0;
        do {
            avail = 0;
            if (!WinHttpQueryDataAvailable(hReq, &avail)) break;
            if (avail == 0) break;
            std::string buf(avail, '\0');
            DWORD read = 0;
            if (!WinHttpReadData(hReq, buf.data(), avail, &read)) break;
            buf.resize(read);
            out += buf;
        } while (avail > 0);
    }

    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConn);
    WinHttpCloseHandle(hSession);
    if (!ok) throw std::runtime_error("WinHttp request failed");
    return out;
}

std::vector<ApEndpoint> resolve_accesspoints() {
    std::vector<ApEndpoint> out;
    try {
        std::string body = https_get(L"apresolve.spotify.com",
                                     L"/?type=accesspoint");
        auto j = nlohmann::json::parse(body, nullptr, false);
        if (!j.is_discarded() && j.contains("accesspoint")) {
            for (auto& item : j["accesspoint"]) {
                if (!item.is_string()) continue;
                std::string s = item.get<std::string>();
                auto pos = s.find(':');
                if (pos == std::string::npos) continue;
                ApEndpoint e;
                e.host = s.substr(0, pos);
                e.port = (uint16_t)std::stoi(s.substr(pos + 1));
                out.push_back(std::move(e));
            }
        }
    } catch (...) {
        // fall through to default
    }
    if (out.empty()) {
        out.push_back({"ap-gew4.spotify.com", 4070});
        out.push_back({"ap.spotify.com",      80});
    }
    return out;
}

} // namespace librespotc::net
