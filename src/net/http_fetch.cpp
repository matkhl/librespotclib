#include "http_fetch.h"

#include <windows.h>
#include <winhttp.h>

#include <cstdio>
#include <stdexcept>
#include <string>
#include <vector>

#pragma comment(lib, "winhttp.lib")

namespace librespotc::net {

namespace {
constexpr int kResolveTimeoutMs = 10000;
constexpr int kConnectTimeoutMs = 10000;
constexpr int kSendTimeoutMs = 10000;
constexpr int kReceiveTimeoutMs = 4000;

void set_request_timeouts(HINTERNET h, const char* scope) {
    if (!WinHttpSetTimeouts(h, kResolveTimeoutMs, kConnectTimeoutMs,
                            kSendTimeoutMs, kReceiveTimeoutMs)) {
        std::fprintf(stderr, "[http] %s WinHttpSetTimeouts failed err=%lu\n",
                     scope, (unsigned long)GetLastError());
    }
}

void note_stream_error(HttpStreamResult& out, const char* phase) {
    DWORD err = GetLastError();
    out.winhttp_error = static_cast<uint32_t>(err);
    out.phase = phase ? phase : "";
    out.timed_out = (err == ERROR_WINHTTP_TIMEOUT);

    char msg[160];
    _snprintf_s(msg, sizeof(msg), _TRUNCATE,
                "%s failed err=%lu%s",
                phase ? phase : "WinHTTP",
                (unsigned long)err,
                out.timed_out ? " timeout" : "");
    out.status_text = msg;

    std::fprintf(stderr,
                 "[http] stream %s bytes=%llu err=%lu%s\n",
                 phase ? phase : "WinHTTP",
                 (unsigned long long)out.bytes_read,
                 (unsigned long)err,
                 out.timed_out ? " timeout" : "");
}

} // namespace

static std::wstring to_w(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), n);
    return w;
}

HttpFetchResult https_get(const std::string& url,
                          const std::map<std::string,std::string>& headers,
                          uint64_t range_start, uint64_t range_end) {
    HttpFetchResult out;
    URL_COMPONENTSW comp{};
    comp.dwStructSize = sizeof(comp);
    wchar_t host[256] = {0}, path[2048] = {0}, extra_info[2048] = {0};
    comp.lpszHostName = host;     comp.dwHostNameLength = sizeof(host)/sizeof(wchar_t);
    comp.lpszUrlPath  = path;     comp.dwUrlPathLength  = sizeof(path)/sizeof(wchar_t);
    comp.lpszExtraInfo = extra_info; comp.dwExtraInfoLength = sizeof(extra_info)/sizeof(wchar_t);

    auto wurl = to_w(url);
    if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &comp)) {
        out.status_text = "WinHttpCrackUrl failed";
        return out;
    }

    HINTERNET hs = WinHttpOpen(L"librespotc/1.0",
                               WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hs) { out.status_text = "WinHttpOpen failed"; return out; }
    HINTERNET hc = WinHttpConnect(hs, host, comp.nPort, 0);
    if (!hc) { WinHttpCloseHandle(hs); out.status_text = "WinHttpConnect failed"; return out; }

    DWORD flags = (comp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    std::wstring req_path = std::wstring(path) + extra_info;
    HINTERNET hr = WinHttpOpenRequest(hc, L"GET", req_path.c_str(), nullptr,
                                      WINHTTP_NO_REFERER,
                                      WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hr) {
        WinHttpCloseHandle(hc); WinHttpCloseHandle(hs);
        out.status_text = "WinHttpOpenRequest failed"; return out;
    }
    set_request_timeouts(hr, "GET");

    std::wstring extra_hdrs;
    for (auto& kv : headers) {
        extra_hdrs += to_w(kv.first) + L": " + to_w(kv.second) + L"\r\n";
    }
    if (range_end >= range_start && (range_start != 0 || range_end != 0)) {
        char buf[80];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "Range: bytes=%llu-%llu\r\n",
                    (unsigned long long)range_start, (unsigned long long)range_end);
        extra_hdrs += to_w(buf);
    }

    BOOL ok = WinHttpSendRequest(hr,
                                 extra_hdrs.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : extra_hdrs.c_str(),
                                 extra_hdrs.empty() ? 0 : (DWORD)-1L,
                                 WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (ok) ok = WinHttpReceiveResponse(hr, nullptr);
    if (ok) {
        DWORD status = 0;
        DWORD sz = sizeof(status);
        WinHttpQueryHeaders(hr, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz, WINHTTP_NO_HEADER_INDEX);
        out.status = (int)status;
    }
    if (ok) {
        DWORD avail = 0;
        do {
            avail = 0;
            if (!WinHttpQueryDataAvailable(hr, &avail)) break;
            if (avail == 0) break;
            size_t old = out.body.size();
            out.body.resize(old + avail);
            DWORD read = 0;
            if (!WinHttpReadData(hr, out.body.data() + old, avail, &read)) break;
            out.body.resize(old + read);
        } while (avail > 0);
    }

    WinHttpCloseHandle(hr); WinHttpCloseHandle(hc); WinHttpCloseHandle(hs);
    if (!ok && out.status == 0) out.status_text = "WinHttp request failed";
    return out;
}

HttpStreamResult https_get_stream(const std::string& url,
                                  const std::map<std::string,std::string>& headers,
                                  ChunkSink on_chunk) {
    HttpStreamResult out;
    URL_COMPONENTSW comp{};
    comp.dwStructSize = sizeof(comp);
    wchar_t host[256] = {0}, path[2048] = {0}, extra_info[2048] = {0};
    comp.lpszHostName = host; comp.dwHostNameLength = sizeof(host)/sizeof(wchar_t);
    comp.lpszUrlPath  = path; comp.dwUrlPathLength  = sizeof(path)/sizeof(wchar_t);
    comp.lpszExtraInfo = extra_info; comp.dwExtraInfoLength = sizeof(extra_info)/sizeof(wchar_t);
    auto wurl = to_w(url);
    if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &comp)) {
        out.status_text = "WinHttpCrackUrl failed";
        return out;
    }

    HINTERNET hs = WinHttpOpen(L"librespotc/1.0",
                               WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hs) {
        out.status_text = "WinHttpOpen failed";
        return out;
    }
    HINTERNET hc = WinHttpConnect(hs, host, comp.nPort, 0);
    if (!hc) {
        WinHttpCloseHandle(hs);
        out.status_text = "WinHttpConnect failed";
        return out;
    }
    DWORD flags = (comp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    std::wstring req_path = std::wstring(path) + extra_info;
    HINTERNET hr = WinHttpOpenRequest(hc, L"GET", req_path.c_str(), nullptr, WINHTTP_NO_REFERER,
                                      WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hr) {
        WinHttpCloseHandle(hc); WinHttpCloseHandle(hs);
        out.status_text = "WinHttpOpenRequest failed";
        return out;
    }
    set_request_timeouts(hr, "stream GET");

    std::wstring extra;
    for (auto& kv : headers) extra += to_w(kv.first) + L": " + to_w(kv.second) + L"\r\n";

    BOOL ok = WinHttpSendRequest(hr,
                                 extra.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : extra.c_str(),
                                 extra.empty() ? 0 : (DWORD)-1L,
                                 WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (!ok) {
        note_stream_error(out, "WinHttpSendRequest");
    }
    if (ok) {
        ok = WinHttpReceiveResponse(hr, nullptr);
        if (!ok) note_stream_error(out, "WinHttpReceiveResponse");
    }

    if (ok) {
        DWORD status = 0;
        DWORD sz = sizeof(status);
        WinHttpQueryHeaders(hr, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz, WINHTTP_NO_HEADER_INDEX);
        out.status = (int)status;

        wchar_t len_buf[64] = {};
        DWORD len_sz = sizeof(len_buf);
        if (WinHttpQueryHeaders(hr, WINHTTP_QUERY_CONTENT_LENGTH,
                                WINHTTP_HEADER_NAME_BY_INDEX, len_buf, &len_sz,
                                WINHTTP_NO_HEADER_INDEX)) {
            wchar_t* end = nullptr;
            unsigned long long len = wcstoull(len_buf, &end, 10);
            if (end && end != len_buf) {
                out.content_length = (uint64_t)len;
                out.content_length_known = true;
            }
        }
    }

    if (ok && out.status == 200) {
        std::vector<uint8_t> buf;
        buf.resize(64 * 1024);
        DWORD avail = 0;
        do {
            avail = 0;
            if (!WinHttpQueryDataAvailable(hr, &avail)) {
                note_stream_error(out, "WinHttpQueryDataAvailable");
                break;
            }
            if (avail == 0) break;
            if (buf.size() < avail) buf.resize(avail);
            DWORD read = 0;
            if (!WinHttpReadData(hr, buf.data(), avail, &read)) {
                note_stream_error(out, "WinHttpReadData");
                break;
            }
            if (read == 0) break;
            out.bytes_read += read;
            if (on_chunk && !on_chunk(buf.data(), read)) {
                out.aborted_by_sink = true;
                break;
            }
        } while (avail > 0);
    }

    WinHttpCloseHandle(hr); WinHttpCloseHandle(hc); WinHttpCloseHandle(hs);
    if (!ok && out.status == 0 && out.status_text.empty()) {
        out.status_text = "WinHttp request failed";
    }
    if (out.status == 200 && !out.aborted_by_sink) {
        out.complete = !out.content_length_known ||
            out.bytes_read >= out.content_length;
    }
    return out;
}

HttpFetchResult https_request(const std::string& method,
                              const std::string& url,
                              const std::string& content_type,
                              const uint8_t* body, size_t body_len,
                              const std::map<std::string,std::string>& headers) {
    HttpFetchResult out;
    URL_COMPONENTSW comp{};
    comp.dwStructSize = sizeof(comp);
    wchar_t host[256] = {0}, path[2048] = {0}, extra_info[2048] = {0};
    comp.lpszHostName = host; comp.dwHostNameLength = sizeof(host)/sizeof(wchar_t);
    comp.lpszUrlPath  = path; comp.dwUrlPathLength  = sizeof(path)/sizeof(wchar_t);
    comp.lpszExtraInfo = extra_info; comp.dwExtraInfoLength = sizeof(extra_info)/sizeof(wchar_t);
    auto wurl = to_w(url);
    if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &comp)) {
        out.status_text = "WinHttpCrackUrl failed"; return out;
    }
    HINTERNET hs = WinHttpOpen(L"librespotc/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hs) { out.status_text = "WinHttpOpen failed"; return out; }
    HINTERNET hc = WinHttpConnect(hs, host, comp.nPort, 0);
    if (!hc) { WinHttpCloseHandle(hs); out.status_text = "WinHttpConnect failed"; return out; }
    DWORD flags = (comp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    auto wmethod = to_w(method);
    std::wstring req_path = std::wstring(path) + extra_info;
    HINTERNET hr = WinHttpOpenRequest(hc, wmethod.c_str(), req_path.c_str(), nullptr, WINHTTP_NO_REFERER,
                                      WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hr) { WinHttpCloseHandle(hc); WinHttpCloseHandle(hs); out.status_text = "OpenRequest failed"; return out; }
    set_request_timeouts(hr, "request");

    std::wstring extra;
    if (!content_type.empty()) extra += L"Content-Type: " + to_w(content_type) + L"\r\n";
    for (auto& kv : headers) extra += to_w(kv.first) + L": " + to_w(kv.second) + L"\r\n";

    BOOL ok = WinHttpSendRequest(hr,
                                 extra.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : extra.c_str(),
                                 extra.empty() ? 0 : (DWORD)-1L,
                                 (LPVOID)body, (DWORD)body_len, (DWORD)body_len, 0);
    if (ok) ok = WinHttpReceiveResponse(hr, nullptr);
    if (ok) {
        DWORD status = 0; DWORD sz = sizeof(status);
        WinHttpQueryHeaders(hr, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz, WINHTTP_NO_HEADER_INDEX);
        out.status = (int)status;
    }
    if (ok) {
        DWORD avail = 0;
        do {
            avail = 0;
            if (!WinHttpQueryDataAvailable(hr, &avail)) break;
            if (avail == 0) break;
            size_t old = out.body.size();
            out.body.resize(old + avail);
            DWORD read = 0;
            if (!WinHttpReadData(hr, out.body.data() + old, avail, &read)) break;
            out.body.resize(old + read);
        } while (avail > 0);
    }
    WinHttpCloseHandle(hr); WinHttpCloseHandle(hc); WinHttpCloseHandle(hs);
    if (!ok && out.status == 0) out.status_text = "WinHttp " + method + " failed";
    return out;
}

HttpFetchResult https_post(const std::string& url,
                           const std::string& content_type,
                           const uint8_t* body, size_t body_len,
                           const std::map<std::string,std::string>& headers) {
    HttpFetchResult out;
    URL_COMPONENTSW comp{};
    comp.dwStructSize = sizeof(comp);
    wchar_t host[256] = {0}, path[2048] = {0}, extra_info[2048] = {0};
    comp.lpszHostName = host; comp.dwHostNameLength = sizeof(host)/sizeof(wchar_t);
    comp.lpszUrlPath  = path; comp.dwUrlPathLength  = sizeof(path)/sizeof(wchar_t);
    comp.lpszExtraInfo = extra_info; comp.dwExtraInfoLength = sizeof(extra_info)/sizeof(wchar_t);

    auto wurl = to_w(url);
    if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &comp)) {
        out.status_text = "WinHttpCrackUrl failed"; return out;
    }
    HINTERNET hs = WinHttpOpen(L"librespotc/1.0",
                               WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hs) { out.status_text = "WinHttpOpen failed"; return out; }
    HINTERNET hc = WinHttpConnect(hs, host, comp.nPort, 0);
    if (!hc) { WinHttpCloseHandle(hs); out.status_text = "WinHttpConnect failed"; return out; }
    DWORD flags = (comp.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    std::wstring req_path = std::wstring(path) + extra_info;
    HINTERNET hr = WinHttpOpenRequest(hc, L"POST", req_path.c_str(), nullptr, WINHTTP_NO_REFERER,
                                      WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hr) { WinHttpCloseHandle(hc); WinHttpCloseHandle(hs); out.status_text = "OpenRequest failed"; return out; }
    set_request_timeouts(hr, "POST");

    std::wstring extra_hdrs = L"Content-Type: " + to_w(content_type) + L"\r\n";
    for (auto& kv : headers) {
        extra_hdrs += to_w(kv.first) + L": " + to_w(kv.second) + L"\r\n";
    }

    BOOL ok = WinHttpSendRequest(hr,
                                 extra_hdrs.c_str(), (DWORD)-1L,
                                 (LPVOID)body, (DWORD)body_len, (DWORD)body_len, 0);
    if (ok) ok = WinHttpReceiveResponse(hr, nullptr);
    if (ok) {
        DWORD status = 0; DWORD sz = sizeof(status);
        WinHttpQueryHeaders(hr, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz, WINHTTP_NO_HEADER_INDEX);
        out.status = (int)status;
    }
    if (ok) {
        DWORD avail = 0;
        do {
            avail = 0;
            if (!WinHttpQueryDataAvailable(hr, &avail)) break;
            if (avail == 0) break;
            size_t old = out.body.size();
            out.body.resize(old + avail);
            DWORD read = 0;
            if (!WinHttpReadData(hr, out.body.data() + old, avail, &read)) break;
            out.body.resize(old + read);
        } while (avail > 0);
    }
    WinHttpCloseHandle(hr); WinHttpCloseHandle(hc); WinHttpCloseHandle(hs);
    if (!ok && out.status == 0) out.status_text = "WinHttp POST failed";
    return out;
}

} // namespace librespotc::net
