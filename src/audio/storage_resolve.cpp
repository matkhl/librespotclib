#include "storage_resolve.h"
#include "../dispatcher.h"
#include "../auth/client_token.h"
#include "../auth/login5.h"
#include "../auth/blob.h"
#include "../proto/track.h"
#include "../net/http_fetch.h"
#include "../../deps/nlohmann/json.hpp"

#include <cstdio>
#include <cstring>
#include <memory>

namespace librespotc::audio {

static std::string hex_of(const uint8_t* p, size_t n) {
    static const char* H = "0123456789abcdef";
    std::string s(n*2, '0');
    for (size_t i = 0; i < n; ++i) { s[2*i]=H[p[i]>>4]; s[2*i+1]=H[p[i]&0xf]; }
    return s;
}

// KEYMASTER client_id from librespot (default for windows + reused for client_token).
static const char* KEYMASTER_CLIENT_ID = "65b708073fc0480ea92a077233ca87bd";

// Cached providers (per-process). For a real library we'd attach these to Session.
static std::unique_ptr<auth::ClientTokenProvider> g_ct;
static std::unique_ptr<auth::Login5Provider>      g_l5;

bool make_spclient_auth_headers(std::map<std::string,std::string>& headers,
                                std::string& err,
                                bool force_refresh,
                                const std::string& bearer_override) {
    headers.clear();

    if (!bearer_override.empty()) {
        headers["Authorization"] = "Bearer " + bearer_override;
        return true;
    }

    if (!g_ct || !g_l5) {
        err = "login5 not initialized";
        return false;
    }
    if (force_refresh) {
        g_ct->invalidate();
        g_l5->invalidate();
    }

    std::string client_token = g_ct->token();
    if (client_token.empty()) {
        err = "client_token failed";
        return false;
    }
    std::string bearer = g_l5->access_token(client_token);
    if (bearer.empty()) {
        err = "login5 token failed";
        return false;
    }

    headers["Authorization"] = "Bearer " + bearer;
    headers["client-token"] = client_token;
    return true;
}

std::string storage_resolve_audio_ex(Dispatcher& /*disp*/, const uint8_t file_id[20],
                                     std::vector<std::string>& out_urls,
                                     uint32_t /*timeout_ms*/,
                                     const std::string& web_api_token) {
    out_urls.clear();

    std::string url = "https://spclient.wg.spotify.com/storage-resolve/files/audio/interactive/"
                    + hex_of(file_id, 20) + "?alt=json";

    for (int attempt = 0; attempt < 2; ++attempt) {
        std::map<std::string,std::string> hdrs;
        std::string err;
        if (!make_spclient_auth_headers(hdrs, err, attempt > 0, web_api_token)) {
            std::fprintf(stderr, "[storage_resolve] auth failed: %s\n", err.c_str());
            return "auth: " + err;
        }
        if (!web_api_token.empty() && attempt == 0) {
            std::fprintf(stderr, "[storage_resolve] using host OAuth token\n");
        }

        auto r = net::https_get(url, hdrs);
        if ((r.status == 401 || r.status == 403) && web_api_token.empty() && attempt == 0) {
            std::fprintf(stderr,
                         "[storage_resolve] auth status=%d, refreshing tokens\n",
                         r.status);
            continue;
        }
        if (r.status != 200) {
            std::string b((const char*)r.body.data(), r.body.size());
            std::fprintf(stderr, "[storage_resolve] spclient status=%d body=%s\n",
                         r.status, b.substr(0,500).c_str());
            return "spclient status=" + std::to_string(r.status);
        }
        std::string body((const char*)r.body.data(), r.body.size());
        auto j = nlohmann::json::parse(body, nullptr, false);
        if (j.is_discarded()) {
            std::fprintf(stderr, "[storage_resolve] not JSON: %s\n", body.c_str());
            return "invalid JSON";
        }
        if (j.contains("cdnurl") && j["cdnurl"].is_array()) {
            for (auto& u : j["cdnurl"]) {
                if (u.is_string()) out_urls.push_back(u.get<std::string>());
            }
        }
        if (out_urls.empty()) {
            std::fprintf(stderr, "[storage_resolve] no cdnurl in response: %s\n", body.c_str());
            return "no cdnurl";
        }
        return {};
    }
    return "auth retry exhausted";
}

bool storage_resolve_audio(Dispatcher& disp, const uint8_t file_id[20],
                           std::vector<std::string>& out_urls,
                           uint32_t timeout_ms,
                           const std::string& web_api_token) {
    return storage_resolve_audio_ex(disp, file_id, out_urls,
                                    timeout_ms, web_api_token).empty();
}

void init_login5_provider(const std::string& device_id,
                          const std::string& username,
                          const std::vector<uint8_t>& stored_blob) {
    g_ct = std::make_unique<auth::ClientTokenProvider>(KEYMASTER_CLIENT_ID, device_id);
    g_l5 = std::make_unique<auth::Login5Provider>(KEYMASTER_CLIENT_ID, device_id,
                                                  username, stored_blob);
}

auth::ClientTokenProvider* get_client_token_provider() { return g_ct.get(); }
auth::Login5Provider*      get_login5_provider()       { return g_l5.get(); }

} // namespace librespotc::audio
