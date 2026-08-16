#include "context_resolver.h"

#include "../auth/client_token.h"
#include "../auth/login5.h"
#include "../net/http_fetch.h"
#include "../../deps/nlohmann/json.hpp"

#include <cstdio>
#include <set>

namespace librespotc::connect {

bool resolve_context_tracks(const std::string& context_uri,
                             auth::ClientTokenProvider& ct,
                             auth::Login5Provider& l5,
                             const std::string& spclient_base,
                             std::vector<ProvidedTrack>& out_tracks) {
    if (context_uri.empty() || spclient_base.empty()) return false;
    std::string ctok = ct.token();
    if (ctok.empty()) return false;
    std::string bearer = l5.access_token(ctok);
    if (bearer.empty()) return false;

    std::string url = spclient_base + "/context-resolve/v1/" + context_uri;
    std::map<std::string, std::string> hdrs;
    hdrs["Authorization"] = "Bearer " + bearer;
    hdrs["client-token"]  = ctok;
    hdrs["Accept"]        = "application/json";

    auto resp = net::https_get(url, hdrs);
    if (resp.status < 200 || resp.status >= 300) {
        std::fprintf(stderr,
            "[context-resolve] %s -> status=%d body=%.300s\n",
            context_uri.c_str(), resp.status,
            (const char*)resp.body.data());
        return false;
    }

    std::string body((const char*)resp.body.data(), resp.body.size());
    auto j = nlohmann::json::parse(body, nullptr, false);
    if (j.is_discarded()) {
        std::fprintf(stderr,
            "[context-resolve] %s -> non-JSON body=%.200s\n",
            context_uri.c_str(), body.c_str());
        return false;
    }

    out_tracks.clear();

    auto extract_meta = [](const nlohmann::json& m, const char* k) -> std::string {
        if (!m.is_object()) return {};
        auto it = m.find(k);
        if (it == m.end() || !it->is_string()) return {};
        return it->get<std::string>();
    };
    auto extract_page_tracks = [&](const nlohmann::json& page) -> size_t {
        size_t added = 0;
        if (!page.is_object() || !page.contains("tracks")) return added;
        if (!page["tracks"].is_array()) return added;
        for (auto& tr : page["tracks"]) {
            if (!tr.is_object()) continue;
            ProvidedTrack pt;
            if (tr.contains("uri") && tr["uri"].is_string())
                pt.uri = tr["uri"].get<std::string>();
            if (pt.uri.rfind("spotify:track:", 0) != 0) continue;
            if (tr.contains("uid") && tr["uid"].is_string())
                pt.uid = tr["uid"].get<std::string>();
            if (pt.uid.empty()) pt.uid = ContextState::generate_uid();
            pt.provider = "context";
            if (tr.contains("metadata") && tr["metadata"].is_object()) {
                pt.album_uri  = extract_meta(tr["metadata"], "album_uri");
                pt.artist_uri = extract_meta(tr["metadata"], "artist_uri");
            }
            pt.metadata_context_uri = context_uri;
            pt.metadata_entity_uri  = context_uri;
            out_tracks.push_back(std::move(pt));
            ++added;
        }
        return added;
    };

    auto page_url_from = [](const nlohmann::json& page) -> std::string {
        if (!page.is_object()) return {};
        static constexpr const char* keys[] = {
            "page_url",
            "next_page_url",
            "nextPageUrl",
            "next"
        };
        for (const char* key : keys) {
            auto it = page.find(key);
            if (it != page.end() && it->is_string()) {
                std::string url = it->get<std::string>();
                if (!url.empty()) return url;
            }
        }
        return {};
    };

    auto next_page_url_from = [](const nlohmann::json& page) -> std::string {
        if (!page.is_object()) return {};
        static constexpr const char* keys[] = {
            "next_page_url",
            "nextPageUrl",
            "next"
        };
        for (const char* key : keys) {
            auto it = page.find(key);
            if (it != page.end() && it->is_string()) {
                std::string url = it->get<std::string>();
                if (!url.empty()) return url;
            }
        }
        return {};
    };

    auto absolute_page_url = [&](const std::string& page_url) -> std::string {
        if (page_url.empty()) return {};
        if (page_url.rfind("http", 0) == 0) return page_url;
        return spclient_base + (page_url[0] == '/' ? page_url : "/" + page_url);
    };

    auto fetch_page = [&](const std::string& page_url,
                          nlohmann::json& page_json) -> bool {
        std::string full = absolute_page_url(page_url);
        if (full.empty()) return false;
        auto sub = net::https_get(full, hdrs);
        if (sub.status < 200 || sub.status >= 300) {
            std::fprintf(stderr,
                "[context-resolve] page fetch %s status=%d (continuing)\n",
                full.c_str(), sub.status);
            return false;
        }
        std::string sbody((const char*)sub.body.data(), sub.body.size());
        page_json = nlohmann::json::parse(sbody, nullptr, false);
        return !page_json.is_discarded();
    };

    // Top-level Context: pages[] either has tracks inline or a page_url to
    // fetch the page contents. Page responses can themselves contain a
    // next_page_url; follow that chain so transferred playlists don't shrink
    // to only the first resolved page. Bound the loop to keep megaplaylists
    // sane.
    if (!j.contains("pages") || !j["pages"].is_array()) {
        std::fprintf(stderr,
            "[context-resolve] %s: no pages[] in response\n",
            context_uri.c_str());
        return false;
    }

    constexpr int MAX_PAGES = 100;
    int pages_followed = 0;
    std::set<std::string> visited_pages;
    for (auto& page : j["pages"]) {
        if (!page.is_object()) continue;
        size_t inline_added = extract_page_tracks(page);
        if (inline_added > 0) {
            std::fprintf(stderr,
                "[context-resolve] inline page added=%zu total=%zu\n",
                inline_added, out_tracks.size());
        }

        std::string purl = page_url_from(page);
        while (!purl.empty() && pages_followed < MAX_PAGES) {
            std::string full = absolute_page_url(purl);
            if (full.empty() || !visited_pages.insert(full).second) break;

            nlohmann::json pj;
            if (!fetch_page(purl, pj)) break;
            ++pages_followed;
            size_t before = out_tracks.size();
            size_t added = extract_page_tracks(pj);
            std::fprintf(stderr,
                "[context-resolve] page %d added=%zu total=%zu url=%s\n",
                pages_followed, added, out_tracks.size(), full.c_str());
            if (out_tracks.size() == before && added == 0) {
                // Keep following if the server provides another page, but
                // make the empty page visible in logs.
            }
            purl = next_page_url_from(pj);
        }
    }

    std::fprintf(stderr,
        "[context-resolve] %s -> %zu tracks (%d pages followed)\n",
        context_uri.c_str(), out_tracks.size(), pages_followed);
    return !out_tracks.empty();
}

bool resolve_autoplay_tracks(const std::string& seed_context_uri,
                              auth::ClientTokenProvider& ct,
                              auth::Login5Provider& l5,
                              const std::string& spclient_base,
                              std::vector<ProvidedTrack>& out_tracks) {
    if (seed_context_uri.empty() || spclient_base.empty()) return false;
    std::string ctok = ct.token();
    if (ctok.empty()) return false;
    std::string bearer = l5.access_token(ctok);
    if (bearer.empty()) return false;

    std::string url = spclient_base + "/context-resolve/autoplay?uri=" + seed_context_uri;
    std::map<std::string, std::string> hdrs;
    hdrs["Authorization"] = "Bearer " + bearer;
    hdrs["client-token"]  = ctok;
    hdrs["Accept"]        = "application/json";

    auto resp = net::https_get(url, hdrs);
    if (resp.status < 200 || resp.status >= 300) {
        std::fprintf(stderr,
            "[autoplay] %s -> status=%d body=%.300s\n",
            seed_context_uri.c_str(), resp.status,
            (const char*)resp.body.data());
        return false;
    }
    std::string body((const char*)resp.body.data(), resp.body.size());
    auto j = nlohmann::json::parse(body, nullptr, false);
    if (j.is_discarded()) return false;

    out_tracks.clear();
    // Autoplay response shares the Context shape: pages[].tracks[].uri
    if (!j.contains("pages") || !j["pages"].is_array()) return false;
    for (auto& page : j["pages"]) {
        if (!page.is_object() || !page.contains("tracks")) continue;
        if (!page["tracks"].is_array()) continue;
        for (auto& tr : page["tracks"]) {
            if (!tr.is_object()) continue;
            ProvidedTrack pt;
            if (tr.contains("uri") && tr["uri"].is_string())
                pt.uri = tr["uri"].get<std::string>();
            if (pt.uri.rfind("spotify:track:", 0) != 0) continue;
            if (tr.contains("uid") && tr["uid"].is_string())
                pt.uid = tr["uid"].get<std::string>();
            if (pt.uid.empty()) pt.uid = ContextState::generate_uid();
            pt.provider = "autoplay";
            // Autoplay tracks share a synthetic context URI so cloud knows
            // they're algorithmic continuation, not the user's chosen
            // context.
            pt.metadata_context_uri = seed_context_uri + ":autoplay";
            pt.metadata_entity_uri  = seed_context_uri + ":autoplay";
            out_tracks.push_back(std::move(pt));
        }
    }
    std::fprintf(stderr,
        "[autoplay] %s -> %zu tracks\n",
        seed_context_uri.c_str(), out_tracks.size());
    return !out_tracks.empty();
}

} // namespace librespotc::connect
