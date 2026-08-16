#include "spirc_device.h"
#include "websocket.h"
#include "put_state.h"
#include "context_resolver.h"

#include "../auth/client_token.h"
#include "../auth/login5.h"
#include "../crypto/base64.h"
#include "../net/apresolve.h"
#include "../net/http_fetch.h"
#include "../proto/pb_codec.h"
#include "../spotify_id.h"
#include "../../deps/nlohmann/json.hpp"

#include <cstdio>
#include <chrono>
#include <cctype>
#include <atomic>
#include <algorithm>
#include <cstring>
#include <utility>
#include <thread>
#include <vector>

namespace librespotc::connect {

struct SpircDevice::Impl {
    WebSocket ws;
};

static constexpr bool kLogSpircWindows = false;
static constexpr size_t kPlayCommandLogLimit = 1800;

SpircDevice::SpircDevice(DeviceConfig dev_cfg,
                         auth::ClientTokenProvider& ct,
                         auth::Login5Provider& l5,
                         SpircCallbacks cb)
    : dev_cfg_(std::move(dev_cfg)),
      ct_(ct), l5_(l5),
      cb_(std::move(cb)),
      impl_(std::make_unique<Impl>()) {}

SpircDevice::~SpircDevice() { stop(); }

static std::string resolve_one(const std::string& type) {
    auto eps = net::resolve_accesspoints(); // not used here, just placeholder
    (void)eps;
    // Direct resolve via apresolve JSON.
    auto r = net::https_get("https://apresolve.spotify.com/?type=" + type);
    if (r.status != 200) return {};
    std::string body((const char*)r.body.data(), r.body.size());
    auto j = nlohmann::json::parse(body, nullptr, false);
    if (j.is_discarded() || !j.contains(type) || !j[type].is_array()) return {};
    for (auto& s : j[type]) if (s.is_string()) return s.get<std::string>();
    return {};
}

bool SpircDevice::start() {
    if (running_) return true;
    std::string ct = ct_.token();
    if (ct.empty()) { std::fprintf(stderr, "[spirc] no client_token\n"); return false; }
    std::string bearer = l5_.access_token(ct);
    if (bearer.empty()) { std::fprintf(stderr, "[spirc] no login5 token\n"); return false; }

    std::string dealer_hp = resolve_one("dealer");
    std::string spclient_hp = resolve_one("spclient");
    if (dealer_hp.empty() || spclient_hp.empty()) {
        std::fprintf(stderr, "[spirc] apresolve failed: dealer='%s' spclient='%s'\n",
                     dealer_hp.c_str(), spclient_hp.c_str());
        return false;
    }
    spclient_base_ = "https://" + spclient_hp;

    std::string ws_url = "wss://" + dealer_hp + "/?access_token=" + bearer;
    std::fprintf(stderr, "[spirc] dealer URL: wss://%s/...\n", dealer_hp.c_str());
    if (!impl_->ws.connect(ws_url)) {
        std::fprintf(stderr, "[spirc] WebSocket connect failed\n");
        return false;
    }

    // First message should contain Spotify-Connection-Id header.
    std::string text; bool is_text = false;
    if (!impl_->ws.recv(text, is_text)) {
        std::fprintf(stderr, "[spirc] no initial dealer message\n");
        return false;
    }
    auto j = nlohmann::json::parse(text, nullptr, false);
    if (j.is_discarded() || !j.contains("headers")) {
        std::fprintf(stderr, "[spirc] bad initial dealer msg: %s\n",
                     text.substr(0, 200).c_str());
        return false;
    }
    if (j["headers"].contains("Spotify-Connection-Id")) {
        connection_id_ = j["headers"]["Spotify-Connection-Id"].get<std::string>();
    } else if (j["headers"].contains("spotify-connection-id")) {
        connection_id_ = j["headers"]["spotify-connection-id"].get<std::string>();
    }
    if (connection_id_.empty()) {
        std::fprintf(stderr, "[spirc] no connection_id in: %s\n",
                     text.substr(0, 300).c_str());
        return false;
    }
    std::fprintf(stderr, "[spirc] got connection_id (len=%zu)\n", connection_id_.size());

    if (!put_state((int32_t)3 /* NEW_DEVICE */, false, "", false, 0, 0)) {
        std::fprintf(stderr, "[spirc] initial PUT state failed\n");
        return false;
    }

    current_volume_.store(dev_cfg_.initial_volume);
    running_ = true;
    stop_flag_ = false;
    put_stop_ = false;
    put_thread_ = std::thread([this]{ put_state_worker_loop(); });
    thread_ = std::thread([this]{ reader_loop(); });
    return true;
}

bool SpircDevice::put_state(int32_t reason,
                            bool is_active,
                            const std::string& current_track_uri,
                            bool is_playing,
                            uint32_t position_ms,
                            uint32_t duration_ms) {
    auto put_t0 = std::chrono::steady_clock::now();
    uint32_t mid;
    {
        std::lock_guard<std::mutex> g(state_m_);
        mid = ++message_id_;
    }
    LastCommand last{};
    last.sent_by_device_id = last_sender_id_;
    last.message_id        = last_sender_msg_id_;
    const LastCommand* lp = last_sender_id_.empty() ? nullptr : &last;
    auto snap = ctx_state_.snapshot(16, 90);
    auto explicit_queue = explicit_queue_snapshot();
    if (!current_track_uri.empty() && snap.has_tracks
        && snap.current.uri != current_track_uri) {
        snap.current.uri = current_track_uri;
        snap.current.uid = ContextState::generate_uid();
        snap.current.provider = "queue";
        snap.current.metadata_context_uri = ctx_uri_.empty()
            ? current_track_uri : ctx_uri_;
        snap.current.metadata_entity_uri = snap.current.metadata_context_uri;
    }
    if (!explicit_queue.empty()) {
        std::vector<ProvidedTrack> merged;
        merged.reserve(explicit_queue.size() + snap.next_tracks.size());
        for (const auto& queued : explicit_queue) {
            if (queued.uri.empty() || queued.uri == current_track_uri) continue;
            bool exists = false;
            for (const auto& t : merged) {
                if (t.uri == queued.uri) { exists = true; break; }
            }
            if (!exists) merged.push_back(queued);
        }
        for (const auto& t : snap.next_tracks) {
            if (t.uri.empty() || t.uri == current_track_uri) continue;
            bool exists = false;
            for (const auto& q : merged) {
                if (q.uri == t.uri) { exists = true; break; }
            }
            if (!exists) merged.push_back(t);
        }
        if (merged.size() != snap.next_tracks.size()) {
            snap.next_tracks = std::move(merged);
            snap.queue_revision =
                ContextState::compute_queue_revision(snap.next_tracks);
            std::fprintf(stderr,
                "[connect-queue] advertising explicit=%zu next_total=%zu current=%s\n",
                explicit_queue.size(), snap.next_tracks.size(),
                current_track_uri.c_str());
        }
    }
    auto body = encode_put_state(dev_cfg_, is_active, reason, mid,
                                 current_track_uri, is_playing, position_ms,
                                 duration_ms, lp,
                                 ctx_uri_, ctx_url_, &snap,
                                 current_volume_.load());

    std::string url = spclient_base_ + "/connect-state/v1/devices/" + dev_cfg_.device_id;
    std::map<std::string, std::string> hdrs;
    std::string ct = ct_.token();
    std::string bearer = l5_.access_token(ct);
    hdrs["Authorization"] = "Bearer " + bearer;
    hdrs["client-token"] = ct;
    hdrs["X-Spotify-Connection-Id"] = connection_id_;
    hdrs["Accept"] = "application/protobuf";

    // PUT via WinHTTP — extend http_fetch to support PUT.
    // For v1, do via raw POST then route as PUT.
    // (We'll add https_put helper if not present; for now use https_post tricked
    //  — but spclient strictly requires PUT method, so we need PUT.)
    auto resp = net::https_request("PUT", url, "application/x-protobuf",
                                   body.data(), body.size(), hdrs);
    if (resp.status < 200 || resp.status >= 300) {
        std::string b((const char*)resp.body.data(), resp.body.size());
        auto put_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - put_t0).count();
        std::fprintf(stderr, "[spirc] PUT state status=%d ms=%lld body=%.300s\n",
                     resp.status, (long long)put_ms, b.c_str());
        return false;
    }
    // Log response body length so we know cloud accepted (cluster typically
    // echoes back).
    std::fprintf(stderr,
        "[spirc] PUT state ok active=%d reason=%d current=%s playing=%d "
        "pos=%u dur=%u volume=%u ctx=%s next=%zu prev=%zu resp=%zu B "
        "ms=%lld\n",
        (int)is_active, (int)reason, current_track_uri.c_str(),
        (int)is_playing, position_ms, duration_ms,
        (unsigned)current_volume_.load(),
        ctx_uri_.empty() ? snap.context_uri.c_str() : ctx_uri_.c_str(),
        snap.next_tracks.size(), snap.prev_tracks.size(), resp.body.size(),
        (long long)std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - put_t0).count());
    return true;
}

void SpircDevice::queue_put_state(int32_t reason,
                                  bool is_active,
                                  std::string current_track_uri,
                                  bool is_playing,
                                  uint32_t position_ms,
                                  uint32_t duration_ms) {
    PendingPutState pending;
    pending.reason = reason;
    pending.is_active = is_active;
    pending.current_track_uri = std::move(current_track_uri);
    pending.is_playing = is_playing;
    pending.position_ms = position_ms;
    pending.duration_ms = duration_ms;
    pending.queued_at = std::chrono::steady_clock::now();
    {
        std::lock_guard<std::mutex> g(put_m_);
        put_queue_.push_back(std::move(pending));
        constexpr size_t kMaxPendingPuts = 8;
        while (put_queue_.size() > kMaxPendingPuts) {
            std::fprintf(stderr,
                "[spirc] async PUT queue dropping stale state update\n");
            put_queue_.pop_front();
        }
    }
    put_cv_.notify_one();
}

void SpircDevice::put_state_worker_loop() {
    for (;;) {
        PendingPutState pending;
        {
            std::unique_lock<std::mutex> lock(put_m_);
            put_cv_.wait(lock, [this]{
                return put_stop_.load() || !put_queue_.empty();
            });
            if (put_stop_.load()) break;
            pending = std::move(put_queue_.front());
            put_queue_.pop_front();
        }
        auto queued_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - pending.queued_at).count();
        if (queued_ms > 1000) {
            std::fprintf(stderr,
                "[spirc] async PUT state starting after queue_delay=%lldms "
                "current=%s\n",
                (long long)queued_ms, pending.current_track_uri.c_str());
        }
        put_state(pending.reason, pending.is_active,
                  pending.current_track_uri, pending.is_playing,
                  pending.position_ms, pending.duration_ms);
    }
    std::fprintf(stderr, "[spirc] async PUT worker exited\n");
}

void SpircDevice::notify_state(bool is_active,
                               const std::string& current_track_uri,
                               bool is_playing,
                               uint32_t position_ms,
                               uint32_t duration_ms,
                               const std::string& context_uri,
                               const std::string& context_url) {
    // Stash the most recent context so subsequent ack-PUTs (from request
    // handlers) keep the same context_uri until the host explicitly clears
    // it. Cloud needs to see a stable context_uri to keep its queue tied
    // to us.
    if (!context_uri.empty()) ctx_uri_ = context_uri;
    if (!context_url.empty()) ctx_url_ = context_url;
    remember_playback_state(current_track_uri, is_playing,
                            position_ms, duration_ms);
    queue_put_state(4 /* PLAYER_STATE_CHANGED */, is_active,
                    current_track_uri, is_playing, position_ms, duration_ms);
}

void SpircDevice::remember_playback_state(
        const std::string& current_track_uri,
        bool is_playing,
        uint32_t position_ms,
        uint32_t duration_ms) {
    std::lock_guard<std::mutex> g(playback_state_m_);
    last_playback_track_uri_ = current_track_uri;
    last_playback_is_playing_ = is_playing;
    last_playback_position_ms_ = position_ms;
    last_playback_duration_ms_ = duration_ms;
    last_playback_clock_ = std::chrono::steady_clock::now();
}

uint32_t SpircDevice::estimated_playback_position_ms(
        const std::string& current_track_uri) const {
    std::lock_guard<std::mutex> g(playback_state_m_);
    if (current_track_uri.empty()
        || current_track_uri != last_playback_track_uri_) {
        return 0;
    }
    uint64_t pos = last_playback_position_ms_;
    if (last_playback_is_playing_) {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - last_playback_clock_).count();
        if (elapsed > 0) pos += (uint64_t)elapsed;
    }
    if (last_playback_duration_ms_ > 0 && pos > last_playback_duration_ms_) {
        pos = last_playback_duration_ms_;
    }
    return (uint32_t)pos;
}

uint32_t SpircDevice::remembered_playback_duration_ms(
        const std::string& current_track_uri) const {
    std::lock_guard<std::mutex> g(playback_state_m_);
    if (current_track_uri.empty()
        || current_track_uri != last_playback_track_uri_) {
        return 0;
    }
    return last_playback_duration_ms_;
}

bool SpircDevice::remembered_playback_is_playing(
        const std::string& current_track_uri,
        bool fallback) const {
    std::lock_guard<std::mutex> g(playback_state_m_);
    if (current_track_uri.empty()
        || current_track_uri != last_playback_track_uri_) {
        return fallback;
    }
    return last_playback_is_playing_;
}

void SpircDevice::clear_context() {
    context_generation_.fetch_add(1, std::memory_order_acq_rel);
    resolver_generation_.store(0, std::memory_order_release);
    resolver_in_flight_.store(false, std::memory_order_release);
    pending_skip_dir_.store(0, std::memory_order_release);
    autoplay_in_flight_.store(false, std::memory_order_release);
    ctx_uri_.clear();
    ctx_url_.clear();
    resolved_ctx_uri_.clear();
    ctx_state_.clear();
    {
        std::lock_guard<std::mutex> g(cloud_queue_m_);
        explicit_queue_tracks_.clear();
    }
}

SpircDevice::ContextSeed SpircDevice::context_seed() const {
    ContextSeed seed;
    auto snap = ctx_state_.snapshot();
    seed.context_uri = ctx_uri_.empty() ? snap.context_uri : ctx_uri_;
    seed.context_url = ctx_url_.empty() ? snap.context_url : ctx_url_;
    seed.current_track_uri = snap.has_tracks ? snap.current.uri : std::string{};
    seed.play_origin = snap.play_origin;
    seed.options = snap.options;
    seed.has_context = !seed.context_uri.empty();
    return seed;
}

void SpircDevice::restore_context(const ContextSeed& seed) {
    if (!seed.has_context || seed.context_uri.empty()) return;

    ctx_uri_ = seed.context_uri;
    ctx_url_ = seed.context_url.empty() ? seed.context_uri : seed.context_url;
    ctx_state_.set_context(ctx_uri_, ctx_url_);
    ctx_state_.set_play_origin(seed.play_origin);
    ctx_state_.set_options(seed.options);

    SkipToHint h;
    h.track_uri = seed.current_track_uri;
    h.already_dispatched = true;
    std::fprintf(stderr,
        "[spirc] restoring context after reconnect ctx=%s current=%s\n",
        ctx_uri_.c_str(), seed.current_track_uri.c_str());
    kick_context_resolver(ctx_uri_, h);
}

// Extract active_device_id from a serialized ClusterUpdate protobuf.
// Cluster update wire shape:
//   ClusterUpdate { Cluster cluster = 1; ... }
//   Cluster       { ... string active_device_id = 2; ... }
// (The library originally tried to read field 2 of the outer message
// directly — that picked up ClusterUpdate.update_reason, which is a
// varint, and bailed.)
static std::string cluster_active_device_id(const uint8_t* data, size_t len) {
    try {
        proto::Reader outer(data, len);
        while (!outer.at_end()) {
            uint32_t f, wt;
            if (!outer.read_tag(f, wt)) break;
            if (f == 1 && wt == proto::WIRE_LEN) {
                auto inner = outer.read_len_delim();
                while (!inner.at_end()) {
                    uint32_t cf, cwt;
                    if (!inner.read_tag(cf, cwt)) break;
                    if (cf == 2 && cwt == proto::WIRE_LEN) return inner.read_string();
                    inner.skip_field(cwt);
                }
            } else {
                outer.skip_field(wt);
            }
        }
    } catch (...) {}
    return {};
}

static bool is_mostly_printable(const std::vector<uint8_t>& bytes) {
    if (bytes.empty()) return false;
    size_t printable = 0;
    for (uint8_t b : bytes) {
        if (b == '\n' || b == '\r' || b == '\t'
            || (b >= 0x20 && b <= 0x7e)) {
            ++printable;
        }
    }
    return printable * 100 / bytes.size() >= 90;
}

static std::string sanitize_proto_string(const std::vector<uint8_t>& bytes) {
    std::string out;
    out.reserve(bytes.size());
    for (uint8_t b : bytes) {
        if (b == '\n') out += "\\n";
        else if (b == '\r') out += "\\r";
        else if (b == '\t') out += "\\t";
        else if (b >= 0x20 && b <= 0x7e) out.push_back((char)b);
        else out.push_back('?');
        if (out.size() >= 220) {
            out += "...";
            break;
        }
    }
    return out;
}

static void append_unique_limited(std::vector<std::string>& out,
                                  std::string value,
                                  size_t limit) {
    if (value.empty() || out.size() >= limit) return;
    for (const auto& existing : out) {
        if (existing == value) return;
    }
    out.push_back(std::move(value));
}

static bool is_base62_char(uint8_t b) {
    return std::isalnum(b) != 0;
}

static void append_unique(std::vector<std::string>& out,
                          std::string value) {
    if (value.empty()) return;
    for (const auto& existing : out) {
        if (existing == value) return;
    }
    out.push_back(std::move(value));
}

static std::string first_exact_spotify_uri(const uint8_t* data,
                                           size_t len,
                                           const char* prefix) {
    size_t prefix_len = std::strlen(prefix);
    constexpr size_t id_len = 22;
    for (size_t i = 0; i + prefix_len + id_len <= len; ++i) {
        if (std::memcmp(data + i, prefix, prefix_len) != 0) continue;
        bool id_ok = true;
        for (size_t j = 0; j < id_len; ++j) {
            if (!is_base62_char(data[i + prefix_len + j])) {
                id_ok = false;
                break;
            }
        }
        if (!id_ok) continue;
        return std::string((const char*)data + i, prefix_len + id_len);
    }
    return {};
}

static void extract_exact_track_uris(const uint8_t* data,
                                     size_t len,
                                     std::vector<std::string>& out,
                                     size_t limit) {
    static const char track_prefix[] = "spotify:track:";
    constexpr size_t prefix_len = sizeof(track_prefix) - 1;
    constexpr size_t id_len = 22;
    for (size_t i = 0; i + prefix_len + id_len <= len; ++i) {
        if (std::memcmp(data + i, track_prefix, prefix_len) != 0) continue;
        bool id_ok = true;
        for (size_t j = 0; j < id_len; ++j) {
            if (!is_base62_char(data[i + prefix_len + j])) {
                id_ok = false;
                break;
            }
        }
        if (!id_ok) continue;
        append_unique(out, std::string((const char*)data + i,
                                       prefix_len + id_len));
        if (out.size() >= limit) return;
        i += prefix_len + id_len - 1;
    }
}

static void extract_exact_spotify_uris(const uint8_t* data,
                                       size_t len,
                                       const char* prefix,
                                       std::vector<std::string>& out,
                                       size_t limit) {
    size_t prefix_len = std::strlen(prefix);
    constexpr size_t id_len = 22;
    for (size_t i = 0; i + prefix_len + id_len <= len; ++i) {
        if (std::memcmp(data + i, prefix, prefix_len) != 0) continue;
        bool id_ok = true;
        for (size_t j = 0; j < id_len; ++j) {
            if (!is_base62_char(data[i + prefix_len + j])) {
                id_ok = false;
                break;
            }
        }
        if (!id_ok) continue;
        append_unique_limited(
            out,
            std::string((const char*)data + i, prefix_len + id_len),
            limit);
        if (out.size() >= limit) return;
        i += prefix_len + id_len - 1;
    }
}

static bool looks_like_proto_message(const std::vector<uint8_t>& bytes) {
    if (bytes.size() < 2) return false;
    try {
        proto::Reader r(bytes.data(), bytes.size());
        int fields = 0;
        while (!r.at_end() && fields < 64) {
            uint32_t f = 0;
            uint32_t wt = 0;
            if (!r.read_tag(f, wt) || f == 0) return false;
            if (wt != proto::WIRE_VARINT && wt != proto::WIRE_64BIT
                && wt != proto::WIRE_LEN && wt != proto::WIRE_32BIT) {
                return false;
            }
            r.skip_field(wt);
            ++fields;
        }
        return r.at_end() && fields >= 2;
    } catch (...) {
        return false;
    }
}

static bool looks_like_liked_songs_context(const std::string& uri) {
    if (uri.rfind("spotify:collection", 0) == 0) return true;
    if (uri.find(":collection") != std::string::npos) return true;
    if (uri.find("liked") != std::string::npos) return true;
    return false;
}

void SpircDevice::remember_cloud_queue_hint(const uint8_t* data,
                                            size_t len,
                                            const std::string& active_device_id) {
    if (active_device_id == dev_cfg_.device_id) return;

    std::string playlist_uri =
        first_exact_spotify_uri(data, len, "spotify:playlist:");
    if (playlist_uri.empty()) return;

    std::vector<std::string> tracks;
    tracks.reserve(96);
    extract_exact_track_uris(data, len, tracks, 96);
    if (tracks.size() < 3) return;

    CloudQueueHint hint;
    hint.context_uri = playlist_uri;
    hint.current_track_uri = tracks.front();
    hint.track_uris = std::move(tracks);
    {
        std::lock_guard<std::mutex> g(cloud_queue_m_);
        hint.generation = ++cloud_queue_generation_;
        cloud_queue_hint_ = std::move(hint);
        std::fprintf(stderr,
            "[cloud-queue] cached gen=%llu ctx=%s current=%s tracks=%zu "
            "active=%s\n",
            (unsigned long long)cloud_queue_hint_.generation,
            cloud_queue_hint_.context_uri.c_str(),
            cloud_queue_hint_.current_track_uri.c_str(),
            cloud_queue_hint_.track_uris.size(),
            active_device_id.empty() ? "<empty>" : active_device_id.c_str());
    }
}

std::vector<std::string> SpircDevice::matching_cloud_queue_hint(
        const std::string& context_uri,
        const std::string& current_track_uri) const {
    std::lock_guard<std::mutex> g(cloud_queue_m_);
    if (context_uri.empty() || current_track_uri.empty()) return {};
    if (cloud_queue_hint_.current_track_uri != current_track_uri) return {};
    if (cloud_queue_hint_.context_uri != context_uri) {
        // Liked Songs is advertised by commercial devices as
        // spotify:user:<user>:collection, but the cluster's queue/order hints
        // still carry Spotify's generated playlist URI for the same list.
        // Use the current-track match to bridge that identity split.
        if (!looks_like_liked_songs_context(context_uri)
            || cloud_queue_hint_.context_uri.rfind("spotify:playlist:", 0) != 0) {
            return {};
        }
    }
    return cloud_queue_hint_.track_uris;
}

static std::string spotify_track_uri_from_gid(const std::vector<uint8_t>& gid) {
    if (gid.size() != 16) return {};
    SpotifyId id;
    if (!SpotifyId::from_raw_bytes(gid.data(), gid.size(), id)) return {};
    return "spotify:track:" + id.to_base62();
}

static bool parse_metadata_pair(const std::vector<uint8_t>& bytes,
                                std::string& key,
                                std::string& value) {
    try {
        proto::Reader r(bytes.data(), bytes.size());
        while (!r.at_end()) {
            uint32_t f = 0;
            uint32_t wt = 0;
            if (!r.read_tag(f, wt)) break;
            if (wt == proto::WIRE_LEN && f == 1) key = r.read_string();
            else if (wt == proto::WIRE_LEN && f == 2) value = r.read_string();
            else r.skip_field(wt);
        }
    } catch (...) {
        return false;
    }
    return !key.empty();
}

static void append_unique_track(std::vector<ProvidedTrack>& out,
                                ProvidedTrack track) {
    if (track.uri.rfind("spotify:track:", 0) != 0) return;
    for (const auto& existing : out) {
        if (existing.uri == track.uri) return;
    }
    if (track.uid.empty()) track.uid = ContextState::generate_uid();
    track.provider = "queue";
    if (track.metadata_context_uri.empty())
        track.metadata_context_uri = track.uri;
    if (track.metadata_entity_uri.empty())
        track.metadata_entity_uri = track.metadata_context_uri;
    out.push_back(std::move(track));
}

static ProvidedTrack make_queue_track(const std::string& uri,
                                      const std::string& uid) {
    ProvidedTrack track;
    track.uri = uri;
    track.uid = uid.empty() ? ContextState::generate_uid() : uid;
    track.provider = "queue";
    track.metadata_context_uri = uri;
    track.metadata_entity_uri = uri;
    return track;
}

static void collect_explicit_queue_tracks(const uint8_t* data,
                                          size_t len,
                                          int depth,
                                          std::vector<ProvidedTrack>& out) {
    if (depth > 7 || len < 2 || out.size() >= 32) return;

    std::vector<std::vector<uint8_t>> children;
    children.reserve(16);
    ProvidedTrack candidate;
    std::vector<uint8_t> gid;
    bool is_queued = false;

    try {
        proto::Reader r(data, len);
        while (!r.at_end()) {
            uint32_t f = 0;
            uint32_t wt = 0;
            if (!r.read_tag(f, wt) || f == 0) break;
            if (wt == proto::WIRE_LEN) {
                auto bytes = r.read_bytes();
                if (f == 1 && is_mostly_printable(bytes)) {
                    std::string s((const char*)bytes.data(), bytes.size());
                    if (s.rfind("spotify:track:", 0) == 0) {
                        candidate.uri = std::move(s);
                    }
                } else if (f == 2 && is_mostly_printable(bytes)) {
                    candidate.uid.assign((const char*)bytes.data(),
                                         bytes.size());
                } else if (f == 3 && bytes.size() == 16) {
                    gid = bytes;
                } else if (f == 4) {
                    std::string key;
                    std::string value;
                    if (parse_metadata_pair(bytes, key, value)) {
                        if (key == "is_queued" && value == "true")
                            is_queued = true;
                        else if (key == "context_uri")
                            candidate.metadata_context_uri = value;
                        else if (key == "entity_uri")
                            candidate.metadata_entity_uri = value;
                    }
                }

                if (bytes.size() >= 2 && bytes.size() <= 65536
                    && looks_like_proto_message(bytes)) {
                    children.push_back(std::move(bytes));
                }
            } else {
                r.skip_field(wt);
            }
        }
    } catch (...) {
        return;
    }

    if (candidate.uri.empty()) candidate.uri = spotify_track_uri_from_gid(gid);
    if (is_queued) append_unique_track(out, std::move(candidate));

    for (const auto& child : children) {
        if (out.size() >= 32) break;
        collect_explicit_queue_tracks(child.data(), child.size(),
                                      depth + 1, out);
    }
}

static void collect_proto_track_uris(const uint8_t* data,
                                     size_t len,
                                     int depth,
                                     std::vector<std::string>& out) {
    if (depth > 7 || len < 2 || out.size() >= 16) return;
    std::vector<std::vector<uint8_t>> children;
    children.reserve(16);
    try {
        proto::Reader r(data, len);
        while (!r.at_end()) {
            uint32_t f = 0;
            uint32_t wt = 0;
            if (!r.read_tag(f, wt) || f == 0) break;
            if (wt == proto::WIRE_LEN) {
                auto bytes = r.read_bytes();
                if (is_mostly_printable(bytes)) {
                    std::string s((const char*)bytes.data(), bytes.size());
                    if (s.rfind("spotify:track:", 0) == 0)
                        append_unique(out, std::move(s));
                }
                if (f == 3 && bytes.size() == 16) {
                    auto uri = spotify_track_uri_from_gid(bytes);
                    if (!uri.empty()) append_unique(out, std::move(uri));
                }
                if (bytes.size() >= 2 && bytes.size() <= 65536
                    && looks_like_proto_message(bytes)) {
                    children.push_back(std::move(bytes));
                }
            } else {
                r.skip_field(wt);
            }
        }
    } catch (...) {
        return;
    }
    for (const auto& child : children) {
        if (out.size() >= 16) break;
        collect_proto_track_uris(child.data(), child.size(),
                                 depth + 1, out);
    }
}

static void collect_json_track_uris(const nlohmann::json& value,
                                    std::vector<std::string>& out) {
    if (out.size() >= 16) return;
    if (value.is_string()) {
        std::string s = value.get<std::string>();
        if (s.rfind("spotify:track:", 0) == 0) {
            append_unique(out, std::move(s));
            return;
        }
        if (s.size() >= 8) {
            auto raw = crypto::b64_decode(s);
            if (!raw.empty()) {
                extract_exact_track_uris(raw.data(), raw.size(), out, 16);
                collect_proto_track_uris(raw.data(), raw.size(), 0, out);
            }
        }
        return;
    }
    if (value.is_object()) {
        for (auto it = value.begin(); it != value.end(); ++it) {
            collect_json_track_uris(it.value(), out);
            if (out.size() >= 16) return;
        }
        return;
    }
    if (value.is_array()) {
        for (const auto& item : value) {
            collect_json_track_uris(item, out);
            if (out.size() >= 16) return;
        }
    }
}

static void collect_json_context_uris(const nlohmann::json& value,
                                      std::vector<std::string>& out,
                                      size_t limit = 8) {
    if (out.size() >= limit) return;
    auto collect_string = [&](const std::string& s) {
        static constexpr const char* prefixes[] = {
            "spotify:playlist:",
            "spotify:album:"
        };
        for (const char* prefix : prefixes) {
            if (s.rfind(prefix, 0) == 0) {
                append_unique_limited(out, s, limit);
                return;
            }
        }
        if (s.size() >= 8) {
            auto raw = crypto::b64_decode(s);
            if (!raw.empty()) {
                for (const char* prefix : prefixes) {
                    extract_exact_spotify_uris(raw.data(), raw.size(),
                                               prefix, out, limit);
                    if (out.size() >= limit) return;
                }
            }
        }
    };

    if (value.is_string()) {
        collect_string(value.get<std::string>());
        return;
    }
    if (value.is_object()) {
        for (auto it = value.begin(); it != value.end(); ++it) {
            collect_json_context_uris(it.value(), out, limit);
            if (out.size() >= limit) return;
        }
        return;
    }
    if (value.is_array()) {
        for (const auto& item : value) {
            collect_json_context_uris(item, out, limit);
            if (out.size() >= limit) return;
        }
    }
}

static std::string json_string_value(const nlohmann::json& obj,
                                     const char* key) {
    if (!obj.is_object()) return {};
    auto it = obj.find(key);
    if (it == obj.end() || !it->is_string()) return {};
    return it->get<std::string>();
}

static bool json_truthy(const nlohmann::json& obj, const char* key) {
    if (!obj.is_object()) return false;
    auto it = obj.find(key);
    if (it == obj.end()) return false;
    if (it->is_boolean()) return it->get<bool>();
    if (it->is_string()) {
        std::string s = it->get<std::string>();
        return s == "true" || s == "1";
    }
    return false;
}

static bool parse_set_queue_track(const nlohmann::json& item,
                                  ProvidedTrack& out) {
    if (!item.is_object()) return false;
    std::string uri = json_string_value(item, "uri");
    if (uri.rfind("spotify:track:", 0) != 0) return false;

    std::string provider = json_string_value(item, "provider");
    const nlohmann::json& meta = item.contains("metadata")
        ? item["metadata"] : nlohmann::json::object();
    bool is_queued = json_truthy(meta, "is_queued");
    if (provider != "queue" && !is_queued) return false;

    out.uri = std::move(uri);
    out.uid = json_string_value(item, "uid");
    if (out.uid.empty()) out.uid = ContextState::generate_uid();
    out.provider = "queue";
    out.album_uri = json_string_value(meta, "album_uri");
    out.artist_uri = json_string_value(meta, "artist_uri");
    out.metadata_context_uri = json_string_value(meta, "context_uri");
    out.metadata_entity_uri = json_string_value(meta, "entity_uri");
    if (out.metadata_context_uri.empty()) out.metadata_context_uri = out.uri;
    if (out.metadata_entity_uri.empty()) out.metadata_entity_uri = out.metadata_context_uri;
    return true;
}

static std::vector<ProvidedTrack> collect_set_queue_tracks(
        const nlohmann::json& cmd,
        size_t* next_track_count = nullptr) {
    std::vector<ProvidedTrack> out;
    auto it = cmd.find("next_tracks");
    if (it == cmd.end() || !it->is_array()) {
        if (next_track_count) *next_track_count = 0;
        return out;
    }
    if (next_track_count) *next_track_count = it->size();
    for (const auto& item : *it) {
        ProvidedTrack track;
        if (!parse_set_queue_track(item, track)) continue;
        bool exists = false;
        for (const auto& existing : out) {
            if (existing.uri == track.uri) {
                exists = true;
                break;
            }
        }
        if (!exists) out.push_back(std::move(track));
    }
    return out;
}

bool SpircDevice::remember_explicit_queue(const uint8_t* data,
                                          size_t len,
                                          const std::string& active_device_id) {
    std::vector<ProvidedTrack> queued;
    collect_explicit_queue_tracks(data, len, 0, queued);
    if (queued.empty()) return false;

    bool changed = false;
    {
        std::lock_guard<std::mutex> g(cloud_queue_m_);
        if (queued.size() != explicit_queue_tracks_.size()) {
            changed = true;
        } else {
            for (size_t i = 0; i < queued.size(); ++i) {
                if (queued[i].uri != explicit_queue_tracks_[i].uri) {
                    changed = true;
                    break;
                }
            }
        }
    }
    if (!changed) return false;

    std::fprintf(stderr,
        "[connect-queue] cached explicit=%zu active=%s\n",
        queued.size(),
        active_device_id.empty() ? "<empty>" : active_device_id.c_str());
    size_t n = std::min<size_t>(queued.size(), 6);
    for (size_t i = 0; i < n; ++i) {
        std::fprintf(stderr,
            "[connect-queue] explicit[%zu]=%s uid=%s\n",
            i, queued[i].uri.c_str(), queued[i].uid.c_str());
    }

    {
        std::lock_guard<std::mutex> g(cloud_queue_m_);
        explicit_queue_tracks_.clear();
        for (auto& t : queued) {
            explicit_queue_tracks_.push_back(std::move(t));
        }
    }
    return true;
}

std::vector<ProvidedTrack> SpircDevice::explicit_queue_snapshot() const {
    std::lock_guard<std::mutex> g(cloud_queue_m_);
    return std::vector<ProvidedTrack>(explicit_queue_tracks_.begin(),
                                      explicit_queue_tracks_.end());
}

std::string SpircDevice::pop_explicit_queue_track() {
    std::lock_guard<std::mutex> g(cloud_queue_m_);
    if (explicit_queue_tracks_.empty()) return {};
    std::string uri = explicit_queue_tracks_.front().uri;
    explicit_queue_tracks_.pop_front();
    std::fprintf(stderr,
        "[connect-queue] popped explicit uri=%s remaining=%zu\n",
        uri.c_str(), explicit_queue_tracks_.size());
    return uri;
}

bool SpircDevice::replace_explicit_queue_tracks(
        std::vector<ProvidedTrack> tracks,
        const char* source) {
    for (auto& track : tracks) {
        if (track.uid.empty()) track.uid = ContextState::generate_uid();
        track.provider = "queue";
        if (track.metadata_context_uri.empty())
            track.metadata_context_uri = track.uri;
        if (track.metadata_entity_uri.empty())
            track.metadata_entity_uri = track.metadata_context_uri;
    }

    bool changed = false;
    {
        std::lock_guard<std::mutex> g(cloud_queue_m_);
        if (tracks.size() != explicit_queue_tracks_.size()) {
            changed = true;
        } else {
            for (size_t i = 0; i < tracks.size(); ++i) {
                if (tracks[i].uri != explicit_queue_tracks_[i].uri) {
                    changed = true;
                    break;
                }
            }
        }
        if (changed) {
            explicit_queue_tracks_.clear();
            for (auto& track : tracks) {
                explicit_queue_tracks_.push_back(std::move(track));
            }
        }
    }

    std::fprintf(stderr,
        "[connect-queue] %s replace explicit=%zu changed=%d\n",
        source ? source : "replace",
        explicit_queue_snapshot().size(), (int)changed);
    auto snap = explicit_queue_snapshot();
    size_t n = std::min<size_t>(snap.size(), 6);
    for (size_t i = 0; i < n; ++i) {
        std::fprintf(stderr,
            "[connect-queue] %s explicit[%zu]=%s uid=%s\n",
            source ? source : "replace", i,
            snap[i].uri.c_str(), snap[i].uid.c_str());
    }
    return changed;
}

bool SpircDevice::add_explicit_queue_track(const std::string& track_uri,
                                           const std::string& uid,
                                           const char* source) {
    if (track_uri.rfind("spotify:track:", 0) != 0) return false;
    ProvidedTrack track = make_queue_track(track_uri, uid);
    {
        std::lock_guard<std::mutex> g(cloud_queue_m_);
        for (const auto& existing : explicit_queue_tracks_) {
            if (existing.uri == track.uri) {
                std::fprintf(stderr,
                    "[connect-queue] %s duplicate explicit uri=%s\n",
                    source ? source : "add", track.uri.c_str());
                return false;
            }
        }
        explicit_queue_tracks_.push_back(track);
    }
    std::fprintf(stderr,
        "[connect-queue] %s added explicit uri=%s uid=%s\n",
        source ? source : "add", track.uri.c_str(), track.uid.c_str());
    return true;
}

void SpircDevice::add_explicit_queue_context_async(std::string context_uri,
                                                   std::string current_track_uri,
                                                   const char* source) {
    if (context_uri.rfind("spotify:playlist:", 0) != 0
        && context_uri.rfind("spotify:album:", 0) != 0) {
        return;
    }
    std::string source_label = source ? source : "set_queue_context";
    std::fprintf(stderr,
        "[connect-queue] %s resolving context uri=%s\n",
        source_label.c_str(), context_uri.c_str());
    std::thread([this,
                 context_uri = std::move(context_uri),
                 current_track_uri = std::move(current_track_uri),
                 source_label = std::move(source_label)] {
        std::vector<ProvidedTrack> tracks;
        if (!resolve_context_tracks(context_uri, ct_, l5_,
                                    spclient_base_, tracks)) {
            std::fprintf(stderr,
                "[connect-queue] %s resolve failed uri=%s\n",
                source_label.c_str(), context_uri.c_str());
            return;
        }

        size_t added = 0;
        {
            std::lock_guard<std::mutex> g(cloud_queue_m_);
            for (auto& track : tracks) {
                if (track.uri.empty() || track.uri == current_track_uri) {
                    continue;
                }
                bool exists = false;
                for (const auto& existing : explicit_queue_tracks_) {
                    if (existing.uri == track.uri) {
                        exists = true;
                        break;
                    }
                }
                if (exists) continue;
                track.provider = "queue";
                if (track.uid.empty()) track.uid = ContextState::generate_uid();
                if (track.metadata_context_uri.empty())
                    track.metadata_context_uri = context_uri;
                if (track.metadata_entity_uri.empty())
                    track.metadata_entity_uri = context_uri;
                explicit_queue_tracks_.push_back(std::move(track));
                ++added;
            }
        }

        std::fprintf(stderr,
            "[connect-queue] %s context uri=%s resolved=%zu added=%zu\n",
            source_label.c_str(), context_uri.c_str(), tracks.size(), added);
        if (added == 0) return;

        auto snap = ctx_state_.snapshot();
        std::string current = snap.has_tracks ? snap.current.uri
                                              : current_track_uri;
        uint32_t pos_ms = estimated_playback_position_ms(current);
        uint32_t dur_ms = remembered_playback_duration_ms(current);
        bool playing = remembered_playback_is_playing(current, true);
        put_state(4 /* PLAYER_STATE_CHANGED */,
                  !current.empty() && is_active_cloud_.load(),
                  current, playing, pos_ms, dur_ms);
    }).detach();
}

void SpircDevice::handle_message(const std::string& json_text) {
    auto j = nlohmann::json::parse(json_text, nullptr, false);
    if (j.is_discarded()) return;
    std::string uri = j.value("uri", std::string{});
    std::fprintf(stderr, "[spirc] cluster msg uri=%s\n", uri.c_str());

    // hm://connect-state/v1/cluster — full cluster snapshot (ClusterUpdate).
    // Parse active_device_id to detect "phone transferred away" and to
    // gate cluster volume updates.
    if (uri == "hm://connect-state/v1/cluster") {
        if (!j.contains("payloads") || !j["payloads"].is_array()) return;
        for (auto& p : j["payloads"]) {
            if (!p.is_string()) continue;
            auto raw = crypto::b64_decode(p.get<std::string>());
            if (raw.empty()) continue;
            std::string active = cluster_active_device_id(raw.data(), raw.size());
            bool explicit_queue_changed =
                remember_explicit_queue(raw.data(), raw.size(), active);
            remember_cloud_queue_hint(raw.data(), raw.size(), active);
            if (active.empty()) continue;
            bool we_active = (active == dev_cfg_.device_id);
            bool was_active = is_active_cloud_.exchange(we_active);
            if (explicit_queue_changed && we_active) {
                auto snap = ctx_state_.snapshot();
                if (snap.has_tracks) {
                    uint32_t pos_ms =
                        estimated_playback_position_ms(snap.current.uri);
                    uint32_t dur_ms =
                        remembered_playback_duration_ms(snap.current.uri);
                    bool playing =
                        remembered_playback_is_playing(snap.current.uri, true);
                    put_state(4 /* PLAYER_STATE_CHANGED */, true,
                              snap.current.uri, playing, pos_ms, dur_ms);
                }
            }
            if (!we_active) {
                if (was_active) {
                    std::fprintf(stderr,
                        "[spirc] cluster: active=%s (we are %s) — "
                        "TRANSITION active->inactive\n",
                        active.c_str(), dev_cfg_.device_id.c_str());
                    if (cb_.on_became_inactive) cb_.on_became_inactive(active);
                } else {
                    std::fprintf(stderr,
                        "[spirc] cluster: active=%s (we are %s) — "
                        "still inactive\n",
                        active.c_str(), dev_cfg_.device_id.c_str());
                }
            } else if (!was_active) {
                std::fprintf(stderr,
                    "[spirc] cluster: active=us — TRANSITION inactive->active\n");
            }
            break;
        }
        return;
    }

    if (uri.find("social-connect/v2/") != std::string::npos) {
        return;
    }

    // hm://connect-state/v1/connect/volume — single-axis volume change for
    // a device. Payload is a SetVolumeCommand proto. Field 1 = device_id,
    // field 2 = volume (varint, 0..65535).
    if (uri == "hm://connect-state/v1/connect/volume") {
        if (!j.contains("payloads") || !j["payloads"].is_array()) return;
        for (auto& p : j["payloads"]) {
            if (!p.is_string()) continue;
            auto raw = crypto::b64_decode(p.get<std::string>());
            if (raw.empty()) continue;
            // Walk all fields. The 40-hex-char string is the controlling
            // device's id (informational only — we apply by active state,
            // not by matching id). First varint <= 65535 is the volume.
            std::string target_device;
            uint64_t volume = (uint64_t)-1;
            try {
                proto::Reader r(raw.data(), raw.size());
                while (!r.at_end()) {
                    uint32_t f, wt;
                    if (!r.read_tag(f, wt)) break;
                    if (wt == proto::WIRE_VARINT) {
                        uint64_t v = r.read_varint();
                        if (v <= 65535 && volume == (uint64_t)-1) volume = v;
                    } else if (wt == proto::WIRE_LEN) {
                        std::string s = r.read_string();
                        if (s.size() == 40) target_device = s;
                    } else {
                        r.skip_field(wt);
                    }
                }
            } catch (...) { continue; }
            // The 40-hex string in this proto is the CONTROLLING device's
            // id (the one whose UI slider was moved), NOT the target.
            // Spotify broadcasts these updates to all clients; we should
            // apply when we're the active player. We learn our active
            // state from the Cluster.active_device_id field in the
            // hm://connect-state/v1/cluster URI handler.
            if (volume == (uint64_t)-1) continue;
            if (!is_active_cloud_.load()) {
                // Not for us — silently skip.
                continue;
            }
            std::fprintf(stderr,
                "[spirc] volume=%llu (controller=%s)\n",
                (unsigned long long)volume, target_device.c_str());
            current_volume_.store((uint32_t)volume);
            if (cb_.on_volume) cb_.on_volume((uint32_t)volume);
            auto snap = ctx_state_.snapshot();
            std::string current = snap.has_tracks
                ? snap.current.uri : std::string{};
            put_state(4 /* PLAYER_STATE_CHANGED */,
                      snap.has_tracks && is_active_cloud_.load(),
                      current,
                      remembered_playback_is_playing(current, true),
                      estimated_playback_position_ms(current),
                      remembered_playback_duration_ms(current));
            break;
        }
        return;
    }
}

// Parse TransferState and extract current_track.uri + is_paused +
// position_ms + playback context (from current_session field) + play_origin
// (also from current_session).
struct TransferInfo {
    std::string track_uri;
    bool is_paused = false;
    uint32_t position_ms = 0;
    std::string context_uri;   // e.g. "spotify:playlist:abc"
    std::string context_url;
    PlayOrigin play_origin;
    ContextState::Options options;
    bool has_options = false;
};

static void parse_play_origin_proto(proto::Reader r, PlayOrigin& out) {
    try {
        while (!r.at_end()) {
            uint32_t f, wt;
            if (!r.read_tag(f, wt)) break;
            if      (f == 1 && wt == proto::WIRE_LEN) out.feature_identifier = r.read_string();
            else if (f == 2 && wt == proto::WIRE_LEN) out.feature_version    = r.read_string();
            else if (f == 3 && wt == proto::WIRE_LEN) out.view_uri           = r.read_string();
            else if (f == 5 && wt == proto::WIRE_LEN) out.referrer_identifier= r.read_string();
            else if (f == 6 && wt == proto::WIRE_LEN) out.device_identifier  = r.read_string();
            else r.skip_field(wt);
        }
    } catch (...) {}
}
static bool parse_transfer_state(const uint8_t* data, size_t len, TransferInfo& out) {
    try {
        proto::Reader r(data, len);
        while (!r.at_end()) {
            uint32_t f, wt;
            if (!r.read_tag(f, wt)) break;
            if (f == 1 && wt == proto::WIRE_LEN) {
                // options = 1 (ContextPlayerOptions)
                auto cpo = r.read_len_delim();
                out.has_options = true;
                while (!cpo.at_end()) {
                    uint32_t of, owt;
                    if (!cpo.read_tag(of, owt)) break;
                    if      (of == 1 && owt == proto::WIRE_VARINT) out.options.shuffling_context = cpo.read_varint() != 0;
                    else if (of == 2 && owt == proto::WIRE_VARINT) out.options.repeating_context = cpo.read_varint() != 0;
                    else if (of == 3 && owt == proto::WIRE_VARINT) out.options.repeating_track   = cpo.read_varint() != 0;
                    else cpo.skip_field(owt);
                }
            } else if (f == 3 && wt == proto::WIRE_LEN) {
                // current_session = 3 (Session). Inside:
                //   play_origin = 1, context = 2 (Context).
                auto cs = r.read_len_delim();
                while (!cs.at_end()) {
                    uint32_t sf, swt;
                    if (!cs.read_tag(sf, swt)) break;
                    if (sf == 1 && swt == proto::WIRE_LEN) {
                        parse_play_origin_proto(cs.read_len_delim(), out.play_origin);
                    } else if (sf == 2 && swt == proto::WIRE_LEN) {
                        auto ctx = cs.read_len_delim();
                        while (!ctx.at_end()) {
                            uint32_t cf, cwt;
                            if (!ctx.read_tag(cf, cwt)) break;
                            if      (cf == 1 && cwt == proto::WIRE_LEN) out.context_uri = ctx.read_string();
                            else if (cf == 2 && cwt == proto::WIRE_LEN) out.context_url = ctx.read_string();
                            else ctx.skip_field(cwt);
                        }
                    } else cs.skip_field(swt);
                }
            } else if (f == 2 && wt == proto::WIRE_LEN) {
                // Playback
                auto pb = r.read_len_delim();
                while (!pb.at_end()) {
                    uint32_t pf, pwt;
                    if (!pb.read_tag(pf, pwt)) break;
                    if (pf == 2 && pwt == proto::WIRE_VARINT) {
                        // position_as_of_timestamp int32
                        uint64_t v = pb.read_varint();
                        out.position_ms = (uint32_t)v;
                    } else if (pf == 4 && pwt == proto::WIRE_VARINT) {
                        out.is_paused = (pb.read_varint() != 0);
                    } else if (pf == 5 && pwt == proto::WIRE_LEN) {
                        // ContextTrack: uri=1 (varies — sometimes empty,
                        // sometimes "spotify:track:...", sometimes raw hex),
                        // gid=3 (16 bytes — most reliable).
                        auto ct = pb.read_len_delim();
                        std::vector<uint8_t> gid;
                        std::string uri_raw;
                        while (!ct.at_end()) {
                            uint32_t cf, cwt;
                            if (!ct.read_tag(cf, cwt)) break;
                            if      (cf == 1 && cwt == proto::WIRE_LEN) uri_raw = ct.read_string();
                            else if (cf == 3 && cwt == proto::WIRE_LEN) gid = ct.read_bytes();
                            else ct.skip_field(cwt);
                        }
                        // Prefer gid; fall back to URI field in either format.
                        if (gid.size() == 16) {
                            SpotifyId id;
                            if (SpotifyId::from_raw_bytes(gid.data(), gid.size(), id))
                                out.track_uri = "spotify:track:" + id.to_base62();
                        }
                        if (out.track_uri.empty()) {
                            if (uri_raw.rfind("spotify:track:", 0) == 0) {
                                out.track_uri = uri_raw;
                            } else if (uri_raw.size() == 32) {
                                SpotifyId id;
                                if (SpotifyId::from_base16(uri_raw, id))
                                    out.track_uri = "spotify:track:" + id.to_base62();
                            }
                        }
                    } else pb.skip_field(pwt);
                }
            } else r.skip_field(wt);
        }
        return !out.track_uri.empty();
    } catch (...) { return false; }
}

// Parse a ContextPlayerOptions submessage from JSON. Used for `play.options.
// player_options_override` and `set_options.options`.
static ContextState::Options parse_options_json(const nlohmann::json& j) {
    ContextState::Options o;
    if (!j.is_object()) return o;
    auto bget = [&](const char* k) -> bool {
        auto it = j.find(k);
        return it != j.end() && it->is_boolean() && it->get<bool>();
    };
    o.shuffling_context = bget("shuffling_context");
    o.repeating_context = bget("repeating_context");
    o.repeating_track   = bget("repeating_track");
    return o;
}

static PlayOrigin parse_play_origin_json(const nlohmann::json& j) {
    PlayOrigin po;
    if (!j.is_object()) return po;
    auto get = [&](const char* k) -> std::string {
        auto it = j.find(k);
        if (it == j.end() || !it->is_string()) return {};
        return it->get<std::string>();
    };
    po.feature_identifier  = get("feature_identifier");
    po.feature_version     = get("feature_version");
    po.view_uri            = get("view_uri");
    po.referrer_identifier = get("referrer_identifier");
    po.device_identifier   = get("device_identifier");
    return po;
}

static std::string truncate_for_log(const std::string& s, size_t max_len) {
    if (s.size() <= max_len) return s;
    return s.substr(0, max_len) + "...";
}

static void log_snapshot_window(const char* label,
                                const ContextState::Snapshot& snap,
                                size_t limit = 12) {
    if (!kLogSpircWindows) return;
    std::fprintf(stderr,
        "[spirc-window] %s current=%s index=%u total=%zu next=%zu prev=%zu "
        "shuffle=%d repeat_ctx=%d repeat_track=%d\n",
        label,
        snap.has_tracks ? snap.current.uri.c_str() : "",
        snap.index_track, snap.track_count, snap.next_tracks.size(),
        snap.prev_tracks.size(),
        (int)snap.options.shuffling_context,
        (int)snap.options.repeating_context,
        (int)snap.options.repeating_track);
    size_t n = std::min(limit, snap.next_tracks.size());
    for (size_t i = 0; i < n; ++i) {
        std::fprintf(stderr,
            "[spirc-window] %s next[%zu]=%s provider=%s uid=%s\n",
            label, i, snap.next_tracks[i].uri.c_str(),
            snap.next_tracks[i].provider.c_str(),
            snap.next_tracks[i].uid.c_str());
    }
}

static std::string station_context_for_empty_next(const std::string& ctx_uri) {
    constexpr const char* prefix = "spotify:";
    constexpr size_t prefix_len = 8;
    if (ctx_uri.rfind("spotify:station:", 0) == 0) return {};
    if (ctx_uri.rfind("spotify:track:", 0) == 0
        || ctx_uri.rfind("spotify:album:", 0) == 0) {
        return std::string("spotify:station:") + ctx_uri.substr(prefix_len);
    }
    return {};
}

static std::string station_context_url(const std::string& station_uri,
                                       const std::string& current_track_uri) {
    std::string url = "context://" + station_uri;
    if (current_track_uri.rfind("spotify:track:", 0) == 0) {
        url += "?prev_uris=" + current_track_uri.substr(14)
            + "&autoplay=true";
    }
    return url;
}

static bool resolve_station_autoplay_tracks(
        const std::string& seed_context_uri,
        const std::string& current_track_uri,
        auth::ClientTokenProvider& ct,
        auth::Login5Provider& l5,
        const std::string& spclient_base,
        std::vector<ProvidedTrack>& out_tracks) {
    std::string station_uri = station_context_for_empty_next(seed_context_uri);
    if (station_uri.empty()) return false;

    std::vector<ProvidedTrack> station_tracks;
    if (!resolve_context_tracks(station_uri, ct, l5, spclient_base,
                                station_tracks)) {
        return false;
    }

    out_tracks.clear();
    out_tracks.reserve(std::min<size_t>(station_tracks.size(), 48));
    for (auto& track : station_tracks) {
        if (track.uri.empty() || track.uri == current_track_uri) continue;
        track.provider = "autoplay";
        track.metadata_context_uri = station_uri;
        track.metadata_entity_uri = station_uri;
        out_tracks.push_back(std::move(track));
        if (out_tracks.size() >= 48) break;
    }
    std::fprintf(stderr,
        "[autoplay] station fallback seed=%s station=%s tracks=%zu\n",
        seed_context_uri.c_str(), station_uri.c_str(), out_tracks.size());
    return !out_tracks.empty();
}

// Spawn a detached worker that resolves the given context_uri via
// spclient/context-resolve, populates ctx_state_, then re-PUTs state so
// cloud sees our next_tracks lookahead.
// Fetch autoplay continuation if we're near the end of the current context
// and we haven't already kicked one off. Detached worker. Same access
// pattern as kick_context_resolver — runs off the dealer reader thread.
void SpircDevice::maybe_kick_autoplay() {
    if (resolved_ctx_uri_.empty()) return;
    if (!ctx_state_.tracks_near_end(2)) return;
    bool expected = false;
    if (!autoplay_in_flight_.compare_exchange_strong(expected, true)) return;
    std::string seed = resolved_ctx_uri_;
    uint64_t generation = context_generation_.load(std::memory_order_acquire);
    std::thread([this, seed, generation]{
        std::vector<ProvidedTrack> more;
        bool resolved =
            resolve_autoplay_tracks(seed, ct_, l5_, spclient_base_, more);
        if (!resolved) {
            auto before = ctx_state_.snapshot();
            std::string current = before.has_tracks
                ? before.current.uri : std::string{};
            resolved = resolve_station_autoplay_tracks(
                seed, current, ct_, l5_, spclient_base_, more);
        }
        if (resolved) {
            if (context_generation_.load(std::memory_order_acquire) != generation
                || resolved_ctx_uri_ != seed) {
                std::fprintf(stderr,
                    "[autoplay] stale result ignored seed=%s\n", seed.c_str());
                autoplay_in_flight_.store(false);
                return;
            }
            ctx_state_.append_tracks(std::move(more));
            // PUT state so cloud sees the extended next_tracks. Use current
            // track URI from the snapshot (PUT skips player_state if empty).
            auto snap = ctx_state_.snapshot();
            if (snap.has_tracks) {
                uint32_t pos_ms =
                    estimated_playback_position_ms(snap.current.uri);
                uint32_t dur_ms =
                    remembered_playback_duration_ms(snap.current.uri);
                bool playing =
                    remembered_playback_is_playing(snap.current.uri, true);
                put_state(4 /* PLAYER_STATE_CHANGED */, true,
                          snap.current.uri, playing, pos_ms, dur_ms);
            }
        }
        autoplay_in_flight_.store(false);
    }).detach();
}

void SpircDevice::kick_context_resolver(const std::string& new_ctx_uri,
                                         const SkipToHint& hint) {
    if (new_ctx_uri.empty()) return;

    // Single-track entry: when a user picks one track in Spotify without
    // selecting a playlist/album, cloud reports context_uri == track_uri.
    // The /context-resolve/v1/<track_uri> endpoint will fail because there
    // is no playlist to enumerate, so without special-casing this we end
    // up with an empty ctx_state and handle_natural_end fires TrackEnded
    // as soon as the track finishes — the official Spotify client keeps
    // playing via autoplay continuation in this case.
    //
    // Seed ctx_state with the single track and kick autoplay immediately,
    // so by the time the track ends ctx_state.next_tracks is populated
    // and advance_to_next_track returns a real continuation URI.
    if (new_ctx_uri.rfind("spotify:track:", 0) == 0) {
        if (new_ctx_uri == resolved_ctx_uri_) {
            std::fprintf(stderr,
                "[context-resolver] single-track %s already resolved\n",
                new_ctx_uri.c_str());
            return;
        }
        context_generation_.fetch_add(1, std::memory_order_acq_rel);
        pending_skip_dir_.store(0, std::memory_order_release);
        autoplay_in_flight_.store(false, std::memory_order_release);
        resolved_ctx_uri_ = new_ctx_uri;
        ProvidedTrack only;
        only.uri      = new_ctx_uri;
        only.uid      = ContextState::generate_uid();
        only.provider = "context";
        std::vector<ProvidedTrack> seed;
        seed.push_back(std::move(only));
        ctx_state_.set_tracks(std::move(seed));
        ctx_state_.set_current_track_uri(new_ctx_uri);
        std::fprintf(stderr,
            "[context-resolver] single-track entry %s — kicking autoplay "
            "to populate continuation\n", new_ctx_uri.c_str());
        maybe_kick_autoplay();
        return;
    }

    // Reuse already-resolved context if hint can be placed inside it.
    if (new_ctx_uri == resolved_ctx_uri_) {
        if (hint.track_uri.empty() && hint.track_uid.empty()
            && hint.track_index < 0) {
            std::fprintf(stderr,
                "[context-resolver] %s already resolved (no skip hint)\n",
                new_ctx_uri.c_str());
            return;
        }
        std::string placed = ctx_state_.resolve_skip_to(
            hint.track_uri, hint.track_uid, hint.track_index);
        if (!placed.empty()) {
            auto opts = ctx_state_.options();
            if (opts.shuffling_context
                && (new_ctx_uri.rfind("spotify:playlist:", 0) == 0
                    || looks_like_liked_songs_context(new_ctx_uri))) {
                auto order = matching_cloud_queue_hint(new_ctx_uri, placed);
            if (!order.empty()) {
                size_t applied =
                    ctx_state_.apply_playback_order(placed, order);
                std::fprintf(stderr,
                    "[cloud-queue] applied reused ctx=%s current=%s "
                        "applied=%zu hinted=%zu\n",
                        new_ctx_uri.c_str(), placed.c_str(), applied,
                        order.size());
                    log_snapshot_window(
                        "after-cloud-queue-reused",
                        ctx_state_.snapshot());
                }
            }
            std::fprintf(stderr,
                "[context-resolver] reusing resolved %s (placed=%s)\n",
                new_ctx_uri.c_str(), placed.c_str());
            // If the play handler didn't already start the track (the
            // skip_to came as uid / index, not uri), dispatch it now. The
            // playback thread otherwise stays on the previous track.
            if (!hint.already_dispatched && cb_.on_transfer)
                cb_.on_transfer(placed, hint.seek_ms, true);
            return;
        }
        // Otherwise fall through and re-resolve.
    }
    uint64_t generation =
        context_generation_.fetch_add(1, std::memory_order_acq_rel) + 1;
    pending_skip_dir_.store(0, std::memory_order_release);
    autoplay_in_flight_.store(false, std::memory_order_release);
    resolved_ctx_uri_ = new_ctx_uri;
    resolver_in_flight_.store(true);
    resolver_generation_.store(generation, std::memory_order_release);
    std::string ctx_uri = new_ctx_uri;
    SkipToHint h = hint;
    std::thread([this, ctx_uri, h, generation]{
        std::vector<ProvidedTrack> tracks;
        if (!resolve_context_tracks(ctx_uri, ct_, l5_,
                                     spclient_base_, tracks)) {
            if (resolver_generation_.load(std::memory_order_acquire) == generation) {
                resolver_in_flight_.store(false);
            }
            return;
        }
        if (context_generation_.load(std::memory_order_acquire) != generation
            || resolved_ctx_uri_ != ctx_uri) {
            std::fprintf(stderr,
                "[context-resolver] stale result ignored ctx=%s\n",
                ctx_uri.c_str());
            if (resolver_generation_.load(std::memory_order_acquire) == generation) {
                resolver_in_flight_.store(false);
            }
            return;
        }

        if (!h.track_uri.empty() &&
            h.track_uri.rfind("spotify:track:", 0) == 0) {
            bool hint_present = false;
            for (const auto& track : tracks) {
                if (track.uri == h.track_uri) {
                    hint_present = true;
                    break;
                }
            }
            if (!hint_present) {
                ProvidedTrack hinted;
                hinted.uri = h.track_uri;
                hinted.uid = h.track_uid.empty()
                    ? ContextState::generate_uid()
                    : h.track_uid;
                hinted.provider = "context";
                hinted.metadata_context_uri = ctx_uri;
                hinted.metadata_entity_uri = ctx_uri;
                tracks.insert(tracks.begin(), std::move(hinted));
                std::fprintf(stderr,
                    "[context-resolver] injected requested track %s into "
                    "resolved %s so lookahead remains usable\n",
                    h.track_uri.c_str(), ctx_uri.c_str());
            }
        }

        std::string first_uri = tracks.empty() ? std::string{} : tracks[0].uri;
        ctx_state_.set_tracks(std::move(tracks));

        // Try each hint (track_uri → track_uid → track_index) against the
        // resolved track list to find the user's actual playback target.
        std::string play_uri = ctx_state_.resolve_skip_to(
            h.track_uri, h.track_uid, h.track_index);
        if (!play_uri.empty() && h.allow_shuffle_start_override) {
            auto opts = ctx_state_.options();
            auto placed = ctx_state_.snapshot();
            if (opts.shuffling_context
                && placed.track_count > 1
                && placed.index_track == 0
                && h.track_uri.empty()
                && !h.track_uid.empty()
                && h.track_index < 0) {
                std::string shuffled =
                    ctx_state_.start_context_playback(/*avoid_index=*/0);
                if (!shuffled.empty()) {
                    play_uri = shuffled;
                }
            }
        }

        if (play_uri.empty() && !h.track_uri.empty()) {
            // URI hint provided but not in resolved page list. Play it
            // anyway; lookahead will be misaligned but the chosen track
            // takes precedence over "first track" fallback.
            play_uri = h.track_uri;
            std::fprintf(stderr,
                "[context-resolver] %s not in resolved %s — playing "
                "anyway with no lookahead\n",
                h.track_uri.c_str(), ctx_uri.c_str());
        } else if (play_uri.empty() && !first_uri.empty()) {
            // No usable hint → context-only entry. Auto-start head.
            play_uri = ctx_state_.start_context_playback();
            if (play_uri.empty()) play_uri = first_uri;
            std::fprintf(stderr,
                "[context-resolver] context-only entry to %s → "
                "auto-starting %s\n",
                ctx_uri.c_str(), play_uri.c_str());
            if (cb_.on_transfer) cb_.on_transfer(play_uri, 0, true);
        } else {
            std::fprintf(stderr,
                "[context-resolver] %s placed at %s\n",
                ctx_uri.c_str(), play_uri.c_str());
            // Same "placed via uid/index" case as the dedup path — start
            // the picked track unless the play handler already did.
            if (!h.already_dispatched && cb_.on_transfer)
                cb_.on_transfer(play_uri, h.seek_ms, true);
        }

        auto opts = ctx_state_.options();
        if (opts.shuffling_context
            && (ctx_uri.rfind("spotify:playlist:", 0) == 0
                || looks_like_liked_songs_context(ctx_uri))) {
            auto order = matching_cloud_queue_hint(ctx_uri, play_uri);
            if (!order.empty()) {
                size_t applied = ctx_state_.apply_playback_order(play_uri, order);
                std::fprintf(stderr,
                    "[cloud-queue] applied ctx=%s current=%s applied=%zu "
                    "hinted=%zu\n",
                    ctx_uri.c_str(), play_uri.c_str(), applied, order.size());
                log_snapshot_window("after-cloud-queue",
                                    ctx_state_.snapshot());
            }
        }

        {
            auto snap = ctx_state_.snapshot();
            std::fprintf(stderr,
                "[context-resolver] state ctx=%s index=%u total=%zu "
                "next_window=%zu prev_window=%zu shuffle=%d repeat_ctx=%d "
                "repeat_track=%d\n",
                ctx_uri.c_str(), snap.index_track, snap.track_count,
                snap.next_tracks.size(), snap.prev_tracks.size(),
                (int)snap.options.shuffling_context,
                (int)snap.options.repeating_context,
                (int)snap.options.repeating_track);
            log_snapshot_window("resolver", snap);
        }

        put_state(4 /* PLAYER_STATE_CHANGED */, true, play_uri,
                  true,
                  estimated_playback_position_ms(play_uri),
                  remembered_playback_duration_ms(play_uri));
        maybe_kick_autoplay();

        // Drain any skip that arrived while we were resolving.
        if (resolver_generation_.load(std::memory_order_acquire) == generation) {
            resolver_in_flight_.store(false);
        }
        int pending = pending_skip_dir_.exchange(0);
        if (pending != 0) {
            std::fprintf(stderr,
                "[context-resolver] applying deferred skip dir=%d\n", pending);
            bool moved = (pending > 0)
                ? ctx_state_.advance_next(/*force_wrap=*/false,
                                          /*ignore_repeat_track=*/true)
                : ctx_state_.advance_prev(/*ignore_repeat_track=*/true);
            if (moved) {
                auto s = ctx_state_.snapshot();
                if (s.has_tracks && cb_.on_transfer)
                    cb_.on_transfer(s.current.uri, 0, true);
            }
        }
    }).detach();
}

void SpircDevice::handle_request(const std::string& json_text) {
    auto j = nlohmann::json::parse(json_text, nullptr, false);
    if (j.is_discarded()) { return; }
    std::string ident = j.value("message_ident", std::string{});
    std::string key   = j.value("key", std::string{});

    nlohmann::json payload = j.value("payload", nlohmann::json::object());
    nlohmann::json cmd     = payload.value("command", nlohmann::json::object());
    std::string endpoint   = cmd.value("endpoint", std::string{});

    // Capture sender info for last_command_* on next state PUT.
    last_sender_id_     = payload.value("sent_by_device_id", std::string{});
    last_sender_msg_id_ = (uint32_t)payload.value("message_id", 0);

    std::fprintf(stderr, "[spirc] request endpoint='%s' key=%s\n",
                 endpoint.c_str(), key.c_str());
    if (!remember_command_key(key)) {
        std::fprintf(stderr, "[spirc] duplicate request ignored key=%s endpoint='%s'\n",
                     key.c_str(), endpoint.c_str());
        send_reply(key, true);
        return;
    }
    if (!remember_command_message_order(last_sender_id_,
                                        last_sender_msg_id_,
                                        endpoint)) {
        send_reply(key, true);
        return;
    }

    // Receiving a SPIRC command implies we're the active player — cloud
    // only routes transfer / play / pause / set_volume etc. to the active
    // device. Mark active here so cluster volume updates that arrive
    // before the next Cluster snapshot are still applied.
    is_active_cloud_.store(true);

    bool ok = true;
    if (endpoint == "transfer") {
        std::string b64 = cmd.value("data", std::string{});
        if (!b64.empty()) {
            auto bytes = crypto::b64_decode(b64);
            TransferInfo ti;
            if (parse_transfer_state(bytes.data(), bytes.size(), ti)) {
                std::fprintf(stderr,
                    "[spirc] transfer uri=%s pos=%ums paused=%d ctx=%s\n",
                    ti.track_uri.c_str(), ti.position_ms,
                    (int)ti.is_paused, ti.context_uri.c_str());
                if (!ti.context_uri.empty()) {
                    ctx_uri_ = ti.context_uri;
                    ctx_url_ = ti.context_url.empty() ? ti.context_uri : ti.context_url;
                    ctx_state_.set_context(ctx_uri_, ctx_url_);
                    ctx_state_.set_play_origin(ti.play_origin);
                    if (ti.has_options) ctx_state_.set_options(ti.options);
                    if (cb_.on_context_change)
                        cb_.on_context_change(ctx_uri_, ctx_url_);
                    {
                        SkipToHint h;
                        h.track_uri = ti.track_uri;
                        h.seek_ms = ti.position_ms;
                        h.already_dispatched = true;
                        kick_context_resolver(ctx_uri_, h);
                    }
                }
                if (cb_.on_transfer)
                    cb_.on_transfer(ti.track_uri, ti.position_ms, !ti.is_paused);
            } else {
                std::fprintf(stderr, "[spirc] transfer: failed to parse TransferState\n");
                ok = false;
            }
        }
    } else if (endpoint == "play") {
        // play.options.skip_to.track_uri tells us a specific track to load.
        // If absent, this is a "resume current" — NOT a new context to start.
        std::string uri;
        std::string skip_to_uid;
        int track_index = -1;
        uint32_t seek_ms = 0;
        if (cmd.contains("options") && cmd["options"].is_object()) {
            auto& o = cmd["options"];
            if (o.contains("skip_to") && o["skip_to"].is_object()) {
                auto& s = o["skip_to"];
                uri          = s.value("track_uri", std::string{});
                skip_to_uid  = s.value("track_uid", std::string{});
                if (s.contains("track_index") && s["track_index"].is_number())
                    track_index = s["track_index"].get<int>();
            }
            if (o.contains("seek_to") && o["seek_to"].is_number())
                seek_ms = (uint32_t)o["seek_to"].get<int>();
        }
        std::fprintf(stderr,
            "[spirc] play skip_to track_uri='%s' uid='%s' idx=%d seek=%ums\n",
            uri.c_str(), skip_to_uid.c_str(), track_index, seek_ms);
        // Stash context (playlist URI) so subsequent state PUTs link us to
        // the cloud-side queue. Then subsequent skip_next commands from
        // cloud will carry the next track URI for us to play directly.
        std::string prev_ctx = ctx_uri_;
        bool context_changed = false;
        if (cmd.contains("context") && cmd["context"].is_object()) {
            auto& c = cmd["context"];
            std::string nctx = c.value("uri", std::string{});
            std::string nurl = c.value("url", std::string{});
            if (!nctx.empty()) {
                if (nctx != ctx_uri_) context_changed = true;
                ctx_uri_ = nctx;
                ctx_url_ = nurl.empty() ? nctx : nurl;
                ctx_state_.set_context(ctx_uri_, ctx_url_);
                if (cb_.on_context_change)
                    cb_.on_context_change(ctx_uri_, ctx_url_);
            }
        }
        if (cmd.contains("play_origin") && cmd["play_origin"].is_object()) {
            ctx_state_.set_play_origin(
                parse_play_origin_json(cmd["play_origin"]));
        }
        if (cmd.contains("options") && cmd["options"].is_object()) {
            auto& o = cmd["options"];
            if (o.contains("player_options_override")
                && o["player_options_override"].is_object()) {
                ctx_state_.set_options(parse_options_json(o["player_options_override"]));
            }
        }
        bool is_track_uri = (uri.rfind("spotify:track:", 0) == 0);
        bool has_skip_hint = is_track_uri || !skip_to_uid.empty()
                             || track_index >= 0;
        std::fprintf(stderr, "[spirc] play track_uri='%s' seek=%ums ctx=%s\n",
                     uri.c_str(), seek_ms, ctx_uri_.c_str());
        // Kick context resolver if we now have a known context. Safe to
        // call whether or not the context changed — it dedupes internally.
        if (is_track_uri && cb_.on_transfer) {
            // Fast path — start the picked track immediately. Resolver
            // will catch up in parallel (update ctx_state index +
            // lookahead) but doesn't need to spawn another transfer.
            cb_.on_transfer(uri, seek_ms, true);
        }
        if (!ctx_uri_.empty()) {
            SkipToHint h;
            h.track_uri          = is_track_uri ? uri : std::string{};
            h.track_uid          = skip_to_uid;
            h.track_index        = track_index;
            h.seek_ms            = seek_ms;
            h.already_dispatched = is_track_uri;  // play handler already did it
            h.allow_shuffle_start_override =
                context_changed && !is_track_uri && track_index < 0;
            kick_context_resolver(ctx_uri_, h);
        }
        if (is_track_uri) {
            // Track already dispatched via on_transfer above.
        } else if (has_skip_hint) {
            // skip_to provided uid/index — resolver fires on_transfer
            // when it places the hint. Don't resume the previous track.
        } else if (context_changed) {
            // Context-only play (no track URI). Two paths:
            //   (a) We've already resolved this context AND have tracks —
            //       kick_context_resolver above already handled it (placed
            //       the current track, on_transfer scheduled). Nothing to
            //       do here; resume current playback so phone UI updates.
            //   (b) Context truly new + no resolved tracks yet — let the
            //       detached resolver own the transition.
            auto snap = ctx_state_.snapshot();
            if (snap.has_tracks) {
                std::fprintf(stderr,
                    "[spirc] play: context-only (%s) — context already "
                    "resolved (%u tracks), resuming\n",
                    ctx_uri_.c_str(), (unsigned)snap.next_tracks.size() + 1);
                if (cb_.on_play) cb_.on_play();
            } else {
                std::fprintf(stderr,
                    "[spirc] play: context-only (%s) — resolver owns start\n",
                    ctx_uri_.c_str());
            }
        } else {
            // Same context, no track URI → resume current playback.
            if (cb_.on_play) cb_.on_play();
        }
        (void)prev_ctx;
    } else if (endpoint == "pause") {
        if (cb_.on_pause) cb_.on_pause();
    } else if (endpoint == "resume") {
        if (cb_.on_play) cb_.on_play();
    } else if (endpoint == "seek_to") {
        uint32_t pos = (uint32_t)cmd.value("value", 0);
        if (cb_.on_seek) cb_.on_seek(pos);
    } else if (endpoint == "skip_next") {
        std::string uri;
        if (cmd.contains("track") && cmd["track"].is_object())
            uri = cmd["track"].value("uri", std::string{});
        // Cloud usually sends an empty URI and expects us, the active
        // device, to advance into our own next_tracks. That's the librespot
        // pattern. Only when cloud is OVERRIDING (e.g. a queued track from
        // another client) does it fill `uri`.
        if (uri.empty()) {
            uri = pop_explicit_queue_track();
            if (!uri.empty()) {
                std::fprintf(stderr,
                    "[connect-queue] skip_next using explicit queue uri=%s\n",
                    uri.c_str());
            }
        }
        if (uri.empty() && ctx_state_.advance_next(
                /*force_wrap=*/false,
                /*ignore_repeat_track=*/true)) {
            auto snap = ctx_state_.snapshot();
            if (snap.has_tracks) uri = snap.current.uri;
            std::fprintf(stderr,
                "[spirc] skip_next local advance uri='%s' index=%u total=%zu "
                "next_window=%zu shuffle=%d repeat_ctx=%d repeat_track=%d\n",
                uri.c_str(), snap.index_track, snap.track_count,
                snap.next_tracks.size(),
                (int)snap.options.shuffling_context,
                (int)snap.options.repeating_context,
                (int)snap.options.repeating_track);
            maybe_kick_autoplay();
        }
        if (uri.empty() && resolver_in_flight_.load()) {
            // Race: context-resolver hasn't populated tracks yet. Defer the
            // skip; the resolver completion handler will pop it.
            pending_skip_dir_.store(+1);
            std::fprintf(stderr,
                "[spirc] skip_next deferred — resolver in flight\n");
            send_reply(key, true);
            return;
        }
        if (uri.empty()) {
            auto snap = ctx_state_.snapshot();
            std::string seed_ctx = ctx_uri_.empty() ? snap.context_uri : ctx_uri_;
            std::string station_uri = station_context_for_empty_next(seed_ctx);
            if (!station_uri.empty() && snap.has_tracks) {
                ctx_uri_ = station_uri;
                ctx_url_ = station_context_url(station_uri, snap.current.uri);
                ctx_state_.set_context(ctx_uri_, ctx_url_);
                std::fprintf(stderr,
                    "[spirc] skip_next empty in %s; switching to station "
                    "continuation %s url=%s\n",
                    seed_ctx.c_str(), ctx_uri_.c_str(), ctx_url_.c_str());
                if (cb_.on_context_change)
                    cb_.on_context_change(ctx_uri_, ctx_url_);
                kick_context_resolver(ctx_uri_, SkipToHint{});
                send_reply(key, true);
                return;
            }
        }
        std::fprintf(stderr, "[spirc] skip_next uri='%s'\n", uri.c_str());
        if (uri.rfind("spotify:track:", 0) == 0 && cb_.on_transfer) {
            bool placed = ctx_state_.set_current_track_uri(uri);
            if (placed) {
                log_snapshot_window("skip-next-cloud-uri",
                                    ctx_state_.snapshot());
            } else {
                std::fprintf(stderr,
                    "[spirc] skip_next cloud uri not in current context: %s\n",
                    uri.c_str());
            }
            cb_.on_transfer(uri, 0, true);
        } else if (cb_.on_skip_next) {
            cb_.on_skip_next();
        }
    } else if (endpoint == "skip_prev") {
        // Same pattern as skip_next — advance backwards in our context
        // state when possible.
        std::string uri;
        if (ctx_state_.advance_prev(/*ignore_repeat_track=*/true)) {
            auto snap = ctx_state_.snapshot();
            if (snap.has_tracks) uri = snap.current.uri;
        }
        if (uri.empty() && resolver_in_flight_.load()) {
            pending_skip_dir_.store(-1);
            std::fprintf(stderr,
                "[spirc] skip_prev deferred — resolver in flight\n");
            send_reply(key, true);
            return;
        }
        std::fprintf(stderr, "[spirc] skip_prev uri='%s'\n", uri.c_str());
        if (uri.rfind("spotify:track:", 0) == 0 && cb_.on_transfer) {
            cb_.on_transfer(uri, 0, true);
        } else if (cb_.on_skip_prev) {
            cb_.on_skip_prev();
        }
    } else if (endpoint == "add_to_queue") {
        std::vector<std::string> uris;
        collect_json_track_uris(cmd, uris);
        if (uris.empty()) {
            std::fprintf(stderr,
                "[connect-queue] add_to_queue no track found command=%s\n",
                truncate_for_log(cmd.dump(), kPlayCommandLogLimit).c_str());
            ok = false;
        } else {
            bool changed = false;
            for (const auto& queued_uri : uris) {
                changed = add_explicit_queue_track(
                    queued_uri, "q" + std::to_string(explicit_queue_snapshot().size()),
                    "add_to_queue") || changed;
            }
            if (changed) {
                auto snap = ctx_state_.snapshot();
                std::string current = snap.has_tracks
                    ? snap.current.uri : std::string{};
                uint32_t pos_ms = estimated_playback_position_ms(current);
                uint32_t dur_ms = remembered_playback_duration_ms(current);
                bool playing = remembered_playback_is_playing(current, true);
                put_state(4 /* PLAYER_STATE_CHANGED */, true,
                          current, playing, pos_ms, dur_ms);
            }
        }
    } else if (endpoint == "set_queue") {
        size_t next_track_count = 0;
        auto queued_tracks = collect_set_queue_tracks(cmd, &next_track_count);
        bool has_next_tracks = cmd.contains("next_tracks")
            && cmd["next_tracks"].is_array();
        bool changed = has_next_tracks
            ? replace_explicit_queue_tracks(std::move(queued_tracks),
                                            "set_queue")
            : false;

        auto snap = ctx_state_.snapshot();
        std::string current = snap.has_tracks ? snap.current.uri
                                              : std::string{};
        std::fprintf(stderr,
            "[connect-queue] set_queue next_tracks=%zu queued=%zu changed=%d\n",
            next_track_count, explicit_queue_snapshot().size(), (int)changed);

        if (has_next_tracks) {
            uint32_t pos_ms = estimated_playback_position_ms(current);
            uint32_t dur_ms = remembered_playback_duration_ms(current);
            bool playing = remembered_playback_is_playing(current, true);
            put_state(4 /* PLAYER_STATE_CHANGED */,
                      !current.empty(), current, playing, pos_ms, dur_ms);
        } else {
            ok = false;
        }
    } else if (endpoint == "set_options"
               || endpoint == "set_shuffling_context"
               || endpoint == "set_repeating_context"
               || endpoint == "set_repeating_track") {
        // Toggling shuffle / repeat from the phone. Cloud uses several
        // overlapping endpoints depending on which UI control the user
        // touched; merge them all into our single Options model.
        ContextState::Options o = ctx_state_.options();
        ContextState::Options before = o;
        auto pull = [&](const nlohmann::json& j, const char* k, bool& tgt) {
            auto it = j.find(k);
            if (it != j.end() && it->is_boolean()) tgt = it->get<bool>();
        };
        // Look in `cmd` directly + the embedded `options` block + plain
        // `value` boolean for the single-axis endpoints.
        pull(cmd, "shuffling_context", o.shuffling_context);
        pull(cmd, "repeating_context", o.repeating_context);
        pull(cmd, "repeating_track",   o.repeating_track);
        // SELECTIVE merge from cmd.options — only overwrite fields that are
        // actually present. Cloud often sends set_options with a partial
        // options object; full overwrite would clobber unrelated flags.
        if (cmd.contains("options") && cmd["options"].is_object()) {
            auto& obj = cmd["options"];
            pull(obj, "shuffling_context", o.shuffling_context);
            pull(obj, "repeating_context", o.repeating_context);
            pull(obj, "repeating_track",   o.repeating_track);
        }
        if (cmd.contains("value") && cmd["value"].is_boolean()) {
            bool v = cmd["value"].get<bool>();
            if      (endpoint == "set_shuffling_context") o.shuffling_context = v;
            else if (endpoint == "set_repeating_context") o.repeating_context = v;
            else if (endpoint == "set_repeating_track")   o.repeating_track   = v;
        }
        std::fprintf(stderr,
            "[spirc] %s → shuffle=%d rep_ctx=%d rep_track=%d\n",
            endpoint.c_str(),
            (int)o.shuffling_context, (int)o.repeating_context,
            (int)o.repeating_track);
        bool changed = o.shuffling_context != before.shuffling_context ||
                       o.repeating_context != before.repeating_context ||
                       o.repeating_track != before.repeating_track;
        ctx_state_.set_options(o);
        if (!changed) {
            std::fprintf(stderr,
                "[spirc] %s duplicate options ignored for PUT state\n",
                endpoint.c_str());
            send_reply(key, true);
            return;
        }
        auto snap = ctx_state_.snapshot();
        if (snap.has_tracks) {
            uint32_t pos_ms =
                estimated_playback_position_ms(snap.current.uri);
            uint32_t dur_ms =
                remembered_playback_duration_ms(snap.current.uri);
            bool playing =
                remembered_playback_is_playing(snap.current.uri, true);
            put_state(4 /* PLAYER_STATE_CHANGED */, true,
                      snap.current.uri, playing, pos_ms, dur_ms);
        }
    } else if (endpoint == "update_context") {
    } else if (endpoint == "set_volume") {
        // SPIRC set_volume command — fired when the phone's device-control
        // UI for OUR device moves the slider. Cloud may use either the
        // cluster URI path (handled in handle_message) or this endpoint;
        // we need both. Volume is in `value` (modern librespot) or
        // `volume` (older clients), 0..65535.
        uint32_t v = (uint32_t)-1;
        if (cmd.contains("value") && cmd["value"].is_number_integer())
            v = (uint32_t)cmd["value"].get<int64_t>();
        else if (cmd.contains("volume") && cmd["volume"].is_number_integer())
            v = (uint32_t)cmd["volume"].get<int64_t>();
        if (v <= 65535) {
            std::fprintf(stderr, "[spirc] set_volume → %u\n", (unsigned)v);
            current_volume_.store(v);
            if (cb_.on_volume) cb_.on_volume(v);
            // PUT state so cloud sees the volume change reflected.
            auto snap = ctx_state_.snapshot();
            std::string current = snap.has_tracks
                ? snap.current.uri : std::string{};
            put_state(4 /* PLAYER_STATE_CHANGED */,
                      snap.has_tracks /* is_active */,
                      current,
                      remembered_playback_is_playing(current, true),
                      estimated_playback_position_ms(current),
                      remembered_playback_duration_ms(current));
        } else {
            std::fprintf(stderr,
                "[spirc] set_volume: no parseable value field\n");
        }
    } else {
        std::fprintf(stderr, "[spirc] unhandled endpoint '%s'\n", endpoint.c_str());
    }

    send_reply(key, ok);
}

void SpircDevice::send_reply(const std::string& key, bool success) {
    if (key.empty()) return;
    nlohmann::json r;
    r["type"] = "reply";
    r["key"] = key;
    r["payload"]["success"] = success;
    impl_->ws.send_text(r.dump());
}

bool SpircDevice::remember_command_key(const std::string& key) {
    if (key.empty()) return true;

    std::lock_guard<std::mutex> lock(command_m_);
    for (const auto& seen : recent_command_keys_) {
        if (seen == key) return false;
    }

    recent_command_keys_.push_back(key);
    constexpr size_t kMaxRecentCommandKeys = 64;
    while (recent_command_keys_.size() > kMaxRecentCommandKeys) {
        recent_command_keys_.pop_front();
    }
    return true;
}

bool SpircDevice::remember_command_message_order(
    const std::string& sender,
    uint32_t message_id,
    const std::string& endpoint) {
    if (sender.empty() || message_id == 0) return true;

    std::lock_guard<std::mutex> lock(command_m_);
    auto it = last_command_msg_by_sender_.find(sender);
    if (it != last_command_msg_by_sender_.end() && message_id <= it->second) {
        std::fprintf(stderr,
            "[spirc] stale request ignored endpoint='%s' sender=%s msg=%u "
            "last_msg=%u\n",
            endpoint.c_str(), sender.c_str(), (unsigned)message_id,
            (unsigned)it->second);
        return false;
    }
    last_command_msg_by_sender_[sender] = message_id;
    return true;
}

void SpircDevice::reader_loop() {
    auto last_recv = std::chrono::steady_clock::now();
    uint64_t recv_count = 0;
    while (!stop_flag_.load() && impl_->ws.is_open()) {
        std::string text; bool is_text = false;
        if (!impl_->ws.recv(text, is_text)) {
            auto now = std::chrono::steady_clock::now();
            auto idle_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - last_recv).count();
            std::fprintf(stderr,
                "[spirc] dealer recv failed; "
                "idle_for=%lldms recv_count=%llu (will reconnect on next session activity)\n",
                (long long)idle_ms, (unsigned long long)recv_count);
            break;
        }
        last_recv = std::chrono::steady_clock::now();
        ++recv_count;
        if (text.empty()) continue;
        auto j = nlohmann::json::parse(text, nullptr, false);
        if (j.is_discarded()) {
            std::fprintf(stderr, "[spirc] non-JSON msg (len=%zu)\n", text.size());
            continue;
        }
        std::string type = j.value("type", std::string{});
        if (type == "ping") {
            nlohmann::json p; p["type"] = "pong";
            impl_->ws.send_text(p.dump());
        } else if (type == "message") {
            handle_message(text);
        } else if (type == "request") {
            handle_request(text);
        } else if (type == "pong") {
            // ignore
        } else {
            std::fprintf(stderr, "[spirc] unknown msg type='%s'\n", type.c_str());
        }
    }
    std::fprintf(stderr, "[spirc] reader loop exited\n");
    running_ = false;
}

void SpircDevice::stop() {
    stop_flag_ = true;
    impl_->ws.close();
    if (thread_.joinable()) thread_.join();
    put_stop_ = true;
    {
        std::lock_guard<std::mutex> g(put_m_);
        put_queue_.clear();
    }
    put_cv_.notify_all();
    if (put_thread_.joinable()) put_thread_.join();
    running_ = false;
}

} // namespace librespotc::connect
