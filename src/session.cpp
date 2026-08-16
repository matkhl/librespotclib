// librespotc — Session implementation with async playback thread.

#include "../include/librespotc/librespotc.h"

#include "net/apresolve.h"
#include "net/tcp_socket.h"
#include "net/http_fetch.h"
#include "handshake/handshake.h"
#include "connection/ap_codec.h"
#include "proto/authentication.h"
#include "proto/pb_codec.h"
#include "proto/track.h"
#include "auth/blob.h"
#include "crypto/bcrypt_wrap.h"
#include "zeroconf/zeroconf.h"
#include "spotify_id.h"
#include "dispatcher.h"
#include "audio/storage_resolve.h"
#include "connect/spirc_device.h"
#include "auth/client_token.h"
#include "auth/login5.h"
#include "audio/decrypt_audio.h"
#include "audio/vorbis.h"
#include "audio/ogg_demuxer.h"

#include <windows.h>
#include <timeapi.h>
#pragma comment(lib, "winmm.lib")

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cctype>
#include <cstring>
#include <deque>
#include <cmath>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace librespotc {

namespace {
std::string hex_lower(const std::vector<uint8_t>& bytes) {
    static const char* h = "0123456789abcdef";
    std::string s;
    s.reserve(bytes.size() * 2);
    for (auto b : bytes) { s.push_back(h[b >> 4]); s.push_back(h[b & 0xf]); }
    return s;
}
std::string make_device_id(const std::string& device_name) {
    auto h = crypto::sha1((const uint8_t*)device_name.data(), device_name.size());
    return hex_lower(h);
}
bool is_hex_device_id(const std::string& s) {
    if (s.size() != 40) return false;
    return std::all_of(s.begin(), s.end(), [](unsigned char c) {
        return (c >= '0' && c <= '9') ||
               (c >= 'a' && c <= 'f') ||
               (c >= 'A' && c <= 'F');
    });
}
std::string normalize_device_id(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}
const char* device_type_str(DeviceType t) {
    switch (t) { case DeviceType::Speaker: return "Speaker"; }
    return "Speaker";
}
constexpr size_t SPOTIFY_OGG_HEADER_END = 0xa7;

// Real-time pacing lead. Library is allowed to be at most this many seconds
// of audio ahead of wall-clock before throttling.
constexpr double PACING_LEAD_SECONDS = 4.0;

// Backpressure poll interval when on_audio rejects a frame.
constexpr int BACKPRESSURE_RETRY_MS = 10;
constexpr size_t MAX_ARTWORK_BYTES = 2 * 1024 * 1024;

bool track_has_playable_vorbis_file(const proto::ParsedTrack& t) {
    for (auto& f : t.files) {
        if (f.file_id.size() == 20 &&
            (f.format == 0 || f.format == 1 || f.format == 2)) {
            return true;
        }
    }
    return false;
}

std::string http_stream_detail(const net::HttpStreamResult& r) {
    std::string detail = r.status_text;
    if (!r.phase.empty()) {
        if (!detail.empty()) detail += " ";
        detail += "phase=" + r.phase;
    }
    if (r.winhttp_error != 0) {
        if (!detail.empty()) detail += " ";
        detail += "winhttp_error=" + std::to_string(r.winhttp_error);
    }
    if (r.timed_out) {
        if (!detail.empty()) detail += " ";
        detail += "timed_out=1";
    }
    return detail;
}

float soft_limit_unit(float sample) {
    if (!std::isfinite(sample)) return 0.0f;
    constexpr float knee = 0.90f;
    constexpr float ceiling = 0.995f;
    const float sign = sample < 0.0f ? -1.0f : 1.0f;
    float a = std::fabs(sample);
    if (a <= knee) return sample;
    const float t = (a - knee) / (1.0f - knee);
    a = knee + (ceiling - knee) * (1.0f - std::exp(-t));
    if (a > ceiling) a = ceiling;
    return sign * a;
}

int16_t unit_to_s16(float sample) {
    sample = soft_limit_unit(sample);
    int v = static_cast<int>(std::lround(sample * 32767.0f));
    if (v > 32767) v = 32767;
    if (v < -32768) v = -32768;
    return static_cast<int16_t>(v);
}

float clean_replaygain_volume_ceiling(const audio::ReplayGainData& data,
                                      const audio::ReplayGainConfig& config,
                                      float configured_max) {
    if (!std::isfinite(configured_max) || configured_max < 1.0f) return 1.0f;
    const double gain_db = config.use_album ? data.album_gain_db : data.track_gain_db;
    const double peak = config.use_album ? data.album_peak : data.track_peak;
    if (!std::isfinite(gain_db) || !std::isfinite(peak) || peak <= 0.0) {
        return std::min(configured_max, 1.0f);
    }

    const double normalized_peak =
        peak * std::pow(10.0, (gain_db + config.pregain_db) / 20.0);
    if (!std::isfinite(normalized_peak) || normalized_peak <= 0.0) {
        return std::min(configured_max, 1.0f);
    }

    // Leave margin for downstream filters so max Connect volume does not drive
    // already-normalized loud tracks into saturation.
    const double clean = 0.88 / normalized_peak;
    return static_cast<float>(std::clamp(clean, 1.0, static_cast<double>(configured_max)));
}

const proto::TrackImage* choose_album_image(const proto::ParsedTrack& track) {
    const proto::TrackImage* best = nullptr;
    auto score = [](const proto::TrackImage& image) -> int64_t {
        if (image.width > 0 && image.height > 0) {
            return static_cast<int64_t>(image.width) * image.height;
        }
        // Spotify's Image.Size enum: DEFAULT=0, SMALL=1, LARGE=2, XLARGE=3.
        if (image.size >= 0) return 1000000000ll + image.size;
        return 0;
    };
    int64_t best_score = -1;
    for (const auto& image : track.album_images) {
        if (image.file_id.size() != 20) continue;
        int64_t s = score(image);
        if (!best || s > best_score) {
            best = &image;
            best_score = s;
        }
    }
    return best;
}

std::string spotify_artwork_url(const std::string& artwork_key) {
    if (artwork_key.empty()) return {};
    return "https://i.scdn.co/image/" + artwork_key;
}

std::string detect_image_mime(const std::vector<uint8_t>& bytes) {
    if (bytes.size() >= 3 && bytes[0] == 0xff && bytes[1] == 0xd8 &&
        bytes[2] == 0xff) {
        return "image/jpeg";
    }
    if (bytes.size() >= 8 && bytes[0] == 0x89 && bytes[1] == 'P' &&
        bytes[2] == 'N' && bytes[3] == 'G' && bytes[4] == '\r' &&
        bytes[5] == '\n' && bytes[6] == 0x1a && bytes[7] == '\n') {
        return "image/png";
    }
    if (bytes.size() >= 12 && bytes[0] == 'R' && bytes[1] == 'I' &&
        bytes[2] == 'F' && bytes[3] == 'F' && bytes[8] == 'W' &&
        bytes[9] == 'E' && bytes[10] == 'B' && bytes[11] == 'P') {
        return "image/webp";
    }
    return "application/octet-stream";
}

struct ArtworkCallbackState {
    std::mutex callback_m;
    uint64_t generation = 0;
    bool shutting_down = false;
};
} // namespace

struct Session::Impl {
    Config config;
    bool connected = false;
    TrackInfo current_track_info;
    std::string canonical_username;
    std::string device_id;
    std::string country_code;

    std::unique_ptr<net::TcpSocket> sock;
    std::unique_ptr<connection::ApCodec> codec;
    std::unique_ptr<Dispatcher> disp;
    std::unique_ptr<connect::SpircDevice> spirc;
    std::vector<uint8_t> last_login_blob;
    std::string          last_login_username;
    int32_t              last_login_auth_type = 0;
    std::shared_ptr<ArtworkCallbackState> artwork_state =
        std::make_shared<ArtworkCallbackState>();

    ConnectError err_code = ConnectError::None;
    std::string err_msg;
    std::atomic<bool> connect_cancel_requested{false};

    // Playback thread + controls.
    std::thread playback_thread;
    std::atomic<bool> stop_flag{false};
    std::atomic<bool> paused{false};
    std::atomic<bool> pause_boundary_pending{false};
    std::atomic<uint8_t> pause_boundary_source{0}; // 0=Local, 1=Cloud
    std::atomic<bool> seek_pending{false};
    std::atomic<uint32_t> seek_target_ms{0};
    std::atomic<uint8_t> next_track_source{0}; // 0=Local, 1=Cloud
    std::atomic<uint32_t> current_position_ms{0};
    std::atomic<uint32_t> current_duration_ms{0};
    std::atomic<uint32_t> current_volume{32768};  // 0..65535
    std::atomic<bool> replaygain_enabled{false};
    std::atomic<bool> extra_volume_headroom_enabled{true};
    std::atomic<float> replaygain_clean_volume_max{1.0f};
    std::atomic<bool> equalizer_enabled{false};
    std::array<std::atomic<float>, kEqualizerBandCount> equalizer_bands_db{};
    std::mutex cv_m;
    std::condition_variable cv;
    std::string current_track_uri;

    // Queue + history. queue_ = upcoming tracks. history_ = previously played.
    // Guarded by queue_m. Touched from public API + playback advance.
    mutable std::mutex queue_m;
    std::deque<std::string>  queue_;
    std::vector<std::string> history_;
    // True while an auto-advance is pending — playback thread is exiting and
    // a detached advancer thread will spawn the next start_playback shortly.
    std::atomic<bool> advancing{false};

    // Serializes start_playback / stop_playback so concurrent callers (host
    // play_track + dealer on_transfer + auto-advance worker) don't try to
    // join/replace the playback_thread concurrently.
    std::mutex transitions_m;
    // Serializes AP/dealer rebuilds. Metadata fetch, prefetch and playback can
    // all notice a dead dispatcher; only one of them may relogin at a time.
    std::mutex reconnect_m;
    // Serializes dispatcher use against AP-only resets. Natural track advance,
    // metadata retry and prefetch may all touch Dispatcher concurrently.
    std::mutex ap_io_m;

    // Pre-fetched bundle for the upcoming next track. Populated when the
    // current track is within ~3 s of its end. Used by playback_run to
    // skip metadata+audio_key+storage_resolve at the transition.
    struct Prefetched {
        std::string uri;
        SpotifyId requested_tid;
        SpotifyId resolved_tid;
        proto::ParsedTrack track;
        uint8_t key[16] = {};
        std::vector<std::string> urls;
        proto::TrackFile chosen;
        bool ready = false;
    };
    std::mutex prefetch_m;
    std::shared_ptr<Prefetched> prefetched;
    std::atomic<bool> prefetching{false};

    void set_error(ConnectError c, const std::string& m) {
        err_code = c; err_msg = m;
        std::fprintf(stderr, "[librespotc] %s\n", m.c_str());
    }


    // --- AP / login ---
    bool open_ap() {
        try {
            auto aps = net::resolve_accesspoints();
            for (auto& ap : aps) {
                std::fprintf(stderr, "[librespotc] trying AP %s:%u\n",
                             ap.host.c_str(), (unsigned)ap.port);
                sock = std::make_unique<net::TcpSocket>();
                if (!sock->connect(ap.host, ap.port)) { sock.reset(); continue; }
                try {
                    auto hs = handshake::perform_handshake(*sock);
                    codec = std::make_unique<connection::ApCodec>(
                        std::move(hs.send_cipher), std::move(hs.recv_cipher), *sock);
                    std::fprintf(stderr, "[librespotc] handshake OK with %s\n", ap.host.c_str());
                    return true;
                } catch (const std::exception& e) {
                    std::fprintf(stderr, "[librespotc]   handshake failed: %s\n", e.what());
                    sock.reset();
                }
            }
            set_error(ConnectError::HandshakeFailed, "all APs failed handshake");
            return false;
        } catch (const std::exception& e) {
            set_error(ConnectError::NetworkError, e.what());
            return false;
        }
    }

    bool send_login_and_wait(int32_t auth_type,
                             const std::string& username,
                             const std::vector<uint8_t>& auth_data) {
        auto payload = proto::encode_client_response_encrypted(
            username, (proto::AuthType)auth_type, auth_data, device_id);
        if (!codec->send(connection::cmd::LOGIN, payload)) {
            set_error(ConnectError::NetworkError, "send LOGIN failed");
            return false;
        }
        for (int i = 0; i < 32; ++i) {
            uint8_t cmd = 0;
            std::vector<uint8_t> body;
            if (!codec->recv(cmd, body)) {
                set_error(ConnectError::NetworkError, "recv failed during login");
                return false;
            }
            if (cmd == connection::cmd::AP_WELCOME) {
                auto w = proto::decode_ap_welcome(body.data(), body.size());
                canonical_username = w.canonical_username;
                std::fprintf(stderr, "[librespotc] AP_WELCOME user=%s\n",
                             w.canonical_username.c_str());
                if (!config.cache_dir.empty() && !w.reusable_auth_credentials.empty()) {
                    auth::Credentials c;
                    c.username = w.canonical_username;
                    c.auth_type = w.reusable_auth_credentials_type;
                    c.auth_data = w.reusable_auth_credentials;
                    auth::save_to_cache(config.cache_dir, c);
                    last_login_blob = c.auth_data;
                    last_login_username = c.username;
                    last_login_auth_type = c.auth_type;
                } else {
                    last_login_blob = auth_data;
                    last_login_username = username.empty() ? canonical_username : username;
                    last_login_auth_type = auth_type;
                }
                disp = std::make_unique<Dispatcher>(*codec);
                disp->start();
                connected = true;
                return true;
            } else if (cmd == connection::cmd::COUNTRY_CODE) {
                country_code.assign((const char*)body.data(), body.size());
                std::transform(country_code.begin(), country_code.end(),
                               country_code.begin(), [](unsigned char c) {
                                   return static_cast<char>(std::toupper(c));
                               });
                std::fprintf(stderr, "[librespotc] AP country=%s\n",
                             country_code.c_str());
            } else if (cmd == connection::cmd::AUTH_FAILURE) {
                auto f = proto::decode_auth_failure(body.data(), body.size());
                ConnectError ec = ConnectError::AuthFailed;
                if (f.error_code == 11) ec = ConnectError::PremiumRequired;
                set_error(ec, "AUTH_FAILURE code=" + std::to_string(f.error_code)
                              + " " + f.error_desc);
                return false;
            }
        }
        set_error(ConnectError::AuthFailed, "no AP_WELCOME after 32 packets");
        return false;
    }

    bool login_with_credentials(const auth::Credentials& c) {
        if (!open_ap()) return false;
        if (!send_login_and_wait(c.auth_type, c.username, c.auth_data)) return false;
        audio::init_login5_provider(device_id, last_login_username, last_login_blob);
        start_spirc();
        return true;
    }

    // Re-attach a fresh AP socket + dispatcher while leaving the SpircDevice
    // (and its ctx_state_) alive. Used by ensure_connected when the AP died
    // silently mid-track but the dealer is still healthy — preserves the
    // cloud-driven playback context so handle_natural_end can still
    // auto-advance to the next track without the user re-transferring from
    // their phone.
    bool relogin_ap_preserving_spirc(const auth::Credentials& c) {
        reset_ap_only();
        if (!open_ap()) return false;
        if (!send_login_and_wait(c.auth_type, c.username, c.auth_data)) {
            return false;
        }
        // Deliberately do NOT call audio::init_login5_provider() here.
        // That helper destroys g_ct/g_l5 and rebuilds them, which would
        // invalidate the references SpircDevice holds (ct_, l5_) and lead
        // to use-after-free the next time the dealer sends a PUT state or
        // resolves a context URL. The existing providers self-refresh
        // their tokens on demand, so they remain valid across an AP
        // reconnect.
        return true;
    }

    void start_spirc() {
        auto* ct = audio::get_client_token_provider();
        auto* l5 = audio::get_login5_provider();
        if (!ct || !l5) {
            std::fprintf(stderr, "[spirc] providers not ready, skipping\n");
            return;
        }
        connect::DeviceConfig dc;
        dc.device_id     = device_id;
        dc.device_name   = config.device_name;
        dc.client_id     = "65b708073fc0480ea92a077233ca87bd"; // KEYMASTER
        dc.device_type   = (int32_t)config.device_type;
        dc.initial_volume = config.initial_volume;

        connect::SpircCallbacks cb;
        cb.on_transfer = [this](const std::string& uri, uint32_t pos, bool play) {
            std::fprintf(stderr, "[spirc] cloud transfer uri=%s pos=%u play=%d\n",
                         uri.c_str(), pos, (int)play);
            if (uri.empty()) return;
            // DO NOT eagerly PUT state with the new track URI here. Cloud
            // would then tell the phone we're already playing the new
            // track, but our playback thread still has to: join the old
            // decoder (~100-200 ms), fetch metadata + audio_key +
            // storage_resolve (~200-500 ms), open the new decoder, and
            // wait for the host audio output buffer to drain.
            // During that window the phone shows track B while audio is
            // still track A — and pause/play commands the user sends look
            // like they apply to the wrong track. Let playback_run send
            // the notify_state itself once it's actually ready to emit
            // the new track's PCM.
            std::thread([this, uri, pos, play]{
                if (uri == current_track_uri && playback_thread.joinable() &&
                    !stop_flag.load(std::memory_order_relaxed)) {
                    uint32_t current = current_position_ms.load(
                        std::memory_order_relaxed);
                    uint32_t delta = (pos > current) ? (pos - current)
                                                     : (current - pos);
                    if (pos > 0 && delta > 5000) {
                        seek_target_ms.store(pos);
                        seek_pending.store(true);
                        current_position_ms.store(pos);
                        cv.notify_all();
                        std::fprintf(stderr,
                            "[spirc] coalesced same-track transfer with "
                            "large seek current=%u target=%u delta=%u\n",
                            current, pos, delta);
                    } else {
                        std::fprintf(stderr,
                            "[spirc] coalesced same-track transfer current=%u "
                            "target=%u delta=%u play=%d\n",
                            current, pos, delta, (int)play);
                    }
                    if (play) {
                        if (paused.load(std::memory_order_relaxed)) {
                            do_resume(EventSource::Cloud);
                        }
                    } else {
                        if (pos > 0 && delta > 1000) {
                            seek_target_ms.store(pos);
                            seek_pending.store(true);
                            current_position_ms.store(pos);
                            cv.notify_all();
                        }
                        if (!paused.load(std::memory_order_relaxed)) {
                            do_pause(EventSource::Cloud);
                        }
                    }
                    return;
                }
                start_playback(uri, /*from_cloud=*/true);
                if (pos > 0) {
                    seek_target_ms.store(pos);
                    seek_pending.store(true);
                    cv.notify_all();
                }
                if (!play) {
                    paused.store(true);
                    fire_event(EventType::PlaybackPaused, uri, EventSource::Cloud);
                }
            }).detach();
        };
        cb.on_play  = [this]{ resume_playback(); };
        cb.on_pause = [this]{ pause_playback(); };
        cb.on_seek  = [this](uint32_t ms) {
            seek_target_ms.store(ms);
            seek_pending.store(true);
            current_position_ms.store(ms);
            cv.notify_all();
            // Echo new position to cloud immediately so phone slider tracks.
            if (spirc) spirc->notify_state(true, current_track_uri,
                                           !paused.load(), ms,
                                           current_duration_ms.load());
        };
        cb.on_volume = [this](uint32_t v) {
            current_volume.store(v);
            fire_event(EventType::VolumeChanged, std::to_string(v), EventSource::Cloud);
        };
        cb.on_context_change = [this](const std::string& uri,
                                      const std::string& /*url*/) {
            fire_event(EventType::ContextChanged, uri, EventSource::Cloud);
        };
        cb.on_became_inactive = [this](const std::string& new_active) {
            std::fprintf(stderr,
                "[librespotc] became inactive (new active=%s) — stopping "
                "playback\n", new_active.c_str());
            stop_playback();
            fire_event(EventType::BecameInactive, new_active, EventSource::Cloud);
        };
        cb.on_skip_next = [this]{
            // Cloud sent skip_next with no track URI. Advance local queue if
            // non-empty; otherwise fire SkipNextRequested so the host can
            // drive via Web API.
            std::string next_uri;
            if (queue_pop_front(next_uri)) {
                std::fprintf(stderr,
                    "[librespotc] SPIRC skip_next → advance local queue: %s\n",
                    next_uri.c_str());
                spawn_advance(next_uri, /*from_cloud=*/true);
            } else {
                std::fprintf(stderr,
                    "[librespotc] SPIRC skip_next → queue empty, "
                    "firing SkipNextRequested for host\n");
                fire_event(EventType::SkipNextRequested,
                           current_track_uri, EventSource::Cloud);
            }
        };
        cb.on_skip_prev = [this]{
            std::string prev_uri;
            if (history_pop_back(prev_uri)) {
                // Push current to the front of the queue so a subsequent
                // skip_next returns to it. start_playback will push the
                // *previous* current to history during the transition, but
                // that's the one we just popped — so we manually skip the
                // auto-push for this call to avoid history churn.
                {
                    std::lock_guard<std::mutex> g(queue_m);
                    if (!current_track_uri.empty())
                        queue_.push_front(current_track_uri);
                }
                std::fprintf(stderr,
                    "[librespotc] SPIRC skip_prev → history: %s\n",
                    prev_uri.c_str());
                advancing.store(true);
                std::thread([this, prev_uri]{
                    start_playback(prev_uri, /*from_cloud=*/true,
                                   /*push_history_for_current=*/false);
                    advancing.store(false);
                }).detach();
            } else {
                std::fprintf(stderr,
                    "[librespotc] SPIRC skip_prev → history empty, "
                    "firing SkipPrevRequested for host\n");
                fire_event(EventType::SkipPrevRequested,
                           current_track_uri, EventSource::Cloud);
            }
        };

        spirc = std::make_unique<connect::SpircDevice>(dc, *ct, *l5, std::move(cb));
        if (!spirc->start()) {
            std::fprintf(stderr, "[spirc] failed to start (device not visible)\n");
            spirc.reset();
        } else {
            std::fprintf(stderr, "[spirc] device registered as '%s'\n", dc.device_name.c_str());
        }
    }

    void do_pause(EventSource src) {
        paused.store(true);
        cv.notify_all();
        fire_event(EventType::PlaybackPaused, current_track_uri, src);
        if (spirc) spirc->notify_state(true, current_track_uri,
                                       false, current_position_ms.load(),
                                       current_duration_ms.load());
    }
    void do_resume(EventSource src) {
        paused.store(false);
        pause_boundary_pending.store(false);
        cv.notify_all();
        fire_event(EventType::PlaybackStarted, current_track_uri, src);
        if (spirc) spirc->notify_state(true, current_track_uri,
                                       true, current_position_ms.load(),
                                       current_duration_ms.load());
    }
    void pause_playback() { do_pause(EventSource::Cloud); }
    void resume_playback(){ do_resume(EventSource::Cloud); }

    void request_pause_at_audio_boundary(EventSource src) {
        if (!playback_thread.joinable() || stop_flag.load(std::memory_order_relaxed)) {
            do_pause(src);
            return;
        }
        pause_boundary_source.store(src == EventSource::Cloud ? 1 : 0,
                                    std::memory_order_release);
        pause_boundary_pending.store(true, std::memory_order_release);
        cv.notify_all();
    }

    bool consume_pause_boundary_request() {
        if (!pause_boundary_pending.exchange(false, std::memory_order_acq_rel)) {
            return false;
        }
        EventSource src = pause_boundary_source.load(std::memory_order_acquire) == 1
            ? EventSource::Cloud
            : EventSource::Local;
        do_pause(src);
        return true;
    }

    void fire_event(EventType t, std::string detail, EventSource source = EventSource::Local) {
        if (config.on_event) config.on_event(Event{t, source, std::move(detail)});
    }

    void shutdown_artwork_callbacks() {
        if (!artwork_state) return;
        std::lock_guard<std::mutex> lock(artwork_state->callback_m);
        artwork_state->shutting_down = true;
        ++artwork_state->generation;
    }

    uint64_t begin_track_artwork_generation() {
        if (!artwork_state) return 0;
        std::lock_guard<std::mutex> lock(artwork_state->callback_m);
        if (artwork_state->shutting_down) return 0;
        return ++artwork_state->generation;
    }

    bool invoke_artwork_callback_if_current(
        const std::shared_ptr<ArtworkCallbackState>& state,
        uint64_t generation,
        const TrackArtwork& artwork,
        const TrackArtworkCallback& callback) {
        if (!state || !callback) return false;
        std::lock_guard<std::mutex> lock(state->callback_m);
        if (state->shutting_down || state->generation != generation) {
            return false;
        }
        callback(artwork);
        return true;
    }

    void publish_artwork_pending(const TrackInfo& info, uint64_t generation) {
        if (!config.on_track_artwork) return;
        TrackArtwork artwork;
        artwork.track_id = info.track_id;
        artwork.artwork_key = info.artwork_key;
        artwork.artwork_url = info.artwork_url;
        artwork.available = false;
        artwork.loading = info.artwork_loading;
        invoke_artwork_callback_if_current(
            artwork_state, generation, artwork, config.on_track_artwork);
    }

    void kick_artwork_fetch(const TrackInfo& info, uint64_t generation) {
        if (!config.on_track_artwork || !artwork_state ||
            info.artwork_key.empty() || info.artwork_url.empty()) {
            return;
        }
        auto state = artwork_state;
        auto callback = config.on_track_artwork;
        const std::string track_id = info.track_id;
        const std::string artwork_key = info.artwork_key;
        const std::string artwork_url = info.artwork_url;
        std::thread([state, callback, generation, track_id, artwork_key, artwork_url] {
            std::vector<uint8_t> bytes;
            bytes.reserve(256 * 1024);
            bool too_large = false;
            auto fetch = net::https_get_stream(
                artwork_url, {},
                [&](const uint8_t* chunk, size_t n) -> bool {
                    if (bytes.size() + n > MAX_ARTWORK_BYTES) {
                        too_large = true;
                        return false;
                    }
                    bytes.insert(bytes.end(), chunk, chunk + n);
                    return true;
                });
            if (too_large || fetch.status != 200 || bytes.empty()) {
                TrackArtwork failed;
                failed.track_id = track_id;
                failed.artwork_key = artwork_key;
                failed.artwork_url = artwork_url;
                failed.available = false;
                failed.loading = false;
                std::lock_guard<std::mutex> lock(state->callback_m);
                if (!state->shutting_down && state->generation == generation) {
                    callback(failed);
                }
                return;
            }

            TrackArtwork artwork;
            artwork.track_id = track_id;
            artwork.artwork_key = artwork_key;
            artwork.artwork_url = artwork_url;
            artwork.artwork_mime = detect_image_mime(bytes);
            artwork.artwork_bytes = std::move(bytes);
            artwork.available = true;
            artwork.loading = false;
            std::lock_guard<std::mutex> lock(state->callback_m);
            if (!state->shutting_down && state->generation == generation) {
                callback(artwork);
            }
        }).detach();
    }

    // Tear down AP state. Safe to call repeatedly.
    void close_ap() {
        if (spirc) { spirc->stop(); spirc.reset(); }
        reset_ap_only();
        connected = false;
    }

    // Tear down JUST the AP socket + dispatcher. Leaves SPIRC (dealer
    // WebSocket) running. Used by the metadata-retry path, where the AP may
    // need a fresh socket but the dealer is independent and may still be
    // healthy. Critically, this does NOT call spirc->stop() — calling that
    // from the playback thread while the dealer reader is dispatching a
    // command back into us via on_transfer → start_playback would deadlock.
    void reset_ap_only() {
        std::lock_guard<std::mutex> io_lock(ap_io_m);
        // Dispatcher::stop() joins its reader thread, which may be blocked in
        // ApCodec::recv(). Closing the AP socket first wakes that recv so
        // source switches cannot hang while disconnecting Spotify Connect.
        if (sock) sock->close();
        if (disp) disp->stop();
        disp.reset();
        codec.reset();
        sock.reset();
        connected = false;
    }

    // Ensure dispatcher is alive; reconnect from cached creds if not.
    bool ensure_connected() {
        std::lock_guard<std::mutex> reconnect_lock(reconnect_m);

        bool ap_dead = true;
        {
            std::lock_guard<std::mutex> io_lock(ap_io_m);
            ap_dead = !disp || !disp->alive();
        }
        bool spirc_dead = !spirc || !spirc->is_running();
        if (!ap_dead && !spirc_dead) return true;

        auto rec_start = std::chrono::steady_clock::now();
        // Choose strategy: if AP is dead but dealer is alive, preserve the
        // SpircDevice (and ctx_state_) by reconnecting AP only. Cloud-side
        // playback context survives, so handle_natural_end can still
        // auto-advance after a silent AP death mid-track.
        bool preserve_spirc = ap_dead && !spirc_dead && spirc;
        std::fprintf(stderr,
            "[librespotc] reconnecting (ap_dead=%d spirc_dead=%d) — "
            "preserve_spirc=%d\n",
            (int)ap_dead, (int)spirc_dead, (int)preserve_spirc);
        fire_event(EventType::Reconnecting,
                   ap_dead ? "AP disconnected" : "dealer disconnected");

        if (ap_dead) {
            auth::Credentials c;
            if (!last_login_blob.empty()) {
                c.username = last_login_username;
                c.auth_type = last_login_auth_type;
                c.auth_data = last_login_blob;
            } else if (config.cache_dir.empty()
                       || !auth::load_from_cache(config.cache_dir, c)) {
                fire_event(EventType::TrackError, "reconnect: no cached creds");
                return false;
            }
            if (preserve_spirc) {
                if (!relogin_ap_preserving_spirc(c)) {
                    // Fall back to full rebuild on AP-only reconnect failure
                    // so a transient login glitch doesn't strand the dealer
                    // pointing at a dead AP.
                    connect::SpircDevice::ContextSeed seed =
                        spirc ? spirc->context_seed()
                              : connect::SpircDevice::ContextSeed{};
                    if (seed.current_track_uri.empty()) {
                        seed.current_track_uri = current_track_uri;
                    }
                    std::fprintf(stderr,
                        "[librespotc] AP-only relogin failed (%s) — "
                        "falling back to full rebuild\n", err_msg.c_str());
                    close_ap();
                    if (!login_with_credentials(c)) {
                        fire_event(EventType::TrackError,
                                   "reconnect failed: " + err_msg);
                        return false;
                    }
                    if (spirc) spirc->restore_context(seed);
                }
            } else {
                close_ap();
                if (!login_with_credentials(c)) {
                    fire_event(EventType::TrackError,
                               "reconnect failed: " + err_msg);
                    return false;
                }
                // login_with_credentials already restarts SPIRC.
            }
        } else {
            // AP fine, dealer dead — just restart SPIRC.
            connect::SpircDevice::ContextSeed seed =
                spirc ? spirc->context_seed()
                      : connect::SpircDevice::ContextSeed{};
            if (seed.current_track_uri.empty()) {
                seed.current_track_uri = current_track_uri;
            }
            spirc.reset();
            start_spirc();
            if (spirc) spirc->restore_context(seed);
        }
        auto rec_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - rec_start).count();
        std::fprintf(stderr,
            "[librespotc] reconnect done in %lldms\n", (long long)rec_ms);
        fire_event(EventType::Reconnected, "");
        return true;
    }

    // --- Playback ---

    // Stop any active playback thread (joins). Caller may already hold cv_m.
    void stop_playback_locked() {
        if (artwork_state) {
            std::lock_guard<std::mutex> lock(artwork_state->callback_m);
            ++artwork_state->generation;
        }
        stop_flag.store(true);
        paused.store(false);
        pause_boundary_pending.store(false);
        seek_pending.store(false);
        cv.notify_all();
    }

    void stop_playback() {
        std::lock_guard<std::mutex> g(transitions_m);
        stop_playback_unlocked();
    }

    void stop_playback_unlocked() {
        stop_playback_locked();
        if (playback_thread.joinable()) playback_thread.join();
        stop_flag.store(false);
        paused.store(false);
        pause_boundary_pending.store(false);
        seek_pending.store(false);
    }

    bool start_playback(const std::string& uri, bool from_cloud = false,
                        bool push_history_for_current = true) {
        std::lock_guard<std::mutex> g(transitions_m);
        stop_playback_unlocked();
        if (push_history_for_current && !current_track_uri.empty()
            && current_track_uri != uri) {
            push_history(current_track_uri);
        }
        current_track_uri = uri;
        stop_flag.store(false);
        paused.store(false);
        pause_boundary_pending.store(false);
        seek_pending.store(false);
        next_track_source.store(from_cloud ? 1 : 0);
        playback_thread = std::thread([this, uri]{ playback_run(uri); });
        return true;
    }

    // Pacing helper: blocks until wall-clock is at most lead_seconds behind
    // the given target_ms-since-t0. Respects pause + stop + seek_pending.
    // Returns false on stop, true otherwise.
    bool pace_to(std::chrono::steady_clock::time_point t0, uint64_t target_ms) {
        auto target = t0 + std::chrono::milliseconds(target_ms);
        auto now = std::chrono::steady_clock::now();
        if (target - now > std::chrono::milliseconds(
                (int64_t)(PACING_LEAD_SECONDS * 1000.0))) {
            std::this_thread::sleep_until(
                target - std::chrono::milliseconds(
                    (int64_t)(PACING_LEAD_SECONDS * 1000.0)));
        }
        if (stop_flag.load(std::memory_order_relaxed)) return false;
        {
            std::unique_lock<std::mutex> lk(cv_m);
            cv.wait(lk, [this]{
                return !paused.load() || stop_flag.load() ||
                       seek_pending.load() || pause_boundary_pending.load();
            });
        }
        return !stop_flag.load(std::memory_order_relaxed);
    }

    // Vorbis-packet emit with pace + pause + backpressure.
    // Returns true if accepted, false if stop signalled.
    bool emit_vorbis_packet(const uint8_t* data, size_t bytes, uint64_t pts_ms,
                            std::chrono::steady_clock::time_point t0,
                            uint64_t& last_known_pts_ms) {
        if (!config.on_vorbis_packet) return true;
        uint64_t pts = pts_ms ? pts_ms : last_known_pts_ms;
        if (!pace_to(t0, pts)) return false;
        if (consume_pause_boundary_request()) {
            if (!pace_to(t0, pts)) return false;
        }
        if (seek_pending.load(std::memory_order_relaxed)) return true; // skip
        while (!stop_flag.load(std::memory_order_relaxed)) {
            if (config.on_vorbis_packet(data, bytes, pts)) {
                if (pts_ms) {
                    last_known_pts_ms = pts_ms;
                    current_position_ms.store((uint32_t)pts_ms);
                }
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(BACKPRESSURE_RETRY_MS));
            if (consume_pause_boundary_request()) {
                if (!pace_to(t0, pts)) return false;
            }
            if (seek_pending.load() || stop_flag.load()) return !stop_flag.load();
        }
        return false;
    }

    // Returns false if stop signalled while emitting (track should abort).
    // True if frame accepted or paused/seek interrupted (caller may keep going).
    bool emit_frame(const int16_t* pcm, size_t frames, int sr, int ch,
                    std::chrono::steady_clock::time_point& t0,
                    uint64_t& samples_emitted_at_realtime,
                    uint64_t seek_offset_samples = 0) {
        if (!config.on_audio) return true;
        AudioFormat fmt;
        fmt.sample_rate = (uint32_t)sr;
        fmt.channels    = (uint16_t)ch;
        fmt.bits_per_sample = 16;

        // Pacing: throttle so we never run more than PACING_LEAD_SECONDS
        // ahead of wall-clock. Uses sleep_until + system 1ms timer (set in
        // Session::create via timeBeginPeriod) for accurate Windows timing.
        {
            auto now = std::chrono::steady_clock::now();
            double elapsed = std::chrono::duration<double>(now - t0).count();
            double emitted_secs = (double)samples_emitted_at_realtime / (double)sr;
            double ahead = emitted_secs - elapsed;
            if (ahead > PACING_LEAD_SECONDS) {
                auto wake = t0 + std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                    std::chrono::duration<double>(emitted_secs - PACING_LEAD_SECONDS));
                std::this_thread::sleep_until(wake);
            }
            if (stop_flag.load(std::memory_order_relaxed)) return false;
        }
        if (stop_flag.load(std::memory_order_relaxed)) return false;

        auto wait_paused_and_shift_clock = [&]() -> bool {
            auto wait_start = std::chrono::steady_clock::now();
            {
                std::unique_lock<std::mutex> lk(cv_m);
                cv.wait(lk, [this]{
                    return !paused.load() || stop_flag.load() || seek_pending.load();
                });
            }
            auto waited = std::chrono::steady_clock::now() - wait_start;
            if (waited > std::chrono::milliseconds(1)) {
                t0 += waited;
            }
            return !stop_flag.load(std::memory_order_relaxed);
        };

        // Host-synchronized pause: stop at the next output boundary, before
        // accepting another frame, so Connect state reflects the last frame the
        // host accepted rather than decoder/network lead.
        if (consume_pause_boundary_request()) {
            if (!wait_paused_and_shift_clock()) return false;
        }

        // Pause: wait until !paused.
        auto wait_start = std::chrono::steady_clock::now();
        {
            std::unique_lock<std::mutex> lk(cv_m);
            cv.wait(lk, [this]{
                return !paused.load() || stop_flag.load() ||
                       seek_pending.load() || pause_boundary_pending.load();
            });
        }
        auto waited = std::chrono::steady_clock::now() - wait_start;
        if (waited > std::chrono::milliseconds(1)) {
            t0 += waited;
        }
        if (stop_flag.load(std::memory_order_relaxed)) return false;
        if (consume_pause_boundary_request()) {
            if (!wait_paused_and_shift_clock()) return false;
        }
        if (seek_pending.load(std::memory_order_relaxed)) return true;

        // Optional volume gain (linear, 0..65535 -> multiplier 0..max).
        // Applied to a local copy so we don't mutate caller's buffer in
        // case of backpressure retry. Skipped when host does its own gain.
        std::vector<int16_t> gained;
        const int16_t* emit_pcm = pcm;
        if (config.apply_volume_gain) {
            uint32_t vol = current_volume.load();
            float max_gain = extra_volume_headroom_enabled.load(std::memory_order_relaxed)
                ? config.volume_gain_max
                : 1.0f;
            if (!std::isfinite(max_gain) || max_gain < 0.0f) max_gain = 1.0f;
            if (replaygain_enabled.load(std::memory_order_relaxed)) {
                float clean_max =
                    replaygain_clean_volume_max.load(std::memory_order_relaxed);
                if (std::isfinite(clean_max) && clean_max > 0.0f) {
                    max_gain = std::min(max_gain, clean_max);
                }
            }
            const float gain = (static_cast<float>(vol) / 65535.0f) * max_gain;
            if (gain < 0.999f || gain > 1.001f) {
                const size_t sample_count = frames * (size_t)ch;
                gained.resize(sample_count);
                for (size_t i = 0; i < sample_count; ++i) {
                    const float unit =
                        static_cast<float>(pcm[i]) * (1.0f / 32768.0f) * gain;
                    gained[i] = unit_to_s16(unit);
                }
                emit_pcm = gained.data();
            }
        }
        // Backpressure: retry same frame on host rejection until accepted or stop.
        while (!stop_flag.load(std::memory_order_relaxed)) {
            bool accepted = config.on_audio(emit_pcm, frames, fmt);
            if (accepted) {
                samples_emitted_at_realtime += frames;
                uint32_t new_pos = (uint32_t)(
                    (samples_emitted_at_realtime + seek_offset_samples)
                    * 1000ULL / (uint64_t)sr);
                current_position_ms.store(new_pos);
                // Gapless: trigger prefetch when within ~3s of track end.
                // Cheap atomic-load gate keeps this ~free per frame.
                if (!prefetching.load(std::memory_order_relaxed)) {
                    uint32_t dur = current_duration_ms.load();
                    if (dur > 0 && new_pos + 3000 >= dur) {
                        maybe_kick_prefetch();
                    }
                }
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(BACKPRESSURE_RETRY_MS));
            if (consume_pause_boundary_request()) {
                if (!wait_paused_and_shift_clock()) return false;
            }
            if (seek_pending.load() || stop_flag.load()) return !stop_flag.load();
        }
        return false;
    }

    // Fetch + parse track metadata. On any failure, force AP reconnect and
    // retry once. Returns "" on success; otherwise a specific reason string
    // (e.g. "mercury timeout", "mercury status=503", "parse failed",
    // "reconnect failed").
    std::string fetch_track_metadata_legacy(const SpotifyId& tid, proto::ParsedTrack& out) {
        std::string meta_uri = "hm://metadata/4/track/" + tid.to_base16();
        MercuryResponse resp;
        if (!ensure_connected()) return "reconnect failed";
        {
            std::lock_guard<std::mutex> io_lock(ap_io_m);
            if (!disp || !disp->alive()) {
                return "dispatcher dead";
            }
            if (!disp->mercury_get(meta_uri, resp, 8000)) {
                return disp->alive() ? "mercury timeout" : "mercury transport lost";
            }
            if (resp.status_code < 200 || resp.status_code >= 300) {
                return "mercury status=" + std::to_string(resp.status_code);
            }
            if (resp.parts.empty()) {
                return "mercury empty body";
            }
            if (!proto::parse_track(resp.parts[0].data(), resp.parts[0].size(), out)) {
                return "metadata parse failed";
            }
        }
        return {};
    }

    std::string fetch_track_metadata_extended(const SpotifyId& tid,
                                              proto::ParsedTrack& out,
                                              bool force_token_refresh) {
        constexpr int32_t TRACK_V4 = 10;
        std::string entity_uri = "spotify:track:" + tid.to_base62();
        auto body = proto::encode_extended_metadata_request(
            entity_uri, TRACK_V4, country_code);

        std::map<std::string,std::string> headers;
        std::string auth_err;
        if (!audio::make_spclient_auth_headers(headers, auth_err,
                                               force_token_refresh,
                                               config.oauth_token)) {
            return "auth: " + auth_err;
        }
        headers["Accept"] = "application/x-protobuf";

        std::string url =
            "https://spclient.wg.spotify.com/extended-metadata/v0/extended-metadata"
            "?product=0";
        if (!country_code.empty()) url += "&country=" + country_code;
        auto resp = net::https_post(url, "application/x-protobuf",
                                    body.data(), body.size(), headers);
        if (resp.status != 200) {
            return "spclient status=" + std::to_string(resp.status);
        }

        std::vector<uint8_t> payload;
        if (!proto::parse_extended_metadata_response(resp.body.data(),
                                                     resp.body.size(),
                                                     TRACK_V4, payload)) {
            return "extended-metadata parse failed";
        }
        if (!proto::parse_track(payload.data(), payload.size(), out)) {
            return "track parse failed";
        }
        return {};
    }

    std::string fetch_track_metadata(const SpotifyId& tid, proto::ParsedTrack& out) {
        for (int attempt = 0; attempt < 2; ++attempt) {
            std::string fail_reason;

            proto::ParsedTrack extended_track;
            fail_reason = fetch_track_metadata_extended(
                tid, extended_track, attempt > 0 && config.oauth_token.empty());
            if (fail_reason.empty()) {
                proto::ParsedTrack legacy_track;
                std::string legacy_err = fetch_track_metadata_legacy(tid, legacy_track);
                if (legacy_err.empty() && track_has_playable_vorbis_file(legacy_track)) {
                    out = legacy_track;
                    std::fprintf(stderr,
                        "[metadata] legacy metadata preferred for %s "
                        "(files=%zu, alternatives=%zu; extended_files=%zu)\n",
                        tid.to_base16().c_str(), out.files.size(),
                        out.alternative_gids.size(), extended_track.files.size());
                } else {
                    out = extended_track;
                    std::fprintf(stderr,
                        "[metadata] extended-metadata OK for %s "
                        "(files=%zu, alternatives=%zu; legacy=%s)\n",
                        tid.to_base16().c_str(), out.files.size(),
                        out.alternative_gids.size(),
                        legacy_err.empty() ? "no playable vorbis" : legacy_err.c_str());
                }
                return {};
            }
            std::fprintf(stderr,
                "[metadata] extended-metadata attempt %d failed: %s\n",
                attempt + 1, fail_reason.c_str());

            std::string legacy_err = fetch_track_metadata_legacy(tid, out);
            if (legacy_err.empty()) {
                std::fprintf(stderr,
                    "[metadata] legacy metadata fallback OK for %s (files=%zu, alternatives=%zu)\n",
                    tid.to_base16().c_str(), out.files.size(),
                    out.alternative_gids.size());
                return {};
            }
            fail_reason += "; legacy: " + legacy_err;

            std::fprintf(stderr,
                "[librespotc] metadata fetch attempt %d failed: %s\n",
                attempt + 1, fail_reason.c_str());

            if (attempt == 0) {
                // Force AP-only tear-down so the next attempt gets a fresh
                // socket. Do NOT touch SPIRC (dealer is independent and
                // tearing it down from the playback thread can deadlock with
                // an in-flight on_transfer callback). Parse errors aren't
                // transport issues but a reconnect is cheap and may pick up
                // a different region with usable metadata.
                reset_ap_only();
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            } else {
                return fail_reason;
            }
        }
        return "metadata fetch exhausted retries";
    }

    std::string resolve_audio_source_with_retry(const SpotifyId& tid,
                                                const SpotifyId* fallback_tid,
                                                const proto::TrackFile& chosen,
                                                uint8_t key[16],
                                                std::vector<std::string>& urls,
                                                const char* label) {
        for (int attempt = 0; attempt < 2; ++attempt) {
            std::string fail_reason;
            if (!ensure_connected()) return "reconnect failed";
            {
                std::lock_guard<std::mutex> io_lock(ap_io_m);
                if (!disp || !disp->alive()) {
                    fail_reason = "dispatcher dead";
                } else {
                    std::string key_err;
                    bool key_ok = disp->audio_key_request_ex(
                        tid.bytes.data(), chosen.file_id.data(), key, key_err, 8000);
                    if (!key_ok && fallback_tid
                        && fallback_tid->to_base16() != tid.to_base16()
                        && disp->alive()) {
                        std::fprintf(stderr,
                            "[audio_key] resolved id %s failed (%s), retrying original uri id %s\n",
                            tid.to_base16().c_str(), key_err.c_str(),
                            fallback_tid->to_base16().c_str());
                        key_err.clear();
                        key_ok = disp->audio_key_request_ex(
                            fallback_tid->bytes.data(), chosen.file_id.data(),
                            key, key_err, 8000);
                    }
                    if (!key_ok) {
                        fail_reason = disp->alive()
                            ? "audio_key_request failed"
                            : "audio_key transport lost";
                        if (!key_err.empty()) fail_reason += ": " + key_err;
                    }
                }
                if (fail_reason.empty()) {
                    fail_reason = audio::storage_resolve_audio_ex(
                        *disp, chosen.file_id.data(), urls, 8000,
                        config.oauth_token);
                    if (!fail_reason.empty() && !disp->alive()) {
                        fail_reason = "storage transport lost";
                    }
                    if (fail_reason.empty()) {
                        return {};
                    }
                }
            }

            std::fprintf(stderr,
                "[librespotc] %s audio-source attempt %d failed: %s\n",
                label, attempt + 1, fail_reason.c_str());
            if (attempt == 0) {
                reset_ap_only();
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            } else {
                return fail_reason;
            }
        }
        return "audio-source retries exhausted";
    }

    // Pop the front of queue_ under lock. Returns true + writes URI to out.
    bool queue_pop_front(std::string& out) {
        std::lock_guard<std::mutex> g(queue_m);
        if (queue_.empty()) return false;
        out = std::move(queue_.front());
        queue_.pop_front();
        return true;
    }
    bool history_pop_back(std::string& out) {
        std::lock_guard<std::mutex> g(queue_m);
        if (history_.empty()) return false;
        out = std::move(history_.back());
        history_.pop_back();
        return true;
    }
    void push_history(const std::string& uri) {
        if (uri.empty()) return;
        std::lock_guard<std::mutex> g(queue_m);
        history_.push_back(uri);
        // Bound to a reasonable size — no one needs > 64 back.
        if (history_.size() > 64) history_.erase(history_.begin());
    }

    // Spawn a detached helper thread that performs the queue advance. This
    // is needed when called from inside playback_run — that thread cannot
    // call start_playback on itself (would self-join).
    void spawn_advance(const std::string& next_uri, bool from_cloud) {
        advancing.store(true);
        std::thread([this, next_uri, from_cloud]{
            start_playback(next_uri, from_cloud);
            advancing.store(false);
        }).detach();
    }

    // Gapless: kick a worker to fetch metadata + audio key + CDN URLs for
    // the next track, so the cross-track transition skips ~3 network
    // round-trips. Worker bails if next URI matches what's already prepared.
    void maybe_kick_prefetch() {
        if (!spirc) return;
        std::string next_uri = spirc->peek_next_track_uri();
        if (next_uri.empty()) {
            std::fprintf(stderr, "[prefetch] skip: peek_next empty\n");
            return;
        }
        {
            std::lock_guard<std::mutex> g(prefetch_m);
            if (prefetched && prefetched->uri == next_uri) return;
        }
        bool expected = false;
        if (!prefetching.compare_exchange_strong(expected, true)) return;
        std::fprintf(stderr, "[prefetch] kick: %s\n", next_uri.c_str());
        std::thread([this, next_uri]{
            auto pf_start = std::chrono::steady_clock::now();
            auto bail = [&](const char* reason) {
                auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - pf_start).count();
                std::fprintf(stderr,
                    "[prefetch] BAIL after %lldms: %s (uri=%s)\n",
                    (long long)ms, reason, next_uri.c_str());
                prefetching.store(false);
            };
            auto pf = std::make_shared<Prefetched>();
            pf->uri = next_uri;
            SpotifyId tid;
            if (!SpotifyId::from_uri(next_uri, tid)) {
                bail("invalid URI"); return;
            }
            SpotifyId requested_tid = tid;
            std::string mderr = fetch_track_with_alternative(tid, pf->track);
            if (!mderr.empty()) {
                bail(("metadata: " + mderr).c_str()); return;
            }
            pf->requested_tid = requested_tid;
            pf->resolved_tid = tid;
            int prefer = (config.bitrate == Bitrate::K320) ? 2
                       : (config.bitrate == Bitrate::K96)  ? 0 : 1;
            pf->chosen.format = -1;
            for (int fmt_try : {prefer, 1, 2, 0}) {
                for (auto& f : pf->track.files) {
                    if (f.format == fmt_try && f.file_id.size() == 20) {
                        pf->chosen = f; goto pf_found;
                    }
                }
            }
        pf_found:
            if (pf->chosen.format < 0) { bail("no playable file"); return; }
            std::string src_err = resolve_audio_source_with_retry(
                tid, &requested_tid, pf->chosen, pf->key, pf->urls, "prefetch");
            if (!src_err.empty()) {
                bail(src_err.c_str());
                return;
            }
            pf->ready = true;
            {
                std::lock_guard<std::mutex> g(prefetch_m);
                prefetched = pf;
            }
            std::fprintf(stderr,
                "[prefetch] ready: %s (%zu CDN urls)\n",
                next_uri.c_str(), pf->urls.size());
            prefetching.store(false);
        }).detach();
    }

    // Return + consume the prefetched bundle for `uri`. Returns nullptr if
    // no match.
    std::shared_ptr<Prefetched> take_prefetched(const std::string& uri) {
        std::lock_guard<std::mutex> g(prefetch_m);
        if (prefetched && prefetched->ready && prefetched->uri == uri) {
            auto r = prefetched;
            prefetched.reset();
            return r;
        }
        return {};
    }

    // Predicate: does `t` have any file in a format the library can decode?
    // We only support the OGG_VORBIS_* enum values (0=96k, 1=160k, 2=320k).
    // Anything else (MP3, MP4_*, FLAC, AAC) is delivered DRM-bound by
    // Spotify and not consumable by our vorbis decoder.
    static bool has_playable_vorbis_file(const proto::ParsedTrack& t) {
        return track_has_playable_vorbis_file(t);
    }

    // Stringify the file list for diagnostic logging when no playable
    // variant is found.
    static std::string describe_files(const proto::ParsedTrack& t) {
        if (t.files.empty()) return "<empty>";
        std::string s;
        for (size_t i = 0; i < t.files.size(); ++i) {
            if (i) s.push_back(',');
            s += "fmt=" + std::to_string(t.files[i].format);
            s += "/id_sz=" + std::to_string(t.files[i].file_id.size());
        }
        return s;
    }

    static std::string describe_restrictions(const proto::ParsedTrack& t) {
        if (t.restrictions.empty()) return "<none>";
        std::string s;
        for (size_t i = 0; i < t.restrictions.size(); ++i) {
            auto& r = t.restrictions[i];
            if (i) s += ";";
            s += "{";
            if (!r.countries_allowed.empty())
                s += "allowed=" + r.countries_allowed;
            if (!r.countries_forbidden.empty()) {
                if (s.back() != '{') s += ",";
                s += "forbidden=" + r.countries_forbidden;
            }
            if (!r.catalogue_strs.empty()) {
                if (s.back() != '{') s += ",";
                s += "catalogue=";
                for (size_t j = 0; j < r.catalogue_strs.size(); ++j) {
                    if (j) s += "|";
                    s += r.catalogue_strs[j];
                }
            }
            s += "}";
        }
        return s;
    }

    static bool parsed_gid_to_id(const proto::ParsedTrack& t, SpotifyId& out) {
        return t.gid.size() == 16
            && SpotifyId::from_raw_bytes(t.gid.data(), t.gid.size(), out);
    }

    // Fetch primary metadata; if it has no playable vorbis file, walk
    // t.alternative_gids[] (Spotify's region-substitute mechanism) and use
    // the first alt whose metadata has a playable file. On success, both
    // the returned ParsedTrack and the SpotifyId are updated to point at
    // the alt (so audio_key + storage_resolve target the right gid).
    std::string fetch_track_with_alternative(SpotifyId& tid,
                                              proto::ParsedTrack& out) {
        std::string err = fetch_track_metadata(tid, out);
        if (!err.empty()) return err;
        if (has_playable_vorbis_file(out)) {
            SpotifyId parsed_tid;
            if (parsed_gid_to_id(out, parsed_tid)
                && parsed_tid.to_base16() != tid.to_base16()) {
                std::fprintf(stderr,
                    "[track] metadata relinked %s -> %s for audio_key\n",
                    tid.to_base16().c_str(), parsed_tid.to_base16().c_str());
                tid = parsed_tid;
            }
            return {};
        }

        std::fprintf(stderr,
            "[track] primary %s has no playable vorbis file (files=[%s], "
            "alternatives=%zu, restrictions=%s) — checking alternatives\n",
            tid.to_base16().c_str(),
            describe_files(out).c_str(),
            out.alternative_gids.size(),
            describe_restrictions(out).c_str());


        for (auto& alt_gid : out.alternative_gids) {
            if (alt_gid.size() != 16) continue;
            SpotifyId alt_tid;
            if (!SpotifyId::from_raw_bytes(alt_gid.data(), alt_gid.size(), alt_tid))
                continue;
            proto::ParsedTrack alt_track;
            std::string alt_err = fetch_track_metadata(alt_tid, alt_track);
            if (!alt_err.empty()) {
                std::fprintf(stderr,
                    "[track] alt %s metadata failed: %s\n",
                    alt_tid.to_base16().c_str(), alt_err.c_str());
                continue;
            }
            if (!has_playable_vorbis_file(alt_track)) {
                std::fprintf(stderr,
                    "[track] alt %s also has no playable file (files=[%s])\n",
                    alt_tid.to_base16().c_str(),
                    describe_files(alt_track).c_str());
                continue;
            }
            SpotifyId parsed_alt_tid;
            if (parsed_gid_to_id(alt_track, parsed_alt_tid)
                && parsed_alt_tid.to_base16() != alt_tid.to_base16()) {
                std::fprintf(stderr,
                    "[track] alt metadata relinked %s -> %s for audio_key\n",
                    alt_tid.to_base16().c_str(), parsed_alt_tid.to_base16().c_str());
                alt_tid = parsed_alt_tid;
            }
            std::fprintf(stderr,
                "[track] using alt %s in place of region-restricted %s\n",
                alt_tid.to_base16().c_str(), tid.to_base16().c_str());
            tid = alt_tid;
            out = std::move(alt_track);
            return {};
        }
        return "unplayable: no playable vorbis file (primary + all alternatives; "
               "primary files=[" + describe_files(out) + "], restrictions="
               + describe_restrictions(out) + ")";
    }

    bool try_advance_after_unplayable(const std::string& failed_uri,
                                      const std::string& reason) {
        std::string next_uri;
        if (queue_pop_front(next_uri)) {
            std::fprintf(stderr,
                "[play] skipping unplayable track %s via local queue: %s; next=%s\n",
                failed_uri.c_str(), reason.c_str(), next_uri.c_str());
            spawn_advance(next_uri, /*from_cloud=*/false);
            return true;
        }
        if (spirc) {
            next_uri = spirc->advance_to_next_track();
            if (!next_uri.empty()) {
                std::fprintf(stderr,
                    "[play] skipping unplayable track %s via context: %s; next=%s\n",
                    failed_uri.c_str(), reason.c_str(), next_uri.c_str());
                spawn_advance(next_uri, /*from_cloud=*/true);
                return true;
            }
        }
        return false;
    }

    void playback_run(const std::string& uri) {
        SpotifyId tid;
        if (!SpotifyId::from_uri(uri, tid)) {
            fire_event(EventType::TrackError, "invalid_uri: " + uri);
            return;
        }
        SpotifyId requested_tid = tid;

        // Gapless: try to consume a pre-fetched bundle for this URI.
        std::shared_ptr<Prefetched> pf = take_prefetched(uri);

        proto::ParsedTrack t;
        if (pf) {
            t = pf->track;
            requested_tid = pf->requested_tid;
            tid = pf->resolved_tid;
            std::fprintf(stderr, "[prefetch] hit for %s — skipping "
                         "metadata+audio_key+storage_resolve\n", uri.c_str());
        } else {
            std::string err = fetch_track_with_alternative(tid, t);
            if (!err.empty()) {
                if (err.rfind("unplayable:", 0) == 0
                    && try_advance_after_unplayable(uri, err)) {
                    return;
                }
                fire_event(EventType::TrackError, "metadata_unavailable: " + err);
                return;
            }
        }
        current_track_info.track_id = tid.to_base16();
        current_track_info.title  = t.name;
        current_track_info.artist = t.artist;
        current_track_info.album  = t.album;
        current_track_info.duration_ms = (uint32_t)t.duration_ms;
        current_track_info.artwork_key.clear();
        current_track_info.artwork_url.clear();
        current_track_info.artwork_mime.clear();
        current_track_info.artwork_loading = false;
        if (const auto* image = choose_album_image(t)) {
            current_track_info.artwork_key = hex_lower(image->file_id);
            current_track_info.artwork_url =
                spotify_artwork_url(current_track_info.artwork_key);
            current_track_info.artwork_loading = !current_track_info.artwork_url.empty();
        }
        uint64_t artwork_generation = begin_track_artwork_generation();
        current_duration_ms.store((uint32_t)t.duration_ms);
        if (config.on_track_change) config.on_track_change(current_track_info);
        publish_artwork_pending(current_track_info, artwork_generation);
        kick_artwork_fetch(current_track_info, artwork_generation);
        EventSource src = (next_track_source.load() == 1) ? EventSource::Cloud : EventSource::Local;
        fire_event(EventType::TrackChanged, uri, src);
        // Respect current paused state set by transfer / pause command.
        bool is_playing = !paused.load(std::memory_order_relaxed);
        uint32_t start_pos = seek_pending.load() ? seek_target_ms.load() : 0;
        current_position_ms.store(start_pos);
        if (is_playing) fire_event(EventType::PlaybackStarted, uri, src);
        else            fire_event(EventType::PlaybackPaused,  uri, src);
        if (spirc) spirc->notify_state(true, uri, is_playing, start_pos,
                                       current_duration_ms.load());
        std::fprintf(stderr, "[play] %s — %s (%s) %d ms\n",
                     t.artist.c_str(), t.name.c_str(), t.album.c_str(), t.duration_ms);

        // Select file. Prefer the prefetched bundle's results when present.
        int prefer = (config.bitrate == Bitrate::K320) ? 2
                   : (config.bitrate == Bitrate::K96)  ? 0 : 1;
        proto::TrackFile chosen; chosen.format = -1;
        if (pf) {
            chosen = pf->chosen;
        } else {
            for (int fmt_try : {prefer, 1, 2, 0}) {
                for (auto& f : t.files) {
                    if (f.format == fmt_try && f.file_id.size() == 20) { chosen = f; goto found; }
                }
            }
        found:
            if (chosen.format < 0) {
                std::string err =
                    "unplayable: no supported OGG_VORBIS file in selected metadata";
                if (try_advance_after_unplayable(uri, err)) return;
                fire_event(EventType::TrackError, err);
                return;
            }
        }

        uint8_t key[16];
        if (pf) {
            std::memcpy(key, pf->key, 16);
        }
        std::vector<std::string> urls;
        if (pf) {
            urls = pf->urls;
        } else {
            std::string src_err = resolve_audio_source_with_retry(
                tid, &requested_tid, chosen, key, urls, "playback");
            if (!src_err.empty()) {
                fire_event(EventType::TrackError,
                           "audio_source: " + src_err);
                return;
            }
        }

        // Buffered stream. file_buf accumulates plaintext audio bytes (after
        // CTR decrypt + Spotify 167-byte header strip). Push decoder consumes
        // sequentially. Seek = re-init decoder over file_buf from byte 0,
        // skip emit until target_samples reached.
        std::vector<uint8_t> file_buf;
        file_buf.reserve(4 * 1024 * 1024);

        size_t total_downloaded = 0;
        size_t header_left = SPOTIFY_OGG_HEADER_END;
        std::array<uint8_t, SPOTIFY_OGG_HEADER_END> spotify_header{};
        size_t spotify_header_bytes = 0;
        auto capture_spotify_header = [&](const uint8_t* bytes, size_t n) {
            if (spotify_header_bytes >= spotify_header.size() || n == 0) return;
            size_t take = std::min(n, spotify_header.size() - spotify_header_bytes);
            std::memcpy(spotify_header.data() + spotify_header_bytes, bytes, take);
            spotify_header_bytes += take;
        };

        bool vorbis_tap = (config.on_vorbis_packet || config.on_vorbis_stream);

        // ===== Vorbis-tap mode =====
        if (vorbis_tap) {
            auto vorb_t0 = std::chrono::steady_clock::now();
            uint64_t last_pts_ms = 0;
            bool emit_error = false;

            audio::OggDemuxer demuxer(
                [this](const uint8_t* hdrs, size_t bytes, uint32_t rate,
                       uint16_t ch, uint32_t bps) {
                    if (config.on_vorbis_stream) {
                        VorbisStreamInfo info;
                        info.setup_data = hdrs;
                        info.setup_bytes = bytes;
                        info.sample_rate = rate;
                        info.channels = ch;
                        info.bitrate_nominal_bps = bps;
                        config.on_vorbis_stream(info);
                    }
                    std::fprintf(stderr, "[vorbis-tap] headers ready: %u Hz x %u ch, %u bps, %zu bytes\n",
                                 rate, (unsigned)ch, bps, bytes);
                },
                [this, &vorb_t0, &last_pts_ms, &emit_error]
                (const uint8_t* data, size_t bytes, uint64_t pts_ms) -> bool {
                    if (!emit_vorbis_packet(data, bytes, pts_ms, vorb_t0, last_pts_ms)) {
                        emit_error = true;
                        return false;
                    }
                    return true;
                });

            bool any_url_ok = false;
            net::HttpStreamResult fetch;
            for (auto& u : urls) {
                total_downloaded = 0;
                header_left = SPOTIFY_OGG_HEADER_END;
                spotify_header_bytes = 0;
                fetch = net::https_get_stream(u, {},
                    [&](const uint8_t* chunk, size_t n) -> bool {
                        if (stop_flag.load()) return false;
                        std::vector<uint8_t> tmp(chunk, chunk + n);
                        crypto::aes128_ctr_at(key, audio::AUDIO_IV, total_downloaded,
                                              tmp.data(), tmp.size());
                        total_downloaded += n;
                        capture_spotify_header(tmp.data(), n);
                        size_t off = 0;
                        if (header_left > 0) {
                            size_t drop = (header_left < n) ? header_left : n;
                            off = drop;
                            header_left -= drop;
                        }
                        if (off < n) {
                            if (!demuxer.push(tmp.data() + off, n - off)) {
                                return false;
                            }
                        }
                        return !stop_flag.load();
                    });
                if (fetch.status == 200 && fetch.complete) {
                    any_url_ok = true;
                    break;
                }
                if (fetch.aborted_by_sink && (stop_flag.load() || emit_error)) {
                    break;
                }
                std::fprintf(stderr,
                    "[play] CDN status=%d complete=%d aborted=%d bytes=%llu/%s detail=\"%s\" (%s)\n",
                    fetch.status, (int)fetch.complete, (int)fetch.aborted_by_sink,
                    (unsigned long long)fetch.bytes_read,
                    fetch.content_length_known
                        ? std::to_string(fetch.content_length).c_str()
                        : "?",
                    http_stream_detail(fetch).c_str(),
                    u.c_str());
            }
            if (!any_url_ok) {
                fire_event(EventType::TrackError,
                           "cdn: all URLs failed or incomplete, last status="
                           + std::to_string(fetch.status)
                           + " bytes=" + std::to_string(fetch.bytes_read)
                           + "/"
                           + (fetch.content_length_known
                               ? std::to_string(fetch.content_length)
                               : "?")
                           + " " + http_stream_detail(fetch));
                return;
            }
            if (stop_flag.load()) return;
            if (emit_error) {
                fire_event(EventType::TrackError, "output: vorbis emit error");
                return;
            }
            std::fprintf(stderr, "[play] vorbis-tap done (downloaded %zu bytes)\n",
                         total_downloaded);
            handle_natural_end();
            return;
        }

        // ===== PCM mode (default) =====
        audio::ReplayGainData replaygain_data;
        audio::ReplayGainConfig replaygain_config;
        replaygain_config.enabled = true;
        replaygain_config.enabled_flag = &replaygain_enabled;
        audio::EqualizerRuntimeConfig equalizer_config;
        equalizer_config.enabled = config.equalizer.enabled;
        equalizer_config.enabled_flag = &equalizer_enabled;
        for (size_t i = 0; i < kEqualizerBandCount; ++i) {
            equalizer_config.bands_db[i] = config.equalizer.bands_db[i];
            equalizer_config.band_flags[i] = &equalizer_bands_db[i];
        }

        // Decoder state
        struct DecState {
            audio::StreamingDecoder* decoder = nullptr;
            uint64_t samples_decoded = 0;
            uint64_t samples_emitted = 0;
            uint64_t target_skip_samples = 0;
            std::chrono::steady_clock::time_point t0;
        } ds;
        ds.t0 = std::chrono::steady_clock::now();

        auto open_decoder = [&](uint64_t target_samples) {
            if (ds.decoder) { delete ds.decoder; ds.decoder = nullptr; }
            ds.samples_decoded = 0;
            ds.samples_emitted = 0;
            ds.target_skip_samples = target_samples;
            ds.t0 = std::chrono::steady_clock::now();
            ds.decoder = new audio::StreamingDecoder(
                [this, &ds](const int16_t* pcm, size_t fc, int sr, int ch) -> bool {
                    if (stop_flag.load()) return false;

                    // Skip samples until we reach seek target.
                    if (ds.samples_decoded + fc <= ds.target_skip_samples) {
                        ds.samples_decoded += fc;
                        return true; // consumed but not emitted
                    }
                    size_t skip = 0;
                    if (ds.samples_decoded < ds.target_skip_samples) {
                        skip = (size_t)(ds.target_skip_samples - ds.samples_decoded);
                        ds.samples_decoded = ds.target_skip_samples;
                    }
                    ds.samples_decoded += (fc - skip);

                    if (skip >= fc) return true;
                    const int16_t* p = pcm + skip * (size_t)ch;
                    size_t emit_frames = fc - skip;
                    return emit_frame(p, emit_frames, sr, ch,
                                      ds.t0, ds.samples_emitted,
                                      ds.target_skip_samples);
                },
                replaygain_config,
                replaygain_data,
                equalizer_config);
        };

        // Push helper: feed bytes to current decoder until exhausted or
        // backpressure signals abort.
        auto drain_decoder = [&]() -> bool {
            // We just feed the latest unconsumed slice. StreamingDecoder
            // keeps its own buffer internally for partial frames.
            return true;
        };
        (void)drain_decoder;

        bool decode_error = false;
        bool aborted = false;
        net::HttpStreamResult fetch;
        bool retry_from_last_position = false;
        for (auto& u : urls) {
            uint32_t retry_ms = retry_from_last_position
                ? current_position_ms.load(std::memory_order_relaxed)
                : 0;
            if (seek_pending.load(std::memory_order_relaxed)) {
                retry_ms = seek_target_ms.load(std::memory_order_relaxed);
            }
            uint64_t initial_target_samples =
                (uint64_t)retry_ms * 44100ULL / 1000ULL;

            total_downloaded = 0;
            header_left = SPOTIFY_OGG_HEADER_END;
            spotify_header_bytes = 0;
            replaygain_data = audio::ReplayGainData{};
            file_buf.clear();
            if (ds.decoder) { delete ds.decoder; ds.decoder = nullptr; }
            if (retry_ms > 0) {
                std::fprintf(stderr,
                             "[play] CDN retry resume target=%ums url=%s\n",
                             retry_ms, u.c_str());
            }

            fetch = net::https_get_stream(u, {},
                [&](const uint8_t* chunk, size_t n) -> bool {
                    if (stop_flag.load()) { aborted = true; return false; }

                    std::vector<uint8_t> tmp(chunk, chunk + n);
                    crypto::aes128_ctr_at(key, audio::AUDIO_IV, total_downloaded,
                                          tmp.data(), tmp.size());
                    total_downloaded += n;
                    capture_spotify_header(tmp.data(), n);

                    size_t off = 0;
                    if (header_left > 0) {
                        size_t drop = (header_left < n) ? header_left : n;
                        off = drop;
                        header_left -= drop;
                        if (header_left == 0) {
                            replaygain_data = audio::parse_spotify_replaygain_header(
                                spotify_header.data(), spotify_header_bytes);
                            replaygain_clean_volume_max.store(
                                clean_replaygain_volume_ceiling(
                                    replaygain_data,
                                    replaygain_config,
                                    config.volume_gain_max),
                                std::memory_order_relaxed);
                            if (replaygain_enabled.load(std::memory_order_relaxed)) {
                                std::fprintf(stderr,
                                             "[replaygain] track_gain=%.2f dB peak=%.6f album_gain=%.2f dB album_peak=%.6f clean_max=%.3f\n",
                                             replaygain_data.track_gain_db,
                                             replaygain_data.track_peak,
                                             replaygain_data.album_gain_db,
                                             replaygain_data.album_peak,
                                             replaygain_clean_volume_max.load(std::memory_order_relaxed));
                            }
                            if (ds.decoder) { delete ds.decoder; ds.decoder = nullptr; }
                            open_decoder(initial_target_samples);
                        }
                    }
                    if (off < n) {
                        if (!ds.decoder) open_decoder(initial_target_samples);
                        file_buf.insert(file_buf.end(),
                                        tmp.data() + off, tmp.data() + n);
                        if (!ds.decoder->push(tmp.data() + off, n - off)) {
                            decode_error = true;
                            return false;
                        }
                    }

                    // Handle seek requests between chunks.
                    if (seek_pending.exchange(false)) {
                        uint32_t ms = seek_target_ms.load();
                        int sr = ds.decoder->sample_rate() > 0 ? ds.decoder->sample_rate() : 44100;
                        uint64_t target = (uint64_t)ms * (uint64_t)sr / 1000;
                        std::fprintf(stderr, "[play] seek %ums (buf=%zu B)\n",
                                     ms, file_buf.size());
                        open_decoder(target);
                        if (!file_buf.empty()) {
                            if (!ds.decoder->push(file_buf.data(), file_buf.size())) {
                                decode_error = true;
                                return false;
                            }
                        }
                    }
                    return !stop_flag.load();
                });
            if (fetch.status == 200 && fetch.complete) break;
            if (fetch.aborted_by_sink &&
                (stop_flag.load() || aborted || decode_error)) {
                break;
            }
            std::fprintf(stderr,
                "[play] CDN status=%d complete=%d aborted=%d bytes=%llu/%s detail=\"%s\" (%s)\n",
                fetch.status, (int)fetch.complete, (int)fetch.aborted_by_sink,
                (unsigned long long)fetch.bytes_read,
                fetch.content_length_known
                    ? std::to_string(fetch.content_length).c_str()
                    : "?",
                http_stream_detail(fetch).c_str(),
                u.c_str());
            retry_from_last_position =
                !stop_flag.load(std::memory_order_relaxed) &&
                !aborted &&
                !decode_error &&
                current_position_ms.load(std::memory_order_relaxed) > 0;
        }

        if (ds.decoder) {
            if (!decode_error && !aborted && !stop_flag.load()) ds.decoder->finish();
            delete ds.decoder;
            ds.decoder = nullptr;
        }

        if (stop_flag.load()) {
            // Quiet exit on user-initiated stop_track / disconnect.
            return;
        }
        if (decode_error) {
            fire_event(EventType::TrackError, "decode: vorbis decode error");
            return;
        }
        if (fetch.status != 200 || !fetch.complete) {
            fire_event(EventType::TrackError,
                       "cdn: all URLs failed or incomplete, last status="
                       + std::to_string(fetch.status)
                       + " bytes=" + std::to_string(fetch.bytes_read)
                       + "/"
                       + (fetch.content_length_known
                           ? std::to_string(fetch.content_length)
                           : "?")
                       + " " + http_stream_detail(fetch));
            return;
        }
        handle_natural_end();
    }

    // Called by playback_run when the current track finishes naturally.
    // If the queue has more, push current to history + spawn next playback.
    // Otherwise fire TrackEnded for the host.
    void handle_natural_end() {
        // 1. Host-driven local queue (Session::enqueue) takes priority.
        std::string next_uri;
        if (queue_pop_front(next_uri)) {
            std::fprintf(stderr,
                "[handle_natural_end] path=LOCAL_QUEUE next=%s\n",
                next_uri.c_str());
            spawn_advance(next_uri, /*from_cloud=*/false);
            return;
        }
        // 2. Walk the cloud-driven context (album / playlist / autoplay).
        if (spirc) {
            std::string ctx_next = spirc->advance_to_next_track();
            if (!ctx_next.empty()) {
                std::fprintf(stderr,
                    "[handle_natural_end] path=CONTEXT_ADVANCE next=%s\n",
                    ctx_next.c_str());
                spawn_advance(ctx_next, /*from_cloud=*/true);
                return;
            }
        }
        // 3. Truly nothing left — tell the host.
        std::fprintf(stderr,
            "[handle_natural_end] path=TRACK_ENDED (queue empty, context "
            "exhausted) — no next track, cloud will see us idle until "
            "next cloud-driven transfer\n");
        fire_event(EventType::TrackEnded, current_track_info.track_id);
    }
};

Session::Session() : impl_(std::make_unique<Impl>()) {}
Session::~Session() {
    impl_->connect_cancel_requested.store(true, std::memory_order_release);
    impl_->shutdown_artwork_callbacks();
    impl_->stop_playback();
    impl_->close_ap();
}

namespace {
struct WinTimerRaise {
    WinTimerRaise()  { timeBeginPeriod(1); }
    ~WinTimerRaise() { timeEndPeriod(1); }
};
} // namespace

std::unique_ptr<Session> Session::create(const Config& config) {
    static WinTimerRaise s_timer_raise; // one-time per process: 1ms timer for pacing
    auto s = std::unique_ptr<Session>(new Session());
    s->impl_->config = config;
    s->impl_->device_id = is_hex_device_id(config.device_id)
        ? normalize_device_id(config.device_id)
        : make_device_id(config.device_name);
    s->impl_->current_volume.store(config.initial_volume);
    s->impl_->replaygain_enabled.store(config.apply_replaygain);
    s->impl_->extra_volume_headroom_enabled.store(config.apply_replaygain);
    s->impl_->equalizer_enabled.store(config.equalizer.enabled);
    for (size_t i = 0; i < kEqualizerBandCount; ++i) {
        s->impl_->equalizer_bands_db[i].store(config.equalizer.bands_db[i]);
    }
    return s;
}

bool Session::connect() {
    auto& I = *impl_;
    I.err_code = ConnectError::None;
    I.err_msg.clear();
    I.connect_cancel_requested.store(false, std::memory_order_release);

    auth::Credentials c;
    if (!I.config.cache_dir.empty() && auth::load_from_cache(I.config.cache_dir, c)
        && !c.auth_data.empty()) {
        std::fprintf(stderr, "[librespotc] using cached credentials for '%s'\n",
                     c.username.c_str());
        if (I.login_with_credentials(c)) return true;
        std::fprintf(stderr, "[librespotc] cached login failed, falling back\n");
        I.close_ap();
    }
    if (!I.config.oauth_token.empty()) {
        if (connect_with_oauth_token(I.config.oauth_token)) return true;
    }
    return connect_via_zeroconf(0);
}

bool Session::connect_with_oauth_token(const std::string& token) {
    auth::Credentials c;
    c.username.clear();
    c.auth_type = (int32_t)proto::AuthType::SPOTIFY_TOKEN;
    c.auth_data.assign(token.begin(), token.end());
    return impl_->login_with_credentials(c);
}

bool Session::connect_via_zeroconf(uint32_t timeout_ms) {
    auto& I = *impl_;
    I.connect_cancel_requested.store(false, std::memory_order_release);
    zeroconf::Config zc;
    zc.device_name = I.config.device_name;
    zc.device_id   = I.device_id;
    zc.device_type = device_type_str(I.config.device_type);
    zc.client_id   = I.config.client_id;
    zc.port        = I.config.zeroconf_port;

    zeroconf::ZeroconfService svc(zc);
    if (!svc.start()) {
        I.set_error(ConnectError::Internal, "zeroconf start failed");
        return false;
    }
    std::fprintf(stderr, "[librespotc] zeroconf ready. Pick '%s' in Spotify app.\n",
                 I.config.device_name.c_str());
    auth::Credentials c;
    bool got_credentials = false;
    if (timeout_ms == 0) {
        while (!I.connect_cancel_requested.load(std::memory_order_acquire)) {
            if (svc.wait_for_credentials(c, 100)) {
                got_credentials = true;
                break;
            }
        }
    } else {
        const auto deadline = std::chrono::steady_clock::now()
            + std::chrono::milliseconds(timeout_ms);
        while (!I.connect_cancel_requested.load(std::memory_order_acquire)) {
            const auto now = std::chrono::steady_clock::now();
            if (now >= deadline) break;
            const auto remaining =
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    deadline - now);
            const uint32_t slice_ms = static_cast<uint32_t>(
                std::min<int64_t>(100, std::max<int64_t>(1, remaining.count())));
            if (svc.wait_for_credentials(c, slice_ms)) {
                got_credentials = true;
                break;
            }
        }
    }
    if (!got_credentials) {
        svc.stop();
        if (I.connect_cancel_requested.load(std::memory_order_acquire)) {
            I.set_error(ConnectError::ZeroconfTimeout, "zeroconf cancelled");
        } else {
            I.set_error(ConnectError::ZeroconfTimeout, "no credentials received");
        }
        return false;
    }
    svc.stop();
    return I.login_with_credentials(c);
}

bool Session::play_track(const std::string& uri) {
    // Clear pending queue (caller's "play this" overrides what's coming up).
    // History is preserved so previous() can step back to recently-played
    // tracks. start_playback will push the current URI onto history.
    {
        std::lock_guard<std::mutex> g(impl_->queue_m);
        impl_->queue_.clear();
    }
    // Host-initiated: no cloud playback context. Clear it so PUT state
    // reflects "playing a single track", not a stale playlist.
    if (impl_->spirc) impl_->spirc->clear_context();
    return impl_->start_playback(uri);
}

void Session::enqueue(const std::string& uri) {
    bool start_now = false;
    {
        std::lock_guard<std::mutex> g(impl_->queue_m);
        impl_->queue_.push_back(uri);
        // If no track is currently playing and no advance pending, start now.
        bool playing = impl_->playback_thread.joinable() &&
                       !impl_->stop_flag.load();
        if (!playing && !impl_->advancing.load() &&
            impl_->current_track_uri.empty()) {
            start_now = true;
            impl_->queue_.pop_back();
        }
    }
    if (start_now) impl_->start_playback(uri);
}

void Session::enqueue_next(const std::string& uri) {
    bool start_now = false;
    {
        std::lock_guard<std::mutex> g(impl_->queue_m);
        impl_->queue_.push_front(uri);
        bool playing = impl_->playback_thread.joinable() &&
                       !impl_->stop_flag.load();
        if (!playing && !impl_->advancing.load() &&
            impl_->current_track_uri.empty()) {
            start_now = true;
            impl_->queue_.pop_front();
        }
    }
    if (start_now) impl_->start_playback(uri);
}

void Session::clear_queue() {
    std::lock_guard<std::mutex> g(impl_->queue_m);
    impl_->queue_.clear();
}

size_t Session::queue_size() const {
    std::lock_guard<std::mutex> g(impl_->queue_m);
    return impl_->queue_.size();
}

std::vector<std::string> Session::queue_snapshot() const {
    std::lock_guard<std::mutex> g(impl_->queue_m);
    return std::vector<std::string>(impl_->queue_.begin(), impl_->queue_.end());
}

bool Session::next() {
    std::string next_uri;
    if (!impl_->queue_pop_front(next_uri)) {
        if (impl_->spirc) {
            // Host-driven "next" should always move to another track when a
            // resolved context exists. Natural endings and cloud skip commands
            // still respect the cloud repeat options.
            next_uri = impl_->spirc->advance_to_next_track(
                /*force_wrap=*/true,
                /*ignore_repeat_track=*/true);
        }
        if (next_uri.empty()) return false;
    }
    // start_playback pushes the current URI onto history.
    return impl_->start_playback(next_uri, /*from_cloud=*/false);
}

bool Session::previous() {
    std::string prev_uri;
    if (!impl_->history_pop_back(prev_uri)) return false;
    {
        std::lock_guard<std::mutex> g(impl_->queue_m);
        if (!impl_->current_track_uri.empty())
            impl_->queue_.push_front(impl_->current_track_uri);
    }
    // Skip auto-history push — current is going to queue front, not history.
    return impl_->start_playback(prev_uri, /*from_cloud=*/false,
                                 /*push_history_for_current=*/false);
}

void Session::pause()  { impl_->do_pause(EventSource::Local); }
void Session::pause_at_audio_boundary() {
    impl_->request_pause_at_audio_boundary(EventSource::Local);
}
void Session::resume() { impl_->do_resume(EventSource::Local); }

bool Session::seek(uint32_t position_ms) {
    impl_->seek_target_ms.store(position_ms);
    impl_->seek_pending.store(true);
    impl_->current_position_ms.store(position_ms);
    impl_->cv.notify_all();
    // Echo the new position to the cloud so the Spotify app's slider updates
    // immediately (mirrors the cloud on_seek path). Without this, a host-driven
    // seek leaves the app showing the stale position until the next
    // pause/resume/track-change state PUT.
    if (impl_->spirc)
        impl_->spirc->notify_state(true, impl_->current_track_uri,
                                   !impl_->paused.load(), position_ms,
                                   impl_->current_duration_ms.load());
    return true;
}

uint32_t Session::current_position_ms() const {
    return impl_->current_position_ms.load(std::memory_order_relaxed);
}

void Session::stop_track() { impl_->stop_playback(); }

void Session::disconnect() {
    impl_->connect_cancel_requested.store(true, std::memory_order_release);
    impl_->stop_playback();
    impl_->close_ap();
}

bool Session::is_connected() const { return impl_->connected; }
TrackInfo    Session::current_track()       const { return impl_->current_track_info; }
ConnectError Session::last_error()          const { return impl_->err_code; }
std::string  Session::last_error_message()  const { return impl_->err_msg; }
std::string  Session::spotify_device_id()   const { return impl_->device_id; }

uint32_t Session::current_volume() const {
    return impl_->current_volume.load();
}

void Session::set_replaygain_enabled(bool enabled) {
    impl_->replaygain_enabled.store(enabled, std::memory_order_relaxed);
}

bool Session::replaygain_enabled() const {
    return impl_->replaygain_enabled.load(std::memory_order_relaxed);
}

void Session::set_extra_volume_headroom_enabled(bool enabled) {
    impl_->extra_volume_headroom_enabled.store(enabled, std::memory_order_relaxed);
}

bool Session::extra_volume_headroom_enabled() const {
    return impl_->extra_volume_headroom_enabled.load(std::memory_order_relaxed);
}

void Session::set_equalizer_enabled(bool enabled) {
    impl_->equalizer_enabled.store(enabled, std::memory_order_relaxed);
}

bool Session::equalizer_enabled() const {
    return impl_->equalizer_enabled.load(std::memory_order_relaxed);
}

void Session::set_equalizer_bands(const std::array<float, kEqualizerBandCount>& bands_db) {
    for (size_t i = 0; i < kEqualizerBandCount; ++i) {
        float value = bands_db[i];
        if (!std::isfinite(value)) value = 0.0f;
        value = std::clamp(value, -6.0f, 6.0f);
        impl_->equalizer_bands_db[i].store(value, std::memory_order_relaxed);
    }
}

std::array<float, kEqualizerBandCount> Session::equalizer_bands() const {
    std::array<float, kEqualizerBandCount> out{};
    for (size_t i = 0; i < kEqualizerBandCount; ++i) {
        out[i] = impl_->equalizer_bands_db[i].load(std::memory_order_relaxed);
    }
    return out;
}

std::string Session::access_token() const {
    auto* ct = audio::get_client_token_provider();
    auto* l5 = audio::get_login5_provider();
    if (!ct || !l5) return {};
    std::string ctok = ct->token();
    if (ctok.empty()) return {};
    return l5->access_token(ctok);
}

} // namespace librespotc
