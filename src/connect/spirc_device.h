#pragma once
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "put_state.h"
#include "context_state.h"

namespace librespotc::auth {
class ClientTokenProvider;
class Login5Provider;
}

namespace librespotc::connect {

// Callbacks SpircDevice fires when a cloud command arrives. Each must be
// thread-safe; called from the dealer reader thread.
struct SpircCallbacks {
    // Transfer playback to this device. uri = current track to start.
    std::function<void(const std::string& track_uri, uint32_t position_ms,
                       bool play)> on_transfer;
    std::function<void()>                       on_play;
    std::function<void()>                       on_pause;
    std::function<void(uint32_t position_ms)>   on_seek;
    std::function<void(uint32_t volume_0_65535)> on_volume;
    std::function<void()>                       on_skip_next;
    std::function<void()>                       on_skip_prev;
    // Cloud-provided playback context (playlist/album URI + URL). Fires
    // before on_transfer/on_play so the host can update its state PUT
    // accordingly. Either string may be empty if the cloud didn't supply it.
    std::function<void(const std::string& context_uri,
                       const std::string& context_url)> on_context_change;
    // Cluster update arrived where active_device_id is not us. Library
    // should stop playback and idle.
    std::function<void(const std::string& new_active_device_id)> on_became_inactive;
};

class SpircDevice {
public:
    struct ContextSeed {
        std::string context_uri;
        std::string context_url;
        std::string current_track_uri;
        PlayOrigin play_origin;
        ContextState::Options options;
        bool has_context = false;
    };

    SpircDevice(DeviceConfig dev_cfg,
                auth::ClientTokenProvider& ct,
                auth::Login5Provider& l5,
                SpircCallbacks cb);
    ~SpircDevice();

    // Connect to dealer + register device. Returns true if dealer opened
    // and PUT /connect-state succeeded. Spawns reader thread.
    bool start();

    // Notify cloud of local state change (player started/paused/track changed).
    // context_uri/url: optional playback context (playlist/album URI + URL).
    // Empty → encode_put_state falls back to the track URI.
    void notify_state(bool is_active,
                      const std::string& current_track_uri,
                      bool is_playing,
                      uint32_t position_ms,
                      uint32_t duration_ms = 0,
                      const std::string& context_uri = "",
                      const std::string& context_url = "");

    void stop();

    // Host-driven entry points should clear the cloud-supplied context so
    // PUT state stops claiming we're inside a playlist that's no longer
    // playing.
    void clear_context();

    // Peek the next track URI for gapless pre-fetch. Empty if context has
    // no next track or library is queue-empty.
    std::string peek_next_track_uri() const {
        auto s = ctx_state_.snapshot();
        if (s.next_tracks.empty()) return {};
        return s.next_tracks.front().uri;
    }

    // Like peek_next_track_uri but also advances current_index — caller is
    // about to start playing it. Used by Session::handle_natural_end.
    std::string advance_to_next_track(bool force_wrap = false,
                                      bool ignore_repeat_track = false) {
        if (auto queued = pop_explicit_queue_track(); !queued.empty()) {
            std::fprintf(stderr,
                "[connect-queue] natural/end advance using explicit queue uri=%s\n",
                queued.c_str());
            return queued;
        }
        auto before = ctx_state_.snapshot();
        if (!ctx_state_.advance_next(force_wrap, ignore_repeat_track)) {
            std::fprintf(stderr,
                "[spirc] local next unavailable current=%s index=%u "
                "next_count=%zu repeat_ctx=%d repeat_track=%d force_wrap=%d "
                "ignore_repeat=%d\n",
                before.current.uri.c_str(), before.index_track,
                before.next_tracks.size(),
                (int)before.options.repeating_context,
                (int)before.options.repeating_track,
                (int)force_wrap,
                (int)ignore_repeat_track);
            return {};
        }
        auto s = ctx_state_.snapshot();
        if (!s.has_tracks) return {};
        if (s.current.uri == before.current.uri && ignore_repeat_track) {
            std::fprintf(stderr,
                "[spirc] manual next resolved same track; suppressing replay "
                "current=%s index=%u total=%zu force_wrap=%d\n",
                s.current.uri.c_str(), s.index_track, s.track_count,
                (int)force_wrap);
            return {};
        }
        std::fprintf(stderr,
            "[spirc] local next resolved current=%s index=%u force_wrap=%d "
            "ignore_repeat=%d provider=%s total=%zu next=%zu\n",
            s.current.uri.c_str(), s.index_track, (int)force_wrap,
            (int)ignore_repeat_track, s.current.provider.c_str(),
            s.track_count, s.next_tracks.size());
        return s.current.uri;
    }

    bool is_running() const { return running_; }
    ContextSeed context_seed() const;
    void restore_context(const ContextSeed& seed);

private:
    void reader_loop();
    bool put_state(int32_t reason,
                   bool is_active,
                   const std::string& current_track_uri,
                   bool is_playing,
                   uint32_t position_ms,
                   uint32_t duration_ms);
    void queue_put_state(int32_t reason,
                         bool is_active,
                         std::string current_track_uri,
                         bool is_playing,
                         uint32_t position_ms,
                         uint32_t duration_ms);
    void put_state_worker_loop();

    std::string last_sender_id_;
    uint32_t    last_sender_msg_id_ = 0;
    void handle_message(const std::string& json_text);
    void handle_request(const std::string& json_text);
    void send_reply(const std::string& key, bool success);
    bool remember_command_key(const std::string& key);
    bool remember_command_message_order(const std::string& sender,
                                        uint32_t message_id,
                                        const std::string& endpoint);
    struct SkipToHint {
        std::string track_uri;
        std::string track_uid;
        int         track_index = -1;
        uint32_t    seek_ms     = 0;
        // True if the play handler already called on_transfer for the
        // resolved URI (always the case when track_uri is non-empty). The
        // resolver then skips a duplicate on_transfer.
        bool        already_dispatched = false;
        // Spotify can start a shuffled playlist by sending only the first
        // track's UID. Commercial devices treat that as a context shuffle
        // start, not a deliberate selection of physical index 0.
        bool        allow_shuffle_start_override = false;
    };
    void kick_context_resolver(const std::string& new_ctx_uri,
                                const SkipToHint& hint);
    void maybe_kick_autoplay();
    void remember_cloud_queue_hint(const uint8_t* data, size_t len,
                                   const std::string& active_device_id);
    bool remember_explicit_queue(const uint8_t* data, size_t len,
                                 const std::string& active_device_id);
    bool add_explicit_queue_track(const std::string& track_uri,
                                  const std::string& uid,
                                  const char* source);
    void add_explicit_queue_context_async(std::string context_uri,
                                          std::string current_track_uri,
                                          const char* source);
    std::vector<std::string> matching_cloud_queue_hint(
        const std::string& context_uri,
        const std::string& current_track_uri) const;
    std::vector<ProvidedTrack> explicit_queue_snapshot() const;
    std::string pop_explicit_queue_track();
    bool replace_explicit_queue_tracks(std::vector<ProvidedTrack> tracks,
                                       const char* source);
    void remember_playback_state(const std::string& current_track_uri,
                                 bool is_playing,
                                 uint32_t position_ms,
                                 uint32_t duration_ms);
    uint32_t estimated_playback_position_ms(
        const std::string& current_track_uri) const;
    uint32_t remembered_playback_duration_ms(
        const std::string& current_track_uri) const;
    bool remembered_playback_is_playing(
        const std::string& current_track_uri,
        bool fallback) const;
    std::atomic<bool> autoplay_in_flight_{false};

    // Set true while the context resolver worker is in flight. Skip
    // commands that arrive in this window are deferred via pending_skip_*.
    std::atomic<bool> resolver_in_flight_{false};
    std::atomic<int>  pending_skip_dir_{0};  // +1 = next, -1 = prev, 0 = none
    std::atomic<uint64_t> context_generation_{0};
    std::atomic<uint64_t> resolver_generation_{0};

    // Live device volume (0..65535). Initialized from DeviceConfig in
    // start(), updated by cluster + set_volume command, echoed in
    // PUT state DeviceInfo.volume so cloud's view stays in sync.
    std::atomic<uint32_t> current_volume_{32768};

    // Cloud's most recent view of whether we're the active player.
    // Updated by Cluster.active_device_id parse. Cluster volume updates
    // are broadcasts that embed the CONTROLLING device's id, not the
    // target — when we're the active player we should apply them.
    std::atomic<bool> is_active_cloud_{false};

    DeviceConfig dev_cfg_;
    auth::ClientTokenProvider& ct_;
    auth::Login5Provider& l5_;
    SpircCallbacks cb_;

    struct Impl;
    std::unique_ptr<Impl> impl_;

    std::thread thread_;
    std::atomic<bool> running_{false};
    std::atomic<bool> stop_flag_{false};
    std::string connection_id_;
    std::string spclient_base_;
    std::mutex state_m_;
    uint32_t message_id_ = 0;
    struct PendingPutState {
        int32_t reason = 4;
        bool is_active = false;
        std::string current_track_uri;
        bool is_playing = false;
        uint32_t position_ms = 0;
        uint32_t duration_ms = 0;
        std::chrono::steady_clock::time_point queued_at{};
    };
    std::thread put_thread_;
    std::atomic<bool> put_stop_{false};
    std::mutex put_m_;
    std::condition_variable put_cv_;
    std::deque<PendingPutState> put_queue_;
    std::mutex command_m_;
    std::deque<std::string> recent_command_keys_;
    std::unordered_map<std::string, uint32_t> last_command_msg_by_sender_;

    struct CloudQueueHint {
        std::string context_uri;
        std::string current_track_uri;
        std::vector<std::string> track_uris;
        uint64_t generation = 0;
    };
    mutable std::mutex cloud_queue_m_;
    CloudQueueHint cloud_queue_hint_;
    std::deque<ProvidedTrack> explicit_queue_tracks_;
    uint64_t cloud_queue_generation_ = 0;

    mutable std::mutex playback_state_m_;
    std::string last_playback_track_uri_;
    bool last_playback_is_playing_ = false;
    uint32_t last_playback_position_ms_ = 0;
    uint32_t last_playback_duration_ms_ = 0;
    std::chrono::steady_clock::time_point last_playback_clock_{};

    // Most recent cloud-provided playback context. Sticky — kept across
    // request acks so cloud sees a stable context_uri until cleared.
    std::string ctx_uri_;
    std::string ctx_url_;

    // Full context state — current position, next_tracks/prev_tracks
    // lookahead, queue_revision. Mutated by parse paths + the context
    // resolver worker. Snapshot()ed on the PUT-state encoder thread.
    ContextState ctx_state_;

    // Last-resolved context URI, so we don't re-fetch tracks for the same
    // context on every state change.
    std::string resolved_ctx_uri_;
};

} // namespace librespotc::connect
